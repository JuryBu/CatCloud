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
  Loader2,
  Package,
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
  type NodeHealthHint,
  type ProbeDefinition,
  type ProbeKind,
  type ProbeSnapshot,
  type ProxyNode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect } from "../components/AppSelect";
import { ContinentRegionFilter, PaginationBar } from "../components/ContinentRegionFilter";
import { GroupMembershipPopover } from "../components/GroupMembershipPopover";
import { MascotSprite } from "../components/MascotSprite";
import { ShareBundleModal } from "../components/ShareBundleModal";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import {
  appActions,
  appStore,
  selectIsProbeEngineBusy,
  useAppSelector,
} from "../store/appStore";
import {
  countVerifiedAiUnlocks,
  formatGoogleRegionTooltip,
  getAiBadgeToneClass,
  getNodeAiBadgeDisplays,
  hasVerifiedAiUnlock,
  isProxyRiskSnapshot,
} from "../utils/aiUnlockDisplay";
import {
  type ResolvedNodeLatency,
  getLatencyTooltipKey,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "../utils/latencyDisplay";
import {
  type ContinentId,
  buildContinentRegionStats,
  getRegionLabel,
  nodeMatchesContinentAndRegion,
  resolveNodeRegionCode,
} from "../utils/regions";
import {
  isBoolPref,
  oneOfPref,
  readUiPref,
  usePersistedState,
  writeUiPref,
} from "../utils/uiPrefs";

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
    title: "Windsurf / Devin 纯净解锁",
    desc: "检测 Windsurf / Devin AI 推理网关与出口 IP 纯净度（防代理风控假绿灯）",
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
    name: "Windsurf / Devin AI 纯净解锁",
    kind: "unlock_regex",
    target: "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage",
    method: "POST",
    expectedStatus: null,
    timeoutMs: 9000,
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
    name: "Windsurf 推理网关可达",
    target: "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage",
    bodyRegex: "",
  },
];

const TIER_LABELS: Record<SpeedTestTier, string> = {
  latency: "仅快测延迟",
  unlock: "测延迟 + 送中/AI",
  full: "含上下行完整测速",
};

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

function hasAnyAiUnlocked(snap: ProbeSnapshot | undefined): boolean {
  return hasVerifiedAiUnlock(snap);
}

function isGoldenCore(snap: ProbeSnapshot | undefined): boolean {
  return Boolean(
    snap &&
      snap.ok &&
      snap.google_clean === true &&
      !isProxyRiskSnapshot(snap) &&
      hasAnyAiUnlocked(snap)
  );
}

function hasMeasuredSpeed(snap: ProbeSnapshot | undefined): boolean {
  return hasValidUpMbps(snap) || hasValidDownMbps(snap);
}

interface ProbeTimestampIdSets {
  latencyIds: ReadonlySet<string>;
  speedIds: ReadonlySet<string>;
}

function buildProbeTimestampIdSets(
  probeList: ReadonlyArray<Pick<ProbeItem, "id" | "kind">>
): ProbeTimestampIdSets {
  const latencyIds = new Set<string>(["builtin_latency"]);
  const speedIds = new Set<string>(["builtin_upload", "builtin_download"]);
  for (const probe of probeList) {
    if (probe.kind === "latency") {
      latencyIds.add(probe.id);
    } else if (
      probe.kind === "upload" ||
      probe.kind === "download" ||
      probe.kind === "external_cmd"
    ) {
      speedIds.add(probe.id);
    }
  }
  return { latencyIds, speedIds };
}

function resolveProbeTimestamps(
  snap: ProbeSnapshot | undefined,
  idSets: ProbeTimestampIdSets
): {
  latencyAt: string | null;
  speedAt: string | null;
  fallbackAt: string | null;
} {
  if (!snap) return { latencyAt: null, speedAt: null, fallbackAt: null };
  const map = snap.per_probe_tested_at;
  const pickNewestIso = (candidates: Array<string | undefined | null>): string | null => {
    let bestIso: string | null = null;
    let bestTs = -Infinity;
    for (const raw of candidates) {
      if (!raw) continue;
      const ts = Date.parse(raw);
      if (Number.isFinite(ts) && ts > bestTs) {
        bestTs = ts;
        bestIso = raw;
      }
    }
    return bestIso;
  };
  if (map && Object.keys(map).length > 0) {
    const latencyCandidates: string[] = [];
    const speedCandidates: string[] = [];
    for (const [pid, ts] of Object.entries(map)) {
      if (!ts) continue;
      const isLat =
        idSets.latencyIds.has(pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_ping_ms ?? {}, pid);
      const isSpeed =
        idSets.speedIds.has(pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_up_mbps ?? {}, pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_down_mbps ?? {}, pid);
      if (isLat) latencyCandidates.push(ts);
      if (isSpeed) speedCandidates.push(ts);
    }
    const latencyAt = pickNewestIso(latencyCandidates);
    const speedAt = pickNewestIso(speedCandidates);
    return {
      latencyAt,
      speedAt,
      fallbackAt: !latencyAt && !speedAt ? (snap.tested_at ?? null) : null,
    };
  }
  return {
    latencyAt: null,
    speedAt: null,
    fallbackAt: snap.tested_at ?? null,
  };
}

function formatSpeedTestLatencyTooltip(
  resolved: ResolvedNodeLatency,
  dict: ReturnType<typeof useUiDict>,
  hint?: NodeHealthHint | null,
  cooldownRemainingSec = 0
): string {
  const tipKey = getLatencyTooltipKey(resolved);
  const base =
    tipKey === "probeHot"
      ? dict.latency.probeHotTooltip
      : tipKey === "healthCold"
        ? dict.latency.healthColdTooltip
        : tipKey === "failed"
          ? dict.latency.failedTooltip
          : dict.latency.untestedTooltip;
  const parts: string[] = [base];
  if (resolved.isProbation) parts.push(dict.latency.probationBadge);
  if (resolved.isDegraded) parts.push(dict.latency.degradedBadge);
  if (hint?.status === "cooldown") {
    parts.push(
      cooldownRemainingSec > 0
        ? formatI18nTemplate(dict.latency.cooldownRetryHint, {
            sec: cooldownRemainingSec,
          })
        : dict.latency.cooldownHint
    );
  }
  if (hint?.reason?.trim()) {
    parts.push(`${dict.latency.reasonPrefix}${hint.reason.trim()}`);
  }
  if (hint?.stage?.trim()) {
    parts.push(`${dict.latency.stagePrefix}${hint.stage.trim()}`);
  }
  return parts.join(" · ");
}

const SPEEDTEST_FILTERS_PREF_KEY = "speedtest.filters.v1";
let speedTestPersistedFiltersHydrated = false;

interface PersistedSpeedTestFilters {
  searchQuery?: string;
  sourceFilter?: string;
  groupFilter?: string;
  filterContinent?: ContinentId;
  regionFilter?: string;
  onlyGolden?: boolean;
  onlyTested?: boolean;
  onlyGoogleClean?: boolean;
  onlyAiUnlocked?: boolean;
  goldenManualSortOverride?: boolean;
}

const VALID_CONTINENTS: readonly ContinentId[] = [
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
];

function validatePersistedSpeedTestFilters(
  raw: unknown
): PersistedSpeedTestFilters | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  const out: PersistedSpeedTestFilters = {};
  if (typeof obj.searchQuery === "string") out.searchQuery = obj.searchQuery;
  if (typeof obj.sourceFilter === "string") out.sourceFilter = obj.sourceFilter;
  if (typeof obj.groupFilter === "string") out.groupFilter = obj.groupFilter;
  if (
    typeof obj.filterContinent === "string" &&
    (VALID_CONTINENTS as readonly string[]).includes(obj.filterContinent)
  ) {
    out.filterContinent = obj.filterContinent as ContinentId;
  }
  if (typeof obj.regionFilter === "string") out.regionFilter = obj.regionFilter;
  if (typeof obj.onlyGolden === "boolean") out.onlyGolden = obj.onlyGolden;
  if (typeof obj.onlyTested === "boolean") out.onlyTested = obj.onlyTested;
  if (typeof obj.onlyGoogleClean === "boolean") out.onlyGoogleClean = obj.onlyGoogleClean;
  if (typeof obj.onlyAiUnlocked === "boolean") out.onlyAiUnlocked = obj.onlyAiUnlocked;
  if (typeof obj.goldenManualSortOverride === "boolean") {
    out.goldenManualSortOverride = obj.goldenManualSortOverride;
  }
  return out;
}

function persistSpeedTestFiltersFromStore(): void {
  const d = appStore.getState().sessionDrafts.speedTest;
  writeUiPref<PersistedSpeedTestFilters>(SPEEDTEST_FILTERS_PREF_KEY, {
    searchQuery: d.searchQuery,
    sourceFilter: d.sourceFilter,
    groupFilter: d.groupFilter,
    filterContinent: (d.filterContinent as ContinentId | undefined) ?? "all",
    regionFilter: d.regionFilter,
    onlyGolden: d.onlyGolden,
    onlyTested: d.onlyTested,
    onlyGoogleClean: d.onlyGoogleClean,
    onlyAiUnlocked: d.onlyAiUnlocked,
    goldenManualSortOverride: Boolean(d.goldenManualSortOverride),
  });
}

function formatRelativeProbeTime(iso?: string | null): { short: string; full: string } | null {
  if (!iso) return null;
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return null;
  const date = new Date(ts);
  const full = date.toLocaleString();
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 45) return { short: "刚刚测过", full };
  if (diffSec < 3600) return { short: `${Math.floor(diffSec / 60)}分钟前`, full };
  if (diffSec < 86400) return { short: `${Math.floor(diffSec / 3600)}小时前`, full };
  const days = Math.floor(diffSec / 86400);
  return { short: `${days}天前`, full };
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
  const dict = useUiDict(normalizeUiLanguage(config.personalization.ui_language));
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const preAccelRelays = useAppSelector((s) => s.preAccelRelays);
  const runtime = useAppSelector((s) => s.runtime);
  const isSingleMode = runtime.route_mode === "single";
  const probes = useAppSelector((s) => s.probes);
  const probeProgress = useAppSelector((s) => s.probeProgress);
  const probeLocalStarting = useAppSelector((s) => s.bgTasks.probeLocalStarting);
  const isPausing = useAppSelector((s) => s.bgTasks.probeIsPausing);
  const probeLockedOrderIds = useAppSelector((s) => s.bgTasks.probeLockedOrderIds);
  const probeActiveNodeIds = useAppSelector((s) => s.bgTasks.probeActiveNodeIds);
  const benchmarkRunning = useAppSelector((s) => s.bgTasks.preaccel.benchmark.running);
  const isProbeEngineBusy = useAppSelector(selectIsProbeEngineBusy);
  const speedTestDraft = useAppSelector((s) => s.sessionDrafts.speedTest);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  const hasEnabledPreAccelRelay = useMemo(
    () => preAccelRelays.some((r) => r.enabled),
    [preAccelRelays]
  );
  const defaultUsePreaccel = config.preaccel.enabled && hasEnabledPreAccelRelay;
  const [manualUsePreaccel, setManualUsePreaccel] = useState<boolean | null>(() =>
    readUiPref<boolean | null>("speedtest.usePreaccel", null, isBoolPref)
  );
  const usePreaccelForProbe = hasEnabledPreAccelRelay
    ? (manualUsePreaccel ?? defaultUsePreaccel)
    : false;

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
  const [showProbeSettings, setShowProbeSettings] = usePersistedState<boolean>(
    "speedtest.showProbeSettings",
    false,
    isBoolPref
  );
  const [moreFiltersOpen, setMoreFiltersOpen] = usePersistedState<boolean>(
    "speedtest.moreFiltersOpen",
    false,
    isBoolPref
  );
  const [showAddProbe, setShowAddProbe] = useState(false);
  const [newProbeId, setNewProbeId] = useState("");
  const [newProbeName, setNewProbeName] = useState("");
  const [newProbeKind, setNewProbeKind] = useState<ProbeKind>("upload");
  const [newProbeTarget, setNewProbeTarget] = useState("");
  const [newProbeRegex, setNewProbeRegex] = useState("");
  const [newProbePayloadKb, setNewProbePayloadKb] = useState(512);
  const [newProbeTimeoutMs, setNewProbeTimeoutMs] = useState(10000);

  // Speed test execution options & state (backed by global appStore.bgTasks)
  const [pendingLargeRun, setPendingLargeRun] = useState<{
    tier: SpeedTestTier;
    targetNodeIds?: string[];
    forceSkipKeepalive?: boolean;
  } | null>(null);
  const [switchingNodeId, setSwitchingNodeId] = useState<string | null>(null);

  // Filters, sorting & pagination (backed by global appStore.sessionDrafts.speedTest + localStorage persistence)
  useEffect(() => {
    if (speedTestPersistedFiltersHydrated) return;
    speedTestPersistedFiltersHydrated = true;
    const saved = readUiPref<PersistedSpeedTestFilters | null>(
      SPEEDTEST_FILTERS_PREF_KEY,
      null,
      validatePersistedSpeedTestFilters
    );
    if (!saved) return;
    const patch: Partial<typeof speedTestDraft> = {};
    if (saved.searchQuery !== undefined) patch.searchQuery = saved.searchQuery;
    if (!initialSubId && saved.sourceFilter !== undefined) {
      patch.sourceFilter = saved.sourceFilter;
    }
    if (saved.groupFilter !== undefined) patch.groupFilter = saved.groupFilter;
    if (saved.filterContinent !== undefined) patch.filterContinent = saved.filterContinent;
    if (saved.regionFilter !== undefined) patch.regionFilter = saved.regionFilter;
    if (saved.onlyGolden !== undefined) patch.onlyGolden = saved.onlyGolden;
    if (saved.onlyTested !== undefined) patch.onlyTested = saved.onlyTested;
    if (saved.onlyGoogleClean !== undefined) patch.onlyGoogleClean = saved.onlyGoogleClean;
    if (saved.onlyAiUnlocked !== undefined) patch.onlyAiUnlocked = saved.onlyAiUnlocked;
    if (saved.goldenManualSortOverride !== undefined) {
      patch.goldenManualSortOverride = saved.goldenManualSortOverride;
    }
    if (Object.keys(patch).length > 0) {
      appActions.patchSessionDraft("speedTest", patch);
    }
  }, [initialSubId]);

  const searchQuery = speedTestDraft.searchQuery;
  const sourceFilter = speedTestDraft.sourceFilter;
  const groupFilter = speedTestDraft.groupFilter;
  const filterContinent = (speedTestDraft.filterContinent as ContinentId | undefined) ?? "all";
  const regionFilter = speedTestDraft.regionFilter;
  const onlyGolden = speedTestDraft.onlyGolden;
  const onlyTested = speedTestDraft.onlyTested;
  const onlyGoogleClean = speedTestDraft.onlyGoogleClean;
  const onlyAiUnlocked = speedTestDraft.onlyAiUnlocked;
  const goldenManualSortOverride = Boolean(speedTestDraft.goldenManualSortOverride);
  const page = speedTestDraft.page;

  const setSearchQuery = useCallback((val: string) => {
    appActions.patchSessionDraft("speedTest", { searchQuery: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setSourceFilter = useCallback((val: string) => {
    appActions.patchSessionDraft("speedTest", { sourceFilter: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setGroupFilter = useCallback((val: string) => {
    appActions.patchSessionDraft("speedTest", { groupFilter: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setFilterContinent = useCallback((val: ContinentId) => {
    appActions.patchSessionDraft("speedTest", { filterContinent: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setRegionFilter = useCallback((val: string) => {
    appActions.patchSessionDraft("speedTest", { regionFilter: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setOnlyGolden = useCallback((val: boolean) => {
    appActions.patchSessionDraft("speedTest", { onlyGolden: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setOnlyTested = useCallback((val: boolean | ((prev: boolean) => boolean)) => {
    const cur = appStore.getState().sessionDrafts.speedTest.onlyTested;
    const next = typeof val === "function" ? val(cur) : val;
    appActions.patchSessionDraft("speedTest", { onlyTested: next });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setOnlyGoogleClean = useCallback((val: boolean | ((prev: boolean) => boolean)) => {
    const cur = appStore.getState().sessionDrafts.speedTest.onlyGoogleClean;
    const next = typeof val === "function" ? val(cur) : val;
    appActions.patchSessionDraft("speedTest", { onlyGoogleClean: next });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setOnlyAiUnlocked = useCallback((val: boolean | ((prev: boolean) => boolean)) => {
    const cur = appStore.getState().sessionDrafts.speedTest.onlyAiUnlocked;
    const next = typeof val === "function" ? val(cur) : val;
    appActions.patchSessionDraft("speedTest", { onlyAiUnlocked: next });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setGoldenManualSortOverride = useCallback((val: boolean) => {
    appActions.patchSessionDraft("speedTest", { goldenManualSortOverride: val });
    persistSpeedTestFiltersFromStore();
  }, []);
  const setPage = useCallback((val: number) => {
    appActions.patchSessionDraft("speedTest", { page: val });
  }, []);

  const prevInitialSubIdRef = useRef<string | null | undefined>(initialSubId);
  const [sortKey, setSortKey] = usePersistedState<SortKey>(
    "speedtest.sortKey",
    "latency",
    oneOfPref(["name", "source", "latency", "up", "down", "google", "unlocks"] as const)
  );
  const [sortDir, setSortDir] = usePersistedState<SortDir>(
    "speedtest.sortDir",
    "asc",
    oneOfPref(["asc", "desc"] as const)
  );
  const [pageSize, setPageSize] = usePersistedState<number>(
    "speedtest.pageSize",
    50,
    oneOfPref(PAGE_SIZE_OPTIONS)
  );

  // Multi-selection & Ctrl+left-button drag selection (backed by sessionDrafts.speedTest.selectedIds)
  const selectedIds = useMemo(
    () => new Set(speedTestDraft.selectedIds),
    [speedTestDraft.selectedIds]
  );
  const setSelectedIds = useCallback(
    (updater: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const prevSet = new Set(appStore.getState().sessionDrafts.speedTest.selectedIds);
      const nextSet = typeof updater === "function" ? updater(prevSet) : updater;
      if (nextSet === prevSet) return;
      appActions.patchSessionDraft("speedTest", { selectedIds: Array.from(nextSet) });
    },
    []
  );
  const [lastAnchorId, setLastAnchorId] = useState<string | null>(null);
  const [ctrlHeld, setCtrlHeld] = useState(false);
  const [modifierHeld, setModifierHeld] = useState(false);

  // Streaming row pulse highlights when new probe snapshots arrive
  const [recentFlashIds, setRecentFlashIds] = useState<Set<string>>(() => new Set());
  const prevTestedAtRef = useRef<Record<string, string>>({});
  const hydratedFlashRef = useRef(false);
  const flashTimersRef = useRef<Map<string, number>>(new Map());

  // Interaction refs
  const suppressClickRef = useRef(false);
  const suppressClickTimerRef = useRef<number | null>(null);
  const latestOrderedIdsRef = useRef<string[]>([]);
  const ctrlDragRef = useRef<CtrlDragState>({
    dragging: false,
    action: "add",
    visitedIds: new Set<string>(),
  });

  const isRunning = probeProgress.running || probeLocalStarting;
  const isBlockedByBenchmark = benchmarkRunning && !isRunning;
  const isProbeActionDisabled = isRunning || isBlockedByBenchmark || isProbeEngineBusy;

  const probeActiveNodeIdSet = useMemo(
    () => new Set(probeActiveNodeIds),
    [probeActiveNodeIds]
  );

  // Global locked row order survives page switches so rows never jump mid-test
  const lockedOrderMap = useMemo(() => {
    if (!isRunning || probeLockedOrderIds.length === 0) return null;
    const map = new Map<string, number>();
    probeLockedOrderIds.forEach((id, idx) => {
      if (!map.has(id)) map.set(id, idx);
    });
    return map;
  }, [isRunning, probeLockedOrderIds]);

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

  const captureCurrentRowOrderIds = useCallback((): string[] => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const id of latestOrderedIdsRef.current) {
      if (!seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
    for (const node of nodes) {
      if (!seen.has(node.id)) {
        seen.add(node.id);
        out.push(node.id);
      }
    }
    return out;
  }, [nodes]);

  // Cleanup only local UI highlight timers on unmount — NEVER cancel running background probes
  useEffect(() => {
    const flashTimers = flashTimersRef.current;
    return () => {
      if (suppressClickTimerRef.current !== null) {
        window.clearTimeout(suppressClickTimerRef.current);
        suppressClickTimerRef.current = null;
      }
      for (const timerId of flashTimers.values()) {
        window.clearTimeout(timerId);
      }
      flashTimers.clear();
    };
  }, []);

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
          appActions.syncProbeDefinitions(mapped);
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

  // Sync explicit subscription jump filter only when initialSubId actually changes
  useEffect(() => {
    if (prevInitialSubIdRef.current !== initialSubId) {
      prevInitialSubIdRef.current = initialSubId;
      setSourceFilter(initialSubId || "all");
      setPage(1);
    }
  }, [initialSubId, setSourceFilter, setPage]);

  useEffect(() => {
    if (!initialized || sourceFilter === "all") return;
    if (!sourceOptions.some((opt) => opt.id === sourceFilter)) {
      setSourceFilter("all");
    }
  }, [initialized, sourceFilter, sourceOptions, setSourceFilter]);

  useEffect(() => {
    if (!initialized || groupFilter === "all") return;
    if (groups.every((g) => g.id !== groupFilter)) {
      setGroupFilter("all");
    }
  }, [initialized, groupFilter, groups, setGroupFilter]);

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

  const baseFilteredRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const healthHints = runtime.node_health_hints;
    return nodes
      .map((node) => {
        const snap = probes[node.id];
        const healthHint = healthHints?.[node.id];
        const resolvedLatency = resolveNodeDisplayLatency(snap, healthHint);
        const hasFreshHealthLatency =
          resolvedLatency.source === "health" && resolvedLatency.latencyMs !== null;
        const isCooldown =
          healthHint?.status === "cooldown" && resolvedLatency.state === "failed";
        const cooldownRemainingSec = isCooldown
          ? Math.max(0, Math.ceil(healthHint?.cooldown_remaining_sec ?? 0))
          : 0;
        const effectiveLatencyMs = resolvedLatency.latencyMs;
        const effectiveLatencyOk: boolean | undefined =
          resolvedLatency.state === "failed"
            ? false
            : resolvedLatency.ok
              ? true
              : undefined;
        const sourceName = subNameById.get(node.sub_id) ?? node.sub_id;
        const regionCode = resolveNodeRegionCode(node);
        const regionLabel = getRegionLabel(regionCode);
        const aiBadges = getNodeAiBadgeDisplays(snap);
        const hasUnlockData = Boolean(
          snap &&
            (Object.keys(snap.unlocked_sites ?? {}).length > 0 ||
              snap.per_probe_ok?.builtin_unlock_windsurf !== undefined ||
              snap.ip_risk_level != null ||
              snap.google_clean !== null)
        );
        const unlockScore = countVerifiedAiUnlocks(snap);
        const isGoogleClean = snap?.google_clean === true;
        const goldenCore = isGoldenCore(snap);
        const measuredSpeed = hasMeasuredSpeed(snap);
        const isGolden = goldenCore && measuredSpeed;
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
          healthHint,
          resolvedLatency,
          hasFreshHealthLatency,
          isCooldown,
          cooldownRemainingSec,
          effectiveLatencyMs,
          effectiveLatencyOk,
          sourceName,
          regionCode,
          regionLabel,
          aiBadges,
          hasUnlockData,
          unlockScore,
          isGoogleClean,
          isGoldenCore: goldenCore,
          hasMeasuredSpeed: measuredSpeed,
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
        if (onlyTested && !row.snap) return false;
        if (onlyGoogleClean && !row.isGoogleClean) return false;
        if (onlyAiUnlocked && row.unlockScore === 0) return false;
        return true;
      });
  }, [
    nodes,
    probes,
    runtime.node_health_hints,
    subNameById,
    searchQuery,
    sourceFilter,
    selectedGroupObj,
    selectedGroupMemberSet,
    selectedGroupDynamicFilter,
    filterContinent,
    regionFilter,
    onlyTested,
    onlyGoogleClean,
    onlyAiUnlocked,
  ]);

  const anyTestedInAllNodes = useMemo(
    () => nodes.some((n) => Boolean(probes[n.id])),
    [nodes, probes]
  );

  const anyUnlockTestedInAllNodes = useMemo(
    () =>
      nodes.some((n) => {
        const snap = probes[n.id];
        if (!snap) return false;
        return (
          snap.google_clean !== null ||
          Object.keys(snap.unlocked_sites ?? {}).length > 0 ||
          snap.per_probe_ok?.builtin_unlock_windsurf !== undefined
        );
      }),
    [nodes, probes]
  );

  const {
    filteredRows,
    isGoldenLatencyFallback,
    goldenFallbackCandidates,
    goldenHiddenCandidates,
    effectiveSortKey,
    effectiveSortDir,
  } = useMemo(() => {
    let list = [...baseFilteredRows];
    let fallbackActive = false;
    let fallbackCandidates: typeof baseFilteredRows = [];
    let hiddenCandidates: typeof baseFilteredRows = [];
    let activeSortKey: SortKey = sortKey;
    let activeSortDir: SortDir = sortDir;

    if (onlyGolden) {
      const goldenCoreRows = baseFilteredRows.filter((row) => row.isGoldenCore);
      const goldenFullRows = goldenCoreRows.filter((row) => row.hasMeasuredSpeed);
      if (goldenFullRows.length > 0) {
        list = [...goldenFullRows];
        hiddenCandidates = goldenCoreRows.filter((row) => !row.hasMeasuredSpeed);
        if (!goldenManualSortOverride) {
          activeSortKey = "up";
          activeSortDir = "desc";
        }
      } else if (goldenCoreRows.length > 0) {
        fallbackActive = true;
        fallbackCandidates = goldenCoreRows;
        list = [...goldenCoreRows];
        if (!goldenManualSortOverride) {
          activeSortKey = "latency";
          activeSortDir = "asc";
        }
      } else {
        list = [];
      }
    }

    if (isRunning && lockedOrderMap) {
      list.sort((a, b) => {
        const aIdx = lockedOrderMap.get(a.node.id) ?? Number.MAX_SAFE_INTEGER;
        const bIdx = lockedOrderMap.get(b.node.id) ?? Number.MAX_SAFE_INTEGER;
        if (aIdx !== bIdx) return aIdx - bIdx;
        return a.node.name.localeCompare(b.node.name);
      });
      return {
        filteredRows: list,
        isGoldenLatencyFallback: fallbackActive,
        goldenFallbackCandidates: fallbackCandidates,
        goldenHiddenCandidates: hiddenCandidates,
        effectiveSortKey: activeSortKey,
        effectiveSortDir: activeSortDir,
      };
    }

    list.sort((a, b) => {
      let diff = 0;
      switch (activeSortKey) {
        case "name":
          diff = a.node.name.localeCompare(b.node.name);
          break;
        case "source":
          diff = a.sourceName.localeCompare(b.sourceName);
          break;
        case "latency": {
          const aVal = a.effectiveLatencyMs;
          const bVal = b.effectiveLatencyMs;
          const aHas = a.resolvedLatency.ok && aVal !== null;
          const bHas = b.resolvedLatency.ok && bVal !== null;
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (aVal ?? 99999) - (bVal ?? 99999);
          break;
        }
        case "up": {
          const aHas = hasValidUpMbps(a.snap);
          const bHas = hasValidUpMbps(b.snap);
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (a.snap?.up_mbps ?? -1) - (b.snap?.up_mbps ?? -1);
          break;
        }
        case "down": {
          const aHas = hasValidDownMbps(a.snap);
          const bHas = hasValidDownMbps(b.snap);
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (a.snap?.down_mbps ?? -1) - (b.snap?.down_mbps ?? -1);
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
      return activeSortDir === "asc" ? diff : -diff;
    });

    return {
      filteredRows: list,
      isGoldenLatencyFallback: fallbackActive,
      goldenFallbackCandidates: fallbackCandidates,
      goldenHiddenCandidates: hiddenCandidates,
      effectiveSortKey: activeSortKey,
      effectiveSortDir: activeSortDir,
    };
  }, [
    baseFilteredRows,
    onlyGolden,
    goldenManualSortOverride,
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

  const moreFilterActiveCount =
    (sourceFilter !== "all" ? 1 : 0) +
    (groupFilter !== "all" ? 1 : 0) +
    (filterContinent !== "all" || regionFilter !== "all" ? 1 : 0) +
    (onlyTested ? 1 : 0);

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

  const probeTimestampIdSets = useMemo(
    () => buildProbeTimestampIdSets(probeList),
    [probeList]
  );

  // Auto-dismiss large-run confirmation bar when selection changes or list shrinks
  useEffect(() => {
    if (!pendingLargeRun) return;
    if (isRunning) {
      setPendingLargeRun(null);
      return;
    }
    if (
      !pendingLargeRun.targetNodeIds &&
      (selectedCount > 0 || totalFiltered <= 50)
    ) {
      setPendingLargeRun(null);
    }
  }, [pendingLargeRun, selectedCount, totalFiltered, isRunning]);

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
    setGoldenManualSortOverride(false);
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
    const builtinLatencyProbe = probeList.find((p) => p.id === "builtin_latency");
    const builtinLatencyDisabled = Boolean(
      builtinLatencyProbe && !builtinLatencyProbe.enabled
    );
    if (tier === "latency" && !activeKinds.has("latency")) {
      appActions.showToast("请先在「测速项目设置」中开启「基础延迟」", "warn");
      return null;
    }
    if (
      (tier === "unlock" || tier === "full") &&
      (!activeKinds.has("latency") || builtinLatencyDisabled)
    ) {
      appActions.showToast(dict.speedTest.latencyDisabledHint, "info", 4800);
    }

    return Array.from(ids);
  };

  const executeProbes = async (
    targetNodeIds: string[],
    tier: SpeedTestTier,
    forceSkipKeepalive = false
  ) => {
    if (isBlockedByBenchmark) {
      appActions.showToast("国内提速对比测速正在后台进行，完成后即可运行节点测速", "info");
      return;
    }
    if (isRunning || isProbeEngineBusy) return;
    if (targetNodeIds.length === 0) {
      appActions.showToast("请先筛选或勾选至少一个节点后再开始测速", "warn");
      return;
    }

    const effectiveKeepalive = forceSkipKeepalive ? false : includeKeepalive;
    const probeIds = resolveProbeIdsForRun(tier, effectiveKeepalive);
    if (probeIds === null) return;

    const lockedOrderIds = captureCurrentRowOrderIds();
    const effectiveUsePreaccel = usePreaccelForProbe && hasEnabledPreAccelRelay;
    setPendingLargeRun(null);

    await appActions.runIsolatedProbesBg({
      nodeIds: targetNodeIds,
      probeIds,
      usePreAccel: effectiveUsePreaccel,
      lockedOrderIds,
      maxTier: tier,
      includeKeepalive: effectiveKeepalive,
    });
  };

  const handleGoldenCandidatesSpeedRun = (candidateNodeIds: string[]) => {
    if (isBlockedByBenchmark) {
      appActions.showToast("国内提速对比测速正在后台进行，完成后即可运行节点测速", "info");
      return;
    }
    if (isRunning || isProbeEngineBusy || candidateNodeIds.length === 0) return;
    if (candidateNodeIds.length > 50) {
      setPendingLargeRun({
        tier: "full",
        targetNodeIds: candidateNodeIds,
        forceSkipKeepalive: true,
      });
      return;
    }
    void executeProbes(candidateNodeIds, "full", true);
  };

  const handlePrimaryTestClick = (tier: SpeedTestTier) => {
    if (isBlockedByBenchmark) {
      appActions.showToast("国内提速对比测速正在后台进行，完成后即可运行节点测速", "info");
      return;
    }
    if (isRunning || isProbeEngineBusy) return;
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
      setPendingLargeRun({ tier });
      return;
    }

    void executeProbes(
      filteredRows.map((r) => r.node.id),
      tier
    );
  };

  const handlePauseTest = async () => {
    if (!isRunning || isPausing) return;
    await appActions.pauseIsolatedProbesBg();
  };

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
        appActions.syncProbeDefinitions(nextList);
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
        appActions.syncProbeDefinitions(nextList);
        return nextList;
      });
      appActions.showToast("已删除自定义测速项目", "info");
    } catch (err) {
      appActions.showToast(`删除测速项目失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSort = (key: SortKey) => {
    if (effectiveSortKey === key) {
      const nextDir: SortDir = effectiveSortDir === "asc" ? "desc" : "asc";
      setSortKey(key);
      setSortDir(nextDir);
    } else {
      setSortKey(key);
      setSortDir(key === "latency" || key === "name" || key === "source" ? "asc" : "desc");
    }
    if (onlyGolden) {
      setGoldenManualSortOverride(true);
    }
    setPage(1);
  };

  const renderSortIcon = (key: SortKey) => {
    if (effectiveSortKey !== key) {
      return <ArrowUpDown className="h-3 w-3 opacity-45" />;
    }
    return effectiveSortDir === "asc" ? (
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

  const probeBreakdown = useMemo(() => {
    let latencyOk = 0;
    let bandwidthOk = 0;
    let keepaliveOk = 0;
    let failed = 0;
    let untested = 0;
    for (const row of filteredRows) {
      const snap = row.snap;
      const resolved = row.resolvedLatency;
      if (resolved.state === "untested" && !snap) {
        untested += 1;
        continue;
      }
      if (resolved.ok && resolved.latencyMs !== null) {
        latencyOk += 1;
      } else if (resolved.state === "failed") {
        failed += 1;
      } else {
        untested += 1;
      }
      if (
        snap &&
        snap.ok !== false &&
        hasValidUpMbps(snap) &&
        hasValidDownMbps(snap)
      ) {
        bandwidthOk += 1;
      }
      if (snap?.keepalive_60s_ok === true) {
        keepaliveOk += 1;
      }
    }
    return { latencyOk, bandwidthOk, keepaliveOk, failed, untested };
  }, [filteredRows]);

  const lastProbeSummary = useAppSelector((s) => s.lastProbeSummary);

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
          </div>
        )}

        {/* Clean Primary Speed Test Controls + Collapsible Probe Options Trigger */}
        <div className={`${embedded ? "" : "mt-3.5"} flex flex-wrap items-center gap-2`}>
          <button
            type="button"
            disabled={isProbeActionDisabled || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("unlock")}
            title={
              isBlockedByBenchmark
                ? "国内提速对比测速正在后台进行，完成后可测速"
                : "主推省流方案：一次测出延迟、谷歌是否送中与 AI 解锁，约 0.2 MB/节点"
            }
            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
            <span>{dict.nodes.recommendedProbeBtn}</span>
            <span className="hidden rounded-md bg-black/15 px-1.5 py-0.5 text-[10px] font-medium sm:inline">
              {targetCountTag}
            </span>
          </button>

          <button
            type="button"
            disabled={isProbeActionDisabled || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("full")}
            title={
              isBlockedByBenchmark
                ? "国内提速对比测速正在后台进行，完成后可测速"
                : "测延迟 + 送中/AI + 真实上传/下载速度，约 3 MB/节点"
            }
            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--sky)]/60 bg-[var(--sky-soft)] px-3 py-2 text-xs font-semibold text-[var(--sky)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Rocket className="h-3.5 w-3.5 shrink-0" />
            <span>含上下行完整测速</span>
          </button>

          <button
            type="button"
            disabled={isProbeActionDisabled || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("latency")}
            title={
              isBlockedByBenchmark
                ? "国内提速对比测速正在后台进行，完成后可测速"
                : "只测节点连通与基础延迟，速度最快、保留旧的上下行和解锁记录"
            }
            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Zap className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            <span>仅快测延迟</span>
          </button>

          <button
            type="button"
            aria-expanded={showProbeSettings}
            onClick={() => setShowProbeSettings((v) => !v)}
            className={`ml-auto inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-2 text-xs font-medium transition-colors ${
              showProbeSettings
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : includeKeepalive
                  ? "border-[var(--amber)]/60 bg-[var(--amber-soft)]/50 text-[var(--text)] hover:border-[var(--amber)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
            }`}
            title="展开测速选项（国内提速、60 秒长连接与自定义测速项目）"
          >
            <Settings className="h-3.5 w-3.5 shrink-0" />
            <span>{dict.speedTest.probeOptionsBtn}</span>
            {includeKeepalive && (
              <span className="rounded-full border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--amber)]">
                {dict.speedTest.keepaliveActiveTag}
              </span>
            )}
            {showProbeSettings ? (
              <ChevronUp className="h-3.5 w-3.5 shrink-0" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5 shrink-0" />
            )}
          </button>
        </div>

        {/* Shared Probe Engine Mutex Notice when PreAccel Benchmark is Running */}
        {isBlockedByBenchmark && (
          <div className="mt-3 flex items-center gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-xs text-[var(--amber)]">
            <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
            <span>
              「国内提速」页正在后台运行提速效果对比测速，完成后即可运行节点测速
            </span>
          </div>
        )}

        {/* Lightweight Confirmation Bar when Batch Target > 50 Nodes */}
        {pendingLargeRun && !isRunning && (() => {
          const confirmTargetIds =
            pendingLargeRun.targetNodeIds ?? filteredRows.map((r) => r.node.id);
          const confirmCount = confirmTargetIds.length;
          return (
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs">
            <div className="flex items-center gap-2 text-[var(--text)]">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--amber)]" />
              <span>
                当前待测共 <strong className="cc-tabular">{confirmCount}</strong> 个节点，建议先筛选或分批测试；或者直接开始「
                {TIER_LABELS[pendingLargeRun.tier]}」：
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  void executeProbes(
                    confirmTargetIds.slice(0, 30),
                    pendingLargeRun.tier,
                    pendingLargeRun.forceSkipKeepalive ?? false
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
                    confirmTargetIds,
                    pendingLargeRun.tier,
                    pendingLargeRun.forceSkipKeepalive ?? false
                  )
                }
                className="rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)]"
              >
                全部测完 ({confirmCount} 个)
              </button>
              <button
                type="button"
                onClick={() => setPendingLargeRun(null)}
                className="rounded-lg px-2 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
              >
                {dict.common.cancel}
              </button>
            </div>
          </div>
          );
        })()}

        {/* Live Progress Strip (always shown when running; idle guide banner omitted in embedded mode to stay clean) */}
        {(!embedded || isRunning || includeKeepalive) && (
          <div
            className={`mt-3 flex flex-wrap ${embedded && !isRunning ? "py-2" : "min-h-[56px] py-2"} items-center justify-between gap-3 rounded-xl border px-3.5 transition-colors ${
              isRunning
                ? "border-[var(--accent)]/50 bg-[var(--bg-elevated)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)]/70"
            }`}
          >
            {isRunning ? (
              <>
                <div className="flex min-w-0 flex-1 flex-col justify-center gap-1.5">
                  <div className="flex min-w-0 items-center gap-2 text-xs">
                    <span className="cc-mono cc-tabular shrink-0 whitespace-nowrap font-semibold text-[var(--accent)]">
                      已完成 {probeProgress.completed} / 总计 {probeProgress.total}
                    </span>
                    <span className="shrink-0 text-[var(--muted)]">·</span>
                    <span className="min-w-0 truncate font-medium text-[var(--text)]">
                      {probeProgress.currentNodeName
                        ? `正在测：${probeProgress.currentNodeName}`
                        : "正在准备独立测速通道…"}
                    </span>
                    <span className="hidden shrink-0 whitespace-nowrap text-[11px] text-[var(--muted)] xl:inline">
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
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--red)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90 disabled:cursor-wait disabled:opacity-65"
                >
                  <Square className="h-3.5 w-3.5 shrink-0 fill-current" />
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

      {/* Collapsible Probe Options & Settings Drawer (Hidden by Default) */}
      {showProbeSettings && (
        <section className="cc-card cc-glass rounded-2xl p-4">
          {/* Quick Execution Options: Pre-Accel & 60s Keepalive */}
          <div className="mb-3.5 flex flex-wrap items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 p-2.5">
            <button
              type="button"
              role="switch"
              aria-checked={usePreaccelForProbe && hasEnabledPreAccelRelay}
              disabled={isRunning || !hasEnabledPreAccelRelay}
              onClick={() => {
                const next = !(usePreaccelForProbe && hasEnabledPreAccelRelay);
                setManualUsePreaccel(next);
                writeUiPref("speedtest.usePreaccel", next);
              }}
              title={
                hasEnabledPreAccelRelay
                  ? "开启后测速将经由已启用的国内提速线路测出真实提速表现；关闭可裸连对比"
                  : "需先在「国内提速」中添加并启用国内提速线路，方可走国内提速测速"
              }
              className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 ${
                usePreaccelForProbe && hasEnabledPreAccelRelay
                  ? "border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              <Zap className="h-3.5 w-3.5 shrink-0" />
              <span>同步走国内提速测速</span>
              <span
                className={`h-2 w-2 shrink-0 rounded-full ${
                  usePreaccelForProbe && hasEnabledPreAccelRelay
                    ? "bg-[var(--green)]"
                    : "bg-[var(--muted)]/50"
                }`}
              />
            </button>

            <label
              title="开启后每节点多耗时约 1 分钟，仅排查断流时建议勾选（与下方测速项目中的 60 秒长连接同步）"
              className={`inline-flex shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-1.5 text-xs transition-colors ${
                includeKeepalive
                  ? "border-[var(--amber)]/60 bg-[var(--amber-soft)] text-[var(--amber)]"
                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              } ${isRunning ? "pointer-events-none opacity-65" : ""}`}
            >
              <input
                type="checkbox"
                checked={includeKeepalive}
                disabled={isRunning}
                onChange={(e) => setKeepaliveSynced(e.target.checked)}
                className="h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
              />
              <Clock className="h-3.5 w-3.5 shrink-0" />
              <span className="font-medium">附带测 60 秒长连接</span>
              <span className="text-[10.5px] opacity-80">（每节点约 +1 分钟）</span>
            </label>
          </div>

          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">
                测速项目设置（{enabledProbeCount} 项已启用）
              </h2>
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
                <div>
                  <span className="block text-[11px] text-[var(--muted)]">测速类型</span>
                  <AppSelect
                    aria-label="测速类型"
                    size="sm"
                    value={newProbeKind}
                    onChange={(v) => setNewProbeKind(v as ProbeKind)}
                    options={[
                      { value: "latency", label: "基础延迟网址" },
                      { value: "upload", label: "上传测速网址" },
                      { value: "download", label: "下载测速网址" },
                      { value: "unlock_regex", label: "网站解锁检测" },
                      { value: "keepalive", label: "60 秒长连接" },
                      { value: "google_cn", label: "谷歌地区检测" },
                      { value: "external_cmd", label: "自定义外部脚本" },
                    ]}
                    className="mt-1 w-full"
                    buttonClassName="rounded-lg bg-[var(--card)]"
                  />
                </div>

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
                          ? "与上方「附带测 60 秒长连接」同步"
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
        {/* Clean First-Screen Filter Row: Search + Golden + Google Clean + AI Ready + More Filters + Reset */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="relative min-w-[180px] flex-1 sm:max-w-[260px]">
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

          <button
            type="button"
            onClick={() => {
              const next = !onlyGolden;
              setOnlyGolden(next);
              setGoldenManualSortOverride(false);
              setPage(1);
            }}
            title="筛选谷歌未送中、AI 有解锁且高速的优质节点；未测上下行时自动按延迟最低排好候选"
            className={`shrink-0 whitespace-nowrap rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold transition-colors ${
              onlyGolden
                ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)] hover:border-[var(--accent)]"
            }`}
          >
            {dict.nodes.goldenButton}
          </button>

          <button
            type="button"
            onClick={() => {
              setOnlyGoogleClean((v) => !v);
              setPage(1);
            }}
            className={`shrink-0 whitespace-nowrap rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
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
            className={`shrink-0 whitespace-nowrap rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              onlyAiUnlocked
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            AI 可用
          </button>

          <button
            type="button"
            aria-expanded={moreFiltersOpen}
            onClick={() => setMoreFiltersOpen((v) => !v)}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              moreFiltersOpen
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : moreFilterActiveCount > 0
                  ? "border-[var(--amber)]/60 bg-[var(--amber-soft)]/50 text-[var(--text)] hover:border-[var(--amber)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
            }`}
          >
            <Filter className="h-3.5 w-3.5 shrink-0" />
            <span>{dict.speedTest.moreFiltersBtn}</span>
            {moreFilterActiveCount > 0 && (
              <span className="cc-mono rounded-full border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--amber)]">
                {formatI18nTemplate(dict.speedTest.activeFiltersCount, {
                  count: moreFilterActiveCount,
                })}
              </span>
            )}
            {moreFiltersOpen ? (
              <ChevronUp className="h-3.5 w-3.5 shrink-0" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5 shrink-0" />
            )}
          </button>

          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleResetFilters}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              <RotateCcw className="h-3 w-3 shrink-0" />
              <span>{dict.speedTest.resetFiltersBtn}</span>
            </button>
          )}
        </div>

        {/* Collapsible More Filters Panel: Source, Multi-Group, Continent/Region, Tested State & Quick Sort */}
        {moreFiltersOpen && (
          <div className="mt-2.5 flex flex-wrap items-center gap-2 border-t border-[var(--line)]/60 pt-2.5 text-xs">
            <div className="inline-flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <AppSelect
                aria-label="按来源筛选"
                size="sm"
                value={sourceFilter}
                onChange={(v) => {
                  setSourceFilter(v);
                  setPage(1);
                }}
                options={[
                  { value: "all", label: "全部来源" },
                  ...sourceOptions.map((sub) => ({ value: sub.id, label: sub.name })),
                ]}
                className="min-w-[120px] max-w-[190px]"
                buttonClassName="rounded-lg"
              />
            </div>

            <div className="inline-flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <AppSelect
                aria-label="按多选组筛选"
                size="sm"
                value={groupFilter}
                onChange={(v) => {
                  setGroupFilter(v);
                  setPage(1);
                }}
                options={[
                  { value: "all", label: "全部多选组" },
                  ...groups.map((grp) => ({
                    value: grp.id,
                    label: formatGroupDisplayName(grp.name),
                  })),
                ]}
                className="min-w-[128px] max-w-[200px]"
                buttonClassName="rounded-lg"
              />
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
                setOnlyTested((v) => !v);
                setPage(1);
              }}
              className={`shrink-0 whitespace-nowrap rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                onlyTested
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              仅看已测
            </button>

            {/* Quick Sort Pills: Upload Fastest / Download Fastest / Lowest Latency */}
            <div
              className="inline-flex shrink-0 items-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
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
                const active = effectiveSortKey === opt.key && effectiveSortDir === opt.dir;
                return (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => {
                      setSortKey(opt.key);
                      setSortDir(opt.dir);
                      if (onlyGolden) {
                        setGoldenManualSortOverride(true);
                      }
                      setPage(1);
                    }}
                    className={`shrink-0 whitespace-nowrap rounded-md px-2 py-1 font-medium transition-colors ${
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
          </div>
        )}

        {/* Prominent Hint Banner when Golden Filter Hides Core-Qualified Candidates Without Speed Tests */}
        {onlyGolden && goldenHiddenCandidates.length > 0 && (
          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/65 px-3.5 py-2 text-xs">
            <div className="flex min-w-0 flex-1 items-center gap-2 text-[var(--text)]">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
              <span className="leading-relaxed">
                {formatI18nTemplate(dict.speedTest.goldenHiddenHint, {
                  count: goldenHiddenCandidates.length,
                })}
              </span>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => {
                  setOnlyGolden(false);
                  setGoldenManualSortOverride(false);
                  setPage(1);
                }}
                className="rounded-lg border border-[var(--line-strong)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              >
                {dict.speedTest.goldenSwitchAllBtn}
              </button>
              <button
                type="button"
                disabled={isProbeActionDisabled}
                onClick={() =>
                  handleGoldenCandidatesSpeedRun(
                    goldenHiddenCandidates.map((r) => r.node.id)
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
              >
                <Rocket className="h-3 w-3 shrink-0" />
                <span>{dict.speedTest.goldenRunSpeedBtn}</span>
              </button>
            </div>
          </div>
        )}

        {/* Gentle Fallback Banner when Golden Filter Has Only Unmeasured-Speed Candidates */}
        {isGoldenLatencyFallback && (
          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-xs">
            <div className="flex min-w-0 flex-1 items-center gap-2 text-[var(--text)]">
              <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
              <span className="leading-relaxed">{dict.nodes.goldenFallbackBanner}</span>
            </div>
            <button
              type="button"
              disabled={isProbeActionDisabled}
              onClick={() =>
                handleGoldenCandidatesSpeedRun(
                  goldenFallbackCandidates.map((r) => r.node.id)
                )
              }
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              <Rocket className="h-3 w-3 shrink-0" />
              <span>
                {formatI18nTemplate(dict.nodes.goldenFallbackAction, {
                  count: goldenFallbackCandidates.length,
                })}
              </span>
            </button>
          </div>
        )}

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
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] cc-tabular">
                <span className="rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]">
                  共 {totalFiltered}
                </span>
                <span
                  className="rounded-md bg-[var(--green-soft)] px-1.5 py-0.5 font-medium text-[var(--green)]"
                  title="基础连通与延迟探测通过的节点数"
                >
                  {dict.nodes.summaryLatencyOk} {probeBreakdown.latencyOk}
                </span>
                <span
                  className="rounded-md bg-[var(--sky-soft)] px-1.5 py-0.5 font-medium text-[var(--sky)]"
                  title="已实测并同时测出有效上传与下载速度的节点数"
                >
                  {dict.nodes.summaryBandwidthOk} {probeBreakdown.bandwidthOk}
                </span>
                {probeBreakdown.keepaliveOk > 0 && (
                  <span
                    className="rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 font-medium text-[var(--accent)]"
                    title="通过 60 秒长连接保活检测的节点数"
                  >
                    {dict.nodes.summaryKeepaliveOk} {probeBreakdown.keepaliveOk}
                  </span>
                )}
                {probeBreakdown.failed > 0 && (
                  <span
                    className="rounded-md bg-[var(--red-soft)] px-1.5 py-0.5 font-medium text-[var(--red)]"
                    title="测速超时、不可达或冷却中的节点数"
                  >
                    {dict.nodes.summaryFailed} {probeBreakdown.failed}
                  </span>
                )}
                {lastProbeSummary && lastProbeSummary.exec_error_count > 0 && (
                  <span
                    className="rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 font-medium text-[var(--amber)]"
                    title="最近一次测速中出现执行异常的次数"
                  >
                    执行异常 {lastProbeSummary.exec_error_count}
                  </span>
                )}
                <span
                  className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[var(--muted)]"
                  title="尚未执行过探测的节点数"
                >
                  {dict.nodes.summaryUntested} {probeBreakdown.untested}
                </span>
              </div>
              {isRunning && (
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--accent)]">
                  测速中已锁定行顺序，结束后自动按结果排序
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              {selectedCount >= 1 && (
                <button
                  type="button"
                  onClick={() => setShareModalOpen(true)}
                  className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--accent)]/55 bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                >
                  <Package className="h-3 w-3 shrink-0" />
                  <span>导出已选 (.zip)</span>
                </button>
              )}
              <button
                type="button"
                disabled={totalFiltered === 0}
                onClick={handleSelectAllFiltered}
                className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
              >
                {allFilteredSelected ? "取消全选当前筛选" : "全选当前筛选"}
              </button>
              <button
                type="button"
                disabled={totalFiltered === 0}
                onClick={handleSelectTop20}
                className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
              >
                选前 20 个
              </button>
              <button
                type="button"
                disabled={selectedCount === 0}
                onClick={handleClearSelection}
                className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--red)]/60 hover:text-[var(--red)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
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
          <table className="w-full min-w-[924px] table-fixed border-collapse text-left text-xs">
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
                    { key: "name", label: "节点名称", cls: "w-[196px] min-w-[178px] px-2" },
                    { key: "source", label: "来源", cls: "w-[84px] px-1.5" },
                    { key: "latency", label: "延迟", cls: "w-[78px] px-1.5" },
                    {
                      key: "up",
                      label: "上传",
                      sub: "Mbps",
                      cls: "w-[72px] px-1",
                      title: "测速带宽单位 Mbps（8 Mbps ≈ 1 MB/s）",
                    },
                    {
                      key: "down",
                      label: "下载",
                      sub: "Mbps",
                      cls: "w-[74px] px-1",
                      title: "测速带宽单位 Mbps（8 Mbps ≈ 1 MB/s）",
                    },
                    { key: "google", label: "谷歌地区", cls: "w-[68px] px-1" },
                    { key: "unlocks", label: "AI 解锁", cls: "w-[126px] px-1" },
                  ] as ReadonlyArray<{
                    key: SortKey;
                    label: string;
                    sub?: string;
                    cls: string;
                    title?: string;
                  }>
                ).map((col) => (
                  <th
                    key={col.key}
                    className={`whitespace-nowrap py-2.5 font-medium ${col.cls}`}
                    title={col.title}
                  >
                    <button
                      type="button"
                      onClick={() => handleSort(col.key)}
                      className="inline-flex max-w-full items-center gap-0.5 whitespace-nowrap text-left transition-colors hover:text-[var(--text)]"
                    >
                      <span>{col.label}</span>
                      {col.sub && (
                        <span className="text-[9.5px] font-normal opacity-75">{col.sub}</span>
                      )}
                      {renderSortIcon(col.key)}
                    </button>
                  </th>
                ))}
                <th className="w-[204px] whitespace-nowrap px-1.5 py-2.5 text-right font-medium">
                  操作
                </th>
              </tr>
            </thead>

            <tbody className="divide-y divide-[var(--line)]/70">
              {pagedRows.map(
                ({
                  node,
                  snap,
                  healthHint,
                  resolvedLatency,
                  isCooldown,
                  cooldownRemainingSec,
                  effectiveLatencyMs,
                  effectiveLatencyOk,
                  sourceName,
                  regionCode,
                  regionLabel,
                  aiBadges,
                  hasUnlockData,
                  regionMismatch,
                }) => {
                  const isSelected = validSelectedIds.has(node.id);
                  const isActiveNode = runtime.active_node_id === node.id;
                  const isSingleActiveNode = isSingleMode && isActiveNode;
                  const isFlashing = recentFlashIds.has(node.id);
                  const isProbingThis = isRunning && probeActiveNodeIdSet.has(node.id);
                  const isSwitchingThis = switchingNodeId === node.id;
                  const latTooltip = formatSpeedTestLatencyTooltip(
                    resolvedLatency,
                    dict,
                    healthHint,
                    cooldownRemainingSec
                  );

                  return (
                    <tr
                      key={node.id}
                      onMouseDown={(e) => handleRowMouseDown(e, node.id)}
                      onMouseEnter={(e) => handleRowMouseEnter(e, node.id)}
                      onClick={(e) => handleRowClick(e, node.id)}
                      className={`cursor-pointer transition-colors duration-500 ${
                        isFlashing
                          ? "bg-[var(--green-soft)]"
                          : isProbingThis
                            ? "bg-[var(--amber-soft)]/45 hover:bg-[var(--amber-soft)]/60"
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
                              : isProbingThis
                                ? "shadow-[inset_3px_0_0_var(--amber)]"
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
                      <td className="w-[196px] min-w-[178px] px-2 py-2">
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
                          {isProbingThis && (
                            <span
                              className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[9.5px] font-semibold text-[var(--amber)]"
                              title="正在后台测速此节点"
                            >
                              <Loader2 className="h-2.5 w-2.5 animate-spin" />
                              测速中
                            </span>
                          )}
                          {isFlashing && !isProbingThis && (
                            <span className="cc-pulse-dot shrink-0 rounded-full bg-[var(--green)] px-1.5 py-0.5 text-[9px] font-semibold text-[var(--accent-ink)]">
                              新
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-x-1 gap-y-0.5 text-[10.5px] text-[var(--muted)]">
                          <span className="truncate">{regionLabel}</span>
                          <span>·</span>
                          <span className="cc-tabular shrink-0">
                            {node.multiplier % 1 === 0
                              ? `${node.multiplier}x`
                              : `${node.multiplier.toFixed(1)}x`}
                          </span>
                          {(() => {
                            const { latencyAt, speedAt, fallbackAt } =
                              resolveProbeTimestamps(snap, probeTimestampIdSets);
                            const latRel = formatRelativeProbeTime(latencyAt);
                            const speedRel = formatRelativeProbeTime(speedAt);
                            if (latRel || speedRel) {
                              const tooltipLines: string[] = [];
                              if (latRel) {
                                tooltipLines.push(
                                  `${dict.latency.testedAtLatency}: ${latRel.full}`
                                );
                              }
                              if (speedRel) {
                                tooltipLines.push(
                                  `${dict.latency.testedAtSpeed}: ${speedRel.full}`
                                );
                              }
                              const fullTitle = tooltipLines.join("\n");
                              return (
                                <>
                                  {latRel && (
                                    <>
                                      <span>·</span>
                                      <span
                                        className="shrink-0 text-[10px] text-[var(--muted)]/90"
                                        title={fullTitle}
                                      >
                                        {dict.latency.testedAtLatency} {latRel.short}
                                      </span>
                                    </>
                                  )}
                                  {speedRel && (
                                    <>
                                      <span>·</span>
                                      <span
                                        className="shrink-0 text-[10px] text-[var(--muted)]/90"
                                        title={fullTitle}
                                      >
                                        {dict.latency.testedAtSpeed} {speedRel.short}
                                      </span>
                                    </>
                                  )}
                                </>
                              );
                            }
                            const rel = formatRelativeProbeTime(fallbackAt);
                            if (!rel) return null;
                            return (
                              <>
                                <span>·</span>
                                <span
                                  className="shrink-0 text-[10px] text-[var(--muted)]/90"
                                  title={`上次测速时间：${rel.full}`}
                                >
                                  {rel.short}
                                </span>
                              </>
                            );
                          })()}
                        </div>
                      </td>

                      {/* Source */}
                      <td className="w-[84px] px-1.5 py-2">
                        <span
                          className="block truncate text-[11px] font-medium text-[var(--text-secondary)]"
                          title={`来源分组：${sourceName}（协议：${node.protocol.toUpperCase()}）`}
                        >
                          {sourceName}
                        </span>
                      </td>

                      {/* Latency */}
                      <td className="w-[78px] px-1.5 py-2 cc-mono cc-tabular text-[11px]">
                        {isCooldown ? (
                          <div>
                            <span
                              className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold text-[var(--amber)]"
                              title={latTooltip}
                            >
                              <span
                                className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                                aria-hidden="true"
                              />
                              <span>
                                {cooldownRemainingSec > 0
                                  ? formatI18nTemplate(dict.latency.cooldownSec, {
                                      sec: cooldownRemainingSec,
                                    })
                                  : dict.latency.cooldownActive}
                              </span>
                            </span>
                            {snap?.keepalive_60s_ok !== null &&
                              snap?.keepalive_60s_ok !== undefined && (
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
                        ) : resolvedLatency.state !== "untested" || snap ? (
                          <div>
                            <span
                              className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold"
                              style={{
                                color: getLatencyColor(effectiveLatencyMs, effectiveLatencyOk),
                              }}
                              title={latTooltip}
                            >
                              <span
                                className="h-1.5 w-1.5 shrink-0 rounded-full"
                                style={{
                                  backgroundColor: getLatencyColor(
                                    effectiveLatencyMs,
                                    effectiveLatencyOk
                                  ),
                                }}
                                aria-hidden="true"
                              />
                              <span>
                                {effectiveLatencyMs !== null
                                  ? `${Math.round(effectiveLatencyMs)} ms`
                                  : resolvedLatency.state === "failed"
                                    ? dict.latency.timeoutShort
                                    : "--"}
                              </span>
                            </span>
                            {snap?.keepalive_60s_ok !== null &&
                              snap?.keepalive_60s_ok !== undefined && (
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
                          <span
                            className="inline-flex items-center gap-1.5 text-[var(--muted)]"
                            title={latTooltip}
                          >
                            <span
                              className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--muted)]/55"
                              aria-hidden="true"
                            />
                            <span>--</span>
                          </span>
                        )}
                      </td>

                      {/* Upload Speed */}
                      <td
                        className="w-[72px] whitespace-nowrap px-1 py-2 cc-mono cc-tabular text-[11px]"
                        title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
                      >
                        {hasValidUpMbps(snap) ? (
                          <span className="font-semibold text-[var(--coral)]">
                            {snap!.up_mbps!.toFixed(1)}
                            <span className="ml-0.5 text-[9.5px] font-normal text-[var(--muted)]">
                              Mbps
                            </span>
                          </span>
                        ) : (
                          <span className="text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Download Speed */}
                      <td
                        className="w-[74px] whitespace-nowrap px-1 py-2 cc-mono cc-tabular text-[11px]"
                        title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
                      >
                        {hasValidDownMbps(snap) ? (
                          <span className="font-semibold text-[var(--sky)]">
                            {snap!.down_mbps! >= 100
                              ? Math.round(snap!.down_mbps!)
                              : snap!.down_mbps!.toFixed(1)}
                            <span className="ml-0.5 text-[9.5px] font-normal text-[var(--muted)]">
                              Mbps
                            </span>
                          </span>
                        ) : (
                          <span className="text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Google Region Status */}
                      <td
                        className="w-[68px] whitespace-nowrap px-1 py-2"
                        title={formatGoogleRegionTooltip(snap, regionCode)}
                      >
                        <div className="flex flex-col items-start gap-1">
                          {snap?.google_clean === true ? (
                            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                              <CheckCircle2 className="h-3 w-3 shrink-0" />
                              正常
                            </span>
                          ) : snap?.google_clean === false ? (
                            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]">
                              <XCircle className="h-3 w-3 shrink-0" />
                              送中
                            </span>
                          ) : (
                            <span className="text-[11px] text-[var(--muted)]">待测</span>
                          )}

                          {regionMismatch && (
                            <span
                              className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1 py-0.5 text-[9px] text-[var(--amber)]"
                              title={formatGoogleRegionTooltip(snap, regionCode)}
                            >
                              <AlertTriangle className="h-2.5 w-2.5 shrink-0" />
                              地区偏差
                            </span>
                          )}
                        </div>
                      </td>

                      {/* AI Unlocks (2x2 compact micro-grid with Windsurf 4-state & per_probe_detail hover) */}
                      <td className="w-[126px] px-1 py-2">
                        {hasUnlockData ? (
                          <div className="grid w-full grid-cols-2 gap-0.5">
                            {aiBadges.map((badge) => {
                              const isLegacy = badge.windsurfState === "legacy_retest";
                              const isDimmed =
                                !isLegacy &&
                                badge.tone === "muted" &&
                                !badge.unlocked;
                              const toneCls = isLegacy
                                ? getAiBadgeToneClass("muted", "legacy")
                                : getAiBadgeToneClass(badge.tone, "soft");
                              return (
                                <span
                                  key={badge.id}
                                  title={badge.tooltip}
                                  className={`truncate whitespace-nowrap rounded-md px-0.5 py-0.5 text-center text-[9.5px] font-medium leading-tight ${toneCls} ${
                                    isDimmed ? "opacity-55" : ""
                                  }`}
                                >
                                  {badge.label}
                                </span>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-[11px] text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Row Actions: Primary Single-Node Use + Compact Full Probe + Lightweight Latency / +Group */}
                      <td className="w-[204px] whitespace-nowrap px-1.5 py-2 text-right">
                        <div className="inline-flex flex-nowrap items-center justify-end gap-0.5">
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
                            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap border px-1.5 py-0.5 text-[10px] font-semibold transition-colors ${
                              isSingleActiveNode
                                ? "rounded-full border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                                : "rounded-lg border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-65"
                            }`}
                          >
                            {isSingleActiveNode ? (
                              <Check className="h-2.5 w-2.5 shrink-0" />
                            ) : (
                              <ArrowRightLeft className="h-2.5 w-2.5 shrink-0" />
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
                            disabled={isProbeActionDisabled}
                            onClick={(e) => {
                              e.stopPropagation();
                              void executeProbes([node.id], "full", true);
                            }}
                            title={
                              isBlockedByBenchmark
                                ? "国内提速对比测速正在后台进行，完成后可测速"
                                : "单测此节点的延迟、谷歌送中/AI 解锁与真实上下行速度，保留其它旧结果"
                            }
                            aria-label={`测全套：${node.name}`}
                            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--sky)]/45 bg-[var(--sky-soft)] px-1 py-0.5 text-[10px] font-medium text-[var(--sky)] transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-55"
                          >
                            {isProbingThis ? (
                              <Loader2 className="h-2.5 w-2.5 shrink-0 animate-spin" />
                            ) : (
                              <Rocket className="h-2.5 w-2.5 shrink-0" />
                            )}
                            <span>{isProbingThis ? "测速中" : "测全套"}</span>
                          </button>

                          <button
                            type="button"
                            disabled={isProbeActionDisabled}
                            onClick={(e) => {
                              e.stopPropagation();
                              void executeProbes([node.id], "latency", true);
                            }}
                            title={
                              isBlockedByBenchmark
                                ? "国内提速对比测速正在后台进行，完成后可测速"
                                : "只快速复测此节点延迟，不洗掉之前测好的上下行和解锁结果"
                            }
                            aria-label={`测延迟：${node.name}`}
                            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-1 py-0.5 text-[10px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:text-[var(--muted)] disabled:opacity-65"
                          >
                            <Play className="h-2.5 w-2.5 shrink-0" />
                            <span>测延迟</span>
                          </button>

                          <GroupMembershipPopover
                            node={node}
                            variant="icon"
                            formatGroupName={formatGroupDisplayName}
                          />
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
                    ) : onlyGolden && (!anyTestedInAllNodes || !anyUnlockTestedInAllNodes) ? (
                      <div className="flex flex-col items-center justify-center gap-2.5">
                        <span className="max-w-md leading-relaxed text-[var(--text-secondary)]">
                          {!anyTestedInAllNodes
                            ? dict.nodes.goldenEmptyUntested
                            : "当前仅测过延迟，尚未检测谷歌地区与 AI 解锁，请先运行『测延迟 + 送中/AI』"}
                        </span>
                        <div className="flex flex-wrap items-center justify-center gap-2">
                          <button
                            type="button"
                            disabled={isProbeActionDisabled}
                            onClick={() => {
                              setOnlyGolden(false);
                              setGoldenManualSortOverride(false);
                              setPage(1);
                              if (nodes.length > 50) {
                                setPendingLargeRun({ tier: "unlock" });
                              } else {
                                void executeProbes(
                                  nodes.map((n) => n.id),
                                  "unlock"
                                );
                              }
                            }}
                            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
                          >
                            <ShieldCheck className="h-3.5 w-3.5" />
                            <span>测延迟 + 送中/AI（省流）</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setOnlyGolden(false);
                              setGoldenManualSortOverride(false);
                              setPage(1);
                            }}
                            className="rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                          >
                            查看全部节点
                          </button>
                        </div>
                      </div>
                    ) : onlyGolden ? (
                      <div className="flex flex-col items-center justify-center gap-2.5">
                        <span className="max-w-md leading-relaxed text-[var(--text-secondary)]">
                          {dict.nodes.goldenEmptyNoMatch}
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            if (baseFilteredRows.length > 0) {
                              setOnlyGolden(false);
                              setGoldenManualSortOverride(false);
                              setPage(1);
                            } else {
                              handleResetFilters();
                            }
                          }}
                          className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--accent)]/60 bg-[var(--accent-soft)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                          <span>恢复查看全部节点</span>
                        </button>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center gap-2">
                        <span>没有找到符合条件的节点，试试放宽筛选条件吧</span>
                        {hasActiveFilters && (
                          <button
                            type="button"
                            onClick={handleResetFilters}
                            className="inline-flex items-center gap-1 rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-3 py-1 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                          >
                            <RotateCcw className="h-3 w-3" />
                            <span>{dict.speedTest.resetFiltersBtn}</span>
                          </button>
                        )}
                      </div>
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

      <ShareBundleModal
        open={shareModalOpen}
        mode="export"
        defaultTab="nodes"
        defaultPackName="精选节点分享包"
        initialNodeIds={Array.from(validSelectedIds)}
        onClose={() => setShareModalOpen(false)}
      />
    </div>
  );
}
