import {
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowUp,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileText,
  Gauge,
  Globe,
  Layers,
  Loader2,
  Package,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Star,
  Terminal,
  Trash2,
  Upload,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type AcceleratedProcessStat,
  type AppConfig,
  type GlobalPreAccelScope,
  type PreAccelDispatchStrategy,
  type PreAccelLbStrategy,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect } from "../components/AppSelect";
import { ShareBundleModal } from "../components/ShareBundleModal";
import { formatBytes } from "../components/TrafficSparkline";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import {
  appActions,
  appStore,
  selectIsProbeEngineBusy,
  useAppSelector,
} from "../store/appStore";
import {
  DEFAULT_GLOBAL_TARGET_PROCESSES,
  buildGlobalPreAccelShellSnippet,
  resolvePlatformOs,
} from "../utils/platform";
import { resolvePreAccelSummary } from "../utils/preaccelStatus";
import { resolveNodeRegionCode } from "../utils/regions";

const DETECTED_BY_LABELS: Record<string, string> = {
  system_proxy_host: "系统代理",
  local_proxy_listener: "本地代理",
  open_core_name: "代理核心",
  outbound_proxy_behavior: "自动识别",
  scope_all: "全局覆盖",
  manual: "手动列表",
};

function formatDetectedByLabel(raw: string | undefined): string {
  if (!raw) return "自动识别";
  return DETECTED_BY_LABELS[raw] ?? "自动识别";
}

type AddModalTab = "manual" | "import";

const RELAY_PROTOCOL_OPTIONS = [
  { value: "anytls", label: "AnyTLS（推荐）" },
  { value: "trojan", label: "Trojan" },
  { value: "vless", label: "VLESS" },
  { value: "hysteria2", label: "Hysteria2" },
  { value: "tuic", label: "TUIC" },
] as const;

const REGION_QUICK_PICKS = ["华东", "华南", "华北", "西南", "香港"] as const;

const DOMESTIC_PROBE_PRESETS = [
  {
    id: "hicloud",
    label: "华为国内检测（推荐）",
    url: "http://connectivitycheck.platform.hicloud.com/generate_204",
  },
  {
    id: "miui",
    label: "小米国内检测（备用）",
    url: "http://connect.rom.miui.com/generate_204",
  },
] as const;

const FORBIDDEN_OVERSEAS_PROBE_PATTERNS = [
  "gstatic.com",
  "google.com",
  "googleapis.com",
  "cloudflare.com",
  "captive.apple.com",
  "firefox.com",
  "msftconnecttest.com",
];

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;

// Internal wire-format constants for import parsing & sanitized demo payload
const IMPORT_SCHEMA_TAG = "mmrelay/v1";
const IMPORT_URI_PREFIX = "mmrelay://v1/";

const DEMO_IMPORT_JSON = JSON.stringify(
  {
    schema: IMPORT_SCHEMA_TAG,
    role: "domestic_pre_accel",
    relays: [
      {
        id: "relay-cn-east-demo",
        name: "上海轻量 1 号",
        provider: "示例云服务器",
        region: "华东",
        server: "198.51.100.12",
        port: 443,
        protocol: "anytls",
        password: "<YOUR_GENERATED_SECRET>",
        sni: "",
        skip_cert_verify: true,
        priority: 3,
        expires_at: "2027-08-12",
        enabled: true,
      },
    ],
  },
  null,
  2
);

function looksLikeIpAddress(raw: string): boolean {
  const cleaned = raw.trim().replace(/^\[|\]$/g, "");
  if (!cleaned) return false;
  if (IPV4_PATTERN.test(cleaned)) {
    return cleaned.split(".").every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  return cleaned.includes(":") && /^[0-9a-fA-F:]+$/.test(cleaned);
}

function encodeBase64UrlUtf8(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64UrlUtf8(input: string): string {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function validateDomesticProbeUrl(raw: string): { ok: boolean; error: string | null } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: "国内连通检测地址不能为空" };
  }
  const lower = trimmed.toLowerCase();
  if (lower.includes("gstatic")) {
    return {
      ok: false,
      error: "不能使用海外检测地址，容易引起绕圈或误判断网，请改用华为或小米的国内检测地址。",
    };
  }
  for (const blocked of FORBIDDEN_OVERSEAS_PROBE_PATTERNS) {
    if (lower.includes(blocked)) {
      return {
        ok: false,
        error: `已拦截海外地址（${blocked}）：请填写国内直连检测地址（推荐使用华为或小米国内检测地址）。`,
      };
    }
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, error: "请输入以 http:// 或 https:// 开头的完整网址" };
    }
  } catch {
    return { ok: false, error: "请输入格式正确的国内检测网址" };
  }
  return { ok: true, error: null };
}

function computeExpiryInfo(expiresAt: string | null): {
  label: string;
  tone: "ok" | "warn" | "expired" | "muted";
} {
  if (!expiresAt) {
    return { label: "", tone: "muted" };
  }
  const target = Date.parse(expiresAt);
  if (!Number.isFinite(target)) {
    return { label: expiresAt, tone: "muted" };
  }
  const diffDays = Math.ceil((target - Date.now()) / 86_400_000);
  if (diffDays < 0) {
    return { label: `已过期 ${Math.abs(diffDays)} 天`, tone: "expired" };
  }
  if (diffDays <= 3) {
    return { label: `剩 ${diffDays} 天到期`, tone: "warn" };
  }
  return { label: `到期 ${expiresAt}`, tone: "ok" };
}

function getRelayLatencyColor(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms) || ms <= 0) return "var(--muted)";
  if (ms <= 60) return "var(--green)";
  if (ms <= 150) return "var(--amber)";
  return "var(--red)";
}

function formatLatencyDisplay(ms: number | null | undefined, emptyLabel = "--"): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms <= 0) {
    return emptyLabel;
  }
  if (ms < 0.5) {
    return "<1 ms";
  }
  return `${Math.round(ms)} ms`;
}

function hasValidLatency(ms: number | null | undefined): ms is number {
  return ms !== null && ms !== undefined && Number.isFinite(ms) && ms > 0;
}

function hasValidSpeed(mbps: number | null | undefined): mbps is number {
  return mbps !== null && mbps !== undefined && Number.isFinite(mbps) && mbps > 0;
}

interface RawRelayInput {
  id?: string;
  name?: string;
  provider?: string;
  region?: string;
  server?: string;
  port?: number;
  protocol?: string;
  password?: string;
  sni?: string | null;
  servername?: string | null;
  skip_cert_verify?: boolean;
  priority?: number;
  expires_at?: string | null;
  enabled?: boolean;
}

function parseRelayImportInput(rawInput: string): {
  relays: PreAccelRelay[];
  warnings: string[];
  error: string | null;
} {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { relays: [], warnings: [], error: "请先粘贴导入码或 JSON 配置内容" };
  }

  let jsonText = trimmed;
  if (trimmed.toLowerCase().startsWith(IMPORT_URI_PREFIX)) {
    const payload = trimmed.slice(IMPORT_URI_PREFIX.length).trim();
    if (!payload) {
      return { relays: [], warnings: [], error: "导入码内容为空，请重新复制后再粘贴" };
    }
    try {
      jsonText = decodeBase64UrlUtf8(payload);
    } catch {
      return { relays: [], warnings: [], error: "导入码解析失败，请检查是否复制完整" };
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return { relays: [], warnings: [], error: "JSON 格式有误，请检查括号与引号是否完整" };
  }

  if (!parsed || typeof parsed !== "object") {
    return { relays: [], warnings: [], error: "导入内容格式不正确，请粘贴完整的配置对象" };
  }

  const record = parsed as Record<string, unknown>;
  if ("schema" in record && record.schema !== IMPORT_SCHEMA_TAG) {
    return {
      relays: [],
      warnings: [],
      error: `暂不支持此配置格式（${String(record.schema)}），请确认来自猫猫云梯导出内容`,
    };
  }

  const rawList: RawRelayInput[] = Array.isArray(record.relays)
    ? (record.relays as RawRelayInput[])
    : [record as RawRelayInput];

  if (rawList.length === 0) {
    return { relays: [], warnings: [], error: "配置中未包含任何中转线路" };
  }

  const warnings: string[] = [];
  const relays: PreAccelRelay[] = [];

  for (let i = 0; i < rawList.length; i++) {
    const item = rawList[i];
    const server = typeof item.server === "string" ? item.server.trim() : "";
    if (!server) {
      return { relays: [], warnings: [], error: `第 ${i + 1} 条线路缺少服务器 IP 地址` };
    }
    const port = typeof item.port === "number" ? item.port : 443;
    const rawSni =
      typeof item.sni === "string"
        ? item.sni.trim()
        : typeof item.servername === "string"
          ? item.servername.trim()
          : "";
    if (port !== 443) {
      warnings.push(`「${item.name ?? server}」端口为 ${port}，推荐使用 443 端口以获得更稳定的上传速度`);
    }
    if (rawSni !== "") {
      warnings.push(`「${item.name ?? server}」填写了自定义域名（${rawSni}），国内 443 中转建议留空域名、直接使用纯 IP`);
    }

    relays.push({
      id:
        typeof item.id === "string" && item.id.trim()
          ? item.id.trim()
          : `relay-import-${Date.now().toString(36)}-${i}`,
      name:
        typeof item.name === "string" && item.name.trim()
          ? item.name.trim()
          : `中转-${server}`,
      provider:
        typeof item.provider === "string" && item.provider.trim()
          ? item.provider.trim()
          : "导入线路",
      region:
        typeof item.region === "string" && item.region.trim()
          ? item.region.trim()
          : "国内",
      server,
      port,
      protocol:
        typeof item.protocol === "string" && item.protocol.trim()
          ? item.protocol.trim().toLowerCase()
          : "anytls",
      password: typeof item.password === "string" ? item.password : "",
      sni: rawSni ? rawSni : null,
      skip_cert_verify: item.skip_cert_verify ?? true,
      priority: typeof item.priority === "number" ? item.priority : 10 + i,
      expires_at: typeof item.expires_at === "string" ? item.expires_at : null,
      enabled: item.enabled ?? true,
      last_probe_ms: null,
      last_mbps: null,
      last_up_mbps: null,
      last_down_mbps: null,
    });
  }

  return { relays, warnings, error: null };
}

function dedupeProcessStats(list: AcceleratedProcessStat[]): AcceleratedProcessStat[] {
  const map = new Map<string, AcceleratedProcessStat>();
  for (const stat of list) {
    const key = stat.process_name.trim().toLowerCase();
    if (!key) continue;
    const prev = map.get(key);
    if (!prev) {
      map.set(key, { ...stat });
    } else {
      prev.active_connections += stat.active_connections;
      prev.total_connections += stat.total_connections;
      prev.tx_bytes += stat.tx_bytes;
      prev.rx_bytes += stat.rx_bytes;
      if (stat.last_seen_ms > prev.last_seen_ms) {
        prev.last_seen_ms = stat.last_seen_ms;
        prev.pid = stat.pid;
        if (stat.detected_by) prev.detected_by = stat.detected_by;
      }
    }
  }
  return Array.from(map.values());
}

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fallback */
  }
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

function formatClockStamp(isoOrMs?: string | number | null): string {
  const d =
    isoOrMs !== undefined && isoOrMs !== null && isoOrMs !== ""
      ? new Date(isoOrMs)
      : new Date();
  if (Number.isNaN(d.getTime())) return typeof isoOrMs === "string" ? isoOrMs : "--";
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function isUdpOnlyProto(proto: string): boolean {
  const p = proto.trim().toLowerCase();
  return (
    p === "hysteria2" ||
    p === "hy2" ||
    p === "hysteria" ||
    p === "tuic" ||
    p === "wireguard"
  );
}

const INPUT_CLS =
  "w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]";

export function PreAccelPage() {
  const config = useAppSelector((s) => s.config);
  const dict = useUiDict(normalizeUiLanguage(config.personalization.ui_language));
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const storeRelays = useAppSelector((s) => s.preAccelRelays);
  const relayChainLatencies = useAppSelector((s) => s.relayChainLatencies);
  const groups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const initialized = useAppSelector((s) => s.initialized);
  const bgPreaccel = useAppSelector((s) => s.bgTasks.preaccel);
  const preAccelDraft = useAppSelector((s) => s.sessionDrafts.preAccel);
  const probeRunning = useAppSelector(
    (s) => s.probeProgress.running || s.bgTasks.probeLocalStarting
  );
  const isProbeEngineBusy = useAppSelector(selectIsProbeEngineBusy);
  const inTauri = isTauriEnv();
  const platformOs = resolvePlatformOs(runtime.os_label);

  const enabled = config.preaccel.enabled;
  const dispatchStrategy: PreAccelDispatchStrategy = config.preaccel.dispatch_strategy ?? "auto";
  const activeRelayId: string | null = config?.preaccel.active_relay_id ?? null;
  const lbStrategy: PreAccelLbStrategy = config.preaccel.lb_strategy ?? "round_robin";
  const [savingDispatch, setSavingDispatch] = useState(false);
  const [togglingEnabled, setTogglingEnabled] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [savingGlobalScope, setSavingGlobalScope] = useState(false);
  const [elevatingGlobal, setElevatingGlobal] = useState(false);
  const [refreshingGlobal, setRefreshingGlobal] = useState(false);
  const [globalScope, setGlobalScope] = useState<GlobalPreAccelScope>(
    config.preaccel.global_scope ?? "proxy_apps_only"
  );
  const [targetProcesses, setTargetProcesses] = useState<string[]>(() =>
    Array.isArray(config.preaccel?.global_target_processes)
      ? config.preaccel.global_target_processes
      : [...DEFAULT_GLOBAL_TARGET_PROCESSES]
  );
  const [newProcessInput, setNewProcessInput] = useState("");
  const [copiedGlobalAddr, setCopiedGlobalAddr] = useState(false);
  const [copiedShellKind, setCopiedShellKind] = useState<string | null>(null);
  const [skip443Native, setSkip443Native] = useState<boolean>(config.preaccel.skip_443_native);
  const [campusPortalGuard, setCampusPortalGuard] = useState<boolean>(
    config.preaccel.campus_portal_guard ?? true
  );
  const [savingCampusGuard, setSavingCampusGuard] = useState(false);
  const [probeUrl, setProbeUrl] = useState<string>(config.preaccel.probe_url);
  const [relays, setRelays] = useState<PreAccelRelay[]>(storeRelays);
  const [failoverBusy, setFailoverBusy] = useState(false);

  // Add Relay Modal (Manual Form + Paste Import Code / JSON)
  const [showAddModal, setShowAddModal] = useState(false);
  const [addModalTab, setAddModalTab] = useState<AddModalTab>("manual");

  // Manual Add Form State
  const [manualName, setManualName] = useState("");
  const [manualServer, setManualServer] = useState("");
  const [manualPort, setManualPort] = useState("443");
  const [manualProtocol, setManualProtocol] = useState<string>("anytls");
  const [manualPassword, setManualPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [manualRegion, setManualRegion] = useState("");
  const [manualNote, setManualNote] = useState("");
  const [manualExpiresAt, setManualExpiresAt] = useState("");
  const [manualError, setManualError] = useState<string | null>(null);
  const [savingManual, setSavingManual] = useState(false);

  // Import Tab State
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importWarnings, setImportWarnings] = useState<string[]>([]);

  // Lightweight Advanced Modals (Probe URL & Share Bundle)
  const [showProbeModal, setShowProbeModal] = useState(false);
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [pendingDeleteRelay, setPendingDeleteRelay] = useState<PreAccelRelay | null>(null);
  const [deletingRelay, setDeletingRelay] = useState(false);

  // Global background task bindings (survive page switches)
  const installingDriver = bgPreaccel.installingDriver;
  const verifyingGlobal = bgPreaccel.verifyingGlobal;
  const probingAll = bgPreaccel.relaysTestingAll;
  const probingIdsSet = useMemo(
    () => new Set(bgPreaccel.relaysTestingIds),
    [bgPreaccel.relaysTestingIds]
  );
  const speedTestingAll = bgPreaccel.relaysSpeedTestingAll;
  const speedTestingIdsSet = useMemo(
    () => new Set(bgPreaccel.relaysSpeedTestingIds),
    [bgPreaccel.relaysSpeedTestingIds]
  );
  const speedTestingAny = speedTestingAll || bgPreaccel.relaysSpeedTestingIds.length > 0;

  const benchmarking = bgPreaccel.benchmark.running;
  const comparison = bgPreaccel.benchmark.result;
  const comparisonError = bgPreaccel.benchmark.error;
  const comparisonFinishedAt = bgPreaccel.benchmark.finishedAt;
  const comparisonIsDemo = Boolean(comparison && !inTauri);
  const selectedCompareNodeId = preAccelDraft.selectedCompareNodeId;
  const setSelectedCompareNodeId = (nextNodeId: string) => {
    appActions.patchSessionDraft("preAccel", { selectedCompareNodeId: nextNodeId });
  };

  const isOtherProbeRunning = probeRunning && !benchmarking;

  // Soft "刚刚更新" badge expires cleanly 2 minutes after benchmark completion
  const [recentClockNow, setRecentClockNow] = useState(() => Date.now());
  useEffect(() => {
    if (!comparisonFinishedAt) return;
    const now = Date.now();
    setRecentClockNow(now);
    const remaining = comparisonFinishedAt + 120_000 - now;
    if (remaining <= 0) return;
    const id = window.setTimeout(() => {
      setRecentClockNow(Date.now());
    }, remaining + 50);
    return () => window.clearTimeout(id);
  }, [comparisonFinishedAt]);

  const isComparisonFresh = Boolean(
    comparison &&
      comparisonFinishedAt !== null &&
      recentClockNow - comparisonFinishedAt < 120_000
  );

  // Campus Network Auth Check Card (backed by global bgTasks.preaccel)
  const checkingPortal = bgPreaccel.campusChecking;
  const campusResult = bgPreaccel.campusResult;
  const campusError = bgPreaccel.campusError;
  const portalRequired = campusResult
    ? campusResult.captive_portal_required
    : runtime.captive_portal_required;
  const portalHttpCode: number | null = campusResult
    ? campusResult.status_code
    : inTauri
      ? null
      : runtime.captive_portal_required
        ? 302
        : 204;
  const portalRedirect = campusResult?.redirect_location ?? null;
  const portalBypassHosts = campusResult?.bypass_hosts ?? [];
  const portalLastCheck = campusResult?.checked_at
    ? formatClockStamp(campusResult.checked_at)
    : inTauri
      ? "尚未检测"
      : "演示态";

  const timersRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      for (const id of timersRef.current) {
        window.clearTimeout(id);
      }
      timersRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (initialized) {
      setRelays(storeRelays);
    }
  }, [storeRelays, initialized]);

  useEffect(() => {
    if (initialized) {
      setSkip443Native(config.preaccel.skip_443_native);
      if (typeof config.preaccel.campus_portal_guard === "boolean") {
        setCampusPortalGuard(config.preaccel.campus_portal_guard);
      }
      if (
        config.preaccel.global_scope === "proxy_apps_only" ||
        config.preaccel.global_scope === "all_non_443_tcp"
      ) {
        setGlobalScope(config.preaccel.global_scope);
      }
      if (Array.isArray(config.preaccel.global_target_processes)) {
        setTargetProcesses(config.preaccel.global_target_processes);
      }
      if (!showProbeModal) {
        setProbeUrl(config.preaccel.probe_url);
      }
    }
  }, [config.preaccel, initialized, showProbeModal]);

  useEffect(() => {
    void appActions.refreshGlobalPreAccelStatus();
  }, []);

  const installBusy =
    installingDriver ||
    globalPreAccel.install_state === "downloading" ||
    globalPreAccel.install_state === "verifying" ||
    runtime.preaccel_install_state === "downloading" ||
    runtime.preaccel_install_state === "verifying";

  const verifyProbingActive =
    verifyingGlobal ||
    globalPreAccel.verify_state === "probing" ||
    runtime.global_preaccel_verify_state === "probing";

  useEffect(() => {
    if (!enabled && !globalPreAccel.running && !installBusy && !verifyProbingActive) return;
    const intervalMs = installBusy || verifyProbingActive ? 1500 : 5000;
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      void appActions.refreshGlobalPreAccelStatus();
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [enabled, globalPreAccel.running, installBusy, verifyProbingActive]);

  useEffect(() => {
    let active = true;
    void catcloudApi
      .getFullConfig()
      .then((full) => {
        if (!active) return;
        const rawPreaccel = full.preaccel as
          | {
              campus_portal_guard?: unknown;
              global_scope?: unknown;
              global_target_processes?: unknown;
            }
          | undefined;
        if (typeof rawPreaccel?.campus_portal_guard === "boolean") {
          setCampusPortalGuard(rawPreaccel.campus_portal_guard);
        }
        if (
          rawPreaccel?.global_scope === "proxy_apps_only" ||
          rawPreaccel?.global_scope === "all_non_443_tcp"
        ) {
          setGlobalScope(rawPreaccel.global_scope);
        }
        if (Array.isArray(rawPreaccel?.global_target_processes)) {
          const list = rawPreaccel.global_target_processes.filter(
            (item): item is string => typeof item === "string" && item.trim().length > 0
          );
          setTargetProcesses(list);
        }
      })
      .catch(() => {
        /* keep fallback preaccel fields */
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!showAddModal && !showProbeModal && !pendingDeleteRelay) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (!savingManual && !importing) {
          setShowAddModal(false);
        }
        if (!deletingRelay) {
          setPendingDeleteRelay(null);
        }
        setShowProbeModal(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [
    showAddModal,
    showProbeModal,
    pendingDeleteRelay,
    savingManual,
    importing,
    deletingRelay,
  ]);

  const scheduleTimer = (fn: () => void, ms: number) => {
    const id = window.setTimeout(() => {
      timersRef.current = timersRef.current.filter((item) => item !== id);
      fn();
    }, ms);
    timersRef.current.push(id);
  };

  const probeValidation = useMemo(() => validateDomesticProbeUrl(probeUrl), [probeUrl]);

  const sortedRelays = useMemo(
    () =>
      [...relays].sort((a, b) => {
        if (a.priority !== b.priority) return a.priority - b.priority;
        return a.id.localeCompare(b.id);
      }),
    [relays]
  );

  const enabledRelayCount = useMemo(
    () => relays.filter((r) => r.enabled).length,
    [relays]
  );

  const physicalHostSummary = useMemo(() => {
    const enabledList = sortedRelays.filter((r) => r.enabled);
    const hostMap = new Map<string, number>();
    for (const r of enabledList) {
      const hostKey = r.server.trim().toLowerCase();
      if (!hostKey) continue;
      hostMap.set(hostKey, (hostMap.get(hostKey) ?? 0) + 1);
    }
    const distinctHosts = hostMap.size;
    const duplicateProtocolCount = Math.max(0, enabledList.length - distinctHosts);
    return {
      enabledCount: enabledList.length,
      distinctHosts,
      duplicateProtocolCount,
    };
  }, [sortedRelays]);

  const isMultiCloudLbStrategy =
    dispatchStrategy === "load_balance" || (dispatchStrategy === "auto" && !activeRelayId);

  const isMultiCloudLbActive =
    physicalHostSummary.distinctHosts >= 2 && isMultiCloudLbStrategy;

  const enabledRankMap = useMemo(() => {
    const map = new Map<string, number>();
    let rank = 0;
    for (const r of sortedRelays) {
      if (r.enabled) {
        map.set(r.id, rank);
        rank += 1;
      }
    }
    return map;
  }, [sortedRelays]);

  const relayLatencyStats = useMemo(() => {
    const enabledList = sortedRelays.filter((r) => r.enabled);
    const probed = enabledList.filter((r) => hasValidLatency(r.last_probe_ms));
    const bestMs =
      probed.length > 0
        ? Math.min(...probed.map((r) => r.last_probe_ms as number))
        : null;
    return {
      enabledTotal: enabledList.length,
      probedCount: probed.length,
      bestMs,
    };
  }, [sortedRelays]);

  const primaryRelayId = useMemo(() => {
    if (runtime.preaccel_relay_name) {
      const matched = sortedRelays.find(
        (r) =>
          r.enabled &&
          (r.name === runtime.preaccel_relay_name || r.id === runtime.preaccel_relay_name)
      );
      if (matched) return matched.id;
    }
    return sortedRelays.find((r) => r.enabled)?.id ?? null;
  }, [sortedRelays, runtime.preaccel_relay_name]);

  const homeCurrentNode = useMemo(() => {
    if (nodes.length === 0) return null;
    if (runtime.active_node_id) {
      const byRuntime = nodes.find((n) => n.id === runtime.active_node_id);
      if (byRuntime) return byRuntime;
    }
    if (runtime.route_mode !== "single") {
      const activeGroup =
        groups.find((g) => g.id === runtime.active_group_id) ?? groups[0] ?? null;
      if (activeGroup?.active_node_id) {
        const byGroupActive = nodes.find((n) => n.id === activeGroup.active_node_id);
        if (byGroupActive) return byGroupActive;
      }
      if (activeGroup && activeGroup.member_node_ids.length > 0) {
        const firstMember = nodes.find((n) => activeGroup.member_node_ids.includes(n.id));
        if (firstMember) return firstMember;
      }
    }
    return null;
  }, [nodes, groups, runtime.active_node_id, runtime.active_group_id, runtime.route_mode]);

  const isHomeCurrentNodeUdpOnly = homeCurrentNode
    ? isUdpOnlyProto(homeCurrentNode.protocol)
    : false;

  const benchmarkableNodes = useMemo(() => {
    const preferredRegions = new Set(["TW", "HK", "SG", "JP", "US", "KR"]);
    const isInfoPlaceholder = (name: string) =>
      /剩余流量|过期时间|到期时间|重置|套餐|官网|发布页|续费地址|使用前|更新订阅/i.test(name);
    const enabledList = nodes.filter(
      (n) => n.enabled && !isUdpOnlyProto(n.protocol) && !isInfoPlaceholder(n.name)
    );
    const base =
      enabledList.length > 0
        ? enabledList
        : nodes.filter((n) => !isUdpOnlyProto(n.protocol) && !isInfoPlaceholder(n.name));
    return [...base].sort((a, b) => {
      const aHighMult = a.multiplier >= 3 ? 1 : 0;
      const bHighMult = b.multiplier >= 3 ? 1 : 0;
      if (aHighMult !== bHighMult) return aHighMult - bHighMult;
      const aPreferredReg = preferredRegions.has(resolveNodeRegionCode(a)) ? 1 : 0;
      const bPreferredReg = preferredRegions.has(resolveNodeRegionCode(b)) ? 1 : 0;
      if (aPreferredReg !== bPreferredReg) return bPreferredReg - aPreferredReg;
      const aLowMult = a.multiplier <= 1.5 ? 1 : 0;
      const bLowMult = b.multiplier <= 1.5 ? 1 : 0;
      if (aLowMult !== bLowMult) return bLowMult - aLowMult;
      const aNon443 = a.is_443_native ? 0 : 1;
      const bNon443 = b.is_443_native ? 0 : 1;
      if (aNon443 !== bNon443) return bNon443 - aNon443;
      const aActive = a.id === runtime.active_node_id ? 1 : 0;
      const bActive = b.id === runtime.active_node_id ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      return a.name.localeCompare(b.name);
    });
  }, [nodes, runtime.active_node_id]);

  const otherBenchmarkableNodes = useMemo(
    () =>
      homeCurrentNode
        ? benchmarkableNodes.filter((n) => n.id !== homeCurrentNode.id)
        : benchmarkableNodes,
    [benchmarkableNodes, homeCurrentNode]
  );

  const resolvedCompareNodeId = useMemo(() => {
    if (
      selectedCompareNodeId &&
      otherBenchmarkableNodes.some((n) => n.id === selectedCompareNodeId)
    ) {
      return selectedCompareNodeId;
    }
    return "";
  }, [otherBenchmarkableNodes, selectedCompareNodeId]);

  const openAddModal = (tab: AddModalTab = "manual") => {
    setAddModalTab(tab);
    setManualError(null);
    setImportError(null);
    setShowAddModal(true);
  };

  const resetManualForm = () => {
    setManualName("");
    setManualServer("");
    setManualPort("443");
    setManualProtocol("anytls");
    setManualPassword("");
    setShowPassword(false);
    setManualRegion("");
    setManualNote("");
    setManualExpiresAt("");
    setManualError(null);
  };

  const persistPreAccelConfig = async (
    nextSkip443: boolean,
    nextProbeUrl: string,
    notice: string,
    overrideEnabled?: boolean
  ): Promise<boolean> => {
    const latestConfig = appStore.getState().config;
    const authoritativeEnabled =
      overrideEnabled ?? latestConfig.preaccel.enabled;
    const nextConfig: AppConfig = {
      ...latestConfig,
      preaccel: {
        ...latestConfig.preaccel,
        enabled: authoritativeEnabled,
        skip_443_native: nextSkip443,
        probe_url: nextProbeUrl,
      },
    };
    try {
      const saved = await catcloudApi.saveConfig(nextConfig);
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
      appActions.showToast(notice, "ok");
      return true;
    } catch (err) {
      appActions.showToast(`保存国内提速设置失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  };

  const handleToggleEnabled = async () => {
    if (togglingEnabled) return;
    const next = !appStore.getState().config.preaccel.enabled;
    setTogglingEnabled(true);
    try {
      await appActions.togglePreAccel(next);
    } finally {
      setTogglingEnabled(false);
    }
  };

  const handleRefreshGlobalStatus = async () => {
    if (refreshingGlobal) return;
    setRefreshingGlobal(true);
    try {
      await appActions.refreshGlobalPreAccelStatus();
    } finally {
      setRefreshingGlobal(false);
    }
  };

  const handleVerifyGlobalPreAccel = async () => {
    if (verifyingGlobal) return;
    await appActions.runVerifyGlobalPreAccel();
  };

  const handleSelectGlobalScope = async (nextScope: GlobalPreAccelScope) => {
    if (savingGlobalScope || nextScope === globalScope) return;
    const prev = globalScope;
    setGlobalScope(nextScope);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        nextScope,
        targetProcesses,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setGlobalScope(prev);
      } else {
        appActions.showToast(
          nextScope === "proxy_apps_only"
            ? "已切换为：智能自动识别代理核心与常用工具"
            : "已切换为：全机非 443 兜底加速",
          "ok"
        );
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleAddTargetProcess = async (ev?: FormEvent) => {
    ev?.preventDefault();
    if (savingGlobalScope) return;
    const raw = newProcessInput.trim();
    if (!raw) return;
    const entries = raw
      .split(/[,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (entries.length === 0) return;

    const existingLower = new Set(targetProcesses.map((p) => p.toLowerCase()));
    const added: string[] = [];
    for (const item of entries) {
      if (!existingLower.has(item.toLowerCase())) {
        existingLower.add(item.toLowerCase());
        added.push(item);
      }
    }
    if (added.length === 0) {
      appActions.showToast("该进程名已在加速列表中", "info");
      setNewProcessInput("");
      return;
    }

    const prev = targetProcesses;
    const nextList = [...targetProcesses, ...added];
    setTargetProcesses(nextList);
    setNewProcessInput("");
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        nextList,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
      } else {
        appActions.showToast(`已添加加速软件：${added.join("、")}`, "ok");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleRemoveTargetProcess = async (procName: string) => {
    if (savingGlobalScope) return;
    const prev = targetProcesses;
    const nextList = targetProcesses.filter((p) => p !== procName);
    setTargetProcesses(nextList);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        nextList,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
      } else {
        appActions.showToast(`已移出加速列表：${procName}`, "info");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleResetTargetProcesses = async () => {
    if (savingGlobalScope) return;
    const prev = targetProcesses;
    const defaults = [...DEFAULT_GLOBAL_TARGET_PROCESSES];
    setTargetProcesses(defaults);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        defaults,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
      } else {
        appActions.showToast("已恢复默认代理核心与传输工具列表", "ok");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleInstallWinDivert = async () => {
    if (installingDriver) return;
    await appActions.runInstallWinDivertDriver();
  };

  const handleRelaunchAdminGlobal = async () => {
    if (elevatingGlobal) return;
    setElevatingGlobal(true);
    try {
      await appActions.relaunchAsAdminForGlobalPreAccel();
    } finally {
      setElevatingGlobal(false);
    }
  };

  const handleCopyGlobalAddress = async (addr: string) => {
    const ok = await copyText(addr);
    if (ok) {
      setCopiedGlobalAddr(true);
      appActions.showToast(`已复制本地独立 443 入口：${addr}`, "ok");
      scheduleTimer(() => setCopiedGlobalAddr(false), 1800);
    } else {
      appActions.showToast("复制失败，请手动选中复制", "warn");
    }
  };

  const handleCopyGlobalShellCmd = async (
    port: number,
    shell: "posix" | "fish" | "powershell",
    label: string
  ) => {
    const cmd = buildGlobalPreAccelShellSnippet(port, shell);
    const ok = await copyText(cmd);
    if (ok) {
      setCopiedShellKind(shell);
      appActions.showToast(`已复制 ${label} 终端加速命令`, "ok");
      scheduleTimer(() => setCopiedShellKind(null), 1800);
    } else {
      appActions.showToast("复制失败，请手动选中复制", "warn");
    }
  };

  const handleToggleSkip443 = async () => {
    const prev = skip443Native;
    const next = !skip443Native;
    setSkip443Native(next);
    const ok = await persistPreAccelConfig(
      next,
      probeValidation.ok ? probeUrl : config.preaccel.probe_url,
      next
        ? "已开启：已是高速通道的线路自动跳过"
        : "已关闭：猫云及第三方代理软件的 443 海外节点均将走国内提速"
    );
    if (!ok) setSkip443Native(prev);
  };

  const handleToggleCampusPortalGuard = async () => {
    if (savingCampusGuard) return;
    const prev = campusPortalGuard;
    const next = !campusPortalGuard;
    setCampusPortalGuard(next);
    setSavingCampusGuard(true);
    try {
      await catcloudApi.saveExtendedSettings({
        preaccel: { campus_portal_guard: next },
      });
      appActions.syncConfig({
        ...config,
        preaccel: {
          ...config.preaccel,
          campus_portal_guard: next,
        },
      });
      appActions.showToast(
        next ? "已开启校园网登录页自动放行" : "已关闭校园网登录页自动放行",
        "ok"
      );
    } catch (err) {
      setCampusPortalGuard(prev);
      appActions.showToast(`更新登录页自动放行失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingCampusGuard(false);
    }
  };

  const handleSelectProbePreset = async (url: string, label: string) => {
    const prev = probeUrl;
    setProbeUrl(url);
    const ok = await persistPreAccelConfig(
      skip443Native,
      url,
      `已切换国内连通检测地址：${label}`
    );
    if (!ok) setProbeUrl(prev);
  };

  const handleSaveCustomProbe = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!probeValidation.ok) {
      appActions.showToast(probeValidation.error ?? "检测地址不合规", "warn");
      return;
    }
    const ok = await persistPreAccelConfig(
      skip443Native,
      probeUrl.trim(),
      "国内连通检测地址已保存"
    );
    if (ok) {
      setShowProbeModal(false);
    }
  };

  const handleManualSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (savingManual) return;

    const trimmedName = manualName.trim();
    const trimmedServer = manualServer.trim();
    const trimmedPassword = manualPassword.trim();
    const trimmedRegion = manualRegion.trim();
    const trimmedNote = manualNote.trim();
    const trimmedExpiry = manualExpiresAt.trim();
    const parsedPort = Number.parseInt(manualPort.trim() || "443", 10);

    if (!trimmedName) {
      setManualError("请填写线路名称，方便区分不同服务器");
      return;
    }
    if (!trimmedServer) {
      setManualError("请填写中转服务器的 IP 地址");
      return;
    }
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setManualError("端口范围应为 1 ～ 65535，推荐使用默认的 443");
      return;
    }
    if (!trimmedPassword) {
      setManualError(
        manualProtocol === "vless" ? "请填写 VLESS 协议的 UUID 密钥" : "请填写连接密码"
      );
      return;
    }
    if (manualProtocol === "vless" && !UUID_PATTERN.test(trimmedPassword)) {
      setManualError("VLESS 密钥需为标准 UUID 格式（如 00000000-0000-4000-8000-000000000000）");
      return;
    }

    const nextPriority =
      relays.length > 0 ? Math.max(...relays.map((r) => r.priority)) + 1 : 1;

    const newRelay: PreAccelRelay = {
      id: `relay-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      name: trimmedName,
      provider: trimmedNote || "自建中转",
      region: trimmedRegion || "国内",
      server: trimmedServer,
      port: parsedPort,
      protocol: manualProtocol,
      password: trimmedPassword,
      sni: null,
      skip_cert_verify: true,
      priority: nextPriority,
      expires_at: trimmedExpiry || null,
      enabled: true,
      last_probe_ms: null,
      last_mbps: null,
      last_up_mbps: null,
      last_down_mbps: null,
    };

    setSavingManual(true);
    setManualError(null);
    try {
      const saved = await catcloudApi.upsertPreAccelRelay(newRelay);
      if (inTauri) {
        const refreshed = await catcloudApi.listPreAccelRelays();
        setRelays(refreshed);
        appActions.syncPreAccelRelays(refreshed);
      } else {
        const nextList = [...relays, saved];
        setRelays(nextList);
        appActions.syncPreAccelRelays(nextList);
      }
      resetManualForm();
      setShowAddModal(false);
      appActions.showToast(`已添加中转线路「${saved.name}」`, "ok");
    } catch (err) {
      const msg = formatErrorMessage(err);
      setManualError(msg);
      appActions.showToast(`添加中转线路失败：${msg}`, "warn");
    } finally {
      setSavingManual(false);
    }
  };

  const handleImportSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (importing) return;
    const raw = importText.trim();
    if (!raw) {
      setImportError("请先粘贴导入码或 JSON 配置内容");
      return;
    }

    if (inTauri) {
      setImporting(true);
      setImportError(null);
      setImportWarnings([]);
      try {
        const imported = await catcloudApi.importMmRelayInput(raw);
        const refreshed = await catcloudApi.listPreAccelRelays();
        setRelays(refreshed);
        appActions.syncPreAccelRelays(refreshed);
        setImportText("");
        setShowAddModal(false);
        appActions.showToast(`成功导入 ${imported.length} 条中转线路`, "ok");
      } catch (err) {
        const msg = formatErrorMessage(err);
        setImportError(msg);
        appActions.showToast(`导入中转线路失败：${msg}`, "warn");
      } finally {
        setImporting(false);
      }
      return;
    }

    const res = parseRelayImportInput(raw);
    if (res.error) {
      setImportError(res.error);
      setImportWarnings([]);
      return;
    }
    setImportError(null);
    setImportWarnings(res.warnings);
    setRelays((prev) => {
      const byId = new Map(prev.map((r) => [r.id, r]));
      for (const incoming of res.relays) {
        byId.set(incoming.id, incoming);
      }
      const next = Array.from(byId.values());
      appActions.syncPreAccelRelays(next);
      return next;
    });
    setImportText("");
    setShowAddModal(false);
    appActions.showToast(
      `成功导入 ${res.relays.length} 条中转线路${res.warnings.length > 0 ? "（请留意配置提醒）" : ""}`,
      res.warnings.length > 0 ? "warn" : "ok"
    );
  };

  const handleFillDemoUri = () => {
    const uri = `${IMPORT_URI_PREFIX}${encodeBase64UrlUtf8(DEMO_IMPORT_JSON)}`;
    setImportText(uri);
    setImportError(null);
  };

  const handleMoveRelay = async (id: string, direction: -1 | 1) => {
    const idx = sortedRelays.findIndex((r) => r.id === id);
    const swapIdx = idx + direction;
    if (idx < 0 || swapIdx < 0 || swapIdx >= sortedRelays.length) return;

    const reordered = [...sortedRelays];
    const [moved] = reordered.splice(idx, 1);
    reordered.splice(swapIdx, 0, moved);

    const normalized = reordered.map((r, i) => ({ ...r, priority: i + 1 }));
    const changed = normalized.filter((r) => {
      const old = relays.find((item) => item.id === r.id);
      return !old || old.priority !== r.priority;
    });

    const prevRelays = relays;
    setRelays(normalized);
    try {
      for (const item of changed) {
        await catcloudApi.upsertPreAccelRelay(item);
      }
      appActions.syncPreAccelRelays(normalized);
      const isMultiCloudLbMode =
        isMultiCloudLbActive ||
        dispatchStrategy === "load_balance" ||
        (dispatchStrategy === "auto" && !activeRelayId);
      if (!isMultiCloudLbMode && (idx === 0 || swapIdx === 0) && normalized[0]?.enabled) {
        await catcloudApi.selectPreAccelRelay(normalized[0].id);
        const freshCfg = await catcloudApi.getConfig();
        appActions.syncConfig(freshCfg);
      }
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`调整线路顺序失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleRelay = async (id: string) => {
    const target = relays.find((r) => r.id === id);
    if (!target) return;
    const updated: PreAccelRelay = { ...target, enabled: !target.enabled };
    const prevRelays = relays;
    const nextRelays = relays.map((r) => (r.id === id ? updated : r));
    setRelays(nextRelays);
    try {
      await catcloudApi.upsertPreAccelRelay(updated);
      appActions.syncPreAccelRelays(nextRelays);
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`更新线路状态失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleUpdateDispatchConfig = async (
    nextStrategy: PreAccelDispatchStrategy,
    nextLbStrategy: PreAccelLbStrategy = lbStrategy,
    customNotice?: string
  ): Promise<boolean> => {
    if (savingDispatch) return false;
    setSavingDispatch(true);
    try {
      const latestConfig = appStore.getState().config;
      const nextPreAccel: AppConfig["preaccel"] = {
        ...latestConfig.preaccel,
        dispatch_strategy: nextStrategy,
        lb_strategy: nextLbStrategy,
        ...(nextStrategy !== "fallback" ? { active_relay_id: null } : {}),
      };
      const nextConfig: AppConfig = {
        ...latestConfig,
        preaccel: nextPreAccel,
      };
      const saved = await catcloudApi.saveConfig(nextConfig);
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
      const notice =
        customNotice ??
        (nextStrategy === "fallback"
          ? "已切换为「单线主备」模式（优先主力线，故障自动切备用）"
          : `已切换为「多云均衡聚合」模式（${
              nextLbStrategy === "consistent_hashing" ? "同站一致哈希" : "轮询并发叠加"
            }）`);
      appActions.showToast(notice, "ok");
      return true;
    } catch (err) {
      appActions.showToast(`切换中转调度方式失败：${formatErrorMessage(err)}`, "warn");
      return false;
    } finally {
      setSavingDispatch(false);
    }
  };

  const handleSelectRelay = async (relay: PreAccelRelay) => {
    if (!relay.enabled) {
      appActions.showToast("请先开启该线路，再设为主力", "warn");
      return;
    }
    const switchingFromMultiCloudLb = isMultiCloudLbActive;
    const prevRelays = relays;
    const reordered = [
      relay,
      ...sortedRelays.filter((r) => r.id !== relay.id),
    ].map((r, i) => ({ ...r, priority: i + 1 }));
    const changed = reordered.filter((r) => {
      const old = relays.find((item) => item.id === r.id);
      return !old || old.priority !== r.priority;
    });

    try {
      if (switchingFromMultiCloudLb) {
        const latestConfig = appStore.getState().config;
        const saved = await catcloudApi.saveConfig({
          ...latestConfig,
          preaccel: {
            ...latestConfig.preaccel,
            dispatch_strategy: "fallback",
          },
        });
        appActions.syncConfig(saved);
      }
      await catcloudApi.selectPreAccelRelay(relay.id);
      try {
        for (const item of changed) {
          await catcloudApi.upsertPreAccelRelay(item);
        }
        setRelays(reordered);
        appActions.syncPreAccelRelays(reordered);
      } catch {
        setRelays(prevRelays);
      }
      const [freshCfg, rt] = await Promise.all([
        catcloudApi.getConfig(),
        catcloudApi.getRuntimeInfo(),
      ]);
      appActions.syncConfig(freshCfg);
      appActions.syncRuntime(rt);
      appActions.showToast(
        switchingFromMultiCloudLb
          ? `已切换为单线主备并优先使用「${relay.name}」（保留其余线路自动兜底），可随时在上方切回多云自动均衡`
          : `已将「${relay.name}」设为主力线路（其余线路继续自动故障兜底）`,
        "ok",
        5200
      );
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`设置主力线路失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleFailover = async () => {
    if (failoverBusy) return;
    setFailoverBusy(true);
    try {
      const nextId = await catcloudApi.failoverPreAccel();
      const [freshCfg, rt] = await Promise.all([
        catcloudApi.getConfig(),
        catcloudApi.getRuntimeInfo(),
      ]);
      appActions.syncConfig(freshCfg);
      appActions.syncRuntime(rt);
      if (nextId) {
        const matched = relays.find((r) => r.id === nextId);
        appActions.showToast(`已切换至备用线路：${matched?.name ?? nextId}`, "ok");
      } else {
        appActions.showToast("当前没有其他可用的备用线路", "warn");
      }
    } catch (err) {
      appActions.showToast(`切换备用线路失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setFailoverBusy(false);
    }
  };

  const handleProbeRelay = async (id: string) => {
    if (probingIdsSet.has(id) || probingAll) return;
    await appActions.runTestPreAccelRelays(id);
  };

  const handleProbeAllRelays = async () => {
    if (probingAll || relays.length === 0) return;
    await appActions.runTestPreAccelRelays(null);
  };

  const handleSpeedTestRelay = async (id: string) => {
    if (speedTestingIdsSet.has(id) || speedTestingAll || isProbeEngineBusy) return;
    await appActions.runTestPreAccelRelaySpeeds(id, resolvedCompareNodeId || null);
  };

  const handleSpeedTestAllRelays = async () => {
    if (speedTestingAll || speedTestingAny || isProbeEngineBusy || relays.length === 0) return;
    await appActions.runTestPreAccelRelaySpeeds(null, resolvedCompareNodeId || null);
  };

  const handleConfirmRemoveRelay = async () => {
    if (!pendingDeleteRelay || deletingRelay) return;
    const target = pendingDeleteRelay;
    setDeletingRelay(true);
    try {
      await catcloudApi.deletePreAccelRelay(target.id);
      const next = relays.filter((r) => r.id !== target.id);
      setRelays(next);
      appActions.syncPreAccelRelays(next);
      setPendingDeleteRelay(null);
      appActions.showToast(`已删除中转线路「${target.name}」`, "info");
    } catch (err) {
      appActions.showToast(`删除线路失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingRelay(false);
    }
  };

  const handleRunBenchmark = async () => {
    if (benchmarking) return;
    if (isOtherProbeRunning) {
      appActions.showToast("节点测速正在后台进行，完成后即可运行提速对比", "info");
      return;
    }
    if (inTauri && enabledRelayCount === 0) {
      appActions.showToast("请先添加并启用至少一条国内中转线路，再进行提速对比", "warn");
      return;
    }
    if (inTauri && benchmarkableNodes.length === 0) {
      appActions.showToast("还没有可对比的海外节点，请先在「节点与测速 → 订阅与导入」中导入节点", "warn");
      return;
    }
    await appActions.runPreAccelBenchmark(resolvedCompareNodeId || null);
  };

  const handleCheckCampusAuth = async () => {
    if (checkingPortal) return;
    await appActions.runCheckCampusPortal();
  };

  const effectiveUpRatio = useMemo(() => {
    if (!comparison) return null;
    if (
      comparison.up_boost_ratio !== null &&
      Number.isFinite(comparison.up_boost_ratio) &&
      comparison.up_boost_ratio > 0
    ) {
      return comparison.up_boost_ratio;
    }
    const accUp = comparison.accelerated.up_mbps;
    const dirUp = comparison.direct.up_mbps;
    if (accUp !== null && dirUp !== null && dirUp > 0) {
      return accUp / dirUp;
    }
    return null;
  }, [comparison]);

  const effectiveDownRatio = useMemo(() => {
    if (!comparison) return null;
    if (
      comparison.down_boost_ratio !== null &&
      Number.isFinite(comparison.down_boost_ratio) &&
      comparison.down_boost_ratio > 0
    ) {
      return comparison.down_boost_ratio;
    }
    const accDown = comparison.accelerated.down_mbps;
    const dirDown = comparison.direct.down_mbps;
    if (accDown !== null && dirDown !== null && dirDown > 0) {
      return accDown / dirDown;
    }
    return null;
  }, [comparison]);

  const maxCompareUpMbps = useMemo(() => {
    if (!comparison) return 100;
    return Math.max(comparison.accelerated.up_mbps ?? 0, comparison.direct.up_mbps ?? 0, 10);
  }, [comparison]);

  const maxCompareDownMbps = useMemo(() => {
    if (!comparison) return 100;
    return Math.max(comparison.accelerated.down_mbps ?? 0, comparison.direct.down_mbps ?? 0, 10);
  }, [comparison]);

  const manualPortNum = Number.parseInt(manualPort.trim() || "443", 10);
  const manualShowNon443Hint =
    manualPort.trim() !== "" && Number.isInteger(manualPortNum) && manualPortNum !== 443;
  const manualShowDomainHint =
    manualServer.trim() !== "" && !looksLikeIpAddress(manualServer);

  const preaccelSummary = resolvePreAccelSummary(runtime, globalPreAccel, enabled);
  const effectiveGlobalPort =
    globalPreAccel.socks_port ?? runtime.global_preaccel_socks_port ?? null;
  const effectiveGlobalConns =
    globalPreAccel.active_connections || runtime.global_preaccel_connections || 0;
  const isWindows = platformOs === "windows";
  const localSocksAddress = effectiveGlobalPort ? `127.0.0.1:${effectiveGlobalPort}` : null;
  const processStats = useMemo(
    () => dedupeProcessStats(globalPreAccel.process_stats ?? []),
    [globalPreAccel.process_stats]
  );
  const acceleratedProcesses = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const proc of globalPreAccel.accelerated_processes ?? []) {
      const key = proc.trim().toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push(proc);
    }
    return out;
  }, [globalPreAccel.accelerated_processes]);
  const enabledRelayIds = useMemo(
    () => sortedRelays.filter((r) => r.enabled).map((r) => r.id),
    [sortedRelays]
  );
  const needsWindowsElevation =
    isWindows &&
    preaccelSummary.enabled &&
    !preaccelSummary.realWinDivertActive &&
    (preaccelSummary.installState === "need_elevation" ||
      (globalPreAccel.windivert_available && !globalPreAccel.is_elevated));
  const isPreparingDriver =
    installingDriver ||
    preaccelSummary.installState === "downloading" ||
    preaccelSummary.installState === "verifying";
  const isProbingVerify = verifyingGlobal || preaccelSummary.verifyState === "probing";
  const isDegradedVerify = preaccelSummary.verifyState === "degraded";
  const isVerifiedVerify =
    preaccelSummary.realWinDivertActive && preaccelSummary.verifyState === "verified";
  const showReprobeButton =
    isWindows && preaccelSummary.enabled && !isPreparingDriver && !needsWindowsElevation;
  const detectedSecurityProducts = globalPreAccel.detected_security_products ?? [];
  const securityGuidanceText = globalPreAccel.security_guidance?.trim() || null;
  const verifyMessageText = globalPreAccel.verify_message?.trim() || null;
  const isAbnormalVerifyState = isDegradedVerify || preaccelSummary.verifyState === "failed";
  const hasDistinctVerifyDetail =
    isAbnormalVerifyState &&
    Boolean(verifyMessageText) &&
    verifyMessageText !== preaccelSummary.detailText.trim();
  const showSecurityGuidanceBox =
    !preaccelSummary.realWinDivertActive &&
    (Boolean(securityGuidanceText) || hasDistinctVerifyDetail);
  const verifyCheckedClock =
    typeof globalPreAccel.verify_checked_at_ms === "number" &&
    globalPreAccel.verify_checked_at_ms > 0
      ? formatClockStamp(globalPreAccel.verify_checked_at_ms)
      : null;
  const verifyStateFallbackLabel = (() => {
    switch (preaccelSummary.verifyState) {
      case "probing":
        return "正在自动探测…";
      case "verified":
        return preaccelSummary.verifyLatencyMs
          ? `探测畅通（${preaccelSummary.verifyLatencyMs} ms）`
          : "探测畅通";
      case "degraded":
        return "已自动保护回退";
      case "failed":
        return "探测未通过";
      default:
        return "尚未探测";
    }
  })();

  const topStatusBadge = (() => {
    const label =
      preaccelSummary.proxyActive && preaccelSummary.subBadgeText
        ? `${preaccelSummary.badgeText} · ${preaccelSummary.subBadgeText}`
        : preaccelSummary.badgeText;
    const cls =
      preaccelSummary.tone === "green"
        ? "bg-[var(--green-soft)] text-[var(--green)]"
        : preaccelSummary.tone === "accent"
          ? "bg-[var(--accent-soft)] text-[var(--accent)]"
          : preaccelSummary.tone === "amber"
            ? "bg-[var(--amber-soft)] text-[var(--amber)]"
            : preaccelSummary.tone === "red"
              ? "bg-[var(--red-soft)] text-[var(--red)]"
              : "bg-[var(--bg-elevated)] text-[var(--muted)]";
    return { label, cls };
  })();

  return (
    <div className="space-y-4">
      {/* 1. 顶部极简总控卡片：全站唯一「开启国内提速」总开关 + 诚实状态条 + 自动识别进程遥测 */}
      <section className="cc-card cc-glass rounded-2xl p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                <Zap className="h-4 w-4" />
              </span>
              <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                国内提速
              </h1>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-medium ${topStatusBadge.cls}`}
              >
                {(isPreparingDriver || isProbingVerify) && (
                  <Loader2 className="h-3 w-3 animate-spin" />
                )}
                <span>{topStatusBadge.label}</span>
              </span>
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-[var(--muted)]">
              国内 443 高速入口，帮你突破宽带上传限速，让传图、传文件和远程访问更顺畅。
            </p>
          </div>

          {/* 轻按钮高级入口 */}
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowProbeModal(true)}
              className="relative inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-[var(--muted)]" />
              <span>检测地址</span>
              {!probeValidation.ok && (
                <span
                  className="h-2 w-2 rounded-full bg-[var(--red)]"
                  title="国内连通检测地址需要修正"
                />
              )}
            </button>

            <button
              type="button"
              onClick={() => appActions.openAiAssistant("preaccel", "web")}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            >
              <FileText className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>AI 部署说明</span>
            </button>
          </div>
        </div>

        {/* 唯一一个「开启国内提速」总开关 */}
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          disabled={togglingEnabled}
          onClick={() => void handleToggleEnabled()}
          className={`mt-4 flex w-full items-center justify-between gap-4 rounded-2xl border px-4 py-3.5 text-left transition-colors disabled:opacity-65 ${
            enabled
              ? "border-[var(--accent)]/60 bg-[var(--accent-soft)]/45 hover:border-[var(--accent)]"
              : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
          }`}
        >
          <div className="flex min-w-0 items-start gap-3">
            <span
              className={`mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl transition-colors ${
                enabled
                  ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                  : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]"
              }`}
            >
              {togglingEnabled ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Zap className="h-4 w-4" />
              )}
            </span>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-[var(--text)]">
                {togglingEnabled ? "正在切换国内提速…" : "开启国内提速"}
              </div>
              <div className="mt-0.5 text-xs leading-relaxed text-[var(--text-secondary)]">
                开启后猫猫云梯与电脑上其它代理软件都会一起走国内 443 提速，关闭则全部一起关
              </div>
            </div>
          </div>

          <span
            className={`inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0.5 transition-colors ${
              enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
            }`}
          >
            <span
              className={`h-5 w-5 rounded-full bg-[var(--card)] transition-transform ${
                enabled ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </span>
        </button>

        {/* 诚实状态条：仅在开启或准备中展示 */}
        {(preaccelSummary.enabled || isPreparingDriver) && (
          <div className="mt-3 space-y-2.5">
            <div
              className={`flex flex-wrap items-center justify-between gap-2.5 rounded-xl border px-3.5 py-2.5 text-xs ${
                isPreparingDriver ||
                needsWindowsElevation ||
                preaccelSummary.installState === "failed" ||
                isDegradedVerify ||
                isProbingVerify ||
                preaccelSummary.tone === "amber"
                  ? "border-[var(--amber)]/45 bg-[var(--amber-soft)]/50"
                  : preaccelSummary.realWinDivertActive || preaccelSummary.proxyActive
                    ? "border-[var(--green)]/35 bg-[var(--green-soft)]/45"
                    : "border-[var(--line)] bg-[var(--bg-elevated)]"
              }`}
            >
              <div className="flex min-w-0 flex-1 items-center gap-2">
                {isPreparingDriver || isProbingVerify ? (
                  <Loader2 className="h-4 w-4 shrink-0 animate-spin text-[var(--amber)]" />
                ) : needsWindowsElevation ||
                  preaccelSummary.installState === "failed" ||
                  isDegradedVerify ||
                  preaccelSummary.tone === "amber" ? (
                  <ShieldAlert className="h-4 w-4 shrink-0 text-[var(--amber)]" />
                ) : preaccelSummary.realWinDivertActive || preaccelSummary.proxyActive ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--green)]" />
                ) : (
                  <Clock className="h-4 w-4 shrink-0 text-[var(--amber)]" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="font-medium text-[var(--text)]">
                      {preaccelSummary.detailText}
                    </span>
                    {isProbingVerify ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        <span>正在自动探测…</span>
                      </span>
                    ) : isVerifiedVerify ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-semibold text-[var(--green)]">
                        <Check className="h-3 w-3" />
                        <span className="cc-mono cc-tabular">
                          链路已验证
                          {preaccelSummary.verifyLatencyMs
                            ? ` ${preaccelSummary.verifyLatencyMs} ms`
                            : ""}
                        </span>
                      </span>
                    ) : isDegradedVerify ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                        <ShieldAlert className="h-3 w-3" />
                        <span>已自动停止拦截防断网</span>
                      </span>
                    ) : preaccelSummary.verifyState === "failed" ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--red)]">
                        <AlertTriangle className="h-3 w-3" />
                        <span>链路探测未通过</span>
                      </span>
                    ) : null}
                  </div>
                  {preaccelSummary.realWinDivertActive && (
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-[var(--text-secondary)]">
                      <span>
                        当前加速连接{" "}
                        <strong className="cc-mono cc-tabular text-[var(--text)]">
                          {effectiveGlobalConns}
                        </strong>
                      </span>
                      <span>
                        累计{" "}
                        <strong className="cc-mono cc-tabular text-[var(--text)]">
                          {globalPreAccel.total_connections}
                        </strong>{" "}
                        次
                      </span>
                      <span>
                        ↑{" "}
                        <strong className="cc-mono cc-tabular text-[var(--coral)]">
                          {formatBytes(globalPreAccel.up_bytes)}
                        </strong>
                      </span>
                      <span>
                        ↓{" "}
                        <strong className="cc-mono cc-tabular text-[var(--sky)]">
                          {formatBytes(globalPreAccel.down_bytes)}
                        </strong>
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                {needsWindowsElevation && (
                  <button
                    type="button"
                    disabled={elevatingGlobal}
                    onClick={() => void handleRelaunchAdminGlobal()}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                  >
                    {elevatingGlobal ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <ShieldCheck className="h-3.5 w-3.5" />
                    )}
                    <span>{elevatingGlobal ? "正在重启…" : "以管理员重启生效"}</span>
                  </button>
                )}

                {isWindows &&
                  preaccelSummary.installState === "failed" &&
                  !preaccelSummary.realWinDivertActive && (
                    <button
                      type="button"
                      disabled={installBusy}
                      onClick={() => void handleInstallWinDivert()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                    >
                      {installBusy ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      <span>{installBusy ? "正在重试…" : "重试准备组件"}</span>
                    </button>
                  )}

                {!isWindows && localSocksAddress && (
                  <button
                    type="button"
                    onClick={() => void handleCopyGlobalAddress(localSocksAddress)}
                    className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    title="复制本地独立 443 SOCKS5 入口地址"
                  >
                    {copiedGlobalAddr ? (
                      <Check className="h-3 w-3 text-[var(--green)]" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    <span className="cc-mono">{localSocksAddress}</span>
                  </button>
                )}

                {showReprobeButton && (
                  <button
                    type="button"
                    disabled={isProbingVerify}
                    onClick={() => void handleVerifyGlobalPreAccel()}
                    className="inline-flex items-center gap-1 rounded-xl border border-[var(--accent)]/45 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]/55 disabled:opacity-60"
                    title="重新实测底层透明拦截与国内 443 中转链路连通性"
                  >
                    <RefreshCw
                      className={`h-3 w-3 ${isProbingVerify ? "animate-spin" : ""}`}
                    />
                    <span>{isProbingVerify ? "探测中…" : "重新探测"}</span>
                  </button>
                )}

                <button
                  type="button"
                  disabled={refreshingGlobal}
                  onClick={() => void handleRefreshGlobalStatus()}
                  className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
                  title="刷新提速状态与实时统计"
                >
                  <RefreshCw className={`h-3 w-3 ${refreshingGlobal ? "animate-spin" : ""}`} />
                  <span>刷新</span>
                </button>
              </div>
            </div>

            {/* 琥珀色环境指引提示框：仅在存在额外放行指引或与上方不重复的诊断明细，且底层拦截未运行时展示 */}
            {showSecurityGuidanceBox && (
              <div className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/55 px-3.5 py-2.5 text-xs">
                <div className="flex min-w-0 flex-1 items-start gap-2">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[var(--amber)]" />
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-[var(--text)]">环境放行指引</span>
                      {detectedSecurityProducts.map((prod) => (
                        <span
                          key={prod}
                          className="rounded-md border border-[var(--amber)]/40 bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                        >
                          {prod}
                        </span>
                      ))}
                    </div>
                    {hasDistinctVerifyDetail && verifyMessageText && (
                      <p className="text-[11px] leading-relaxed text-[var(--text)]">
                        {verifyMessageText}
                      </p>
                    )}
                    {securityGuidanceText && (
                      <p className="whitespace-pre-line text-[11px] leading-relaxed text-[var(--text-secondary)]">
                        {securityGuidanceText}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* 已自动识别并加速的进程小胶囊列表（含连接数与流量） */}
            {(processStats.length > 0 ||
              (preaccelSummary.realWinDivertActive &&
                acceleratedProcesses.length > 0)) && (
              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/80 px-3.5 py-2.5">
                <div className="mb-2 flex items-center justify-between gap-2 text-[11px]">
                  <span className="font-medium text-[var(--text-secondary)]">
                    已自动识别并加速（
                    {processStats.length > 0
                      ? processStats.length
                      : acceleratedProcesses.length}
                    ）
                  </span>
                  <span className="text-[10px] text-[var(--muted)]">
                    自动排除猫猫云梯自身，零手动配置
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {processStats.length > 0
                    ? processStats.slice(0, 12).map((stat) => (
                        <span
                          key={stat.process_name.toLowerCase()}
                          title={`PID ${stat.pid} · 来源：${formatDetectedByLabel(stat.detected_by)} · 累计 ${stat.total_connections} 连接`}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)]/35 bg-[var(--card)] px-2 py-1 text-[11px]"
                        >
                          <span className="cc-mono font-semibold text-[var(--text)]">
                            {stat.process_name}
                          </span>
                          <span className="rounded bg-[var(--accent-soft)] px-1 py-0.5 text-[9.5px] font-medium text-[var(--accent)]">
                            {formatDetectedByLabel(stat.detected_by)}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--text-secondary)]">
                            {stat.active_connections > 0
                              ? `${stat.active_connections} 连`
                              : `累计 ${stat.total_connections}`}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--coral)]">
                            ↑{formatBytes(stat.tx_bytes)}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--sky)]">
                            ↓{formatBytes(stat.rx_bytes)}
                          </span>
                        </span>
                      ))
                    : acceleratedProcesses.slice(0, 10).map((proc) => (
                        <span
                          key={proc.toLowerCase()}
                          className="cc-mono rounded-lg border border-[var(--accent)]/35 bg-[var(--accent-soft)]/60 px-2 py-1 text-[11px] font-medium text-[var(--accent)]"
                        >
                          {proc}
                        </span>
                      ))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* 2. 中转线路列表卡片 */}
      <section className="cc-card cc-glass rounded-2xl p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--text)]">中转线路</h2>
              <span className="rounded-full bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--muted)]">
                {sortedRelays.length} 条
              </span>
              {physicalHostSummary.distinctHosts >= 2 && (
                <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--green)]">
                  {physicalHostSummary.distinctHosts} 台物理云
                </span>
              )}
            </div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              {isMultiCloudLbActive
                ? "多云均衡模式：自动按不同物理主机聚合并发带宽，同机多协议自动去重并保留故障兜底"
                : "单线主备模式：排在首位的是主力线路，遇到波动时自动按顺序切换到备用线路"}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShareModalOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              title="一键导出或导入国内提速中转与节点 .zip 分享包"
            >
              <Package className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{dict.common.shareBundle}</span>
            </button>

            <button
              type="button"
              disabled={probingAll || relays.length === 0}
              onClick={() => void handleProbeAllRelays()}
              title="快速检测所有中转线路的连通性与实时延迟"
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${probingAll ? "animate-spin" : ""}`} />
              <span>{probingAll ? "检测中..." : "测延迟"}</span>
            </button>

            <button
              type="button"
              disabled={speedTestingAll || speedTestingAny || isProbeEngineBusy || relays.length === 0}
              onClick={() => void handleSpeedTestAllRelays()}
              title="逐条实测所有中转线路的实际上传与下载速率（切页不中断）"
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
            >
              {speedTestingAll ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--accent)]" />
              ) : (
                <Gauge className="h-3.5 w-3.5 text-[var(--accent)]" />
              )}
              <span>{speedTestingAll ? "测速中..." : "测上下行"}</span>
            </button>

            <button
              type="button"
              disabled={failoverBusy || enabledRelayCount < 2}
              onClick={() => void handleFailover()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
              title="将当前流量切换到下一条可用的备用线路"
            >
              <ArrowLeftRight className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{failoverBusy ? "切换中..." : "切换备用"}</span>
            </button>

            <button
              type="button"
              onClick={() => openAddModal("manual")}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>添加中转</span>
            </button>
          </div>
        </div>

        {/* 多云均衡聚合 / 单线主备 调度方式控制条 */}
        {sortedRelays.length > 0 && (
          <div className="mb-4 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1.5 font-medium text-[var(--text-secondary)]">
                  <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span>{dict.preaccel.dispatchLabel}</span>
                </span>
                <div
                  className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--card)] p-0.5 text-[11px]"
                  role="group"
                  aria-label={dict.preaccel.dispatchLabel}
                >
                  <button
                    type="button"
                    disabled={savingDispatch}
                    onClick={() => void handleUpdateDispatchConfig("auto", lbStrategy)}
                    className={`rounded-lg px-2.5 py-1 font-medium transition-colors disabled:opacity-60 ${
                      isMultiCloudLbStrategy
                        ? "bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                        : "text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    {dict.preaccel.dispatchAutoLb}
                  </button>
                  <button
                    type="button"
                    disabled={savingDispatch}
                    onClick={() => void handleUpdateDispatchConfig("fallback", lbStrategy)}
                    className={`rounded-lg px-2.5 py-1 font-medium transition-colors disabled:opacity-60 ${
                      !isMultiCloudLbStrategy
                        ? "bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                        : "text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    {dict.preaccel.dispatchFallback}
                  </button>
                </div>
              </div>

              {isMultiCloudLbActive && (
                <div className="flex items-center gap-1.5 text-[11px]">
                  <span className="text-[var(--muted)]">均衡算法</span>
                  <button
                    type="button"
                    disabled={savingDispatch}
                    onClick={() =>
                      void handleUpdateDispatchConfig(
                        dispatchStrategy,
                        lbStrategy === "round_robin" ? "consistent_hashing" : "round_robin"
                      )
                    }
                    className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
                    title="轮询可最大化多云并发叠加带宽；一致哈希可让同一目标站固定走同一台云"
                  >
                    {lbStrategy === "consistent_hashing" ? "同站一致哈希" : "轮询并发叠加"}
                  </button>
                </div>
              )}
            </div>

            {physicalHostSummary.distinctHosts >= 2 && isMultiCloudLbActive && (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--green)]/40 bg-[var(--green-soft)]/45 px-3.5 py-2 text-[11.5px] text-[var(--text)]">
                <div className="flex min-w-0 items-center gap-2">
                  <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                  <span>
                    已自动聚合{" "}
                    <strong className="cc-mono text-[var(--green)]">
                      {physicalHostSummary.distinctHosts}
                    </strong>{" "}
                    台物理云并发带宽
                    {physicalHostSummary.duplicateProtocolCount > 0
                      ? `（同机多余 ${physicalHostSummary.duplicateProtocolCount} 条协议已自动去重防抢占网卡）`
                      : "（同机多协议自动去重）"}
                    ，单台故障自动切换备用与直连兜底。
                  </span>
                </div>
              </div>
            )}

            {physicalHostSummary.distinctHosts >= 2 && !isMultiCloudLbActive && (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/45 px-3.5 py-2 text-[11.5px] text-[var(--text)]">
                <span className="text-[var(--text-secondary)]">
                  当前已手动固定为单线主备模式（优先使用首位主力线，其余线路作故障兜底）。检测到{" "}
                  <strong className="cc-mono text-[var(--text)]">
                    {physicalHostSummary.distinctHosts}
                  </strong>{" "}
                  台不同物理云，可随时切回并发聚合。
                </span>
                <button
                  type="button"
                  disabled={savingDispatch}
                  onClick={() => void handleUpdateDispatchConfig("auto", lbStrategy)}
                  className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  <Layers className="h-3 w-3" />
                  <span>{dict.preaccel.switchBackLbBtn}</span>
                </button>
              </div>
            )}
          </div>
        )}

        {importWarnings.length > 0 && (
          <div className="mb-4 flex items-start justify-between gap-3 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs text-[var(--amber)]">
            <div>
              <div className="font-semibold">导入配置提醒</div>
              <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px]">
                {importWarnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </div>
            <button
              type="button"
              onClick={() => setImportWarnings([])}
              className="shrink-0 rounded-md p-1 opacity-75 hover:opacity-100"
              aria-label="关闭提醒"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* 中转机卡片列表 */}
        <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2">
          {sortedRelays.map((relay, idx) => {
            const enabledRank = enabledRankMap.get(relay.id);
            const isTopEnabled = relay.enabled && enabledRank === 0;
            const roleLabel = !relay.enabled
              ? "已停用"
              : isTopEnabled
                ? "主力线路"
                : `备用 ${enabledRank ?? 1}`;
            const isActivePrimary = relay.id === primaryRelayId && relay.enabled;
            const isProbing = probingIdsSet.has(relay.id) || probingAll;
            const isSpeedTesting = speedTestingIdsSet.has(relay.id) || speedTestingAll;
            const hasUpSpeed = hasValidSpeed(relay.last_up_mbps);
            const hasDownSpeed = hasValidSpeed(relay.last_down_mbps);
            const hasLegacySpeed = !hasUpSpeed && !hasDownSpeed && hasValidSpeed(relay.last_mbps);
            const expiry = computeExpiryInfo(relay.expires_at);
            const hasUrgentExpiry = expiry.tone === "warn" || expiry.tone === "expired";
            const safeSni = (relay.sni ?? "").trim();
            const hasConfigTip = relay.port !== 443 || safeSni !== "";
            const canSetPrimary =
              relay.enabled && (isMultiCloudLbActive || !isTopEnabled || !isActivePrimary);
            const rawChainMs = relayChainLatencies[relay.id];
            const validChainMs =
              typeof rawChainMs === "number" && Number.isFinite(rawChainMs) && rawChainMs > 0
                ? Math.round(rawChainMs)
                : null;

            return (
              <div
                key={relay.id}
                className={`rounded-2xl border p-4 transition-colors ${
                  isTopEnabled || isActivePrimary
                    ? "border-[var(--accent)]/75 bg-[var(--accent-soft)]/35"
                    : "border-[var(--line)] bg-[var(--bg-elevated)]"
                } ${!relay.enabled ? "opacity-70" : ""}`}
              >
                {/* 卡片第一行：名称 + 角色徽章 + 状态开关 */}
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Server
                        className={`h-4 w-4 shrink-0 ${
                          isTopEnabled || isActivePrimary
                            ? "text-[var(--accent)]"
                            : "text-[var(--muted)]"
                        }`}
                      />
                      <span className="truncate text-sm font-semibold text-[var(--text)]">
                        {relay.name}
                      </span>
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                          isTopEnabled
                            ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                            : !relay.enabled
                              ? "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]"
                              : "border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
                        }`}
                      >
                        {roleLabel}
                      </span>
                      {isActivePrimary && !isTopEnabled && (
                        <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                          当前使用
                        </span>
                      )}
                      {hasUrgentExpiry && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--red)]">
                          <Clock className="h-3 w-3" />
                          {expiry.label}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* 状态开关 */}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={relay.enabled}
                    aria-label={relay.enabled ? `停用 ${relay.name}` : `开启 ${relay.name}`}
                    title={relay.enabled ? "已开启，点击停用" : "已停用，点击开启"}
                    onClick={() => void handleToggleRelay(relay.id)}
                    className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                      relay.enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                    }`}
                  >
                    <span
                      className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                        relay.enabled ? "translate-x-4" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>

                {/* 卡片第二行：地区、备注/地址 + 实时延迟 */}
                <div className="mt-3 flex items-center justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-secondary)]">
                      <span className="inline-flex items-center gap-1">
                        <Globe className="h-3.5 w-3.5 text-[var(--muted)]" />
                        <span>{relay.region || "国内"}</span>
                      </span>
                      {relay.provider && (
                        <span className="text-[11px] text-[var(--muted)]">
                          · {relay.provider}
                        </span>
                      )}
                      {!hasUrgentExpiry && expiry.label && (
                        <span className="text-[11px] text-[var(--muted)]">
                          · {expiry.label}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]">
                      <span className="cc-mono truncate">
                        {relay.server}:{relay.port}
                      </span>
                      <span className="uppercase">{relay.protocol}</span>
                      {hasConfigTip && (
                        <span className="rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] text-[var(--amber)]">
                          {safeSni !== "" ? "建议留空域名" : "建议使用 443 端口"}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* 实时直连延迟 + 真实上下行 + 经海外对比延迟（严格区分绝不混淆） */}
                  <div className="shrink-0 text-right">
                    <div
                      className="cc-mono cc-tabular text-base font-bold leading-tight"
                      style={{ color: getRelayLatencyColor(relay.last_probe_ms) }}
                      title="本机直连国内中转的真实延迟（绝不被经海外节点的两跳测速延迟污染）"
                    >
                      {relay.last_probe_ms !== null
                        ? formatLatencyDisplay(relay.last_probe_ms, "--")
                        : "待测速"}
                    </div>
                    {hasUpSpeed || hasDownSpeed ? (
                      <div
                        title="实测中转速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
                        className="mt-0.5 flex items-center justify-end gap-1.5 whitespace-nowrap cc-mono cc-tabular text-[11px] font-semibold"
                      >
                        {hasUpSpeed && (
                          <span className="text-[var(--coral)]">
                            ↑{relay.last_up_mbps!.toFixed(1)} Mbps
                          </span>
                        )}
                        {hasDownSpeed && (
                          <span className="text-[var(--sky)]">
                            ↓{relay.last_down_mbps!.toFixed(1)} Mbps
                          </span>
                        )}
                      </div>
                    ) : hasLegacySpeed ? (
                      <div
                        title="实测中转上传速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
                        className="mt-0.5 whitespace-nowrap cc-mono cc-tabular text-[11px] font-semibold text-[var(--coral)]"
                      >
                        ↑{relay.last_mbps!.toFixed(1)} Mbps
                      </div>
                    ) : (
                      <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                        {relay.last_probe_ms !== null ? "直连延迟 · 未测上下行" : "直连实时延迟"}
                      </div>
                    )}
                    {validChainMs !== null && (
                      <div
                        className="mt-0.5 whitespace-nowrap cc-mono text-[10px] text-[var(--muted)]"
                        title="经国内中转 + 海外参考节点的两跳对比延迟，仅作上下行测试参考，不影响上方直连延迟"
                      >
                        {dict.preaccel.chainLatencyLabel} {validChainMs} ms
                      </div>
                    )}
                  </div>
                </div>

                {/* 卡片第三行：操作栏 */}
                <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)]/65 pt-2.5 text-[11px]">
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      disabled={idx === 0}
                      onClick={() => void handleMoveRelay(relay.id, -1)}
                      className="inline-flex items-center gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)] disabled:opacity-75"
                      title="上移一位"
                    >
                      <ArrowUp className="h-3 w-3" />
                      <span>上移</span>
                    </button>
                    <button
                      type="button"
                      disabled={idx === sortedRelays.length - 1}
                      onClick={() => void handleMoveRelay(relay.id, 1)}
                      className="inline-flex items-center gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)] disabled:opacity-75"
                      title="下移一位"
                    >
                      <ArrowDown className="h-3 w-3" />
                      <span>下移</span>
                    </button>
                  </div>

                  <div className="flex items-center gap-2.5">
                    {canSetPrimary && (
                      <button
                        type="button"
                        onClick={() => void handleSelectRelay(relay)}
                        title={
                          isMultiCloudLbActive
                            ? "切换为单线主备模式并固定优先使用此线（随时可切回多云自动均衡）"
                            : "设为首选主力线路（其余启用线路继续自动故障兜底）"
                        }
                        className="inline-flex items-center gap-1 whitespace-nowrap font-medium text-[var(--accent)] transition-opacity hover:opacity-80"
                      >
                        <Star className="h-3.5 w-3.5" />
                        <span>
                          {isMultiCloudLbActive ? dict.preaccel.pinPrimaryBtn : "设为主力"}
                        </span>
                      </button>
                    )}

                    <button
                      type="button"
                      disabled={isProbing}
                      onClick={() => void handleProbeRelay(relay.id)}
                      title="快速检测该中转线路的连通延迟"
                      className="inline-flex items-center gap-1 whitespace-nowrap text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${isProbing ? "animate-spin" : ""}`} />
                      <span>{isProbing ? "测延迟中" : "测延迟"}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isSpeedTesting || isProbeEngineBusy}
                      onClick={() => void handleSpeedTestRelay(relay.id)}
                      title="实测该中转线路的实际上传与下载速率（切页不中断）"
                      className="inline-flex items-center gap-1 whitespace-nowrap text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {isSpeedTesting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--accent)]" />
                      ) : (
                        <Gauge className="h-3.5 w-3.5" />
                      )}
                      <span>{isSpeedTesting ? "测速中" : "测上下行"}</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setPendingDeleteRelay(relay)}
                      className="inline-flex items-center gap-1 whitespace-nowrap text-[var(--muted)] transition-colors hover:text-[var(--red)]"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      <span>删除</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}

          {sortedRelays.length === 0 && (
            <div className="col-span-full rounded-2xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/35 p-5">
              <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-[var(--accent-soft)] text-[var(--accent)]">
                    <Sparkles className="h-5 w-5" />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      {dict.preaccel.emptyFriendlyTitle}
                    </h3>
                    <p className="mt-1 max-w-2xl text-xs leading-relaxed text-[var(--text-secondary)]">
                      {dict.preaccel.emptyFriendlyDesc}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => appActions.openAiAssistant("preaccel", "agent")}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                >
                  <Bot className="h-3.5 w-3.5" />
                  <span>{dict.preaccel.emptyAskAiDeploy}</span>
                </button>
                <button
                  type="button"
                  onClick={() => openAddModal("manual")}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3.5 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>添加中转</span>
                </button>
                <button
                  type="button"
                  onClick={() => openAddModal("import")}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                >
                  <Upload className="h-3.5 w-3.5" />
                  <span>粘贴导入码</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShareModalOpen(true)}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                >
                  <Package className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span>{dict.common.importShareBundle}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* 3. 底部两张实用卡片：提速前后测速对比 + 校园网认证检测 */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {/* 提速效果实测对比 */}
        <div
          className={`cc-card cc-glass rounded-2xl p-5 transition-colors lg:col-span-7 ${
            isComparisonFresh && !benchmarking ? "ring-1 ring-[var(--green)]/35" : ""
          }`}
        >
          <div className="mb-4 flex flex-wrap items-start justify-between gap-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Gauge className="h-4 w-4 shrink-0 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  提速效果实测对比
                </h2>
                {isComparisonFresh && !benchmarking && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                    刚刚更新
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                默认直接拿首页当前节点对比「走国内中转」和「普通直连」的真实上传、下载速度（也可下拉换测其它节点）
              </p>
            </div>
            <button
              type="button"
              disabled={benchmarking || isOtherProbeRunning || isProbeEngineBusy}
              onClick={() => void handleRunBenchmark()}
              title={
                speedTestingAny
                  ? "中转上下行测速正在后台进行，完成后可运行提速对比"
                  : isOtherProbeRunning
                    ? "节点测速正在后台进行，完成后可运行提速对比"
                    : undefined
              }
              className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${benchmarking ? "animate-spin" : ""}`} />
              <span>
                {benchmarking
                  ? "正在实测对比（约 5～10 秒）…"
                  : speedTestingAny
                    ? "中转测速进行中…"
                    : isOtherProbeRunning
                      ? "节点测速进行中…"
                      : "一键对比提速效果"}
              </span>
            </button>
          </div>

          {isOtherProbeRunning && (
            <div className="mb-3 flex items-center gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-[11px] text-[var(--amber)]">
              <Clock className="h-3.5 w-3.5 shrink-0" />
              <span>
                「节点与测速」页正在后台运行节点测速，测速结束后即可一键对比提速效果
              </span>
            </div>
          )}

          {benchmarking && comparison && (
            <div className="mb-3 flex items-center gap-2 rounded-xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/45 px-3.5 py-2 text-[11px] text-[var(--accent)]">
              <RefreshCw className="h-3.5 w-3.5 shrink-0 animate-spin" />
              <span>正在后台执行新一轮实测对比（约 5～10 秒），完成后自动刷新下方数据…</span>
            </div>
          )}

          {/* 中转连通概况 + 对照海外节点选择器 */}
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
            <span className="text-[var(--text-secondary)]">
              已启用中转{" "}
              <strong className="cc-mono text-[var(--text)]">
                {relayLatencyStats.enabledTotal}
              </strong>{" "}
              条 · 已测通{" "}
              <strong className="cc-mono text-[var(--green)]">
                {relayLatencyStats.probedCount}
              </strong>{" "}
              条
              {hasValidLatency(relayLatencyStats.bestMs) && (
                <span className="cc-mono text-[var(--muted)]">
                  {" "}
                  · 最快 {formatLatencyDisplay(relayLatencyStats.bestMs)}
                </span>
              )}
            </span>

            <div className="flex items-center gap-1.5">
              <span className="shrink-0 text-[11px] text-[var(--muted)]">对照节点</span>
              {benchmarkableNodes.length > 0 || homeCurrentNode ? (
                <AppSelect
                  aria-label="对照节点"
                  size="xs"
                  value={resolvedCompareNodeId}
                  disabled={benchmarking}
                  onChange={setSelectedCompareNodeId}
                  options={[
                    {
                      value: "",
                      label: homeCurrentNode
                        ? `跟随首页当前节点（${homeCurrentNode.name}）`
                        : "跟随首页当前节点",
                    },
                    ...otherBenchmarkableNodes.map((node) => ({
                      value: node.id,
                      label: node.name,
                    })),
                  ]}
                  className="max-w-[240px]"
                  buttonClassName="bg-[var(--card)]"
                />
              ) : (
                <span className="text-[11px] text-[var(--muted)]">暂未导入海外节点</span>
              )}
            </div>
          </div>

          {resolvedCompareNodeId === "" && isHomeCurrentNodeUdpOnly && (
            <div className="mb-3 flex items-start gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                首页当前节点为纯 UDP 协议，无法套 TCP 中转；点击对比时将自动改测其它可用节点，或请直接从右侧下拉指定
              </span>
            </div>
          )}

          {!comparison ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-[var(--line-strong)] bg-[var(--bg-elevated)]/65 px-5 py-9 text-center">
              {benchmarking ? (
                <>
                  <RefreshCw className="h-6 w-6 animate-spin text-[var(--accent)]" />
                  <p className="mt-3 text-xs font-semibold text-[var(--text)]">
                    正在实测对比（约 5～10 秒）…
                  </p>
                  <p className="mt-1 max-w-md text-[11px] leading-relaxed text-[var(--muted)]">
                    正在依次检测中转连通性，并对所选海外节点实测「走国内中转」与「普通直连」的上传、下载速度
                  </p>
                </>
              ) : (
                <>
                  <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-[var(--accent-soft)] text-[var(--accent)]">
                    <Gauge className="h-5 w-5" />
                  </span>
                  <p className="mt-3 text-xs font-semibold text-[var(--text)]">
                    点击右上角按钮，立刻实测走中转能快多少
                  </p>
                  <p className="mt-1 max-w-md text-[11px] leading-relaxed text-[var(--muted)]">
                    系统会用同一海外节点现场对比「开启国内提速（走国内中转）」与「普通线路直连」的真实上下行速度，平时零后台流量。
                  </p>
                </>
              )}

              {comparisonError && (
                <div className="mt-3.5 flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-left text-[11px] text-[var(--red)]">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span>{comparisonError}</span>
                </div>
              )}
            </div>
          ) : (
            <>
              {/* 本次实测对照组合 + 提速倍数徽章 */}
              <div className="mb-3 rounded-xl border border-[var(--accent)]/35 bg-[var(--accent-soft)]/35 px-3.5 py-2 text-[11px]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[var(--text-secondary)]">
                    <span className="shrink-0 text-[var(--muted)]">本次对照：</span>
                    <span className="truncate font-semibold text-[var(--text)]">
                      {comparison.relay_name}
                    </span>
                    <span className="text-[var(--muted)]">+</span>
                    <span className="truncate font-semibold text-[var(--text)]">
                      {comparison.node_name}
                    </span>
                    {comparisonIsDemo && (
                      <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                        演示数据
                      </span>
                    )}
                  </div>

                  <div className="flex shrink-0 items-center gap-1.5">
                    {effectiveUpRatio !== null && (
                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                          effectiveUpRatio >= 1.1
                            ? "bg-[var(--green)] text-[var(--accent-ink)]"
                            : "border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
                        }`}
                      >
                        <Zap className="h-3 w-3" />
                        <span>
                          {effectiveUpRatio >= 1.1
                            ? `上传提速 ${effectiveUpRatio.toFixed(1)} 倍`
                            : `上传约 ${effectiveUpRatio.toFixed(1)} 倍`}
                        </span>
                      </span>
                    )}
                    {effectiveDownRatio !== null && effectiveDownRatio >= 1.1 && (
                      <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                        下载 {effectiveDownRatio.toFixed(1)} 倍
                      </span>
                    )}
                  </div>
                </div>

                {comparison.fallback_reason?.trim() && (
                  <div className="mt-2 flex items-start gap-1.5 border-t border-[var(--accent)]/20 pt-2 leading-relaxed text-[var(--amber)]">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>{comparison.fallback_reason.trim()}</span>
                  </div>
                )}
              </div>

              <div className="space-y-3">
                {/* 走国内中转 */}
                {(() => {
                  const side = comparison.accelerated;
                  const sideHasLatency = hasValidLatency(side.latency_ms);
                  const sideError = side.error?.trim() || "";
                  return (
                    <div className="rounded-xl border border-[var(--green)]/35 bg-[var(--bg-elevated)] p-3.5">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="font-semibold text-[var(--text)]">
                          开启国内提速（走国内中转）
                        </span>
                        <span
                          className={`cc-mono text-[11px] ${
                            side.ok
                              ? "text-[var(--green)]"
                              : sideHasLatency
                                ? "text-[var(--amber)]"
                                : "text-[var(--red)]"
                          }`}
                        >
                          {sideHasLatency
                            ? `延迟 ${formatLatencyDisplay(side.latency_ms)}${
                                side.ok ? "" : " · 部分超时"
                              }`
                            : side.ok
                              ? "测速成功"
                              : "测速失败"}
                        </span>
                      </div>
                      <div className="mt-2.5 space-y-2">
                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-[var(--muted)]">上传速度</span>
                            <span
                              className={`cc-mono cc-tabular font-semibold ${
                                side.up_mbps !== null
                                  ? "text-[var(--green)]"
                                  : "text-[var(--muted)]"
                              }`}
                            >
                              {side.up_mbps !== null
                                ? `${side.up_mbps.toFixed(1)} Mbps`
                                : sideHasLatency
                                  ? "测速超时"
                                  : "未测出"}
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                            <div
                              className="h-full rounded-full bg-[var(--green)] transition-all duration-300"
                              style={{
                                width:
                                  side.up_mbps !== null && side.up_mbps > 0
                                    ? `${Math.max(
                                        3,
                                        Math.min(100, (side.up_mbps / maxCompareUpMbps) * 100)
                                      )}%`
                                    : "0%",
                              }}
                            />
                          </div>
                        </div>
                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-[var(--muted)]">下载速度</span>
                            <span
                              className={`cc-mono cc-tabular font-medium ${
                                side.down_mbps !== null
                                  ? "text-[var(--sky)]"
                                  : "text-[var(--muted)]"
                              }`}
                            >
                              {side.down_mbps !== null
                                ? `${side.down_mbps.toFixed(1)} Mbps`
                                : sideHasLatency
                                  ? "测速超时"
                                  : "未测出"}
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                            <div
                              className="h-full rounded-full bg-[var(--sky)] transition-all duration-300"
                              style={{
                                width:
                                  side.down_mbps !== null && side.down_mbps > 0
                                    ? `${Math.max(
                                        3,
                                        Math.min(100, (side.down_mbps / maxCompareDownMbps) * 100)
                                      )}%`
                                    : "0%",
                              }}
                            />
                          </div>
                        </div>
                        {sideError && (
                          <p
                            className={`text-[11px] leading-relaxed ${
                              !side.ok && !sideHasLatency
                                ? "text-[var(--red)]"
                                : "text-[var(--amber)]"
                            }`}
                          >
                            {!side.ok && !sideHasLatency ? "失败原因：" : "异常说明："}
                            {sideError}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* 普通直连 */}
                {(() => {
                  const side = comparison.direct;
                  const sideHasLatency = hasValidLatency(side.latency_ms);
                  const sideError = side.error?.trim() || "";
                  return (
                    <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="font-semibold text-[var(--text)]">普通线路直连</span>
                        <span
                          className={`cc-mono text-[11px] ${
                            side.ok
                              ? "text-[var(--amber)]"
                              : sideHasLatency
                                ? "text-[var(--amber)]"
                                : "text-[var(--red)]"
                          }`}
                        >
                          {sideHasLatency
                            ? `延迟 ${formatLatencyDisplay(side.latency_ms)}${
                                side.ok ? "" : " · 部分超时"
                              }`
                            : side.ok
                              ? "测速成功"
                              : "测速失败"}
                        </span>
                      </div>
                      <div className="mt-2.5 space-y-2">
                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-[var(--muted)]">上传速度</span>
                            <span
                              className={`cc-mono cc-tabular font-semibold ${
                                side.up_mbps !== null
                                  ? "text-[var(--amber)]"
                                  : "text-[var(--muted)]"
                              }`}
                            >
                              {side.up_mbps !== null
                                ? `${side.up_mbps.toFixed(1)} Mbps`
                                : sideHasLatency
                                  ? "测速超时"
                                  : "未测出"}
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                            <div
                              className="h-full rounded-full bg-[var(--amber)] transition-all duration-300"
                              style={{
                                width:
                                  side.up_mbps !== null && side.up_mbps > 0
                                    ? `${Math.max(
                                        3,
                                        Math.min(100, (side.up_mbps / maxCompareUpMbps) * 100)
                                      )}%`
                                    : "0%",
                              }}
                            />
                          </div>
                        </div>
                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-[var(--muted)]">下载速度</span>
                            <span
                              className={`cc-mono cc-tabular font-medium ${
                                side.down_mbps !== null
                                  ? "text-[var(--text-secondary)]"
                                  : "text-[var(--muted)]"
                              }`}
                            >
                              {side.down_mbps !== null
                                ? `${side.down_mbps.toFixed(1)} Mbps`
                                : sideHasLatency
                                  ? "测速超时"
                                  : "未测出"}
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                            <div
                              className="h-full rounded-full bg-[var(--text-secondary)]/65 transition-all duration-300"
                              style={{
                                width:
                                  side.down_mbps !== null && side.down_mbps > 0
                                    ? `${Math.max(
                                        3,
                                        Math.min(100, (side.down_mbps / maxCompareDownMbps) * 100)
                                      )}%`
                                    : "0%",
                              }}
                            />
                          </div>
                        </div>
                        {sideError && (
                          <p
                            className={`text-[11px] leading-relaxed ${
                              !side.ok && !sideHasLatency
                                ? "text-[var(--red)]"
                                : "text-[var(--amber)]"
                            }`}
                          >
                            {!side.ok && !sideHasLatency ? "失败原因：" : "异常说明："}
                            {sideError}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })()}
              </div>

              {comparisonError && (
                <div className="mt-3 flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span>上次重新测速出错：{comparisonError}</span>
                </div>
              )}

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
                <span className="text-[var(--text-secondary)]">
                  {effectiveUpRatio !== null && effectiveUpRatio >= 1.1 ? (
                    <>
                      实测走国内中转上传速度提升{" "}
                      <strong className="cc-mono text-[var(--accent)]">
                        {effectiveUpRatio.toFixed(1)} 倍
                      </strong>
                      {comparisonIsDemo ? "（演示数据）" : "，建议保持开启国内提速。"}
                    </>
                  ) : comparison.accelerated.ok && comparison.direct.ok ? (
                    "当前所选节点直连表现良好，可换一个普通海外节点再次对比。"
                  ) : (
                    "部分测速未通过，可切换其他中转或海外节点重试。"
                  )}
                </span>
                <span className="cc-mono text-[var(--muted)]">
                  实测时间：{formatClockStamp(comparison.tested_at)}
                </span>
              </div>
            </>
          )}
        </div>

        {/* 校园网认证检测 */}
        <div className="cc-card cc-glass flex flex-col justify-between rounded-2xl p-5 lg:col-span-5">
          <div>
            <div className="mb-4 flex items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <Wifi className="h-4 w-4 text-[var(--accent)]" />
                  <h2 className="text-sm font-semibold text-[var(--text)]">
                    校园网认证检测
                  </h2>
                </div>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  自动识别校园网或公共 Wi-Fi 登录页
                </p>
              </div>
              <button
                type="button"
                disabled={checkingPortal}
                onClick={() => void handleCheckCampusAuth()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${checkingPortal ? "animate-spin" : ""}`} />
                <span>{checkingPortal ? "检测中..." : "立即检测"}</span>
              </button>
            </div>

            <div
              className={`mb-3.5 rounded-xl border px-3.5 py-3 ${
                portalRequired
                  ? "border-[var(--amber)]/50 bg-[var(--amber-soft)]"
                  : portalHttpCode === null
                    ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                    : "border-[var(--green)]/40 bg-[var(--green-soft)]"
              }`}
            >
              <div className="flex items-start gap-2.5">
                {portalRequired ? (
                  <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[var(--amber)]" />
                ) : portalHttpCode === null ? (
                  <Clock className="mt-0.5 h-5 w-5 shrink-0 text-[var(--muted)]" />
                ) : (
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-[var(--green)]" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    {portalRequired
                      ? "检测到需要登录校园网 / 公共 Wi-Fi"
                      : portalHttpCode === null
                        ? "尚未检测当前网络"
                        : "当前国内网络正常，无需网页认证"}
                  </div>
                  <div className="mt-1 text-[11px] text-[var(--muted)]">
                    {portalHttpCode !== null
                      ? portalRequired
                        ? "检测到登录页跳转 · "
                        : portalHttpCode === 204 || (portalHttpCode >= 200 && portalHttpCode < 300)
                          ? "检测状态正常 · "
                          : "检测状态异常 · "
                      : ""}
                    上次检测：<span className="cc-mono">{portalLastCheck}</span>
                  </div>
                  {portalRedirect && (
                    <div className="mt-1 truncate cc-mono text-[11px] text-[var(--amber)]">
                      认证页：{portalRedirect}
                    </div>
                  )}
                  {portalBypassHosts.length > 0 && (
                    <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                      已临时放行：{portalBypassHosts.join("、")}
                    </div>
                  )}
                  {campusError && (
                    <div className="mt-1 flex items-center gap-1 text-[11px] text-[var(--red)]">
                      <AlertTriangle className="h-3 w-3 shrink-0" />
                      <span className="truncate">上次检测失败：{campusError}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-[var(--text)]">登录页自动放行</span>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[11px] font-medium ${
                        campusPortalGuard ? "text-[var(--accent)]" : "text-[var(--muted)]"
                      }`}
                    >
                      {campusPortalGuard ? "已开启" : "已关闭"}
                    </span>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={campusPortalGuard}
                      aria-label="切换校园网登录页自动放行"
                      disabled={savingCampusGuard}
                      onClick={() => void handleToggleCampusPortalGuard()}
                      className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-60 ${
                        campusPortalGuard ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                      }`}
                    >
                      <span
                        className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                          campusPortalGuard ? "translate-x-4" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                  遇到校园网认证跳转时自动临时直连，完成登录后自动恢复提速。
                </p>
              </div>

              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-[var(--text)]">国内直连防绕路</span>
                  {probeValidation.ok ? (
                    <span className="text-[11px] font-medium text-[var(--green)]">正常</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setShowProbeModal(true)}
                      className="text-[11px] font-medium text-[var(--amber)] underline-offset-2 hover:underline"
                    >
                      去修正检测地址
                    </button>
                  )}
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                  中转服务器与连通检测自动走国内直连，不会出现网络反复绕圈。
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4. 底部折叠区：高级选项（通常无需调整），默认收起 */}
      <section className="cc-card cc-glass rounded-2xl">
        <button
          type="button"
          aria-expanded={advancedOpen}
          onClick={() => setAdvancedOpen((v) => !v)}
          className="flex w-full items-center justify-between gap-3 rounded-2xl px-5 py-3.5 text-left transition-colors hover:bg-[var(--bg-elevated)]/45"
        >
          <div className="flex min-w-0 items-center gap-2.5">
            {advancedOpen ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-[var(--muted)]" />
            )}
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">
                高级选项（通常无需调整）
              </div>
              <div className="mt-0.5 truncate text-[11px] text-[var(--muted)]">
                高速直连自动跳过 · 驱动状态与重装诊断 · 加速范围及自定义额外/排除进程名
              </div>
            </div>
          </div>
          <span className="shrink-0 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[10px] font-medium text-[var(--muted)]">
            {advancedOpen ? "收起" : "展开"}
          </span>
        </button>

        {advancedOpen && (
          <div className="space-y-4 border-t border-[var(--line)]/70 px-5 pb-5 pt-4">
            {/* 4.1 路由优化开关：已是高速通道的线路自动跳过 */}
            <button
              type="button"
              role="switch"
              aria-checked={skip443Native}
              onClick={() => void handleToggleSkip443()}
              className="flex w-full items-center justify-between gap-4 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
            >
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[var(--text)]">
                  已是高速通道的线路自动跳过
                </div>
                <div className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                  {dict.preaccel.skip443Hint}
                </div>
              </div>
              <span
                className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                  skip443Native ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                }`}
              >
                <span
                  className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                    skip443Native ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </span>
            </button>

            {/* 4.2 驱动状态 / 重装诊断（Windows）或 本地独立通道终端命令（macOS / Linux） */}
            {isWindows ? (
              <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-semibold text-[var(--text)]">
                        提速组件与权限诊断（WinDivert）
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                          preaccelSummary.verifyState === "probing"
                            ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                            : preaccelSummary.realWinDivertActive
                              ? "bg-[var(--green-soft)] text-[var(--green)]"
                              : globalPreAccel.windivert_available
                                ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                                : "bg-[var(--amber-soft)] text-[var(--amber)]"
                        }`}
                      >
                        {preaccelSummary.verifyState === "probing"
                          ? "探测链路中…"
                          : preaccelSummary.realWinDivertActive
                            ? "运行中"
                            : globalPreAccel.windivert_available
                              ? "组件已就绪"
                              : "尚未下载"}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                          globalPreAccel.is_elevated
                            ? "bg-[var(--green-soft)] text-[var(--green)]"
                            : "bg-[var(--amber-soft)] text-[var(--amber)]"
                        }`}
                      >
                        {globalPreAccel.is_elevated ? "已获管理员权限" : "普通权限运行"}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                      开启顶部总开关时会自动下载并校验官方开源 WinDivert v2.2.2（SHA-256 指纹校验，仅存于应用目录）；如被安全软件误拦可在此手动重试安装。
                    </p>
                    {globalPreAccel.windivert_path && (
                      <div
                        className="mt-1 truncate cc-mono text-[10px] text-[var(--muted)]"
                        title={globalPreAccel.windivert_path}
                      >
                        组件路径：{globalPreAccel.windivert_path}
                      </div>
                    )}
                  </div>

                  <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      disabled={installBusy}
                      onClick={() => void handleInstallWinDivert()}
                      className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
                    >
                      {installBusy ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {installBusy
                          ? "正在下载并校验…"
                          : globalPreAccel.windivert_available
                            ? "重新下载并校验组件"
                            : "下载并校验官方组件"}
                      </span>
                    </button>

                    {!globalPreAccel.is_elevated && (
                      <button
                        type="button"
                        disabled={elevatingGlobal}
                        onClick={() => void handleRelaunchAdminGlobal()}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                      >
                        {elevatingGlobal ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <ShieldCheck className="h-3.5 w-3.5" />
                        )}
                        <span>{elevatingGlobal ? "正在重启…" : "以管理员重启生效"}</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* 紧凑一行环境诊断信息：物理出口网卡 + 安全环境标签 + 上次探测时间与结论 */}
                <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)]/75 px-3 py-2 text-[11px]">
                  <span className="inline-flex items-center gap-1 text-[var(--muted)]">
                    <span>物理出口网卡：</span>
                    <strong className="cc-mono font-medium text-[var(--text)]">
                      {globalPreAccel.bound_physical_interface || "自动识别"}
                    </strong>
                  </span>

                  <span className="inline-flex flex-wrap items-center gap-1 text-[var(--muted)]">
                    <span>安全环境：</span>
                    {detectedSecurityProducts.length > 0 ? (
                      detectedSecurityProducts.map((prod) => (
                        <span
                          key={prod}
                          className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]"
                        >
                          {prod}
                        </span>
                      ))
                    ) : (
                      <span className="text-[var(--text-secondary)]">常规环境</span>
                    )}
                  </span>

                  <span
                    className="inline-flex min-w-0 items-center gap-1 text-[var(--muted)]"
                    title={verifyMessageText ?? verifyStateFallbackLabel}
                  >
                    <span className="shrink-0">上次探测：</span>
                    {verifyCheckedClock && (
                      <span className="cc-mono shrink-0 text-[var(--text-secondary)]">
                        {verifyCheckedClock}
                      </span>
                    )}
                    <span
                      className={`truncate font-medium ${
                        isVerifiedVerify
                          ? "text-[var(--green)]"
                          : isDegradedVerify || preaccelSummary.verifyState === "failed"
                            ? "text-[var(--amber)]"
                            : "text-[var(--text-secondary)]"
                      }`}
                    >
                      {verifyCheckedClock ? "· " : ""}
                      {verifyMessageText ?? verifyStateFallbackLabel}
                    </span>
                  </span>
                </div>

                {localSocksAddress && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--muted)]">本地独立 443 通道入口</span>
                      <code className="cc-mono cc-selectable font-semibold text-[var(--text)]">
                        {localSocksAddress}
                      </code>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleCopyGlobalAddress(localSocksAddress)}
                      className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    >
                      {copiedGlobalAddr ? (
                        <Check className="h-3 w-3 text-[var(--green)]" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                      <span>{copiedGlobalAddr ? "已复制" : "复制地址"}</span>
                    </button>
                  </div>
                )}

                {globalPreAccel.last_error && (
                  <div className="flex items-start gap-2 rounded-lg border border-[var(--amber)]/45 bg-[var(--amber-soft)]/60 px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>{globalPreAccel.last_error}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-[var(--text)]">
                      {platformOs === "macos" ? "macOS" : "Linux"} 本地独立 443 SOCKS5 入口
                    </div>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                      {effectiveGlobalPort
                        ? "把其它代理软件的前置代理或终端环境变量指向此地址，免开猫猫主代理也能直享国内 443 上传加速。"
                        : "开启顶部「开启国内提速」总开关后会自动分配本地独立 443 SOCKS5 通道端口。"}
                    </p>
                  </div>
                  {effectiveGlobalPort && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopyGlobalShellCmd(
                            effectiveGlobalPort,
                            "posix",
                            platformOs === "macos" ? "Zsh / Bash" : "Bash / Zsh"
                          )
                        }
                        className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                      >
                        {copiedShellKind === "posix" ? (
                          <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                        ) : (
                          <Terminal className="h-3.5 w-3.5" />
                        )}
                        <span>
                          {copiedShellKind === "posix"
                            ? "已复制命令"
                            : platformOs === "macos"
                              ? "复制 Zsh / Bash 加速命令"
                              : "复制 Bash / Zsh 加速命令"}
                        </span>
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopyGlobalShellCmd(effectiveGlobalPort, "fish", "Fish")
                        }
                        className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                      >
                        {copiedShellKind === "fish" ? (
                          <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                        ) : (
                          <Terminal className="h-3.5 w-3.5" />
                        )}
                        <span>{copiedShellKind === "fish" ? "已复制 Fish" : "复制 Fish 命令"}</span>
                      </button>
                    </div>
                  )}
                </div>
                {effectiveGlobalPort && (
                  <div className="mt-2 rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono cc-selectable text-[11px] text-[var(--text-secondary)]">
                    {buildGlobalPreAccelShellSnippet(effectiveGlobalPort, "posix")}
                  </div>
                )}
              </div>
            )}

            {/* 4.3 Windows 加速范围与自定义额外/排除进程名 */}
            {isWindows && (
              <div className="space-y-3">
                <div className="text-xs font-semibold text-[var(--text)]">加速范围</div>
                <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                  <button
                    type="button"
                    disabled={savingGlobalScope}
                    onClick={() => void handleSelectGlobalScope("proxy_apps_only")}
                    className={`rounded-xl border p-3.5 text-left transition-colors disabled:opacity-70 ${
                      globalScope === "proxy_apps_only"
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]/50"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[var(--text)]">
                        智能自动识别代理核心
                      </span>
                      <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                        默认推荐
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                      实时识别本机运行的其它代理核心与远程命令行工具，不绕走日常国内大文件与普通软件。
                    </p>
                  </button>

                  <button
                    type="button"
                    disabled={savingGlobalScope}
                    onClick={() => void handleSelectGlobalScope("all_non_443_tcp")}
                    className={`rounded-xl border p-3.5 text-left transition-colors disabled:opacity-70 ${
                      globalScope === "all_non_443_tcp"
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]/50"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[var(--text)]">
                        全机非 443 兜底加速
                      </span>
                      {globalScope === "all_non_443_tcp" && (
                        <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                          当前生效
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                      除私网、中转机与 443 端口外全部非 443 TCP 连接走 443 加速（可能带入其它国内非 443 传输）。
                    </p>
                  </button>
                </div>

                {globalScope === "proxy_apps_only" && (
                  <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <span className="text-xs font-medium text-[var(--text)]">
                          自定义额外 / 排除进程名（当前 {targetProcesses.length} 项）
                        </span>
                        <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                          运行时会自动识别代理核心；如需额外补充指定程序或点 × 移除不想包含的进程，可在此调整。
                        </p>
                      </div>
                      <button
                        type="button"
                        disabled={savingGlobalScope}
                        onClick={() => void handleResetTargetProcesses()}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-55"
                      >
                        <RotateCcw className="h-3 w-3" />
                        <span>恢复默认</span>
                      </button>
                    </div>

                    <div className="mt-2.5 flex flex-wrap gap-1.5">
                      {targetProcesses.map((proc) => (
                        <span
                          key={proc}
                          className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 cc-mono text-[11px] text-[var(--text-secondary)]"
                        >
                          <span>{proc}</span>
                          <button
                            type="button"
                            disabled={savingGlobalScope}
                            onClick={() => void handleRemoveTargetProcess(proc)}
                            className="rounded p-0.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--red)] disabled:opacity-45"
                            aria-label={`移除 ${proc}`}
                            title={`移除 ${proc}`}
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))}
                      {targetProcesses.length === 0 && (
                        <span className="text-[11px] text-[var(--muted)]">
                          当前完全依赖自动识别，也可在下方手动补充进程名
                        </span>
                      )}
                    </div>

                    <form
                      onSubmit={(ev) => void handleAddTargetProcess(ev)}
                      className="mt-2.5 flex flex-wrap items-center gap-2"
                    >
                      <input
                        type="text"
                        value={newProcessInput}
                        onChange={(e) => setNewProcessInput(e.target.value)}
                        placeholder="输入额外进程名（如 mihomo.exe, sing-box.exe, ssh.exe）"
                        className="cc-mono min-w-[220px] flex-1 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                      />
                      <button
                        type="submit"
                        disabled={savingGlobalScope || !newProcessInput.trim()}
                        className="inline-flex shrink-0 items-center gap-1 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        <span>添加进程</span>
                      </button>
                    </form>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </section>

      {/* ====================================================================
       * 弹窗 1：添加中转线路（手动填表添加 + 粘贴导入码 / JSON 双标签）
       * ==================================================================== */}
      {showAddModal &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!savingManual && !importing) setShowAddModal(false);
            }}
          >
          <div
            role="dialog"
            aria-modal="true"
            aria-label="添加中转线路"
            onClick={(e) => e.stopPropagation()}
            className="cc-surface w-full max-w-lg rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">添加中转线路</h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  可以手动填写服务器信息，也可以直接粘贴导入码一键添加
                </p>
              </div>
              <button
                type="button"
                disabled={savingManual || importing}
                onClick={() => setShowAddModal(false)}
                className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
                aria-label="关闭弹窗"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* 双标签切换 */}
            <div className="mt-4 grid grid-cols-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-1 text-xs">
              <button
                type="button"
                onClick={() => {
                  setAddModalTab("manual");
                  setManualError(null);
                }}
                className={`rounded-lg py-1.5 font-medium transition-colors ${
                  addModalTab === "manual"
                    ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                    : "text-[var(--muted)] hover:text-[var(--text)]"
                }`}
              >
                手动填表添加
              </button>
              <button
                type="button"
                onClick={() => {
                  setAddModalTab("import");
                  setImportError(null);
                }}
                className={`rounded-lg py-1.5 font-medium transition-colors ${
                  addModalTab === "import"
                    ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                    : "text-[var(--muted)] hover:text-[var(--text)]"
                }`}
              >
                粘贴导入码 / JSON
              </button>
            </div>

            {/* 标签 1：手动填表添加 */}
            {addModalTab === "manual" && (
              <form onSubmit={(ev) => void handleManualSubmit(ev)} className="mt-4 space-y-3.5">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      线路名称 <span className="text-[var(--red)]">*</span>
                    </label>
                    <input
                      type="text"
                      value={manualName}
                      onChange={(e) => {
                        setManualName(e.target.value);
                        setManualError(null);
                      }}
                      placeholder="例如：上海轻量 1 号"
                      className={INPUT_CLS}
                    />
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      地区
                    </label>
                    <input
                      type="text"
                      value={manualRegion}
                      onChange={(e) => setManualRegion(e.target.value)}
                      placeholder="例如：华东 / 华南 / 香港"
                      className={INPUT_CLS}
                    />
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {REGION_QUICK_PICKS.map((r) => (
                        <button
                          key={r}
                          type="button"
                          onClick={() => setManualRegion(r)}
                          className={`rounded-md border px-1.5 py-0.5 text-[10px] transition-colors ${
                            manualRegion === r
                              ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                              : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                          }`}
                        >
                          {r}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2">
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      服务器 IP <span className="text-[var(--red)]">*</span>
                    </label>
                    <input
                      type="text"
                      value={manualServer}
                      onChange={(e) => {
                        setManualServer(e.target.value);
                        setManualError(null);
                      }}
                      placeholder="例如：198.51.100.10"
                      className={`${INPUT_CLS} cc-mono`}
                    />
                    {manualShowDomainHint && (
                      <p className="mt-1 text-[10px] text-[var(--amber)]">
                        建议直接填写服务器纯 IP，连接更稳定
                      </p>
                    )}
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      端口
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={manualPort}
                      onChange={(e) => {
                        setManualPort(e.target.value);
                        setManualError(null);
                      }}
                      placeholder="443"
                      className={`${INPUT_CLS} cc-mono`}
                    />
                    {manualShowNon443Hint && (
                      <p className="mt-1 text-[10px] text-[var(--amber)]">推荐 443</p>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <span className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      连接协议
                    </span>
                    <AppSelect
                      aria-label="连接协议"
                      size="md"
                      value={manualProtocol}
                      onChange={(v) => {
                        setManualProtocol(v);
                        setManualError(null);
                      }}
                      options={RELAY_PROTOCOL_OPTIONS.map((opt) => ({
                        value: opt.value,
                        label: opt.label,
                      }))}
                      className="w-full"
                      buttonClassName="bg-[var(--card)]"
                    />
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      {manualProtocol === "vless" ? "UUID 密钥" : "连接密码"}{" "}
                      <span className="text-[var(--red)]">*</span>
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? "text" : "password"}
                        value={manualPassword}
                        onChange={(e) => {
                          setManualPassword(e.target.value);
                          setManualError(null);
                        }}
                        placeholder={
                          manualProtocol === "vless"
                            ? "粘贴标准 UUID"
                            : "填写服务端设置的密码"
                        }
                        className={`${INPUT_CLS} cc-mono pr-9`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((v) => !v)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                        aria-label={showPassword ? "隐藏密码" : "显示密码"}
                      >
                        {showPassword ? (
                          <EyeOff className="h-3.5 w-3.5" />
                        ) : (
                          <Eye className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      备注（选填）
                    </label>
                    <input
                      type="text"
                      value={manualNote}
                      onChange={(e) => setManualNote(e.target.value)}
                      placeholder="例如：轻量云服务器、月付"
                      className={INPUT_CLS}
                    />
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      到期日期（选填）
                    </label>
                    <input
                      type="date"
                      value={manualExpiresAt}
                      onChange={(e) => setManualExpiresAt(e.target.value)}
                      className={`${INPUT_CLS} cc-mono`}
                    />
                  </div>
                </div>

                {manualError && (
                  <div className="flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    <span>{manualError}</span>
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    disabled={savingManual}
                    onClick={() => setShowAddModal(false)}
                    className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
                  >
                    取消
                  </button>
                  <button
                    type="submit"
                    disabled={savingManual}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>{savingManual ? "保存中..." : "保存并添加"}</span>
                  </button>
                </div>
              </form>
            )}

            {/* 标签 2：粘贴导入码 / JSON */}
            {addModalTab === "import" && (
              <form onSubmit={(ev) => void handleImportSubmit(ev)} className="mt-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <span className="text-[var(--text-secondary)]">
                    支持单行导入码或 JSON 配置
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        setImportText(DEMO_IMPORT_JSON);
                        setImportError(null);
                      }}
                      className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                    >
                      填入示例 JSON
                    </button>
                    <button
                      type="button"
                      onClick={handleFillDemoUri}
                      className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                    >
                      填入示例导入码
                    </button>
                  </div>
                </div>

                <textarea
                  rows={6}
                  value={importText}
                  onChange={(e) => {
                    setImportText(e.target.value);
                    setImportError(null);
                  }}
                  spellCheck={false}
                  placeholder="直接粘贴导入码，或 JSON 格式的中转配置内容..."
                  className="cc-mono cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />

                {importError && (
                  <div className="flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    <span>{importError}</span>
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    disabled={importing}
                    onClick={() => setShowAddModal(false)}
                    className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
                  >
                    取消
                  </button>
                  <button
                    type="submit"
                    disabled={importing}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                  >
                    <Upload className="h-3.5 w-3.5" />
                    <span>{importing ? "导入中..." : "识别并导入"}</span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>,
        document.body
      )}

      {/* ====================================================================
       * 弹窗 2：国内连通检测地址（华为 / 小米 204 + 自定义）
       * ==================================================================== */}
      {showProbeModal &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => setShowProbeModal(false)}
          >
          <div
            role="dialog"
            aria-modal="true"
            aria-label="国内连通检测地址"
            onClick={(e) => e.stopPropagation()}
            className="cc-surface w-full max-w-lg rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">
                  国内连通检测地址
                </h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  用于检测国内网络连通与校园网登录页，请保持国内直连地址
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowProbeModal(false)}
                className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
                aria-label="关闭弹窗"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              {DOMESTIC_PROBE_PRESETS.map((preset) => {
                const selected = probeUrl.trim() === preset.url;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => void handleSelectProbePreset(preset.url, preset.label)}
                    className={`rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                      selected
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>

            <form onSubmit={(ev) => void handleSaveCustomProbe(ev)} className="mt-3.5 space-y-3">
              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  当前检测网址
                </label>
                <input
                  type="text"
                  value={probeUrl}
                  onChange={(e) => setProbeUrl(e.target.value)}
                  placeholder="http://connectivitycheck.platform.hicloud.com/generate_204"
                  className={`cc-mono w-full rounded-xl border bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] outline-none ${
                    probeValidation.ok
                      ? "border-[var(--line)] focus:border-[var(--accent)]"
                      : "border-[var(--red)] focus:border-[var(--red)]"
                  }`}
                />
              </div>

              {!probeValidation.ok && (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-medium">
                    <ShieldAlert className="h-4 w-4 shrink-0" />
                    <span>{probeValidation.error}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      void handleSelectProbePreset(
                        DOMESTIC_PROBE_PRESETS[0].url,
                        DOMESTIC_PROBE_PRESETS[0].label
                      )
                    }
                    className="shrink-0 rounded-lg border border-[var(--red)]/40 bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                  >
                    恢复华为默认地址
                  </button>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setShowProbeModal(false)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
                >
                  关闭
                </button>
                  <button
                    type="submit"
                    disabled={!probeValidation.ok}
                    className="rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-45"
                  >
                    保存地址
                  </button>
                </div>
              </form>
            </div>
          </div>,
          document.body
        )}

      {/* ====================================================================
       * 弹窗 3：猫云分享包（导出 / 导入国内提速中转与节点 .zip）
       * ==================================================================== */}
      <ShareBundleModal
        open={shareModalOpen}
        mode={relays.length > 0 ? "export" : "import"}
        allowModeSwitch
        defaultTab="relays"
        defaultPackName="国内提速中转分享包"
        initialRelayIds={enabledRelayIds}
        onClose={() => setShareModalOpen(false)}
      />

      {/* ====================================================================
       * 弹窗 4：删除中转线路二次确认
       * ==================================================================== */}
      {pendingDeleteRelay &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!deletingRelay) setPendingDeleteRelay(null);
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label="确认删除国内中转机"
              onClick={(e) => e.stopPropagation()}
              className="cc-surface w-full max-w-md rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--red-soft)] text-[var(--red)]">
                    <AlertTriangle className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      确认删除国内中转机？
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      即将移除中转线路「
                      <span className="font-semibold text-[var(--text)]">
                        {pendingDeleteRelay.name}
                      </span>
                      」（<span className="cc-mono">{pendingDeleteRelay.server}:{pendingDeleteRelay.port}</span>
                      ）。删除后无法撤销，如仍在使用将自动回落至其它中转或直连。
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={deletingRelay}
                  onClick={() => setPendingDeleteRelay(null)}
                  className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                  aria-label="关闭弹窗"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={deletingRelay}
                  onClick={() => setPendingDeleteRelay(null)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  取消
                </button>
                <button
                  type="button"
                  disabled={deletingRelay}
                  onClick={() => void handleConfirmRemoveRelay()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--red)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  <span>{deletingRelay ? "删除中…" : "确认删除"}</span>
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
}
