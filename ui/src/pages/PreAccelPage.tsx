import {
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowUp,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileText,
  Gauge,
  Globe,
  Loader2,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
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
  type AppConfig,
  type GlobalPreAccelScope,
  type PreAccelComparisonResult,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect } from "../components/AppSelect";
import { formatBytes } from "../components/TrafficSparkline";
import { appActions, useAppSelector } from "../store/appStore";
import {
  DEFAULT_GLOBAL_TARGET_PROCESSES,
  buildGlobalPreAccelShellSnippet,
  resolvePlatformOs,
} from "../utils/platform";

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
    });
  }

  return { relays, warnings, error: null };
}

function buildAiDeployGuide(probeUrl: string, skip443: boolean): string {
  return [
    "# 猫猫云梯 · 国内提速中转部署说明（给 AI 助手）",
    "",
    "请协助我在国内轻量云服务器上部署一套纯 IP 443 中转服务，用于提升非 443 海外线路的上传与连接稳定性。",
    "",
    "## 1. 适用情况",
    "- 普通海外节点上传被宽带限制在 2～4 Mbps，而标准 443 端口可跑满 50～250+ Mbps。",
    "- 传图、AI 编程或远程访问频繁卡顿，但下载速度正常。",
    "- 校园网或公司内网对非常用端口限速明显，或需要网页登录认证。",
    "",
    "## 2. 服务器部署要求",
    "- 准备 1～2 台国内轻量云服务器，监听 TCP 443 端口，协议优先 AnyTLS，也支持 Trojan / VLESS / Hysteria2 / TUIC。",
    "- 使用自签 IP 证书；TLS 域名字段（sni / servername）请严格留空，并开启跳过证书校验（skip_cert_verify: true），不要填写未备案域名。",
    `- 当前国内连通检测地址：${probeUrl}（必须保持国内直连地址，不要改为海外网址）。`,
    `- 已是高速通道的线路自动跳过：${skip443 ? "已开启" : "未开启"}。`,
    "",
    "## 3. 导入方式与常用命令",
    "- 图形界面：打开「国内提速」→ 点击右上角「+ 添加中转」→ 手动填表或直接粘贴下方格式的 JSON / 导入码。",
    "- 查看中转列表：`catcloud relay list --json`",
    "- 查看运行状态：`catcloud status --json`",
    "- 重载当前配置：`catcloud config reload --json`",
    "",
    "## 4. 交付配置模板（请替换为真实参数）",
    "```json",
    JSON.stringify(
      {
        schema: IMPORT_SCHEMA_TAG,
        role: "domestic_pre_accel",
        relays: [
          {
            id: "relay-cn-east-1",
            name: "上海轻量 1 号",
            provider: "轻量云服务器",
            region: "华东",
            server: "203.0.113.10",
            port: 443,
            protocol: "anytls",
            password: "<YOUR_GENERATED_SECRET>",
            sni: "",
            skip_cert_verify: true,
            priority: 1,
            expires_at: "2027-08-12",
            enabled: true,
          },
        ],
      },
      null,
      2
    ),
    "```",
  ].join("\n");
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

function formatClockStamp(isoOrNow?: string): string {
  const d = isoOrNow ? new Date(isoOrNow) : new Date();
  if (Number.isNaN(d.getTime())) return isoOrNow ?? "--";
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
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const storeRelays = useAppSelector((s) => s.preAccelRelays);
  const groups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();
  const platformOs = resolvePlatformOs(runtime.os_label);

  const [enabled, setEnabled] = useState<boolean>(config.preaccel.enabled);
  const [togglingEnabled, setTogglingEnabled] = useState(false);
  const [togglingGlobal, setTogglingGlobal] = useState(false);
  const [savingGlobalScope, setSavingGlobalScope] = useState(false);
  const [installingDriver, setInstallingDriver] = useState(false);
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
  const [probingIds, setProbingIds] = useState<Record<string, boolean>>({});
  const [probingAll, setProbingAll] = useState(false);
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

  // Lightweight Advanced Modals (Probe URL & AI Deploy Guide)
  const [showProbeModal, setShowProbeModal] = useState(false);
  const [showGuideModal, setShowGuideModal] = useState(false);
  const [copiedGuide, setCopiedGuide] = useState(false);
  const [pendingDeleteRelay, setPendingDeleteRelay] = useState<PreAccelRelay | null>(null);
  const [deletingRelay, setDeletingRelay] = useState(false);

  // Real Pre-Accel vs Direct Speed Comparison Card
  const [benchmarking, setBenchmarking] = useState(false);
  const [selectedCompareNodeId, setSelectedCompareNodeId] = useState<string>("");
  const [comparison, setComparison] = useState<PreAccelComparisonResult | null>(null);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [comparisonIsDemo, setComparisonIsDemo] = useState(false);

  // Campus Network Auth Check Card
  const [checkingPortal, setCheckingPortal] = useState(false);
  const [portalRequired, setPortalRequired] = useState<boolean>(runtime.captive_portal_required);
  const [portalHttpCode, setPortalHttpCode] = useState<number | null>(
    inTauri ? null : runtime.captive_portal_required ? 302 : 204
  );
  const [portalRedirect, setPortalRedirect] = useState<string | null>(null);
  const [portalBypassHosts, setPortalBypassHosts] = useState<string[]>([]);
  const [portalLastCheck, setPortalLastCheck] = useState<string>(inTauri ? "尚未检测" : "演示态");

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
      setEnabled(config.preaccel.enabled);
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

  useEffect(() => {
    if (!globalPreAccel.running) return;
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      void appActions.refreshGlobalPreAccelStatus();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [globalPreAccel.running]);

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
    if (!showAddModal && !showProbeModal && !showGuideModal && !pendingDeleteRelay) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (!savingManual && !importing) {
          setShowAddModal(false);
        }
        if (!deletingRelay) {
          setPendingDeleteRelay(null);
        }
        setShowProbeModal(false);
        setShowGuideModal(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [
    showAddModal,
    showProbeModal,
    showGuideModal,
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
    nextEnabled: boolean,
    nextSkip443: boolean,
    nextProbeUrl: string,
    notice: string
  ): Promise<boolean> => {
    const nextConfig: AppConfig = {
      ...config,
      preaccel: {
        ...config.preaccel,
        enabled: nextEnabled,
        skip_443_native: nextSkip443,
        probe_url: nextProbeUrl,
      },
    };
    try {
      const saved = await catcloudApi.saveConfig(nextConfig);
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast(notice, "ok");
      return true;
    } catch (err) {
      appActions.showToast(`保存国内提速设置失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  };

  const handleToggleEnabled = async () => {
    if (togglingEnabled) return;
    const prev = enabled;
    const next = !enabled;
    setEnabled(next);
    setTogglingEnabled(true);
    try {
      const ok = await appActions.togglePreAccel(next);
      if (next && !ok) {
        setEnabled(prev);
      }
    } finally {
      setTogglingEnabled(false);
    }
  };

  const handleToggleGlobalPreAccel = async () => {
    if (togglingGlobal) return;
    setTogglingGlobal(true);
    try {
      await appActions.toggleGlobalPreAccel();
    } finally {
      setTogglingGlobal(false);
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
            ? "已切换为：智能识别其它梯子与常用工具"
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
        appActions.showToast("已恢复默认其它梯子与传输工具列表", "ok");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleInstallWinDivert = async () => {
    if (installingDriver) return;
    setInstallingDriver(true);
    try {
      await appActions.installWinDivertDriver();
    } finally {
      setInstallingDriver(false);
    }
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
      enabled,
      next,
      probeValidation.ok ? probeUrl : config.preaccel.probe_url,
      next ? "已开启：已是高速通道的线路自动跳过" : "已关闭：所有海外节点均可使用国内提速"
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
      enabled,
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
      enabled,
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
      if ((idx === 0 || swapIdx === 0) && normalized[0]?.enabled) {
        await catcloudApi.selectPreAccelRelay(normalized[0].id);
        const rt = await catcloudApi.getRuntimeInfo();
        appActions.syncRuntime(rt);
      }
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

  const handleSelectRelay = async (relay: PreAccelRelay) => {
    if (!relay.enabled) {
      appActions.showToast("请先开启该线路，再设为主力", "warn");
      return;
    }
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
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast(`已将「${relay.name}」设为主力线路`, "ok");
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
      const rt = await catcloudApi.getRuntimeInfo();
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
    if (probingIds[id]) return;
    setProbingIds((prev) => ({ ...prev, [id]: true }));
    try {
      const results = await catcloudApi.testPreAccelRelays([id]);
      const item = results.find((r) => r.relay_id === id) ?? results[0];
      if (inTauri) {
        const latestRelays = await catcloudApi.listPreAccelRelays();
        setRelays(latestRelays);
        appActions.syncPreAccelRelays(latestRelays);
      } else if (item) {
        setRelays((prev) => {
          const next = prev.map((r) =>
            r.id === id ? { ...r, last_probe_ms: item.latency_ms } : r
          );
          appActions.syncPreAccelRelays(next);
          return next;
        });
      }
      if (item && !item.ok) {
        appActions.showToast(`测速失败：${item.error ?? "连接超时"}`, "warn");
      } else {
        const msText = hasValidLatency(item?.latency_ms)
          ? `（${formatLatencyDisplay(item.latency_ms)}）`
          : "";
        appActions.showToast(`中转线路连通正常${msText}`, "ok");
      }
    } catch (err) {
      appActions.showToast(`中转测速失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setProbingIds((prev) => ({ ...prev, [id]: false }));
    }
  };

  const handleProbeAllRelays = async () => {
    if (probingAll || relays.length === 0) return;
    setProbingAll(true);
    try {
      const results = await catcloudApi.testPreAccelRelays(null);
      if (inTauri) {
        const latestRelays = await catcloudApi.listPreAccelRelays();
        setRelays(latestRelays);
        appActions.syncPreAccelRelays(latestRelays);
      } else {
        const resultMap = new Map(results.map((r) => [r.relay_id, r]));
        setRelays((prev) => {
          const next = prev.map((r) => {
            const matched = resultMap.get(r.id);
            return matched ? { ...r, last_probe_ms: matched.latency_ms } : r;
          });
          appActions.syncPreAccelRelays(next);
          return next;
        });
      }
      const okCount = results.filter((r) => r.ok).length;
      appActions.showToast(
        `全部测速完成：${okCount}/${results.length} 条线路可用`,
        okCount > 0 ? "ok" : "warn"
      );
    } catch (err) {
      appActions.showToast(`全部测速失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setProbingAll(false);
    }
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
    if (inTauri && enabledRelayCount === 0) {
      appActions.showToast("请先添加并启用至少一条国内中转线路，再进行提速对比", "warn");
      return;
    }
    if (inTauri && benchmarkableNodes.length === 0) {
      appActions.showToast("还没有可对比的海外节点，请先在「节点与订阅」中导入节点", "warn");
      return;
    }

    setBenchmarking(true);
    setComparisonError(null);

    try {
      // 1) Test domestic relay connectivity first so relay cards show fresh latency
      try {
        const relayResults = await catcloudApi.testPreAccelRelays(null);
        if (inTauri) {
          const latestRelays = await catcloudApi.listPreAccelRelays();
          setRelays(latestRelays);
          appActions.syncPreAccelRelays(latestRelays);
        } else {
          const resultMap = new Map(relayResults.map((r) => [r.relay_id, r]));
          setRelays((prev) => {
            const next = prev.map((r) => {
              const matched = resultMap.get(r.id);
              return matched ? { ...r, last_probe_ms: matched.latency_ms } : r;
            });
            appActions.syncPreAccelRelays(next);
            return next;
          });
        }
      } catch {
        /* continue to real comparison benchmark even if relay pre-check fails */
      }

      // 2) Run real accelerated vs direct upload/download speed comparison
      const result = await catcloudApi.benchmarkPreAccelComparison(
        primaryRelayId ?? null,
        resolvedCompareNodeId || null
      );
      setComparison(result);
      setComparisonIsDemo(!inTauri);
      if (inTauri) {
        try {
          const latestRelays = await catcloudApi.listPreAccelRelays();
          setRelays(latestRelays);
          appActions.syncPreAccelRelays(latestRelays);
        } catch {
          /* ignore secondary relay refresh failure */
        }
      }

      const accUp = result.accelerated.up_mbps;
      const dirUp = result.direct.up_mbps;
      const ratio =
        result.up_boost_ratio ??
        (accUp !== null && dirUp !== null && dirUp > 0 ? accUp / dirUp : null);

      if (!inTauri) {
        appActions.showToast(
          ratio !== null
            ? `演示模式：走国内中转上传提速约 ${ratio.toFixed(1)} 倍`
            : "演示模式：已完成提速效果对比",
          "info"
        );
      } else if (result.ok && result.accelerated.ok && result.direct.ok) {
        appActions.showToast(
          ratio !== null && ratio >= 1.1 && accUp !== null
            ? `实测完成：走国内中转上传 ${accUp.toFixed(1)} Mbps（提速 ${ratio.toFixed(1)} 倍）`
            : accUp !== null
              ? `实测对比完成：走国内中转上传 ${accUp.toFixed(1)} Mbps`
              : "提速效果实测对比完成",
          "ok"
        );
      } else {
        const errParts: string[] = [];
        if (!result.accelerated.ok) {
          const latHint = hasValidLatency(result.accelerated.latency_ms)
            ? `延迟 ${formatLatencyDisplay(result.accelerated.latency_ms)}，`
            : "";
          const reason = result.accelerated.error?.trim() || "连接超时";
          errParts.push(`走中转（${latHint}${reason}）`);
        }
        if (!result.direct.ok) {
          const latHint = hasValidLatency(result.direct.latency_ms)
            ? `延迟 ${formatLatencyDisplay(result.direct.latency_ms)}，`
            : "";
          const reason = result.direct.error?.trim() || "连接超时";
          errParts.push(`普通直连（${latHint}${reason}）`);
        }
        appActions.showToast(
          errParts.length > 0 ? errParts.join("；") : "本次对比测速未全部成功，请检查中转与节点状态",
          "warn"
        );
      }
    } catch (err) {
      const msg = formatErrorMessage(err);
      setComparisonError(msg);
      appActions.showToast(`提速效果对比测速失败：${msg}`, "warn");
    } finally {
      setBenchmarking(false);
    }
  };

  const handleCheckCampusAuth = async () => {
    if (checkingPortal) return;
    setCheckingPortal(true);
    try {
      const status = await catcloudApi.checkCampusPortal();
      setPortalRequired(status.captive_portal_required);
      setPortalHttpCode(status.status_code);
      setPortalRedirect(status.redirect_location);
      setPortalBypassHosts(status.bypass_hosts);
      setPortalLastCheck(formatClockStamp(status.checked_at));
      if (status.captive_portal_required) {
        appActions.showToast("检测到需要登录校园网，已自动临时放行认证页", "warn");
      } else {
        appActions.showToast("当前国内网络连通正常，无需网页认证", "ok");
      }
    } catch (err) {
      appActions.showToast(`校园网认证检测失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCheckingPortal(false);
    }
  };

  const guideMarkdown = useMemo(
    () => buildAiDeployGuide(probeUrl, skip443Native),
    [probeUrl, skip443Native]
  );

  const handleCopyGuide = async () => {
    let textToCopy = guideMarkdown;
    if (inTauri) {
      try {
        const exported = await catcloudApi.exportAgentDocs("preaccel", false);
        if (exported && exported.trim()) {
          textToCopy = exported;
        }
      } catch {
        /* fallback to local guide markdown */
      }
    }
    const ok = await copyText(textToCopy);
    if (ok) {
      setCopiedGuide(true);
      appActions.showToast("已复制给 AI 助手的部署说明", "ok");
      scheduleTimer(() => setCopiedGuide(false), 2200);
    } else {
      appActions.showToast("复制失败，请手动选中文本复制", "warn");
    }
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

  const isProxyEnabled =
    runtime.running && (runtime.system_proxy_enabled || runtime.tun_enabled);
  const isGlobalRunning = Boolean(
    globalPreAccel.running || runtime.global_preaccel_active
  );
  const effectiveGlobalMode =
    globalPreAccel.mode !== "off"
      ? globalPreAccel.mode
      : runtime.global_preaccel_mode ?? "off";
  const effectiveGlobalPort =
    globalPreAccel.socks_port ?? runtime.global_preaccel_socks_port ?? null;
  const effectiveGlobalConns =
    globalPreAccel.active_connections || runtime.global_preaccel_connections || 0;
  const isProxyPreAccelActive = Boolean(isProxyEnabled && (enabled || runtime.preaccel_active));

  const topStatusBadge = (() => {
    if (isGlobalRunning && isProxyPreAccelActive) {
      return {
        label: "全局 + 代理提速中",
        cls: "bg-[var(--green-soft)] text-[var(--green)]",
      };
    }
    if (isGlobalRunning) {
      return {
        label: "底层全局提速中",
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (isProxyPreAccelActive) {
      return {
        label: "代理提速中",
        cls: "bg-[var(--green-soft)] text-[var(--green)]",
      };
    }
    if (enabled) {
      return {
        label: "已开启 · 待启动",
        cls: "bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    return {
      label: "未开启",
      cls: "bg-[var(--bg-elevated)] text-[var(--muted)]",
    };
  })();

  const globalModeBadge = (() => {
    if (isGlobalRunning && effectiveGlobalMode === "windivert") {
      return {
        label: "最底层透明接管中 (WinDivert)",
        cls: "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]",
      };
    }
    if (isGlobalRunning && effectiveGlobalMode === "local_socks5") {
      return {
        label: "本地独立 443 通道运行中",
        cls: "border-[var(--accent)]/50 bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    if (isProxyPreAccelActive) {
      return {
        label: "跟随猫猫代理加速",
        cls: "border-[var(--green)]/40 bg-[var(--green-soft)]/80 text-[var(--green)]",
      };
    }
    return {
      label: "未启动",
      cls: "border-[var(--line)] bg-[var(--card)] text-[var(--muted)]",
    };
  })();

  const isWindows = platformOs === "windows";
  const windowsTransparentReady =
    isWindows && globalPreAccel.windivert_available && globalPreAccel.is_elevated;
  const localSocksAddress = effectiveGlobalPort ? `127.0.0.1:${effectiveGlobalPort}` : null;

  return (
    <div className="space-y-4">
      {/* 1. 顶部总控卡片 */}
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
                className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium ${topStatusBadge.cls}`}
              >
                {topStatusBadge.label}
              </span>
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-[var(--muted)]">
              国内高速入口，帮你突破宽带上传限速，让传图、传文件和远程访问更顺畅。
            </p>
          </div>

          {/* 折叠进轻按钮的高级项 */}
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
              onClick={() => setShowGuideModal(true)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            >
              <FileText className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>AI 部署说明</span>
            </button>
          </div>
        </div>

        {/* 两个清晰的主开关 */}
        <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={togglingEnabled}
            onClick={() => void handleToggleEnabled()}
            className="flex items-center justify-between gap-4 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3 text-left transition-colors hover:border-[var(--line-strong)] disabled:opacity-65"
          >
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">
                {togglingEnabled ? "正在切换国内提速…" : "开启国内提速"}
              </div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                自动通过国内中转线路转发海外流量，关闭代理时也可自动切入底层提速
              </div>
            </div>
            <span
              className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
              }`}
            >
              <span
                className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                  enabled ? "translate-x-4" : "translate-x-0"
                }`}
              />
            </span>
          </button>

          <button
            type="button"
            role="switch"
            aria-checked={skip443Native}
            onClick={() => void handleToggleSkip443()}
            className="flex items-center justify-between gap-4 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
          >
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">
                已是高速通道的线路自动跳过
              </div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                本身已是高速直连的海外节点直接连接不重复中转，可在节点页单独调整
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
        </div>
      </section>

      {/* 1.5 全局底层提速（免开猫猫代理给其它软件加速）控制卡 */}
      <section className="cc-card cc-glass rounded-2xl p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--text)]">
                全局底层提速（给电脑上其它梯子 / 软件一起加速）
              </h2>
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${globalModeBadge.cls}`}
              >
                {globalModeBadge.label}
              </span>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-[var(--muted)]">
              不用打开猫猫云梯自己的代理或虚拟网卡，也能从系统底层自动把落云、鲨鱼、夜煞云、TAG、Clash、v2rayN、SSH/SCP 等软件的上传流量送进国内 443 通道。
            </p>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              disabled={refreshingGlobal}
              onClick={() => void handleRefreshGlobalStatus()}
              className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
              title="刷新底层提速运行状态与统计"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshingGlobal ? "animate-spin" : ""}`} />
              <span>刷新</span>
            </button>

            <button
              type="button"
              role="switch"
              aria-checked={isGlobalRunning}
              aria-label={isGlobalRunning ? "关闭全局底层提速" : "开启全局底层提速"}
              disabled={togglingGlobal}
              onClick={() => void handleToggleGlobalPreAccel()}
              className={`inline-flex items-center gap-2 rounded-xl border px-3 py-1.5 text-xs font-semibold transition-colors disabled:opacity-65 ${
                isGlobalRunning
                  ? "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)]"
              }`}
            >
              {togglingGlobal ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5" />
              )}
              <span>{togglingGlobal ? "切换中…" : isGlobalRunning ? "底层运行中" : "开启底层提速"}</span>
            </button>
          </div>
        </div>

        {/* 实时状态条 */}
        <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-[var(--muted)]">独立入口</span>
              {localSocksAddress ? (
                <>
                  <code className="cc-mono cc-selectable rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] font-semibold text-[var(--text)]">
                    {localSocksAddress}
                  </code>
                  <button
                    type="button"
                    onClick={() => void handleCopyGlobalAddress(localSocksAddress)}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    title="一键复制本地独立 443 SOCKS5 入口地址"
                  >
                    {copiedGlobalAddr ? (
                      <Check className="h-3 w-3 text-[var(--green)]" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    <span>{copiedGlobalAddr ? "已复制" : "复制"}</span>
                  </button>
                </>
              ) : (
                <span className="text-[11px] text-[var(--muted)]">开启后自动分配本地 443 通道端口</span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[var(--text-secondary)]">
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
          </div>

          {globalPreAccel.accelerated_processes.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 text-[10px]">
              <span className="text-[var(--muted)]">正在加速：</span>
              {globalPreAccel.accelerated_processes.slice(0, 5).map((proc) => (
                <span
                  key={proc}
                  className="cc-mono rounded-md border border-[var(--accent)]/35 bg-[var(--accent-soft)]/70 px-1.5 py-0.5 text-[var(--accent)]"
                >
                  {proc}
                </span>
              ))}
              {globalPreAccel.accelerated_processes.length > 5 && (
                <span className="text-[var(--muted)]">
                  +{globalPreAccel.accelerated_processes.length - 5}
                </span>
              )}
            </div>
          )}
        </div>

        {globalPreAccel.last_error && (
          <div className="mt-2.5 flex items-start gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/70 px-3.5 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{globalPreAccel.last_error}</span>
          </div>
        )}

        {/* Windows 一键就绪引导条（就绪后自动收起为干净绿标） */}
        {isWindows ? (
          windowsTransparentReady ? (
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--green)]/35 bg-[var(--green-soft)]/55 px-3.5 py-2 text-[11px] text-[var(--green)]">
              <span className="inline-flex items-center gap-1.5 font-medium">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                <span>WinDivert 官方底层驱动与管理员权限已就绪，可直接透明接管其它软件</span>
              </span>
              {globalPreAccel.windivert_path && (
                <span className="cc-mono truncate text-[10px] opacity-80" title={globalPreAccel.windivert_path}>
                  已加载驱动
                </span>
              )}
            </div>
          ) : (
            <div className="mt-3 space-y-2.5 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/45 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    还差一步即可开启 Windows 最底层透明加速
                  </div>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                    {!globalPreAccel.windivert_available
                      ? "下载官方开源 WinDivert v2.2.2 驱动后，其它梯子不用改任何配置也能自动走国内 443 加速。"
                      : "驱动已就绪，使用管理员身份运行猫猫云梯即可自动拦截加速其它梯子的非 443 连接。"}
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {!globalPreAccel.windivert_available && (
                    <button
                      type="button"
                      disabled={installingDriver}
                      onClick={() => void handleInstallWinDivert()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                    >
                      {installingDriver ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {installingDriver
                          ? "正在下载并校验驱动…"
                          : "一键下载并校验官方驱动（WinDivert v2.2.2）"}
                      </span>
                    </button>
                  )}

                  {!globalPreAccel.is_elevated && (
                    <button
                      type="button"
                      disabled={elevatingGlobal}
                      onClick={() => void handleRelaunchAdminGlobal()}
                      className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-semibold transition-opacity hover:opacity-90 disabled:opacity-65 ${
                        globalPreAccel.windivert_available
                          ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                          : "border border-[var(--line-strong)] bg-[var(--card)] text-[var(--text)]"
                      }`}
                    >
                      {elevatingGlobal ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <ShieldCheck className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {elevatingGlobal
                          ? "正在拉起管理员实例…"
                          : "以管理员身份启用最底层透明加速"}
                      </span>
                    </button>
                  )}
                </div>
              </div>

              {!globalPreAccel.windivert_available && (
                <p className="text-[11px] text-[var(--muted)]">
                  温馨提示：官方开源驱动偶尔可能触发安全软件误报，如被拦截放行即可（下载后会自动校验官方 SHA256 指纹，绝不写入系统目录）。
                </p>
              )}
            </div>
          )
        ) : (
          /* macOS / Linux 友好呈现：直接展示本地独立 443 SOCKS5 入口与一键复制终端加速命令 */
          <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/80 p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[var(--text)]">
                  {platformOs === "macos" ? "macOS" : "Linux"} 本地独立 443 SOCKS5 入口
                </div>
                <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                  {effectiveGlobalPort
                    ? "把其它代理软件的前置代理或终端环境变量指向此地址，免开猫猫主代理也能直享国内 443 上传加速。"
                    : "点击右上角「开启底层提速」即可启动本地独立 443 SOCKS5 通道，随后可直接一键复制终端加速命令。"}
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

        {/* Windows 拦截范围双选卡片 + 可编辑目标进程标签 */}
        {isWindows && (
          <div className="mt-3.5 space-y-3">
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
                    智能识别其它梯子与常用工具
                  </span>
                  <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                    默认推荐
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                  不绕走 QQ、网盘、游戏等国内大文件，只精准加速其它梯子和下方自选传输工具。
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
                  除私网、中转机与 443 端口外全部非 443 连接走 443 加速（温和提示：可能带入其它国内非 443 传输）。
                </p>
              </button>
            </div>

            {globalScope === "proxy_apps_only" && (
              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-medium text-[var(--text)]">
                    加速软件进程名单（共 {targetProcesses.length} 个）
                  </span>
                  <button
                    type="button"
                    disabled={savingGlobalScope}
                    onClick={() => void handleResetTargetProcesses()}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-55"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>恢复默认名单</span>
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
                      暂未指定进程，可在下方输入进程名添加或点击右上角恢复默认名单
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
                    placeholder="添加其它梯子或工具进程名（如 mihomotag-serv.exe、scp.exe）"
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
            </div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              排在首位的是主力线路，遇到波动时自动按顺序切换到备用线路
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={probingAll || relays.length === 0}
              onClick={() => void handleProbeAllRelays()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${probingAll ? "animate-spin" : ""}`} />
              <span>{probingAll ? "检测中..." : "全部测速"}</span>
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
            const isProbing = Boolean(probingIds[relay.id]) || probingAll;
            const expiry = computeExpiryInfo(relay.expires_at);
            const hasUrgentExpiry = expiry.tone === "warn" || expiry.tone === "expired";
            const safeSni = (relay.sni ?? "").trim();
            const hasConfigTip = relay.port !== 443 || safeSni !== "";
            const canSetPrimary = relay.enabled && (!isTopEnabled || !isActivePrimary);

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

                  {/* 实时延迟 */}
                  <div className="shrink-0 text-right">
                    <div
                      className="cc-mono cc-tabular text-base font-bold leading-tight"
                      style={{ color: getRelayLatencyColor(relay.last_probe_ms) }}
                    >
                      {relay.last_probe_ms !== null
                        ? formatLatencyDisplay(relay.last_probe_ms, "--")
                        : "待测速"}
                    </div>
                    <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                      {relay.last_mbps !== null
                        ? `${relay.last_mbps.toFixed(0)} Mbps`
                        : "实时延迟"}
                    </div>
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

                  <div className="flex items-center gap-3">
                    {canSetPrimary && (
                      <button
                        type="button"
                        onClick={() => void handleSelectRelay(relay)}
                        className="inline-flex items-center gap-1 font-medium text-[var(--accent)] transition-opacity hover:opacity-80"
                      >
                        <Star className="h-3.5 w-3.5" />
                        <span>设为主力</span>
                      </button>
                    )}

                    <button
                      type="button"
                      disabled={isProbing}
                      onClick={() => void handleProbeRelay(relay.id)}
                      className="inline-flex items-center gap-1 text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${isProbing ? "animate-spin" : ""}`} />
                      <span>{isProbing ? "测速中" : "测速"}</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setPendingDeleteRelay(relay)}
                      className="inline-flex items-center gap-1 text-[var(--muted)] transition-colors hover:text-[var(--red)]"
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
            <div className="col-span-full flex flex-col items-center justify-center rounded-2xl border border-dashed border-[var(--line)] py-10 text-center">
              <Server className="h-7 w-7 text-[var(--muted)]/70" />
              <p className="mt-2.5 text-xs font-medium text-[var(--text-secondary)]">
                还没有添加中转线路
              </p>
              <p className="mt-1 text-[11px] text-[var(--muted)]">
                添加一台国内轻量云服务器即可显著提升上传速度
              </p>
              <button
                type="button"
                onClick={() => openAddModal("manual")}
                className="mt-3.5 inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>添加中转</span>
              </button>
            </div>
          )}
        </div>
      </section>

      {/* 3. 底部两张实用卡片：提速前后测速对比 + 校园网认证检测 */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {/* 提速效果实测对比 */}
        <div className="cc-card cc-glass rounded-2xl p-5 lg:col-span-7">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Gauge className="h-4 w-4 shrink-0 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  提速效果实测对比
                </h2>
              </div>
              <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                默认直接拿首页当前节点对比「走国内中转」和「普通直连」的真实上传、下载速度（也可下拉换测其它节点）
              </p>
            </div>
            <button
              type="button"
              disabled={benchmarking}
              onClick={() => void handleRunBenchmark()}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${benchmarking ? "animate-spin" : ""}`} />
              <span>{benchmarking ? "正在实测对比（约 5～10 秒）…" : "一键对比提速效果"}</span>
            </button>
          </div>

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
                      placeholder="例如：腾讯云轻量、月付"
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
       * 弹窗 3：给 AI 助手的部署说明
       * ==================================================================== */}
      {showGuideModal &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => setShowGuideModal(false)}
          >
          <div
            role="dialog"
            aria-modal="true"
            aria-label="给 AI 助手的部署说明"
            onClick={(e) => e.stopPropagation()}
            className="cc-surface w-full max-w-2xl rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">
                  给 AI 助手的部署说明
                </h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  复制下方说明发给你的 AI 助手，即可让它帮你快速搭建中转并生成导入配置
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowGuideModal(false)}
                className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
                aria-label="关闭弹窗"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <pre className="cc-mono cc-selectable mt-4 max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
              {guideMarkdown}
            </pre>

            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowGuideModal(false)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
              >
                关闭
              </button>
              <button
                type="button"
                onClick={() => void handleCopyGuide()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                {copiedGuide ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedGuide ? "已复制到剪贴板" : "一键复制说明"}</span>
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}

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
