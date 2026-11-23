import {
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowUp,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Eye,
  EyeOff,
  FileText,
  Gauge,
  Globe,
  Plus,
  RefreshCw,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Star,
  Trash2,
  Upload,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  type AppConfig,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { appActions, useAppSelector } from "../store/appStore";

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
  if (ms === null) return "var(--muted)";
  if (ms <= 60) return "var(--green)";
  if (ms <= 150) return "var(--amber)";
  return "var(--red)";
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

interface BenchmarkMetrics {
  port443UpMbps: number | null;
  port443DownMbps: number | null;
  port443RetransPct: number | null;
  non443UpMbps: number | null;
  non443DownMbps: number | null;
  non443RetransPct: number | null;
  testedAt: string;
  isPreviewDemo?: boolean;
}

const INPUT_CLS =
  "w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]";

export function PreAccelPage() {
  const config = useAppSelector((s) => s.config);
  const runtime = useAppSelector((s) => s.runtime);
  const storeRelays = useAppSelector((s) => s.preAccelRelays);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  const [enabled, setEnabled] = useState<boolean>(config.preaccel.enabled);
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

  // Speed Comparison Card
  const [benchmarking, setBenchmarking] = useState(false);
  const [benchmark, setBenchmark] = useState<BenchmarkMetrics>(() =>
    inTauri
      ? {
          port443UpMbps: null,
          port443DownMbps: null,
          port443RetransPct: null,
          non443UpMbps: null,
          non443DownMbps: null,
          non443RetransPct: null,
          testedAt: "尚未测速",
        }
      : {
          port443UpMbps: 184.6,
          port443DownMbps: 242.0,
          port443RetransPct: 0.2,
          non443UpMbps: 3.1,
          non443DownMbps: 46.8,
          non443RetransPct: 4.8,
          testedAt: "演示数据",
          isPreviewDemo: true,
        }
  );

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
      if (!showProbeModal) {
        setProbeUrl(config.preaccel.probe_url);
      }
    }
  }, [config.preaccel, initialized, showProbeModal]);

  useEffect(() => {
    let active = true;
    void catcloudApi
      .getFullConfig()
      .then((full) => {
        if (!active) return;
        const rawPreaccel = full.preaccel as { campus_portal_guard?: unknown } | undefined;
        if (typeof rawPreaccel?.campus_portal_guard === "boolean") {
          setCampusPortalGuard(rawPreaccel.campus_portal_guard);
        }
      })
      .catch(() => {
        /* keep fallback campus_portal_guard state */
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!showAddModal && !showProbeModal && !showGuideModal) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (!savingManual && !importing) {
          setShowAddModal(false);
        }
        setShowProbeModal(false);
        setShowGuideModal(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [showAddModal, showProbeModal, showGuideModal, savingManual, importing]);

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
    const probed = enabledList.filter((r) => r.last_probe_ms !== null);
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
    const prev = enabled;
    const next = !enabled;
    setEnabled(next);
    try {
      const applied = await catcloudApi.togglePreAccel(next);
      setEnabled(applied);
      const saved = await catcloudApi.getConfig();
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast(applied ? "已开启国内提速" : "已关闭国内提速", "ok");
    } catch (err) {
      setEnabled(prev);
      appActions.showToast(`切换国内提速失败：${formatErrorMessage(err)}`, "warn");
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
        const msText = item?.latency_ms != null ? `（${Math.round(item.latency_ms)} ms）` : "";
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

  const handleRemoveRelay = async (id: string) => {
    try {
      await catcloudApi.deletePreAccelRelay(id);
      const next = relays.filter((r) => r.id !== id);
      setRelays(next);
      appActions.syncPreAccelRelays(next);
      appActions.showToast("已删除该中转线路", "info");
    } catch (err) {
      appActions.showToast(`删除线路失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleRunBenchmark = async () => {
    if (benchmarking) return;
    setBenchmarking(true);
    if (!inTauri) {
      scheduleTimer(() => {
        setBenchmark({
          port443UpMbps: 184.6,
          port443DownMbps: 242.0,
          port443RetransPct: 0.2,
          non443UpMbps: 3.1,
          non443DownMbps: 46.8,
          non443RetransPct: 4.8,
          testedAt: `${formatClockStamp()}（演示）`,
          isPreviewDemo: true,
        });
        setBenchmarking(false);
        appActions.showToast("演示模式：已完成中转连通与延迟检测", "info");
      }, 420);
      return;
    }

    try {
      const results = await catcloudApi.testPreAccelRelays(null);
      const [latestRelays, latestProbes] = await Promise.all([
        catcloudApi.listPreAccelRelays(),
        catcloudApi.listProbeSnapshots(),
      ]);
      setRelays(latestRelays);
      appActions.syncPreAccelRelays(latestRelays);
      appActions.syncProbes(latestProbes);

      const node443Ups: number[] = [];
      const node443Downs: number[] = [];
      const nodeNon443Ups: number[] = [];
      const nodeNon443Downs: number[] = [];

      for (const node of nodes) {
        const snap = latestProbes[node.id] ?? probes[node.id];
        if (!snap) continue;
        if (node.is_443_native) {
          if (snap.up_mbps !== null) node443Ups.push(snap.up_mbps);
          if (snap.down_mbps !== null) node443Downs.push(snap.down_mbps);
        } else {
          if (snap.up_mbps !== null) nodeNon443Ups.push(snap.up_mbps);
          if (snap.down_mbps !== null) nodeNon443Downs.push(snap.down_mbps);
        }
      }
      const relayMbps = latestRelays
        .map((r) => r.last_mbps)
        .filter((v): v is number => v !== null && v > 0);
      if (relayMbps.length > 0) {
        node443Ups.push(...relayMbps);
      }

      const avg = (arr: number[]) =>
        arr.length > 0
          ? Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1))
          : null;

      const up443 = avg(node443Ups);
      const down443 = avg(node443Downs);
      const upNon443 = avg(nodeNon443Ups);
      const downNon443 = avg(nodeNon443Downs);

      setBenchmark({
        port443UpMbps: up443,
        port443DownMbps: down443,
        port443RetransPct: null,
        non443UpMbps: upNon443,
        non443DownMbps: downNon443,
        non443RetransPct: null,
        testedAt: formatClockStamp(),
      });

      const okCount = results.filter((r) => r.ok).length;
      if (results.length === 0) {
        appActions.showToast("还没有可检测的中转线路，请先添加国内中转", "info");
      } else if (up443 === null && upNon443 === null) {
        appActions.showToast(
          `中转检测完成（${okCount}/${results.length} 条可用）；上下行速度参考需先到「节点测速」测试`,
          okCount > 0 ? "ok" : "warn"
        );
      } else {
        appActions.showToast(
          `中转连通与延迟检测完成（${okCount}/${results.length} 条可用），已同步最新节点速度参考`,
          okCount > 0 ? "ok" : "warn"
        );
      }
    } catch (err) {
      appActions.showToast(`中转连通检测失败：${formatErrorMessage(err)}`, "warn");
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

  const speedupRatio =
    benchmark.port443UpMbps !== null &&
    benchmark.non443UpMbps !== null &&
    benchmark.non443UpMbps > 0
      ? (benchmark.port443UpMbps / benchmark.non443UpMbps).toFixed(1)
      : "--";

  const manualPortNum = Number.parseInt(manualPort.trim() || "443", 10);
  const manualShowNon443Hint =
    manualPort.trim() !== "" && Number.isInteger(manualPortNum) && manualPortNum !== 443;
  const manualShowDomainHint =
    manualServer.trim() !== "" && !looksLikeIpAddress(manualServer);

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
                className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium ${
                  enabled
                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                    : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                }`}
              >
                {enabled ? "已开启" : "未开启"}
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
            onClick={() => void handleToggleEnabled()}
            className="flex items-center justify-between gap-4 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
          >
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">开启国内提速</div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                自动通过国内中转线路转发海外流量，断线时无缝切换备用线路
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
                        ? `${Math.round(relay.last_probe_ms)} ms`
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
                      onClick={() => void handleRemoveRelay(relay.id)}
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
        {/* 中转连通检测与速度参考 */}
        <div className="cc-card cc-glass rounded-2xl p-5 lg:col-span-7">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <Gauge className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  中转连通检测与速度参考
                </h2>
              </div>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                一键检测中转线路连通性与延迟；下方上下行速度汇总自「节点测速」的已有记录
              </p>
            </div>
            <button
              type="button"
              disabled={benchmarking}
              onClick={() => void handleRunBenchmark()}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${benchmarking ? "animate-spin" : ""}`} />
              <span>{benchmarking ? "检测中..." : "一键检测中转连通与延迟"}</span>
            </button>
          </div>

          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
            <span className="text-[var(--text-secondary)]">
              当前已启用中转{" "}
              <strong className="cc-mono text-[var(--text)]">
                {relayLatencyStats.enabledTotal}
              </strong>{" "}
              条 · 已测通{" "}
              <strong className="cc-mono text-[var(--green)]">
                {relayLatencyStats.probedCount}
              </strong>{" "}
              条
            </span>
            <span className="cc-mono text-[var(--muted)]">
              {relayLatencyStats.bestMs !== null
                ? `最快延迟 ${Math.round(relayLatencyStats.bestMs)} ms`
                : "点击右侧按钮立即检测延迟"}
            </span>
          </div>

          <div className="space-y-3">
            {/* 提速通道 */}
            <div className="rounded-xl border border-[var(--green)]/35 bg-[var(--bg-elevated)] p-3.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[var(--text)]">
                  开启国内提速（443 高速通道）
                </span>
                <span className="cc-mono text-[11px] text-[var(--green)]">
                  {benchmark.port443RetransPct !== null
                    ? `丢包重传 ${benchmark.port443RetransPct}%`
                    : "提速通道"}
                </span>
              </div>
              <div className="mt-2.5 space-y-2">
                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-[var(--muted)]">上传速度</span>
                    <span className="cc-mono cc-tabular font-semibold text-[var(--green)]">
                      {benchmark.port443UpMbps !== null
                        ? `${benchmark.port443UpMbps.toFixed(1)} Mbps`
                        : "--"}
                    </span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                    <div
                      className="h-full rounded-full bg-[var(--green)] transition-all duration-300"
                      style={{
                        width:
                          benchmark.port443UpMbps !== null
                            ? `${Math.min(100, (benchmark.port443UpMbps / 250) * 100)}%`
                            : "0%",
                      }}
                    />
                  </div>
                </div>
                <div className="flex justify-between text-[11px] text-[var(--muted)]">
                  <span>下载速度</span>
                  <span className="cc-mono text-[var(--sky)]">
                    {benchmark.port443DownMbps !== null
                      ? `${benchmark.port443DownMbps.toFixed(1)} Mbps`
                      : "--"}
                  </span>
                </div>
              </div>
            </div>

            {/* 普通直连 */}
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[var(--text)]">普通线路直连</span>
                <span className="cc-mono text-[11px] text-[var(--amber)]">
                  {benchmark.non443RetransPct !== null
                    ? `丢包重传 ${benchmark.non443RetransPct}%`
                    : "直连基线"}
                </span>
              </div>
              <div className="mt-2.5 space-y-2">
                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-[var(--muted)]">上传速度</span>
                    <span className="cc-mono cc-tabular font-semibold text-[var(--amber)]">
                      {benchmark.non443UpMbps !== null
                        ? `${benchmark.non443UpMbps.toFixed(1)} Mbps`
                        : "--"}
                    </span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                    <div
                      className="h-full rounded-full bg-[var(--amber)] transition-all duration-300"
                      style={{
                        width:
                          benchmark.non443UpMbps !== null
                            ? `${Math.max(3, Math.min(100, (benchmark.non443UpMbps / 250) * 100))}%`
                            : "0%",
                      }}
                    />
                  </div>
                </div>
                <div className="flex justify-between text-[11px] text-[var(--muted)]">
                  <span>下载速度</span>
                  <span className="cc-mono text-[var(--text-secondary)]">
                    {benchmark.non443DownMbps !== null
                      ? `${benchmark.non443DownMbps.toFixed(1)} Mbps`
                      : "--"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
            <span className="text-[var(--text-secondary)]">
              {speedupRatio !== "--" ? (
                <>
                  已有记录中上传速度约提升{" "}
                  <strong className="cc-mono text-[var(--accent)]">{speedupRatio} 倍</strong>
                  {benchmark.isPreviewDemo ? "（演示数据）" : "，建议保持开启国内提速。"}
                </>
              ) : (
                "点击「一键检测中转连通与延迟」验证中转延迟；前往「节点测速」完成上下行测速后此处将自动汇总参考。"
              )}
            </span>
            <span className="cc-mono text-[var(--muted)]">时间：{benchmark.testedAt}</span>
          </div>
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
      {showAddModal && (
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
                    <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                      连接协议
                    </label>
                    <select
                      value={manualProtocol}
                      onChange={(e) => {
                        setManualProtocol(e.target.value);
                        setManualError(null);
                      }}
                      className={INPUT_CLS}
                    >
                      {RELAY_PROTOCOL_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
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
        </div>
      )}

      {/* ====================================================================
       * 弹窗 2：国内连通检测地址（华为 / 小米 204 + 自定义）
       * ==================================================================== */}
      {showProbeModal && (
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
        </div>
      )}

      {/* ====================================================================
       * 弹窗 3：给 AI 助手的部署说明
       * ==================================================================== */}
      {showGuideModal && (
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
        </div>
      )}
    </div>
  );
}
