import {
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowUp,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  FileCode2,
  Gauge,
  Plus,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
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

const DOMESTIC_PROBE_PRESETS = [
  {
    id: "hicloud",
    label: "华为 HiCloud 204（推荐）",
    url: "http://connectivitycheck.platform.hicloud.com/generate_204",
  },
  {
    id: "miui",
    label: "小米 MIUI 204（备用）",
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

const DEMO_MMRELAY_JSON = JSON.stringify(
  {
    schema: "mmrelay/v1",
    role: "domestic_pre_accel",
    relays: [
      {
        id: "relay-cn-north-demo",
        name: "CN-North-443 Backup",
        provider: "Demo Relay C",
        region: "CN-North",
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
    return { ok: false, error: "国内 204 探针地址不能为空" };
  }
  const lower = trimmed.toLowerCase();
  if (lower.includes("gstatic")) {
    return {
      ok: false,
      error: "已拦截：禁止使用海外 gstatic 探针，否则会触发代理回环或国内断网误判，请改用 hicloud / miui 国内 204。",
    };
  }
  for (const blocked of FORBIDDEN_OVERSEAS_PROBE_PATTERNS) {
    if (lower.includes(blocked)) {
      return {
        ok: false,
        error: `已拦截海外探测域名（${blocked}）：国内预加速健康探针必须严格保持国内直连 204 端点。`,
      };
    }
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, error: "探针 URL 仅支持 HTTP / HTTPS 协议" };
    }
  } catch {
    return { ok: false, error: "请输入格式合法的国内 204 探针 URL" };
  }
  return { ok: true, error: null };
}

function computeExpiryInfo(expiresAt: string | null): {
  label: string;
  tone: "ok" | "warn" | "expired" | "muted";
  daysLeft: number | null;
} {
  if (!expiresAt) {
    return { label: "长期有效", tone: "muted", daysLeft: null };
  }
  const target = Date.parse(expiresAt);
  if (!Number.isFinite(target)) {
    return { label: expiresAt, tone: "muted", daysLeft: null };
  }
  const diffDays = Math.ceil((target - Date.now()) / 86_400_000);
  if (diffDays < 0) {
    return { label: `已过期 ${Math.abs(diffDays)} 天`, tone: "expired", daysLeft: diffDays };
  }
  if (diffDays <= 3) {
    return { label: `即将到期（剩 ${diffDays} 天）`, tone: "warn", daysLeft: diffDays };
  }
  return { label: `剩余 ${diffDays} 天 · ${expiresAt}`, tone: "ok", daysLeft: diffDays };
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

function parseMmRelayImport(rawInput: string): {
  relays: PreAccelRelay[];
  warnings: string[];
  error: string | null;
} {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { relays: [], warnings: [], error: "请粘贴 mmrelay/v1 JSON 或 mmrelay://v1/... 单行 URI" };
  }

  let jsonText = trimmed;
  if (trimmed.toLowerCase().startsWith("mmrelay://v1/")) {
    const payload = trimmed.slice("mmrelay://v1/".length).trim();
    if (!payload) {
      return { relays: [], warnings: [], error: "mmrelay://v1/ 负载为空" };
    }
    try {
      jsonText = decodeBase64UrlUtf8(payload);
    } catch {
      return { relays: [], warnings: [], error: "mmrelay://v1/ Base64URL 解码失败，请核对单行 URI" };
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return { relays: [], warnings: [], error: "JSON 语法解析失败，请核对括号与引号" };
  }

  if (!parsed || typeof parsed !== "object") {
    return { relays: [], warnings: [], error: "导入内容必须为 mmrelay/v1 JSON 对象" };
  }

  const record = parsed as Record<string, unknown>;
  if ("schema" in record && record.schema !== "mmrelay/v1") {
    return {
      relays: [],
      warnings: [],
      error: `不支持的 schema：${String(record.schema)}（仅接受 mmrelay/v1）`,
    };
  }

  const rawList: RawRelayInput[] = Array.isArray(record.relays)
    ? (record.relays as RawRelayInput[])
    : [record as RawRelayInput];

  if (rawList.length === 0) {
    return { relays: [], warnings: [], error: "relays 数组为空" };
  }

  const warnings: string[] = [];
  const relays: PreAccelRelay[] = [];

  for (let i = 0; i < rawList.length; i++) {
    const item = rawList[i];
    const server = typeof item.server === "string" ? item.server.trim() : "";
    if (!server) {
      return { relays: [], warnings: [], error: `第 ${i + 1} 条跳板缺少 server 地址` };
    }
    const port = typeof item.port === "number" ? item.port : 443;
    const rawSni =
      typeof item.sni === "string"
        ? item.sni.trim()
        : typeof item.servername === "string"
          ? item.servername.trim()
          : "";
    if (port !== 443) {
      warnings.push(`${item.name ?? server} 端口为 :${port}（强烈建议国内预加速监听 TCP :443）`);
    }
    if (rawSni !== "") {
      warnings.push(`${item.name ?? server} 包含非空 SNI「${rawSni}」，国内 :443 跳板请保持纯 IP 无 SNI`);
    }

    relays.push({
      id:
        typeof item.id === "string" && item.id.trim()
          ? item.id.trim()
          : `relay-import-${Date.now().toString(36)}-${i}`,
      name:
        typeof item.name === "string" && item.name.trim()
          ? item.name.trim()
          : `Relay-${server}`,
      provider: typeof item.provider === "string" && item.provider.trim() ? item.provider.trim() : "Custom Relay",
      region: typeof item.region === "string" && item.region.trim() ? item.region.trim() : "CN",
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

function buildPreAccelAgentMarkdown(probeUrl: string, skip443: boolean): string {
  return [
    "# CatCloud Agent Guide: Domestic Pre-Acceleration (国内预加速)",
    "",
    "> 国内 TCP :443 纯 IP 无 SNI 双活中继前置链（dialer-proxy），含国内 204 探针防环与校园网 Captive Portal 防假连。",
    "",
    "## 1. 适用场景与量化信号",
    "- 非 443 端口海外代理单流上行被限速在 2～4 Mbps，而标准 TCP :443 TLS 单流可稳定达到 50～250+ Mbps。",
    "- 多图上传或 AI 代码请求频繁卡顿、TCP 重传率 > 2%，但下行带宽正常。",
    "- 处于高校校园网或企业内网环境，非标高位端口易被 QoS 限流或遇 Captive Portal 假连断网。",
    "",
    "## 2. 外部前提与 `mmrelay/v1` 标准规范",
    "- 准备 1～2 台国内轻量云服务器，在 TCP `:443` 部署 AnyTLS / Trojan-TLS / VLESS-TLS 并使用自签 ECDSA IP 证书。",
    '- **强制合规红线**：TLS `sni`（及 VLESS `servername`）必须严格置空（`""` / `null`）并设置 `skip_cert_verify: true`，禁止在国内 `:443` 填未备案第三方域名 SNI。',
    "- 通过标准 `mmrelay/v1` JSON 或单行 `mmrelay://v1/<base64url>` URI 交付猫猫云梯热导入。",
    `- 健康探针必须保持国内直连 204（当前：\`${probeUrl}\`），严禁使用海外 \`gstatic\`。`,
    `- 默认自动跳过原生 443 节点：\`${skip443 ? "true" : "false"}\`（避免对原生 443 节点二次封装）。`,
    "",
    "## 3. GUI 路径与 Headless CLI 热写入验收命令",
    "- GUI 路径：左侧「国内预加速」→ 开启总开关 → 导入 `mmrelay/v1` → 探活与限速体检。",
    "- CLI 查看跳板池：`catcloud relay list --json`",
    "- CLI 查看全局状态：`catcloud status --json`",
    "- CLI 热重载核心：`catcloud config reload --json`",
    "- CLI 导出本模块文档：`catcloud docs export --module preaccel --json`",
    "",
    "## 4. 安全回退与排障清单",
    "- 一键退回纯直连节点：关闭 GUI 总开关并执行 `catcloud config reload --json`。",
    "- 若出现连通但回环：检查跳板 IP/域名与 `hicloud`/`miui` 204 域名是否位于编译后 `rules` 顶部（`DIRECT,no-resolve`）并已加入 `dns.fake-ip-filter`。",
    "- 若校园网返回 302 门户页：通过猫猫云梯临时放行门户完成认证，恢复 HTTP 204 后系统会自动回收临时直连规则。",
    "",
    "## Reference Contract Snippet (`mmrelay/v1` · Sanitized)",
    "```json",
    JSON.stringify(
      {
        schema: "mmrelay/v1",
        role: "domestic_pre_accel",
        relays: [
          {
            id: "relay-cn-east-1",
            name: "CN-East-443 Primary",
            provider: "cloud-a",
            region: "CN-East",
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
  const [probeUrl, setProbeUrl] = useState<string>(config.preaccel.probe_url);
  const [relays, setRelays] = useState<PreAccelRelay[]>(storeRelays);
  const [probingIds, setProbingIds] = useState<Record<string, boolean>>({});
  const [probingAll, setProbingAll] = useState(false);
  const [failoverBusy, setFailoverBusy] = useState(false);

  // Import Panel
  const [showImport, setShowImport] = useState(false);
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importWarnings, setImportWarnings] = useState<string[]>([]);

  // 443 vs Non-443 Speed Benchmark Card
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
          testedAt: "尚未体检",
        }
      : {
          port443UpMbps: 184.6,
          port443DownMbps: 242.0,
          port443RetransPct: 0.2,
          non443UpMbps: 3.1,
          non443DownMbps: 46.8,
          non443RetransPct: 4.8,
          testedAt: "预览演示基线",
          isPreviewDemo: true,
        }
  );

  // Campus Captive Portal Card
  const [checkingPortal, setCheckingPortal] = useState(false);
  const [portalRequired, setPortalRequired] = useState<boolean>(runtime.captive_portal_required);
  const [portalHttpCode, setPortalHttpCode] = useState<number | null>(
    inTauri ? null : runtime.captive_portal_required ? 302 : 204
  );
  const [portalRedirect, setPortalRedirect] = useState<string | null>(null);
  const [portalBypassHosts, setPortalBypassHosts] = useState<string[]>([]);
  const [portalLastCheck, setPortalLastCheck] = useState<string>(inTauri ? "尚未检测" : "预览态");

  // Agent Guide Export
  const [copiedGuide, setCopiedGuide] = useState(false);
  const [showGuidePreview, setShowGuidePreview] = useState(false);

  const syncedRelaysRef = useRef(false);
  const syncedCfgRef = useRef(false);
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
    if (initialized && !syncedRelaysRef.current) {
      syncedRelaysRef.current = true;
      setRelays(storeRelays);
    }
  }, [storeRelays, initialized]);

  useEffect(() => {
    if (initialized && !syncedCfgRef.current) {
      syncedCfgRef.current = true;
      setEnabled(config.preaccel.enabled);
      setSkip443Native(config.preaccel.skip_443_native);
      setProbeUrl(config.preaccel.probe_url);
    }
  }, [config.preaccel, initialized]);

  const scheduleTimer = (fn: () => void, ms: number) => {
    const id = window.setTimeout(() => {
      timersRef.current = timersRef.current.filter((item) => item !== id);
      fn();
    }, ms);
    timersRef.current.push(id);
  };

  const probeValidation = useMemo(() => validateDomesticProbeUrl(probeUrl), [probeUrl]);

  const sortedRelays = useMemo(
    () => [...relays].sort((a, b) => a.priority - b.priority),
    [relays]
  );

  const primaryRelayId = useMemo(() => {
    if (runtime.preaccel_relay_name) {
      const matched = sortedRelays.find(
        (r) => r.enabled && (r.name === runtime.preaccel_relay_name || r.id === runtime.preaccel_relay_name)
      );
      if (matched) return matched.id;
    }
    return sortedRelays.find((r) => r.enabled)?.id ?? null;
  }, [sortedRelays, runtime.preaccel_relay_name]);

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
      appActions.showToast(`保存预加速配置失败：${formatErrorMessage(err)}`, "warn");
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
      appActions.showToast(
        applied ? "国内预加速（Domestic Pre-Acceleration）已开启" : "国内预加速已关闭",
        "ok"
      );
    } catch (err) {
      setEnabled(prev);
      appActions.showToast(`切换国内预加速失败：${formatErrorMessage(err)}`, "warn");
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
      next ? "已开启：默认自动跳过原生 443 节点" : "已关闭：允许对原生 443 节点叠加预加速"
    );
    if (!ok) setSkip443Native(prev);
  };

  const handleSelectProbePreset = async (url: string, label: string) => {
    const prev = probeUrl;
    setProbeUrl(url);
    const ok = await persistPreAccelConfig(enabled, skip443Native, url, `已切换国内 204 探针：${label}`);
    if (!ok) setProbeUrl(prev);
  };

  const handleSaveCustomProbe = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!probeValidation.ok) {
      appActions.showToast(probeValidation.error ?? "国内 204 探针不合规", "warn");
      return;
    }
    await persistPreAccelConfig(enabled, skip443Native, probeUrl.trim(), "国内 204 探针已保存");
  };

  const handleImportSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    const raw = importText.trim();
    if (!raw) {
      setImportError("请粘贴 mmrelay/v1 JSON 或 mmrelay://v1/... 单行 URI");
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
        setShowImport(false);
        appActions.showToast(`成功导入 ${imported.length} 台国内预加速跳板`, "ok");
      } catch (err) {
        const msg = formatErrorMessage(err);
        setImportError(msg);
        appActions.showToast(`导入跳板失败：${msg}`, "warn");
      } finally {
        setImporting(false);
      }
      return;
    }

    const res = parseMmRelayImport(raw);
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
    setShowImport(false);
    appActions.showToast(
      `成功导入 ${res.relays.length} 台国内预加速跳板${
        res.warnings.length > 0 ? "（含合规提醒，请留意徽章）" : ""
      }`,
      res.warnings.length > 0 ? "warn" : "ok"
    );
  };

  const handleFillDemoUri = () => {
    const uri = `mmrelay://v1/${encodeBase64UrlUtf8(DEMO_MMRELAY_JSON)}`;
    setImportText(uri);
    setImportError(null);
  };

  const handleMovePriority = async (id: string, delta: -1 | 1) => {
    const target = relays.find((r) => r.id === id);
    if (!target) return;
    const updated: PreAccelRelay = { ...target, priority: Math.max(1, target.priority + delta) };
    const prevRelays = relays;
    const nextRelays = relays.map((r) => (r.id === id ? updated : r));
    setRelays(nextRelays);
    try {
      await catcloudApi.upsertPreAccelRelay(updated);
      appActions.syncPreAccelRelays(nextRelays);
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`调整优先级失败：${formatErrorMessage(err)}`, "warn");
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
      appActions.showToast(`更新跳板状态失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSelectRelay = async (relay: PreAccelRelay) => {
    try {
      await catcloudApi.selectPreAccelRelay(relay.id);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast(`已切换主用跳板至 ${relay.name}`, "ok");
    } catch (err) {
      appActions.showToast(`切换主用跳板失败：${formatErrorMessage(err)}`, "warn");
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
        appActions.showToast(`已触发主备故障切换 → ${matched?.name ?? nextId}`, "ok");
      } else {
        appActions.showToast("当前无可用备用跳板可供切换", "warn");
      }
    } catch (err) {
      appActions.showToast(`主备故障切换失败：${formatErrorMessage(err)}`, "warn");
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
        setRelays((prev) =>
          prev.map((r) => (r.id === id ? { ...r, last_probe_ms: item.latency_ms } : r))
        );
      }
      if (item && !item.ok) {
        appActions.showToast(`跳板探活失败：${item.error ?? "连接超时"}`, "warn");
      } else {
        const msText = item?.latency_ms != null ? ` (${Math.round(item.latency_ms)} ms)` : "";
        appActions.showToast(`跳板国内探活通过${msText}`, "ok");
      }
    } catch (err) {
      appActions.showToast(`跳板探活失败：${formatErrorMessage(err)}`, "warn");
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
      }
      const okCount = results.filter((r) => r.ok).length;
      appActions.showToast(
        `批量跳板探活完成：${okCount}/${results.length} 台可用`,
        okCount > 0 ? "ok" : "warn"
      );
    } catch (err) {
      appActions.showToast(`批量探活失败：${formatErrorMessage(err)}`, "warn");
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
      appActions.showToast("已移除该跳板配置", "info");
    } catch (err) {
      appActions.showToast(`移除跳板失败：${formatErrorMessage(err)}`, "warn");
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
          testedAt: `${formatClockStamp()} (预览)`,
          isPreviewDemo: true,
        });
        setBenchmarking(false);
        appActions.showToast("预览模式：已刷新 443 vs 非 443 演示对照", "info");
      }, 420);
      return;
    }

    try {
      await catcloudApi.testPreAccelRelays(null);
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
        arr.length > 0 ? Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1)) : null;

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

      if (up443 === null && upNon443 === null) {
        appActions.showToast("已完成跳板探活；暂无吞吐快照，可前往「隔离测速」采集真实上下行", "info");
      } else {
        appActions.showToast("已基于真实探活与测速快照更新 443 对比体检", "ok");
      }
    } catch (err) {
      appActions.showToast(`限速体检失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setBenchmarking(false);
    }
  };

  const handleCheckCaptivePortal = async () => {
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
        appActions.showToast(
          `检测到校园网认证拦截（HTTP ${status.status_code ?? 302}），已记录门户豁免`,
          "warn"
        );
      } else {
        appActions.showToast(
          `国内 204 探针返回 HTTP ${status.status_code ?? 204}，未检测到门户劫持`,
          "ok"
        );
      }
    } catch (err) {
      appActions.showToast(`校园网门户检测失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCheckingPortal(false);
    }
  };

  const guideMarkdown = useMemo(
    () => buildPreAccelAgentMarkdown(probeUrl, skip443Native),
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
      appActions.showToast("已复制「国内预加速」四段式 Agent 辅助指南（Markdown）", "ok");
      scheduleTimer(() => setCopiedGuide(false), 2200);
    } else {
      appActions.showToast("复制失败，请手动展开预览复制", "warn");
    }
  };

  const speedupRatio =
    benchmark.port443UpMbps !== null &&
    benchmark.non443UpMbps !== null &&
    benchmark.non443UpMbps > 0
      ? (benchmark.port443UpMbps / benchmark.non443UpMbps).toFixed(1)
      : "--";

  return (
    <div className="space-y-4">
      {/* Top Control Panel: Master Toggle, Skip 443 Native, Domestic 204 Probe Guard & Agent Guide Export */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Zap className="h-4 w-4 text-[var(--accent)]" />
              <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                国内预加速（Domestic Pre-Acceleration）
              </h1>
              <span
                className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium ${
                  enabled
                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                    : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                }`}
              >
                {enabled ? "双活主备已启用" : "已暂停"}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[var(--muted)]">
              前置国内纯 IP <span className="cc-mono text-[var(--text-secondary)]">:443</span> TLS 跳板承载非 443 海外上行流量，有效突破校园网与跨网非标端口限速，内置自动防环与故障秒级切换。
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void handleCopyGuide()}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
            >
              {copiedGuide ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              <span>
                {copiedGuide
                  ? "已复制四段式 Agent 指南"
                  : "导出「国内预加速」四段式 Agent 指南"}
              </span>
            </button>
            <button
              type="button"
              onClick={() => setShowGuidePreview((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            >
              <FileCode2 className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{showGuidePreview ? "收起指南" : "预览 Markdown"}</span>
            </button>
          </div>
        </div>

        {/* Two Master Toggles */}
        <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
          <button
            type="button"
            onClick={() => void handleToggleEnabled()}
            className="flex items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
          >
            <div>
              <div className="text-xs font-semibold text-[var(--text)]">国内预加速总开关</div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                通过 dialer-proxy 将符合条件的海外节点自动编排经由国内 443 双活跳板出站
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
            onClick={() => void handleToggleSkip443()}
            className="flex items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
          >
            <div>
              <div className="text-xs font-semibold text-[var(--text)]">
                默认自动跳过原生 443 节点
              </div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                原生监听 TCP :443 的节点默认直连免二次封装；单节点可在节点页独立覆盖
              </div>
            </div>
            <span
              className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                skip443Native ? "bg-[var(--green)]" : "bg-[var(--line-strong)]"
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

        {/* Domestic 204 Probe Selector + Overseas gstatic Real-Time Blocker */}
        <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-semibold text-[var(--text)]">
                国内 204 连通与健康探针（严禁海外 gstatic）
              </div>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                用于识别国内真实断网、跳板切换与校园网 302 门户劫持，自动置顶 DIRECT 防环
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {DOMESTIC_PROBE_PRESETS.map((preset) => {
                const selected = probeUrl.trim() === preset.url;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => void handleSelectProbePreset(preset.url, preset.label)}
                    className={`rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                      selected
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>
          </div>

          <form onSubmit={(ev) => void handleSaveCustomProbe(ev)} className="mt-2.5 flex flex-wrap gap-2">
            <input
              type="text"
              value={probeUrl}
              onChange={(e) => setProbeUrl(e.target.value)}
              placeholder="http://connectivitycheck.platform.hicloud.com/generate_204"
              className={`cc-mono flex-1 rounded-lg border bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none ${
                probeValidation.ok
                  ? "border-[var(--line)] focus:border-[var(--accent)]"
                  : "border-[var(--red)] focus:border-[var(--red)]"
              }`}
            />
            <button
              type="submit"
              disabled={!probeValidation.ok}
              className="rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-45"
            >
              应用探针
            </button>
          </form>

          {!probeValidation.ok && (
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
              <span className="inline-flex items-center gap-1.5 font-medium">
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
                className="shrink-0 rounded-md border border-[var(--red)]/40 bg-[var(--card)] px-2 py-0.5 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
              >
                一键恢复 HiCloud 204
              </button>
            </div>
          )}
        </div>

        {/* Collapsible Agent Guide Preview */}
        {showGuidePreview && (
          <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3">
            <div className="mb-2 flex items-center justify-between text-xs">
              <span className="font-semibold text-[var(--text)]">
                国内预加速 · 四段式 Agent 辅助指南预览（Markdown）
              </span>
              <button
                type="button"
                onClick={() => void handleCopyGuide()}
                className="inline-flex items-center gap-1 rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] text-[var(--accent)]"
              >
                <Copy className="h-3 w-3" />
                复制全文
              </button>
            </div>
            <pre className="cc-mono cc-selectable max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">
              {guideMarkdown}
            </pre>
          </div>
        )}
      </section>

      {/* Active-Standby Dual Relay Pool Cards + mmrelay/v1 Importer */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              双活跳板主备池（纯 IP :443 · 无 SNI 强校验）
            </h2>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              按优先级自动主备容灾切换，到期前 3 天触发续费倒计时预警
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={probingAll || relays.length === 0}
              onClick={() => void handleProbeAllRelays()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${probingAll ? "animate-spin" : ""}`} />
              <span>{probingAll ? "批量探活中..." : "全部探活"}</span>
            </button>
            <button
              type="button"
              disabled={failoverBusy || relays.length < 2}
              onClick={() => void handleFailover()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-50"
              title="将活跃预加速跳板切换至下一可用备用节点"
            >
              <ArrowLeftRight className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{failoverBusy ? "切换中..." : "主备切换"}</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setShowImport((v) => !v);
                setImportError(null);
              }}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
            >
              {showImport ? <X className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
              <span>{showImport ? "收起导入" : "导入 mmrelay/v1 JSON / URI"}</span>
            </button>
          </div>
        </div>

        {/* Import mmrelay/v1 JSON or mmrelay://v1/... URI Panel */}
        {showImport && (
          <form
            onSubmit={(ev) => void handleImportSubmit(ev)}
            className="mb-4 space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5 text-xs"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-semibold text-[var(--text)]">
                导入标准 <span className="cc-mono text-[var(--accent)]">mmrelay/v1</span> JSON 或{" "}
                <span className="cc-mono text-[var(--accent)]">mmrelay://v1/...</span> 单行 URI
              </span>
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setImportText(DEMO_MMRELAY_JSON);
                    setImportError(null);
                  }}
                  className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                >
                  填入脱敏 JSON 示例
                </button>
                <button
                  type="button"
                  onClick={handleFillDemoUri}
                  className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                >
                  填入 mmrelay://v1 示例
                </button>
              </div>
            </div>

            <textarea
              rows={5}
              value={importText}
              onChange={(e) => {
                setImportText(e.target.value);
                setImportError(null);
              }}
              spellCheck={false}
              placeholder='粘贴 {"schema":"mmrelay/v1","relays":[...]} 或 mmrelay://v1/<base64url>'
              className="cc-mono cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />

            {importError && (
              <div className="flex items-center gap-1.5 text-[11px] text-[var(--red)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span>{importError}</span>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowImport(false)}
                className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={importing}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Upload className="h-3.5 w-3.5" />
                <span>{importing ? "导入中..." : "校验并导入主备池"}</span>
              </button>
            </div>
          </form>
        )}

        {importWarnings.length > 0 && (
          <div className="mb-3 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3 py-2 text-xs text-[var(--amber)]">
            <div className="font-semibold">导入合规提示：</div>
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px]">
              {importWarnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Relay Cards Grid */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {sortedRelays.map((relay) => {
            const safeSni = (relay.sni ?? "").trim();
            const noSniCompliant =
              safeSni === "" && relay.port === 443 && relay.skip_cert_verify;
            const expiry = computeExpiryInfo(relay.expires_at);
            const isPrimary = relay.id === primaryRelayId;
            const isProbing = Boolean(probingIds[relay.id]) || probingAll;

            return (
              <div
                key={relay.id}
                className={`rounded-2xl border p-4 transition-colors ${
                  isPrimary
                    ? "border-[var(--accent)] bg-[var(--accent-soft)]/50"
                    : "border-[var(--line)] bg-[var(--bg-elevated)]"
                } ${!relay.enabled ? "opacity-65" : ""}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Server className="h-4 w-4 shrink-0 text-[var(--accent)]" />
                      <span className="truncate text-sm font-semibold text-[var(--text)]">
                        {relay.name}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                          isPrimary
                            ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                            : "bg-[var(--card)] text-[var(--muted)]"
                        }`}
                      >
                        {isPrimary ? "主用 P" : "备用 P"}
                        {relay.priority}
                      </span>
                    </div>

                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      {noSniCompliant ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                          <ShieldCheck className="h-3 w-3" />
                          纯 IP 无 SNI · 合规
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--red)]">
                          <ShieldAlert className="h-3 w-3" />
                          {safeSni !== ""
                            ? `存在非空 SNI (${safeSni})`
                            : `端口 :${relay.port} 非标准 443`}
                        </span>
                      )}

                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 cc-mono text-[10px] font-medium ${
                          expiry.tone === "warn" || expiry.tone === "expired"
                            ? "bg-[var(--red-soft)] text-[var(--red)]"
                            : "bg-[var(--card)] text-[var(--muted)]"
                        }`}
                      >
                        <Clock className="h-3 w-3" />
                        {expiry.label}
                      </span>
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      onClick={() => void handleMovePriority(relay.id, -1)}
                      className="rounded-md border border-[var(--line)] bg-[var(--card)] p-1 text-[var(--muted)] hover:text-[var(--text)]"
                      title="提升优先级"
                      aria-label="提升优先级"
                    >
                      <ArrowUp className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleMovePriority(relay.id, 1)}
                      className="rounded-md border border-[var(--line)] bg-[var(--card)] p-1 text-[var(--muted)] hover:text-[var(--text)]"
                      title="降低优先级"
                      aria-label="降低优先级"
                    >
                      <ArrowDown className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleToggleRelay(relay.id)}
                      className={`rounded-md px-2 py-1 text-[10px] font-medium ${
                        relay.enabled
                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                          : "bg-[var(--card)] text-[var(--muted)]"
                      }`}
                    >
                      {relay.enabled ? "启用" : "停用"}
                    </button>
                  </div>
                </div>

                {/* Relay Specs & Live Telemetry */}
                <div className="mt-3 grid grid-cols-3 gap-2 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-xs">
                  <div>
                    <div className="text-[10px] text-[var(--muted)]">节点地址</div>
                    <div className="mt-0.5 truncate cc-mono font-medium text-[var(--text)]">
                      {relay.server}:{relay.port}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-[var(--muted)]">实时延迟</div>
                    <div className="mt-0.5 cc-mono cc-tabular font-semibold text-[var(--green)]">
                      {relay.last_probe_ms !== null ? `${Math.round(relay.last_probe_ms)} ms` : "--"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-[var(--muted)]">实测吞吐</div>
                    <div className="mt-0.5 cc-mono cc-tabular font-semibold text-[var(--accent)]">
                      {relay.last_mbps !== null ? `${relay.last_mbps.toFixed(1)} Mbps` : "--"}
                    </div>
                  </div>
                </div>

                <div className="mt-2.5 flex items-center justify-between text-[11px] text-[var(--muted)]">
                  <span className="cc-mono">
                    {relay.provider} · {relay.region} · {relay.protocol.toUpperCase()}
                  </span>
                  <div className="flex items-center gap-2.5">
                    {!isPrimary && relay.enabled && (
                      <button
                        type="button"
                        onClick={() => void handleSelectRelay(relay)}
                        className="inline-flex items-center gap-1 text-[var(--text-secondary)] hover:text-[var(--accent)]"
                      >
                        <Star className="h-3 w-3" />
                        设为主用
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={isProbing}
                      onClick={() => void handleProbeRelay(relay.id)}
                      className="inline-flex items-center gap-1 text-[var(--text-secondary)] hover:text-[var(--accent)] disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3 w-3 ${isProbing ? "animate-spin" : ""}`} />
                      探活
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleRemoveRelay(relay.id)}
                      className="inline-flex items-center gap-1 text-[var(--muted)] hover:text-[var(--red)]"
                    >
                      <Trash2 className="h-3 w-3" />
                      移除
                    </button>
                  </div>
                </div>
              </div>
            );
          })}

          {sortedRelays.length === 0 && (
            <div className="col-span-full rounded-xl border border-dashed border-[var(--line)] py-8 text-center text-xs text-[var(--muted)]">
              暂无国内 443 跳板配置，点击右上角「导入 mmrelay/v1 JSON / URI」接入主备中继。
            </div>
          )}
        </div>
      </section>

      {/* Bottom Row: 443 vs Non-443 Speed Benchmark Card + Campus Captive Portal Protection Card */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {/* 443 vs Non-443 Throttling Diagnostic Comparison Card */}
        <div className="cc-card cc-glass rounded-2xl p-4 lg:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <Gauge className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  443 vs 非 443 限速体检对照
                </h2>
              </div>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                量化对比标准 TCP :443 预加速链路与非 443 高位端口直连的真实单流上行差异
              </p>
            </div>
            <button
              type="button"
              disabled={benchmarking}
              onClick={() => void handleRunBenchmark()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${benchmarking ? "animate-spin" : ""}`} />
              <span>{benchmarking ? "对比体检中..." : "运行限速体检"}</span>
            </button>
          </div>

          <div className="space-y-3">
            {/* TCP 443 Pre-Accel Row */}
            <div className="rounded-xl border border-[var(--green)]/35 bg-[var(--bg-elevated)] p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[var(--text)]">
                  TCP :443 国内预加速链路（纯 IP 无 SNI）
                </span>
                <span className="cc-mono text-[11px] text-[var(--green)]">
                  {benchmark.port443RetransPct !== null ? `重传 ${benchmark.port443RetransPct}%` : "实时统计"}
                </span>
              </div>
              <div className="mt-2 space-y-1.5">
                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-[var(--muted)]">单流上行速率</span>
                    <span className="cc-mono cc-tabular font-semibold text-[var(--green)]">
                      {benchmark.port443UpMbps !== null ? `${benchmark.port443UpMbps.toFixed(1)} Mbps` : "--"}
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
                  <span>单流下行速率</span>
                  <span className="cc-mono text-[var(--sky)]">
                    {benchmark.port443DownMbps !== null ? `${benchmark.port443DownMbps.toFixed(1)} Mbps` : "--"}
                  </span>
                </div>
              </div>
            </div>

            {/* Non-443 Direct Row */}
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[var(--text)]">
                  非 443 高位端口直连基线
                </span>
                <span className="cc-mono text-[11px] text-[var(--amber)]">
                  {benchmark.non443RetransPct !== null ? `重传 ${benchmark.non443RetransPct}%` : "实时统计"}
                </span>
              </div>
              <div className="mt-2 space-y-1.5">
                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-[var(--muted)]">单流上行速率</span>
                    <span className="cc-mono cc-tabular font-semibold text-[var(--amber)]">
                      {benchmark.non443UpMbps !== null ? `${benchmark.non443UpMbps.toFixed(1)} Mbps` : "--"}
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
                  <span>单流下行速率</span>
                  <span className="cc-mono text-[var(--text-secondary)]">
                    {benchmark.non443DownMbps !== null ? `${benchmark.non443DownMbps.toFixed(1)} Mbps` : "--"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px]">
            <span className="text-[var(--text-secondary)]">
              {speedupRatio !== "--" ? (
                <>
                  体检结论：:443 上行较非 443 提升{" "}
                  <strong className="cc-mono text-[var(--accent)]">{speedupRatio}x</strong>
                  {benchmark.isPreviewDemo ? "（预览演示值）" : "，建议保持开启国内预加速。"}
                </>
              ) : (
                "点击「运行限速体检」或在「隔离测速」完成上下行采集后自动计算提升倍率。"
              )}
            </span>
            <span className="cc-mono text-[var(--muted)]">时间：{benchmark.testedAt}</span>
          </div>
        </div>

        {/* Campus Network Captive Portal Anti-False-Connection Status Card */}
        <div className="cc-card cc-glass flex flex-col justify-between rounded-2xl p-4 lg:col-span-5">
          <div>
            <div className="mb-3 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Wifi className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  校园网 Captive Portal 防假连
                </h2>
              </div>
              <button
                type="button"
                disabled={checkingPortal}
                onClick={() => void handleCheckCaptivePortal()}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
              >
                <RefreshCw className={`h-3 w-3 ${checkingPortal ? "animate-spin" : ""}`} />
                <span>检测门户</span>
              </button>
            </div>

            <div
              className={`mb-3 flex items-center justify-between rounded-xl border px-3.5 py-3 ${
                portalRequired
                  ? "border-[var(--amber)]/50 bg-[var(--amber-soft)]"
                  : portalHttpCode === null
                    ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                    : "border-[var(--green)]/40 bg-[var(--green-soft)]"
              }`}
            >
              <div className="flex items-center gap-2.5">
                {portalRequired ? (
                  <ShieldAlert className="h-5 w-5 shrink-0 text-[var(--amber)]" />
                ) : portalHttpCode === null ? (
                  <Clock className="h-5 w-5 shrink-0 text-[var(--muted)]" />
                ) : (
                  <CheckCircle2 className="h-5 w-5 shrink-0 text-[var(--green)]" />
                )}
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    {portalRequired
                      ? "检测到校园网认证门户拦截"
                      : portalHttpCode === null
                        ? "尚未执行校园网门户检测"
                        : "国内直连放行正常（无门户劫持）"}
                  </div>
                  <div className="mt-0.5 cc-mono text-[11px] text-[var(--muted)]">
                    最近探测状态：{portalHttpCode !== null ? `HTTP ${portalHttpCode}` : "待检测"} · {portalLastCheck}
                  </div>
                  {portalRedirect && (
                    <div className="mt-1 truncate cc-mono text-[10px] text-[var(--amber)]">
                      重定向：{portalRedirect}
                    </div>
                  )}
                  {portalBypassHosts.length > 0 && (
                    <div className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]">
                      临时放行主机：{portalBypassHosts.join(", ")}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-2 text-xs">
              {[
                {
                  title: "国内 204 真值回包校验",
                  detail: "严格识别 HTTP 204 与 302 重定向，避免认证过期时误判跳板宕机。",
                  ok: probeValidation.ok,
                },
                {
                  title: "认证门户临时 DIRECT 豁免与自动回收",
                  detail: "检测到 302 门户页时临时放行认证网关，恢复 204 后自动撤销临时直连规则。",
                  ok: true,
                },
                {
                  title: "跳板 IP 与国内 204 域名防环置顶",
                  detail: "自动注入 DIRECT,no-resolve 至分流顶部并写入 dns.fake-ip-filter 防止代理死循环。",
                  ok: true,
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[var(--text)]">{item.title}</span>
                    <span
                      className="text-[10px] font-medium"
                      style={{ color: item.ok ? "var(--green)" : "var(--amber)" }}
                    >
                      {item.ok ? "已护航" : "待修正探针"}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                    {item.detail}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
