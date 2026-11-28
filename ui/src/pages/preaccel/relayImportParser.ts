import type { AcceleratedProcessStat, PreAccelRelay } from "../../api/tauri";

export const DETECTED_BY_LABELS: Record<string, string> = {
  system_proxy_host: "系统代理",
  local_proxy_listener: "本地代理",
  open_core_name: "代理核心",
  outbound_proxy_behavior: "自动识别",
  scope_all: "全局覆盖",
  manual: "手动列表",
};

export function formatDetectedByLabel(raw: string | undefined): string {
  if (!raw) return "自动识别";
  return DETECTED_BY_LABELS[raw] ?? "自动识别";
}

export type AddModalTab = "manual" | "import";

export const RELAY_PROTOCOL_OPTIONS = [
  { value: "anytls", label: "AnyTLS（推荐）" },
  { value: "trojan", label: "Trojan" },
  { value: "vless", label: "VLESS" },
  { value: "hysteria2", label: "Hysteria2" },
  { value: "tuic", label: "TUIC" },
] as const;

export const REGION_QUICK_PICKS = ["华东", "华南", "华北", "西南", "香港"] as const;

export const DOMESTIC_PROBE_PRESETS = [
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

export const FORBIDDEN_OVERSEAS_PROBE_PATTERNS = [
  "gstatic.com",
  "google.com",
  "googleapis.com",
  "cloudflare.com",
  "captive.apple.com",
  "firefox.com",
  "msftconnecttest.com",
];

export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;

// Internal wire-format constants for import parsing & sanitized demo payload
export const IMPORT_SCHEMA_TAG = "mmrelay/v1";
export const IMPORT_URI_PREFIX = "mmrelay://v1/";

export const DEMO_IMPORT_JSON = JSON.stringify(
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

export const INPUT_CLS =
  "w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]";

export function looksLikeIpAddress(raw: string): boolean {
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

export function encodeBase64UrlUtf8(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function decodeBase64UrlUtf8(input: string): string {
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

export function validateDomesticProbeUrl(raw: string): { ok: boolean; error: string | null } {
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

export function computeExpiryInfo(expiresAt: string | null): {
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

export function getRelayLatencyColor(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms) || ms <= 0) return "var(--muted)";
  if (ms <= 60) return "var(--green)";
  if (ms <= 150) return "var(--amber)";
  return "var(--red)";
}

export function formatLatencyDisplay(ms: number | null | undefined, emptyLabel = "--"): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms <= 0) {
    return emptyLabel;
  }
  if (ms < 0.5) {
    return "<1 ms";
  }
  return `${Math.round(ms)} ms`;
}

export function hasValidLatency(ms: number | null | undefined): ms is number {
  return ms !== null && ms !== undefined && Number.isFinite(ms) && ms > 0;
}

export function hasValidSpeed(mbps: number | null | undefined): mbps is number {
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

export function parseRelayImportInput(rawInput: string): {
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

export function dedupeProcessStats(list: AcceleratedProcessStat[]): AcceleratedProcessStat[] {
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

export function formatClockStamp(isoOrMs?: string | number | null): string {
  const d =
    isoOrMs !== undefined && isoOrMs !== null && isoOrMs !== ""
      ? new Date(isoOrMs)
      : new Date();
  if (Number.isNaN(d.getTime())) return typeof isoOrMs === "string" ? isoOrMs : "--";
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

export function isUdpOnlyProto(proto: string): boolean {
  const p = proto.trim().toLowerCase();
  return (
    p === "hysteria2" ||
    p === "hy2" ||
    p === "hysteria" ||
    p === "tuic" ||
    p === "wireguard"
  );
}
