import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Cpu,
  FileCode2,
  FileText,
  Filter,
  FolderOpen,
  GitMerge,
  Globe,
  Layers,
  Link2,
  Minus,
  Package,
  Pencil,
  Play,
  Plus,
  QrCode,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type DesktopAppCandidate,
  type LiveCaptureOutcomeDto,
  type LiveCaptureStatusDto,
  type MigrationPreviewDto,
  type MultiGroup,
  type PreAccelOverrideMode,
  type ProbeSnapshot,
  type ProxyNode,
  type SubscriptionRecord,
  type SubscriptionUpdateMode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect } from "../components/AppSelect";
import {
  ContinentRegionFilter,
  PaginationBar,
} from "../components/ContinentRegionFilter";
import { GroupMembershipPopover } from "../components/GroupMembershipPopover";
import { ShareBundleModal, type ShareBundleTransport } from "../components/ShareBundleModal";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import {
  type AiSiteBadgeDisplay,
  formatGoogleRegionTooltip,
  getAiBadgeToneClass,
  getNodeAiBadgeDisplays,
  hasVerifiedAiUnlock,
} from "../utils/aiUnlockDisplay";
import {
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
import { isBoolPref, oneOfPref, usePersistedState } from "../utils/uiPrefs";

/* ============================================================================
 * Domain Types & Demo Presets
 * ============================================================================ */

type MultiplierRange = "all" | "le1" | "1to2" | "ge3";
type Native443Filter = "all" | "only_443" | "non_443";
type NodeSortBy = "default" | "latency" | "up" | "down";
type MigrationSourceKind =
  | "clash_verge"
  | "flclash"
  | "v2rayn"
  | "local_file"
  | "clipboard_text";

interface HealthFilters {
  googleClean: boolean;
  keepalive60s: boolean;
  aiUnlocked: boolean;
}

interface MigrationPreviewItem {
  id: string;
  source_kind: MigrationSourceKind;
  client_label: string;
  source_client_label?: string;
  display_name?: string | null;
  source_path: string | null;
  nodes: ProxyNode[];
  prepend_rules: string[];
  append_rules: string[];
  warnings: string[];
}

const SUB_KIND_LABELS: Record<SubscriptionRecord["kind"], string> = {
  url: "订阅链接",
  file: "本地文件",
  migrated: "已有软件导入",
  process_adapter: "软件抓取",
};

const KNOWN_CLIENT_SPECS: Array<{
  kind: "clash_verge" | "flclash" | "v2rayn";
  label: string;
  readonlyPathHint: string;
  desc: string;
}> = [
  {
    kind: "clash_verge",
    label: "Clash Verge / Rev",
    readonlyPathHint:
      "%APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\profiles",
    desc: "只读复制里面的节点列表和自定义分流规则，不改原软件",
  },
  {
    kind: "flclash",
    label: "FlClash",
    readonlyPathHint: "%APPDATA%\\com.follow.clash\\profiles",
    desc: "只读提取多份配置里的节点、地区和倍率信息",
  },
  {
    kind: "v2rayn",
    label: "v2rayN",
    readonlyPathHint: "%APPDATA%\\v2rayN\\guiConfigs\\config.json",
    desc: "只读读取已保存的节点以及直连/代理规则",
  },
];

const DEMO_PASTE_SAMPLE = `proxies:
  - name: "JP-Osaka-05 · 0.5x"
    type: vless
    server: 203.0.113.41
    port: 443
    uuid: "00000000-0000-4000-8000-000000000041"
    tls: true
    servername: jp05.example.invalid
  - name: "SG-Lite-06 · 1.5x"
    type: trojan
    server: 198.51.100.42
    port: 8443
    password: "placeholder-demo-pass"
  - name: "UK-London-07 · 2x"
    type: anytls
    server: 203.0.113.43
    port: 443
    password: "placeholder-anytls-pass"
rules:
  - DOMAIN-SUFFIX,local.example.invalid,DIRECT
  - PROCESS-NAME,sample-app.exe,DIRECT`;

const DEMO_MIGRATION_SCANS: Record<
  "clash_verge" | "flclash" | "v2rayn",
  MigrationPreviewItem
> = {
  clash_verge: {
    id: "mig-clash-verge",
    source_kind: "clash_verge",
    client_label: "Clash Verge / Rev",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\io.github.clash-verge-rev.clash-verge-rev\\profiles\\demo_main.yaml",
    nodes: [
      {
        id: "mig-cv-jp-01",
        sub_id: "sub-mig-clash-verge",
        name: "JP-Tokyo-Verge · 0.5x",
        protocol: "vless",
        server: "203.0.113.61",
        port: 443,
        region_code: "JP",
        multiplier: 0.5,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443"],
        enabled: true,
      },
      {
        id: "mig-cv-sg-02",
        sub_id: "sub-mig-clash-verge",
        name: "SG-Transit-Verge · 1.5x",
        protocol: "trojan",
        server: "198.51.100.62",
        port: 8443,
        region_code: "SG",
        multiplier: 1.5,
        is_443_native: false,
        preaccel_override: null,
        tags: ["migrated"],
        enabled: true,
      },
    ],
    prepend_rules: [
      "DOMAIN-SUFFIX,intranet.example.invalid,DIRECT",
      "PROCESS-NAME,sample-sync.exe,DIRECT",
    ],
    append_rules: ["DOMAIN-SUFFIX,openai.com,PROXY"],
    warnings: ["已自动忽略原配置中的默认兜底规则，避免覆盖猫猫云梯路由策略"],
  },
  flclash: {
    id: "mig-flclash",
    source_kind: "flclash",
    client_label: "FlClash",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\com.follow.clash\\profiles\\demo_pool.yaml",
    nodes: [
      {
        id: "mig-fl-hk-01",
        sub_id: "sub-mig-flclash",
        name: "HK-Edge-FlClash · 2x",
        protocol: "hysteria2",
        server: "203.0.113.71",
        port: 443,
        region_code: "HK",
        multiplier: 2.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443"],
        enabled: true,
      },
    ],
    prepend_rules: ["DOMAIN-SUFFIX,campus.example.invalid,DIRECT"],
    append_rules: [],
    warnings: [],
  },
  v2rayn: {
    id: "mig-v2rayn",
    source_kind: "v2rayn",
    client_label: "v2rayN",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\v2rayN\\guiConfigs\\config.json",
    nodes: [
      {
        id: "mig-v2-us-01",
        sub_id: "sub-mig-v2rayn",
        name: "US-SanJose-v2rayN · 1x",
        protocol: "vless",
        server: "198.51.100.75",
        port: 443,
        region_code: "US",
        multiplier: 1.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443", "ai-ready"],
        enabled: true,
      },
      {
        id: "mig-v2-de-02",
        sub_id: "sub-mig-v2rayn",
        name: "DE-Frankfurt-v2rayN · 3x",
        protocol: "vmess",
        server: "198.51.100.76",
        port: 2053,
        region_code: "DE",
        multiplier: 3.0,
        is_443_native: false,
        preaccel_override: null,
        tags: ["migrated"],
        enabled: true,
      },
    ],
    prepend_rules: ["DOMAIN-SUFFIX,direct.example.invalid,DIRECT"],
    append_rules: [],
    warnings: ["已跳过 freedom / blackhole 内置出站标签"],
  },
};

/* ============================================================================
 * Helpers: Formatting, Backend DTO Mappers & Pure Client-Side Parser
 * ============================================================================ */

function getSubSource(sub: SubscriptionRecord): string {
  return sub.url_or_cmd || "";
}

function maskSubscriptionSource(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";

  const secretSepIdx = trimmed.indexOf("|secret=");
  const hasInlineSecret = secretSepIdx >= 0;
  const basePart = hasInlineSecret ? trimmed.slice(0, secretSepIdx).trim() : trimmed;

  if (/^https?:\/\//i.test(basePart)) {
    try {
      const parsed = new URL(basePart);
      const isLocalLoopback =
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "localhost" ||
        parsed.hostname === "::1";
      const segs = parsed.pathname.split("/").filter(Boolean);
      const hasQuery = parsed.search.length > 0;

      if (isLocalLoopback) {
        const cleanPath = segs.length > 0 ? `/${segs.join("/")}` : "";
        const secretHint = hasInlineSecret || hasQuery ? "（已设口令）" : "";
        return `${parsed.protocol}//${parsed.host}${cleanPath}${secretHint}`;
      }

      if (segs.length === 0) {
        return hasQuery
          ? `${parsed.protocol}//${parsed.host}/••••••`
          : `${parsed.protocol}//${parsed.host}`;
      }
      const firstSeg = segs[0];
      const firstLooksSecret = firstSeg.length >= 12 || /[0-9a-f]{10,}/i.test(firstSeg);
      const maskedPath = firstLooksSecret ? "/••••••" : `/${firstSeg}/••••••`;
      return `${parsed.protocol}//${parsed.host}${maskedPath}`;
    } catch {
      return basePart.replace(/([?&][^=&\s]+=)[^&\s]+/g, "$1••••••");
    }
  }

  return basePart
    .replace(/[A-Za-z]:[\\/]Users[\\/][^\\/]+/gi, "C:\\Users\\<USER>")
    .replace(/\/(?:Users|home)\/[^/]+/g, "/home/<USER>");
}

function formatQuotaBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0.0 GB";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  if (idx === 0) return `${Math.round(value)} B`;
  return `${value.toFixed(1)} ${units[idx]}`;
}

function inferSubNameFromUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.replace(/^www\./i, "");
    if (host) return host;
  } catch {
    /* use fallback */
  }
  return "我的订阅";
}

const SINGLE_NODE_URI_RE =
  /^(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls):\/\//i;

function isSingleNodeShareUri(raw: string): boolean {
  const firstLine = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0 && !line.startsWith("#"));
  if (!firstLine) return false;
  return SINGLE_NODE_URI_RE.test(firstLine);
}

function containsSingleNodeShareUriLine(raw: string): boolean {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .some((line) => line.length > 0 && !line.startsWith("#") && SINGLE_NODE_URI_RE.test(line));
}

function normalizeSubSourceForCompare(kind: "url" | "file", raw: string): string {
  const trimmed = raw.trim();
  if (kind !== "url") return trimmed;
  return trimmed.replace(/^(https?:\/\/[^/?#]+)/i, (prefix) => prefix.toLowerCase());
}

function parseClashInstallConfigUrl(
  raw: string
): { url: string; name?: string } | null {
  const trimmed = raw.trim();
  if (!/^(?:clash|clashmeta):\/\/install-config\b/i.test(trimmed)) {
    return null;
  }
  const queryIdx = trimmed.indexOf("?");
  if (queryIdx < 0) {
    return null;
  }
  const query = trimmed.slice(queryIdx + 1);
  const urlParamMatch = /(?:^|&)url=/i.exec(query);
  if (!urlParamMatch) {
    return null;
  }

  const beforeUrl = query.slice(0, urlParamMatch.index);
  const afterUrl = query.slice(urlParamMatch.index + urlParamMatch[0].length);
  let targetUrl = "";
  let rawName = "";

  if (/^https?:\/\//i.test(afterUrl)) {
    // Plaintext nested URL: capture everything up to outer &name= (or end of string) so nested &flag=clash params are preserved
    const nameMatch = /&name=([^&]*)/i.exec(afterUrl);
    if (nameMatch && nameMatch.index !== undefined) {
      targetUrl = afterUrl.slice(0, nameMatch.index).trim();
      rawName = nameMatch[1]?.trim() ?? "";
    } else {
      targetUrl = afterUrl.trim();
    }
    if (!rawName && beforeUrl) {
      try {
        rawName = new URLSearchParams(beforeUrl).get("name")?.trim() ?? "";
      } catch {
        /* ignore malformed leading query */
      }
    }
  } else {
    // Percent-encoded nested URL (single or double encoded)
    const nextAmpIdx = afterUrl.indexOf("&");
    targetUrl = (nextAmpIdx >= 0 ? afterUrl.slice(0, nextAmpIdx) : afterUrl).trim();
    for (let i = 0; i < 2; i += 1) {
      if (/^https?:\/\//i.test(targetUrl)) break;
      if (!/%[0-9a-f]{2}/i.test(targetUrl)) break;
      try {
        const decoded = decodeURIComponent(targetUrl).trim();
        if (decoded === targetUrl) break;
        targetUrl = decoded;
      } catch {
        break;
      }
    }
    try {
      const parsed = new URL(trimmed);
      rawName = parsed.searchParams.get("name")?.trim() ?? "";
    } catch {
      const nameMatch = /(?:^|&)name=([^&]*)/i.exec(query);
      rawName = nameMatch?.[1]?.trim() ?? "";
    }
  }

  if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) {
    return null;
  }

  let decodedName = rawName;
  if (rawName) {
    try {
      decodedName = decodeURIComponent(rawName).trim();
    } catch {
      decodedName = rawName;
    }
  }
  return {
    url: targetUrl,
    name: decodedName || undefined,
  };
}

function hasPausedCaptureSession(cap: {
  active: boolean;
  timedOut?: boolean;
  sessionId: string | null;
  status: LiveCaptureStatusDto | null;
}): boolean {
  const hasSessionRef = Boolean(cap.sessionId || cap.status?.session_id);
  if (!hasSessionRef || cap.active) return false;
  return Boolean(cap.timedOut || (cap.status && !cap.status.active));
}

function migrationClientLabel(kind: string): string {
  switch (kind) {
    case "clash_verge":
      return "Clash Verge / Rev";
    case "flclash":
      return "FlClash";
    case "v2rayn":
      return "v2rayN";
    case "local_file":
      return "本地配置文件";
    case "clipboard_text":
      return "粘贴的配置文本";
    default:
      return kind;
  }
}

function normalizeMigrationKind(kind: string): MigrationSourceKind {
  if (
    kind === "clash_verge" ||
    kind === "flclash" ||
    kind === "v2rayn" ||
    kind === "local_file" ||
    kind === "clipboard_text"
  ) {
    return kind;
  }
  return "local_file";
}

const KNOWN_MIGRATION_CLIENT_KINDS = new Set<MigrationSourceKind>([
  "clash_verge",
  "flclash",
  "v2rayn",
]);

function extractPathBasename(path: string | null | undefined): string | null {
  const trimmed = path?.trim();
  if (!trimmed) return null;
  const withoutTrailing = trimmed.replace(/[\\/]+$/, "");
  if (!withoutTrailing) return null;
  const segs = withoutTrailing.split(/[\\/]/).filter(Boolean);
  return segs[segs.length - 1] ?? null;
}

function normalizeMigrationSourcePath(path: string | null | undefined): string | null {
  const trimmed = path?.trim();
  if (!trimmed) return null;
  let unified = trimmed.replace(/\\/g, "/");
  if (unified.startsWith("//?/UNC/")) {
    unified = `//${unified.slice(8)}`;
  } else if (unified.startsWith("//?/")) {
    unified = unified.slice(4);
  }
  unified = unified.replace(/(^|[^:])\/+/g, "$1/");
  if (unified.length > 3 && !/^[a-z]:\/$/i.test(unified)) {
    unified = unified.replace(/\/+$/, "");
  }
  const isWindowsLike =
    /^[a-z]:\//i.test(unified) ||
    trimmed.includes("\\") ||
    (typeof navigator !== "undefined" &&
      /win/i.test(navigator.platform || navigator.userAgent || ""));
  return isWindowsLike ? unified.toLowerCase() : unified;
}

function getMigrationDedupeKey(item: MigrationPreviewItem): string {
  const norm = normalizeMigrationSourcePath(item.source_path);
  return norm ? `path:${norm}` : `id:${item.id}`;
}

function isNormalizedPathInDir(candidateNorm: string, dirNorm: string): boolean {
  if (candidateNorm === dirNorm) return true;
  const prefix = dirNorm.endsWith("/") ? dirNorm : `${dirNorm}/`;
  return candidateNorm.startsWith(prefix);
}

function defaultMigrationSubName(item: MigrationPreviewItem): string {
  const customDisplay = item.display_name?.trim();
  if (customDisplay) return customDisplay;
  const basename = extractPathBasename(item.source_path);
  if (basename) return basename;
  return `导入 · ${item.client_label}`;
}

function mapMigrationDtoToPreview(
  dto: MigrationPreviewDto,
  index: number
): MigrationPreviewItem {
  const sourceKind = normalizeMigrationKind(dto.source_kind);
  const sourceClientLabel = migrationClientLabel(sourceKind);
  const displayName = dto.display_name?.trim() || null;
  const normPath = normalizeMigrationSourcePath(dto.source_path);
  const stableId = normPath ? `mig-path:${normPath}` : `mig-${sourceKind}-inline-${index}`;
  return {
    id: stableId,
    source_kind: sourceKind,
    client_label: displayName ?? sourceClientLabel,
    source_client_label: sourceClientLabel,
    display_name: displayName,
    source_path: dto.source_path ?? null,
    nodes: Array.isArray(dto.nodes) ? dto.nodes : [],
    prepend_rules: Array.isArray(dto.prepend_rules) ? dto.prepend_rules : [],
    append_rules: Array.isArray(dto.append_rules) ? dto.append_rules : [],
    warnings: Array.isArray(dto.warnings) ? dto.warnings : [],
  };
}

function mergeSingleMigrationItem(
  existing: MigrationPreviewItem,
  incoming: MigrationPreviewItem
): MigrationPreviewItem {
  // If an already-detected known client file is re-scanned via generic custom path ("local_file"),
  // keep the specific client identity while refreshing nodes/rules/warnings from disk.
  if (
    KNOWN_MIGRATION_CLIENT_KINDS.has(existing.source_kind) &&
    incoming.source_kind === "local_file"
  ) {
    const resolvedDisplay = incoming.display_name ?? existing.display_name ?? null;
    return {
      ...incoming,
      id: existing.id,
      source_kind: existing.source_kind,
      source_client_label: existing.source_client_label ?? migrationClientLabel(existing.source_kind),
      display_name: resolvedDisplay,
      client_label:
        resolvedDisplay ?? existing.source_client_label ?? migrationClientLabel(existing.source_kind),
    };
  }
  return incoming;
}

function mergeScannedMigrationItems(
  baseItems: MigrationPreviewItem[],
  incomingItems: MigrationPreviewItem[],
  prependIncoming: boolean
): MigrationPreviewItem[] {
  // First deduplicate incomingItems themselves by normalized source_path
  const dedupedIncoming: MigrationPreviewItem[] = [];
  const incomingIndexByKey = new Map<string, number>();
  for (const item of incomingItems) {
    const key = getMigrationDedupeKey(item);
    const existingIdx = incomingIndexByKey.get(key);
    if (existingIdx !== undefined) {
      dedupedIncoming[existingIdx] = mergeSingleMigrationItem(dedupedIncoming[existingIdx], item);
    } else {
      incomingIndexByKey.set(key, dedupedIncoming.length);
      dedupedIncoming.push(item);
    }
  }

  const baseByKey = new Map<string, MigrationPreviewItem>();
  for (const item of baseItems) {
    const key = getMigrationDedupeKey(item);
    if (!baseByKey.has(key)) {
      baseByKey.set(key, item);
    }
  }

  const mergedByKey = new Map<string, MigrationPreviewItem>();
  if (prependIncoming) {
    for (const next of dedupedIncoming) {
      const key = getMigrationDedupeKey(next);
      const prev = baseByKey.get(key);
      mergedByKey.set(key, prev ? mergeSingleMigrationItem(prev, next) : next);
    }
    for (const [key, prev] of baseByKey.entries()) {
      if (!mergedByKey.has(key)) {
        mergedByKey.set(key, prev);
      }
    }
  } else {
    for (const [key, prev] of baseByKey.entries()) {
      mergedByKey.set(key, prev);
    }
    for (const next of dedupedIncoming) {
      const key = getMigrationDedupeKey(next);
      const prev = mergedByKey.get(key);
      mergedByKey.set(key, prev ? mergeSingleMigrationItem(prev, next) : next);
    }
  }

  return Array.from(mergedByKey.values());
}

function formatTimeShort(iso: string | null): string {
  if (!iso) return "尚未刷新";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${mm}-${dd} ${hh}:${mi}`;
}

function formatExpireInfo(expiresAt: string | null): {
  label: string;
  tone: "normal" | "warn" | "danger";
} {
  if (!expiresAt) return { label: "不限期", tone: "normal" };
  const target = new Date(expiresAt);
  if (Number.isNaN(target.getTime())) {
    return { label: expiresAt, tone: "normal" };
  }
  const diffDays = Math.ceil((target.getTime() - Date.now()) / 86_400_000);
  if (diffDays < 0) {
    return { label: `已过期 (${expiresAt.slice(0, 10)})`, tone: "danger" };
  }
  if (diffDays <= 14) {
    return { label: `剩 ${diffDays} 天 (${expiresAt.slice(0, 10)})`, tone: "warn" };
  }
  return { label: `${expiresAt.slice(0, 10)} (剩 ${diffDays} 天)`, tone: "normal" };
}

function detectRegionFromName(name: string): string {
  const upper = name.toUpperCase();
  const pairs: Array<[string, RegExp]> = [
    ["JP", /(?:^|[^A-Z])JP(?:[^A-Z]|$)|东京|大阪|日本|TOKYO|OSAKA/i],
    ["SG", /(?:^|[^A-Z])SG(?:[^A-Z]|$)|新加坡|狮城|SINGAPORE/i],
    ["US", /(?:^|[^A-Z])US(?:[^A-Z]|$)|美国|洛杉矶|硅谷|圣何塞|SAN\s*JOSE|WEST/i],
    ["TW", /(?:^|[^A-Z])TW(?:[^A-Z]|$)|台湾|台北|TAIPEI/i],
    ["HK", /(?:^|[^A-Z])HK(?:[^A-Z]|$)|香港|HONG\s*KONG/i],
    ["UK", /(?:^|[^A-Z])UK(?:[^A-Z]|$)|英国|伦敦|LONDON/i],
    ["DE", /(?:^|[^A-Z])DE(?:[^A-Z]|$)|德国|法兰克福|FRANKFURT/i],
    ["KR", /(?:^|[^A-Z])KR(?:[^A-Z]|$)|韩国|首尔|SEOUL/i],
  ];
  for (const [code, re] of pairs) {
    if (re.test(upper) || re.test(name)) return code;
  }
  return "UNK";
}

function extractMultiplierFromName(name: string): number {
  const m =
    /(?:^|[\s[\]()·|-])(\d+(?:\.\d+)?)\s*(?:x|倍|倍率)(?:$|[\s[\]()·|-])/i.exec(
      name
    ) ?? /(?:^|[\s[\]()·|-])x(\d+(?:\.\d+)?)(?:$|[\s[\]()·|-])/i.exec(name);
  if (!m) return 1.0;
  const val = Number(m[1]);
  return Number.isFinite(val) && val >= 0 ? val : 1.0;
}

function parsePastedConfigPreview(rawInput: string): MigrationPreviewItem {
  let text = rawInput.trim();
  const warnings: string[] = [];

  // Attempt single-pass Base64 decode when input looks like a compact URI payload
  if (
    text.length >= 24 &&
    !text.includes("://") &&
    !text.includes("proxies:") &&
    /^[A-Za-z0-9+/=\r\n]+$/.test(text)
  ) {
    try {
      const decoded = atob(text.replace(/\s+/g, ""));
      if (decoded.includes("://") || decoded.includes("proxies:")) {
        text = decoded.trim();
      }
    } catch {
      /* keep raw text */
    }
  }

  const subId = `sub-mig-clip-${Date.now()}`;
  const nodes: ProxyNode[] = [];
  const prependRules: string[] = [];
  const appendRules: string[] = [];

  if (/^\s*proxies\s*:/m.test(text)) {
    // Lightweight read-only YAML proxies/rules extractor for instant preview
    const lines = text.split(/\r?\n/);
    let section: "none" | "proxies" | "rules" = "none";
    let current: Record<string, string> | null = null;

    const flushCurrent = () => {
      if (!current) return;
      const name = (current.name ?? "").replace(/^["']|["']$/g, "").trim();
      const protocol = (current.type ?? "").replace(/^["']|["']$/g, "").trim().toLowerCase();
      const server = (current.server ?? "").replace(/^["']|["']$/g, "").trim();
      const port = Number(current.port ?? 0);
      if (name && protocol && server && Number.isFinite(port) && port > 0) {
        const is443 =
          port === 443 &&
          (["trojan", "anytls", "hysteria2", "hy2", "tuic"].includes(protocol) ||
            current.tls === "true" ||
            Boolean(current.servername));
        nodes.push({
          id: `${subId}-n-${nodes.length + 1}`,
          sub_id: subId,
          name,
          protocol: protocol === "hy2" ? "hysteria2" : protocol,
          server,
          port,
          region_code: detectRegionFromName(name),
          multiplier: extractMultiplierFromName(name),
          is_443_native: is443,
          preaccel_override: null,
          tags: is443 ? ["migrated", "native-443"] : ["migrated"],
          enabled: true,
        });
      }
      current = null;
    };

    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      if (/^proxies\s*:/.test(rawLine)) {
        flushCurrent();
        section = "proxies";
        continue;
      }
      if (/^(?:rules|prepend-rules|append-rules)\s*:/.test(rawLine)) {
        flushCurrent();
        section = "rules";
        continue;
      }
      if (/^[a-zA-Z0-9_-]+\s*:/.test(rawLine) && !rawLine.startsWith(" ")) {
        flushCurrent();
        section = "none";
        continue;
      }

      if (section === "proxies") {
        if (trimmed.startsWith("- ")) {
          flushCurrent();
          current = {};
          const rest = trimmed.slice(2).trim();
          const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.+)$/.exec(rest);
          if (kv) current[kv[1].toLowerCase()] = kv[2].trim();
        } else if (current) {
          const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.+)$/.exec(trimmed);
          if (kv) current[kv[1].toLowerCase()] = kv[2].trim();
        }
      } else if (section === "rules" && trimmed.startsWith("- ")) {
        const rule = trimmed
          .slice(2)
          .trim()
          .replace(/^["']|["']$/g, "");
        if (/^MATCH\s*,/i.test(rule)) {
          warnings.push("已跳过默认兜底规则，保留猫猫云梯主分流结构");
        } else if (/,DIRECT$/i.test(rule)) {
          prependRules.push(rule);
        } else if (rule.includes(",")) {
          appendRules.push(rule);
        }
      }
    }
    flushCurrent();
  } else {
    // Parse plain proxy URI lines
    const uriLines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => Boolean(l) && !l.startsWith("#"));
    for (const line of uriLines) {
      const protoMatch =
        /^(vless|vmess|trojan|ssr|ss|hy2|hysteria2|tuic|anytls):\/\//i.exec(line);
      if (!protoMatch) continue;
      const rawProto = protoMatch[1].toLowerCase();
      const protocol = rawProto === "hy2" ? "hysteria2" : rawProto;

      let name = `${protocol.toUpperCase()}-Imported-${nodes.length + 1}`;
      let server = "203.0.113.99";
      let port = 443;

      const hashIdx = line.indexOf("#");
      if (hashIdx >= 0) {
        try {
          const decodedHash = decodeURIComponent(line.slice(hashIdx + 1).trim());
          if (decodedHash) name = decodedHash;
        } catch {
          const rawHash = line.slice(hashIdx + 1).trim();
          if (rawHash) name = rawHash;
        }
      }

      const hostPortMatch = /@([^/?#:]+):(\d+)/.exec(line);
      if (hostPortMatch) {
        server = hostPortMatch[1];
        port = Number(hostPortMatch[2]) || 443;
      }

      const is443 =
        port === 443 &&
        ["vless", "trojan", "anytls", "hysteria2", "tuic"].includes(protocol);

      nodes.push({
        id: `${subId}-u-${nodes.length + 1}`,
        sub_id: subId,
        name,
        protocol,
        server,
        port,
        region_code: detectRegionFromName(name),
        multiplier: extractMultiplierFromName(name),
        is_443_native: is443,
        preaccel_override: null,
        tags: is443 ? ["migrated", "native-443"] : ["migrated"],
        enabled: true,
      });
    }
  }

  if (nodes.length === 0) {
    warnings.push("未提取到有效节点，请确认粘贴的是完整的节点配置或节点分享链接");
  }

  return {
    id: `mig-clip-${Date.now()}`,
    source_kind: "clipboard_text",
    client_label: "粘贴文本 / 剪贴板",
    source_path: null,
    nodes,
    prepend_rules: prependRules,
    append_rules: appendRules,
    warnings,
  };
}

function getNodeAiInfo(probe: ProbeSnapshot | undefined): {
  passed: number;
  total: number;
  unlockedLabels: string[];
  badges: AiSiteBadgeDisplay[];
  detail: string;
} {
  if (!probe) {
    return { passed: 0, total: 0, unlockedLabels: [], badges: [], detail: "暂无解锁快照" };
  }
  const allBadges = getNodeAiBadgeDisplays(probe);
  const measured = allBadges.filter((item) => item.measured);
  const unlocked = measured.filter((item) => item.unlocked);
  const displayBadges = measured.filter(
    (item) =>
      item.unlocked ||
      item.windsurfState === "proxy_risk" ||
      item.windsurfState === "legacy_retest"
  );
  if (measured.length === 0) {
    const sites = probe.unlocked_sites ?? {};
    const fallbackEntries = Object.entries(sites);
    const passed = fallbackEntries.filter(([, ok]) => ok).length;
    return {
      passed,
      total: fallbackEntries.length,
      unlockedLabels: fallbackEntries.filter(([, ok]) => ok).map(([k]) => k),
      badges: [],
      detail:
        fallbackEntries.length > 0
          ? fallbackEntries.map(([k, ok]) => `${k}: ${ok ? "解锁" : "受限"}`).join(" · ")
          : "暂无解锁快照",
    };
  }
  return {
    passed: unlocked.length,
    total: measured.length,
    unlockedLabels: unlocked.map((item) => item.shortLabel),
    badges: displayBadges,
    detail: measured.map((item) => item.tooltip).join("\n"),
  };
}

function isAiUnlocked(probe: ProbeSnapshot | undefined): boolean {
  return hasVerifiedAiUnlock(probe);
}

/* ============================================================================
 * Slide-Over Drawer 1: Read-Only Legacy Config Migration
 * ============================================================================ */

interface MigrationDrawerProps {
  open: boolean;
  initialTab?: "scan" | "paste";
  initialPasteText?: string | null;
  onClose: () => void;
  onImport: (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ) => Promise<boolean>;
}

function MigrationDrawer({
  open,
  initialTab = "scan",
  initialPasteText = null,
  onClose,
  onImport,
}: MigrationDrawerProps) {
  const [tab, setTab] = useState<"scan" | "paste">("scan");
  const [scanningKind, setScanningKind] = useState<
    "all" | "clash_verge" | "flclash" | "v2rayn" | "custom_dir" | "custom_file" | null
  >(null);
  const [scannedItems, setScannedItems] = useState<MigrationPreviewItem[]>([]);
  const [selectedPreviewId, setSelectedPreviewId] = useState<string | null>(null);
  const [pasteText, setPasteText] = useState("");
  const [pastePreview, setPastePreview] = useState<MigrationPreviewItem | null>(
    null
  );
  const [scanSubName, setScanSubName] = useState("");
  const [pasteSubName, setPasteSubName] = useState("");
  const [includeRules, setIncludeRules] = useState(true);
  const [importing, setImporting] = useState(false);
  const openSessionRef = useRef(false);
  const scannedItemsRef = useRef<MigrationPreviewItem[]>(scannedItems);
  scannedItemsRef.current = scannedItems;
  const selectedPreviewIdRef = useRef<string | null>(selectedPreviewId);
  selectedPreviewIdRef.current = selectedPreviewId;

  const runScanClient = useCallback(
    async (
      kind: "clash_verge" | "flclash" | "v2rayn" | "all",
      autoTriggered = false
    ) => {
      setScanningKind(kind);
      try {
        let items: MigrationPreviewItem[];
        if (isTauriEnv()) {
          const rawList = await catcloudApi.scanLocalMigrations();
          const mapped = rawList.map((dto, idx) => mapMigrationDtoToPreview(dto, idx));
          items =
            kind === "all"
              ? mapped
              : mapped.filter((item) => item.source_kind === kind);
        } else {
          items =
            kind === "all"
              ? [
                  DEMO_MIGRATION_SCANS.clash_verge,
                  DEMO_MIGRATION_SCANS.flclash,
                  DEMO_MIGRATION_SCANS.v2rayn,
                ]
              : [DEMO_MIGRATION_SCANS[kind]];
        }

        // Replace stale entries of the re-scanned source_kind(s) so deleted files are evicted
        const retained = scannedItemsRef.current.filter((prevItem) =>
          kind === "all"
            ? !KNOWN_MIGRATION_CLIENT_KINDS.has(prevItem.source_kind)
            : prevItem.source_kind !== kind
        );
        const nextList = mergeScannedMigrationItems(retained, items, false);
        setScannedItems(nextList);

        if (items.length > 0) {
          const firstKey = getMigrationDedupeKey(items[0]);
          const matchedFirst =
            nextList.find((it) => getMigrationDedupeKey(it) === firstKey) ?? items[0];
          setSelectedPreviewId(matchedFirst.id);
          setScanSubName(defaultMigrationSubName(matchedFirst));

          const totalNodes = items.reduce((acc, i) => acc + i.nodes.length, 0);
          const totalRules = items.reduce(
            (acc, i) => acc + i.prepend_rules.length + i.append_rules.length,
            0
          );
          if (totalNodes > 0) {
            appActions.showToast(
              `已找到 ${totalNodes} 个可导入节点（不会改动原软件）`,
              "ok"
            );
          } else if (totalRules > 0 && !autoTriggered) {
            appActions.showToast(
              `扫描到 ${items.length} 份仅含分流规则的配置（共 ${totalRules} 条规则，无代理节点）`,
              "info"
            );
          }
        } else {
          const currentSelected = selectedPreviewIdRef.current;
          const stillExists = currentSelected
            ? nextList.some((it) => it.id === currentSelected)
            : false;
          if (!stillExists) {
            const fallback = nextList[0] ?? null;
            setSelectedPreviewId(fallback ? fallback.id : null);
            setScanSubName(fallback ? defaultMigrationSubName(fallback) : "");
          }
          if (!autoTriggered) {
            appActions.showToast(
              "未在常见位置找到已有软件配置，也可以点击「选择目录扫描」「选择配置文件」或切换到「粘贴配置文本」导入",
              "info"
            );
          }
        }
      } catch (err) {
        appActions.showToast(`扫描已有配置失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setScanningKind(null);
      }
    },
    []
  );

  const handlePickCustomPathScan = useCallback(
    async (pickMode: "directory" | "file") => {
      const targetLabel = pickMode === "directory" ? "目录" : "配置文件";
      if (!isTauriEnv()) {
        appActions.showToast(
          `当前为浏览器预览模式，请在桌面端猫猫云梯中使用本地${targetLabel}只读扫描，或先切换到「粘贴配置文本」体验导入`,
          "info"
        );
        return;
      }
      setScanningKind(pickMode === "directory" ? "custom_dir" : "custom_file");
      try {
        const picked =
          pickMode === "directory"
            ? await catcloudApi.pickMigrationDirectory(
                "选择已有代理软件配置目录（只读，不改动原软件）"
              )
            : await catcloudApi.pickMigrationFile(
                "选择代理配置文件（只读，不改动原文件）"
              );
        if (!picked) return;

        const rawList = await catcloudApi.scanMigrationPath(picked);
        const mapped = rawList.map((dto, idx) => mapMigrationDtoToPreview(dto, idx));

        const pickedNorm = normalizeMigrationSourcePath(picked);
        // Evict stale local_file entries under the re-scanned path/directory so deleted files disappear
        const retained = scannedItemsRef.current.filter((prevItem) => {
          if (prevItem.source_kind !== "local_file" || !pickedNorm) return true;
          const prevNorm = normalizeMigrationSourcePath(prevItem.source_path);
          if (!prevNorm) return true;
          return pickMode === "directory"
            ? !isNormalizedPathInDir(prevNorm, pickedNorm)
            : prevNorm !== pickedNorm;
        });

        const nextList = mergeScannedMigrationItems(retained, mapped, true);
        setScannedItems(nextList);

        if (mapped.length > 0) {
          const firstKey = getMigrationDedupeKey(mapped[0]);
          const matchedFirst =
            nextList.find((it) => getMigrationDedupeKey(it) === firstKey) ?? mapped[0];
          setSelectedPreviewId(matchedFirst.id);
          setScanSubName(defaultMigrationSubName(matchedFirst));

          const totalNodes = mapped.reduce((acc, i) => acc + i.nodes.length, 0);
          const totalRules = mapped.reduce(
            (acc, i) => acc + i.prepend_rules.length + i.append_rules.length,
            0
          );
          if (totalNodes > 0) {
            appActions.showToast(
              `从所选${targetLabel}找到 ${mapped.length} 份配置、共 ${totalNodes} 个可导入节点（只读，未改动原软件）`,
              "ok"
            );
          } else if (totalRules > 0) {
            appActions.showToast(
              `所选${targetLabel}仅包含 ${totalRules} 条分流规则、无代理节点，请查看下方说明或选择含节点的配置文件`,
              "info"
            );
          } else {
            appActions.showToast(
              `所选${targetLabel}未解析出可用代理节点，请换选其他配置文件`,
              "info"
            );
          }
        } else {
          const currentSelected = selectedPreviewIdRef.current;
          if (currentSelected && !nextList.some((it) => it.id === currentSelected)) {
            const fallback = nextList[0] ?? null;
            setSelectedPreviewId(fallback ? fallback.id : null);
            setScanSubName(fallback ? defaultMigrationSubName(fallback) : "");
          }
          appActions.showToast(
            pickMode === "directory"
              ? "所选目录中未找到可识别的明文代理配置，可尝试选择具体配置文件或切换到「粘贴配置文本」导入"
              : "所选文件中未识别到有效的代理配置，请确认是明文 YAML / JSON / 节点链接文件",
            "info"
          );
        }
      } catch (err) {
        appActions.showToast(`扫描所选${targetLabel}失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setScanningKind(null);
      }
    },
    []
  );

  const parsePasteContent = useCallback(
    async (rawText: string, preferredName = "") => {
      const trimmed = rawText.trim();
      if (!trimmed) {
        appActions.showToast("请先粘贴配置文件内容或节点链接", "warn");
        return;
      }
      try {
        let parsed: MigrationPreviewItem;
        if (isTauriEnv()) {
          const res = await catcloudApi.previewMigrationFromText(
            preferredName.trim() || "粘贴导入的节点",
            trimmed
          );
          parsed = {
            id: `mig-clip-${Date.now()}`,
            source_kind: "clipboard_text",
            client_label: res.name || "粘贴的配置文本",
            source_path: null,
            nodes: Array.isArray(res.nodes) ? res.nodes : [],
            prepend_rules: Array.isArray(res.prepend_rules) ? res.prepend_rules : [],
            append_rules: Array.isArray(res.append_rules) ? res.append_rules : [],
            warnings: Array.isArray(res.warnings) ? res.warnings : [],
          };
        } else {
          parsed = parsePastedConfigPreview(trimmed);
        }
        setPastePreview(parsed);
        setPasteSubName(
          (prev) => prev.trim() || preferredName.trim() || parsed.client_label || "粘贴导入的节点"
        );
        const parsedRuleCount = parsed.prepend_rules.length + parsed.append_rules.length;
        if (parsed.nodes.length > 0) {
          appActions.showToast(
            `解析成功：找到 ${parsed.nodes.length} 个可用节点`,
            "ok"
          );
        } else if (parsedRuleCount > 0) {
          appActions.showToast(
            `仅识别到 ${parsedRuleCount} 条分流规则、无可用节点，无法直接作为节点订阅导入`,
            "warn"
          );
        } else {
          appActions.showToast("没有识别出可用节点，请检查粘贴的内容是否完整", "warn");
        }
      } catch (err) {
        appActions.showToast(`解析失败：${formatErrorMessage(err)}`, "warn");
      }
    },
    []
  );

  useEffect(() => {
    if (!open) {
      openSessionRef.current = false;
      return;
    }
    if (!openSessionRef.current) {
      openSessionRef.current = true;
      if (initialTab === "paste") {
        setTab("paste");
        if (initialPasteText && initialPasteText.trim()) {
          const seed = initialPasteText.trim();
          setPasteText(seed);
          setPastePreview(null);
          setPasteSubName("");
          void parsePasteContent(seed);
        }
      } else {
        setTab("scan");
        void runScanClient("all", true);
      }
    }
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !importing) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    open,
    importing,
    onClose,
    runScanClient,
    initialTab,
    initialPasteText,
    parsePasteContent,
  ]);

  if (!open) return null;

  const activePreview =
    tab === "scan"
      ? scannedItems.find((item) => item.id === selectedPreviewId) ??
        scannedItems[0] ??
        null
      : pastePreview;
  const activeSubName = tab === "scan" ? scanSubName : pasteSubName;
  const setActiveSubName = tab === "scan" ? setScanSubName : setPasteSubName;
  const activeRuleCount = activePreview
    ? activePreview.prepend_rules.length + activePreview.append_rules.length
    : 0;
  const isRulesOnlyPreview = Boolean(
    activePreview && activePreview.nodes.length === 0 && activeRuleCount > 0
  );

  const handleParsePaste = async () => {
    if (importing) return;
    await parsePasteContent(pasteText, pasteSubName);
  };

  const handleConfirmImport = async () => {
    if (importing || !activePreview || activePreview.nodes.length === 0) return;
    const finalName =
      activeSubName.trim() || defaultMigrationSubName(activePreview);
    setImporting(true);
    try {
      const ok = await onImport(activePreview, finalName, includeRules);
      if (ok) {
        onClose();
      }
    } catch {
      /* onImport 已弹出错误提示，保留抽屉与当前输入状态供直接重试 */
    } finally {
      setImporting(false);
    }
  };

  const safeClose = () => {
    if (importing) return;
    onClose();
  };

  if (typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="从电脑已有梯子导入"
      onClick={safeClose}
    >
      <div
        className="cc-surface flex h-full w-full max-w-[620px] flex-col border-l border-[var(--line-strong)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-[var(--line)] px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <FolderOpen className="h-4 w-4 shrink-0 text-[var(--accent)]" />
              <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                从电脑已有梯子导入
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              自动查找 Clash Verge / FlClash / v2rayN 等其他代理客户端的已有配置，也支持直接粘贴配置或节点链接。
            </p>
          </div>
          <button
            type="button"
            disabled={importing}
            onClick={safeClose}
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            aria-label="关闭导入窗口"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Read-Only Safety Banner */}
        <div className="mx-5 mt-3 flex items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--green-soft)] px-3 py-2 text-xs text-[var(--green)]">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span className="min-w-0">
            只读安全复制：只会把节点复制一份进猫猫云梯，绝不改动你原来的软件和配置文件。
          </span>
        </div>

        {/* Mode Tabs */}
        <div className="mx-5 mt-3 flex flex-wrap items-center gap-2 border-b border-[var(--line)] pb-2.5">
          <button
            type="button"
            disabled={importing}
            onClick={() => setTab("scan")}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${
              tab === "scan"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Search className="h-3.5 w-3.5 shrink-0" />
            自动找电脑里的梯子
          </button>
          <button
            type="button"
            disabled={importing}
            onClick={() => setTab("paste")}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${
              tab === "paste"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <FileText className="h-3.5 w-3.5 shrink-0" />
            粘贴配置文本 / 节点链接
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {tab === "scan" ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-medium text-[var(--text-secondary)]">
                  常见代理客户端配置位置
                </span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void handlePickCustomPathScan("directory")}
                    title="手动挑选桌面、D 盘或任意配置文件夹进行只读扫描"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    {scanningKind === "custom_dir" ? "正在扫描..." : "选择目录扫描"}
                  </button>
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void handlePickCustomPathScan("file")}
                    title="直接选取单个 .yaml / .yml / .json / .txt 配置文件进行只读解析"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                  >
                    <FileCode2 className="h-3.5 w-3.5" />
                    {scanningKind === "custom_file" ? "正在解析..." : "选择配置文件"}
                  </button>
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void runScanClient("all", false)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)] bg-[var(--accent-soft)] px-2.5 py-1 text-xs font-medium text-[var(--accent)] hover:opacity-90 disabled:opacity-50"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${scanningKind === "all" ? "animate-spin" : ""}`}
                    />
                    {scanningKind === "all" ? "正在扫描..." : "重新扫描全部"}
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {KNOWN_CLIENT_SPECS.map((spec) => {
                  const foundList = scannedItems.filter(
                    (s) => s.source_kind === spec.kind
                  );
                  const found = foundList[0];
                  const totalNodes = foundList.reduce(
                    (acc, item) => acc + item.nodes.length,
                    0
                  );
                  const isSpecActive = foundList.some(
                    (item) => activePreview?.id === item.id
                  );
                  const isBusy =
                    scanningKind === spec.kind || scanningKind === "all";
                  return (
                    <div
                      key={spec.kind}
                      className={`rounded-xl border p-3 transition-colors ${
                        isSpecActive
                          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                          : "border-[var(--line)] bg-[var(--card)]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-semibold text-[var(--text)]">
                              {spec.label}
                            </span>
                            {found && (
                              <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                                {foundList.length > 1
                                  ? `${foundList.length} 份配置 · ${totalNodes} 节点`
                                  : `${found.nodes.length} 节点 · ${
                                      found.prepend_rules.length +
                                      found.append_rules.length
                                    } 规则`}
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                            {spec.readonlyPathHint}
                          </div>
                          <div className="mt-1 text-[11px] text-[var(--text-secondary)]">
                            {spec.desc}
                          </div>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          {found && (
                            <button
                              type="button"
                              disabled={importing}
                              onClick={() => {
                                setSelectedPreviewId(found.id);
                                setScanSubName(defaultMigrationSubName(found));
                              }}
                              className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                            >
                              查看
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={isBusy || importing}
                            onClick={() => void runScanClient(spec.kind, false)}
                            className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                          >
                            <Search className="h-3 w-3" />
                            {isBusy ? "扫描中" : "扫描"}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {scannedItems.length > 0 && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                    <span>已扫描到的配置（点击切换预览，悬停路径看完整位置）</span>
                    <span className="cc-mono">{scannedItems.length} 份</span>
                  </div>
                  <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
                    {scannedItems.map((item) => {
                      const selected = activePreview?.id === item.id;
                      const showSourceBadge =
                        Boolean(item.source_client_label) &&
                        item.source_client_label !== item.client_label;
                      const itemRuleCount =
                        item.prepend_rules.length + item.append_rules.length;
                      const itemBasename =
                        extractPathBasename(item.source_path) ?? item.source_path;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          disabled={importing}
                          onClick={() => {
                            setSelectedPreviewId(item.id);
                            setScanSubName(defaultMigrationSubName(item));
                          }}
                          className={`flex w-full items-center justify-between gap-2 rounded-xl border px-3 py-2 text-left transition-colors disabled:opacity-60 ${
                            selected
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                              : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="truncate text-xs font-semibold text-[var(--text)]">
                                {item.client_label}
                              </span>
                              {showSourceBadge && (
                                <span className="shrink-0 rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                                  {item.source_client_label}
                                </span>
                              )}
                            </div>
                            {item.source_path && (
                              <div
                                title={item.source_path}
                                className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]"
                              >
                                {itemBasename}
                              </div>
                            )}
                          </div>
                          {item.nodes.length > 0 ? (
                            <span className="shrink-0 rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                              {item.nodes.length} 节点
                            </span>
                          ) : itemRuleCount > 0 ? (
                            <span
                              title="该条目仅含分流规则，没有可导入的代理节点"
                              className="shrink-0 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--amber)]"
                            >
                              仅规则 · {itemRuleCount} 条
                            </span>
                          ) : (
                            <span className="shrink-0 rounded-full bg-[var(--bg-elevated)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--muted)]">
                              0 节点
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="cc-migration-paste"
                  className="text-xs font-medium text-[var(--text-secondary)]"
                >
                  支持粘贴其他代理客户端的配置文件内容、编码文本或单条/多条节点分享链接
                </label>
                <button
                  type="button"
                  disabled={importing}
                  onClick={() => setPasteText(DEMO_PASTE_SAMPLE)}
                  className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--accent)] hover:border-[var(--accent)] disabled:opacity-50"
                >
                  填入示例内容
                </button>
              </div>
              <textarea
                id="cc-migration-paste"
                value={pasteText}
                disabled={importing}
                onChange={(e) => setPasteText(e.target.value)}
                rows={8}
                placeholder="在这里粘贴配置内容，或者粘贴 vless:// / trojan:// / ss:// 等节点链接..."
                className="cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-60"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  disabled={importing}
                  onClick={() => {
                    setPasteText("");
                    setPastePreview(null);
                    setPasteSubName("");
                  }}
                  className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  清空
                </button>
                <button
                  type="button"
                  disabled={importing}
                  onClick={() => void handleParsePaste()}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                >
                  <Upload className="h-3.5 w-3.5" />
                  解析并预览节点
                </button>
              </div>
            </div>
          )}

          {/* Active Preview Panel */}
          {activePreview && (
            <div className="space-y-3 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    预览结果 · {activePreview.client_label}
                  </div>
                  {activePreview.source_path && (
                    <div
                      title={activePreview.source_path}
                      className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]"
                    >
                      {extractPathBasename(activePreview.source_path) ??
                        activePreview.source_path}
                    </div>
                  )}
                </div>
                <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                  {activePreview.nodes.length} 个节点
                </span>
              </div>

              {isRulesOnlyPreview && (
                <div className="flex items-start gap-2 rounded-lg border border-[var(--amber)]/40 bg-[var(--amber-soft)] px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div>
                    <div className="font-semibold">
                      该配置仅包含 {activeRuleCount} 条分流规则，未包含可导入的代理节点
                    </div>
                    <div className="mt-0.5 opacity-90">
                      此处迁移需至少包含 1 个可用代理节点，因此「确认导入」暂不可用。这通常是纯规则覆写或模板文件，请选择包含节点列表的配置文件，或前往「分流与连接」页面配置分流规则。
                    </div>
                  </div>
                </div>
              )}

              {activePreview.nodes.length === 0 && !isRulesOnlyPreview && (
                <div className="flex items-start gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
                  <span>
                    当前条目未解析到任何代理节点，因此无法执行导入。请改选包含有效节点的配置文件，或检查粘贴内容是否完整。
                  </span>
                </div>
              )}

              {activePreview.warnings.length > 0 && (
                <div className="space-y-1 rounded-lg bg-[var(--amber-soft)] px-2.5 py-2 text-[11px] text-[var(--amber)]">
                  {activePreview.warnings.map((w, idx) => (
                    <div key={idx} className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}

              {activePreview.nodes.length > 0 && (
                <div className="max-h-44 space-y-1.5 overflow-y-auto pr-1">
                  {activePreview.nodes.map((node) => (
                    <div
                      key={node.id}
                      className="flex items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-medium text-[var(--text)]">
                          {node.name}
                        </div>
                        <div className="cc-mono text-[10px] text-[var(--muted)]">
                          {node.protocol.toUpperCase()} · {node.server}:{node.port}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5 cc-mono text-[10px]">
                        <span
                          title={getRegionLabel(resolveNodeRegionCode(node))}
                          className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                        >
                          {resolveNodeRegionCode(node)}
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
                    </div>
                  ))}
                </div>
              )}

              {(activePreview.prepend_rules.length > 0 ||
                activePreview.append_rules.length > 0) && (
                <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[var(--text)]">
                      检测到分流规则（优先 {activePreview.prepend_rules.length} 条 / 兜底{" "}
                      {activePreview.append_rules.length} 条）
                    </span>
                    <label className="inline-flex cursor-pointer items-center gap-1.5 text-[var(--text-secondary)]">
                      <input
                        type="checkbox"
                        disabled={importing}
                        checked={includeRules}
                        onChange={(e) => setIncludeRules(e.target.checked)}
                        className="accent-[var(--accent)]"
                      />
                      同步导入规则
                    </label>
                  </div>
                  <div className="mt-1.5 space-y-0.5 cc-mono text-[10px] text-[var(--muted)]">
                    {[...activePreview.prepend_rules, ...activePreview.append_rules]
                      .slice(0, 4)
                      .map((r, idx) => (
                        <div key={idx} className="truncate">
                          {r}
                        </div>
                      ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 gap-2 pt-1">
                <label className="text-[11px] text-[var(--muted)]">
                  导入后的订阅名称
                  <input
                    type="text"
                    disabled={importing}
                    value={activeSubName}
                    onChange={(e) => setActiveSubName(e.target.value)}
                    placeholder={defaultMigrationSubName(activePreview)}
                    className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-60"
                  />
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between gap-2 border-t border-[var(--line)] px-5 py-3">
          <span className="text-[11px] text-[var(--muted)]">
            {importing
              ? "正在导入节点与规则，请稍候..."
              : isRulesOnlyPreview
                ? `当前条目仅含 ${activeRuleCount} 条规则、无代理节点，暂不可导入`
                : activePreview && activePreview.nodes.length === 0
                  ? "当前条目未包含可用代理节点，暂不可导入"
                  : "只复制到猫猫云梯本地，不会修改原软件"}
          </span>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              disabled={importing}
              onClick={safeClose}
              className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            >
              取消
            </button>
            <button
              type="button"
              disabled={importing || !activePreview || activePreview.nodes.length === 0}
              title={
                isRulesOnlyPreview
                  ? "当前配置仅含分流规则、无代理节点，无法导入"
                  : !activePreview || activePreview.nodes.length === 0
                    ? "请先选择包含至少 1 个可用节点的配置"
                    : undefined
              }
              onClick={() => void handleConfirmImport()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
            >
              {importing ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5" />
              )}
              {importing ? "正在导入..." : "确认导入"}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

/* ============================================================================
 * Slide-Over Drawer 2: 1 -> 2 -> 3 Live Capture Wizard
 * ============================================================================ */

const UNSUPPORTED_CAPTURE_NOTICE =
  "该软件暂不支持直接抓取，建议尝试其它支持的软件或前往官网查看是否提供标准订阅链接";

function isSelfCatCloudCandidate(cand: DesktopAppCandidate): boolean {
  const joined = `${cand.friendly_name} ${cand.window_title} ${cand.process_name}`.toLowerCase();
  return joined.includes("catcloud") || joined.includes("猫猫云梯");
}

function formatCaptureEventTime(tsMs: number): string {
  const d = new Date(tsMs);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

interface CaptureConfirmPayload {
  name: string;
  outcome: LiveCaptureOutcomeDto;
  selectedNodes: ProxyNode[];
  targetMode: "new" | "existing";
  targetSubId?: string;
  updateMode?: SubscriptionUpdateMode;
}

interface ProcessAttachDrawerProps {
  open: boolean;
  onClose: () => void;
  onConfirmCapture: (payload: CaptureConfirmPayload) => Promise<boolean>;
  onGoToSubUrl: () => void;
}

function ProcessAttachDrawer({
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

  // Step 1: Silently detect newly launched desktop apps every 1.5s (shares fetchCandidatesInFlightRef)
  useEffect(() => {
    if (!open || step !== 1) return;
    const timer = window.setInterval(() => {
      if (!openRef.current || fetchCandidatesInFlightRef.current) return;
      void fetchCandidates(false, false);
    }, 1500);
    return () => {
      window.clearInterval(timer);
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

/* ============================================================================
 * Main Page Export: NodesSubsPage
 * ============================================================================ */

export interface NodesSubsPageProps {
  embeddedSubsOnly?: boolean;
  onViewSubNodes?: (subId: string | null) => void;
}

export function NodesSubsPage({
  embeddedSubsOnly = false,
  onViewSubNodes,
}: NodesSubsPageProps = {}) {
  const storeSubs = useAppSelector((s) => s.subscriptions);
  const storeNodes = useAppSelector((s) => s.nodes);
  const storeProbes = useAppSelector((s) => s.probes);
  const storeGroups = useAppSelector((s) => s.groups);
  const initialized = useAppSelector((s) => s.initialized);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.config.preaccel);
  const uiLang = useAppSelector((s) => s.config.personalization.ui_language);
  const dict = useUiDict(normalizeUiLanguage(uiLang));
  const subsBg = useAppSelector((s) => s.bgTasks.subs);
  const bgCapture = useAppSelector((s) => s.bgTasks.capture);
  const nodesTabHint = useAppSelector((s) => s.nodesTabHint);
  const isSingleMode = runtime.route_mode === "single";

  // Directly subscribe to appStore so edits on other pages always stay in sync
  const subscriptions = storeSubs;
  const nodes = storeNodes;
  const groups = storeGroups;

  // Global background subscription & capture task state (survives tab & route switches)
  const refreshingAll = subsBg.refreshingAll;
  const refreshingIdSet = useMemo(
    () => new Set(subsBg.refreshingIds),
    [subsBg.refreshingIds]
  );
  const importingSub = subsBg.importing;

  // Top subscription controls & quick import form
  const [selectingSingleNodeId, setSelectingSingleNodeId] = useState<string | null>(null);
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

  useEffect(() => {
    if (!mergeModalOpen) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !mergingSubs) {
        setMergeModalOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mergeModalOpen, mergingSubs]);
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

  useEffect(() => {
    if (!pendingDeleteSub) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !deletingSub) {
        setPendingDeleteSub(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingDeleteSub, deletingSub]);

  // Multi-dimensional node filters, sorting & pagination (persisted across tab switches & reloads)
  const isStringPref = (raw: unknown): string | undefined =>
    typeof raw === "string" ? raw : undefined;
  const [keyword, setKeyword] = usePersistedState<string>(
    "nodes.keyword",
    "",
    isStringPref
  );
  const [filterSubId, setFilterSubId] = usePersistedState<string>(
    "nodes.filterSubId",
    "all",
    isStringPref
  );
  const [filterContinent, setFilterContinent] = usePersistedState<ContinentId>(
    "nodes.filterContinent",
    "all",
    oneOfPref([
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
    ] as const)
  );
  const [filterRegion, setFilterRegion] = usePersistedState<string>(
    "nodes.filterRegion",
    "all",
    isStringPref
  );
  const [filterMultiplier, setFilterMultiplier] = usePersistedState<MultiplierRange>(
    "nodes.filterMultiplier",
    "all",
    oneOfPref(["all", "le1", "1to2", "ge3"] as const)
  );
  const [filterProtocol, setFilterProtocol] = usePersistedState<string>(
    "nodes.filterProtocol",
    "all",
    isStringPref
  );
  const [filter443, setFilter443] = usePersistedState<Native443Filter>(
    "nodes.filter443",
    "all",
    oneOfPref(["all", "only_443", "non_443"] as const)
  );
  const [healthFilters, setHealthFilters] = usePersistedState<HealthFilters>(
    "nodes.healthFilters",
    {
      googleClean: false,
      keepalive60s: false,
      aiUnlocked: false,
    },
    (raw: unknown): HealthFilters | undefined => {
      if (!raw || typeof raw !== "object") return undefined;
      const obj = raw as Partial<HealthFilters>;
      if (
        typeof obj.googleClean === "boolean" &&
        typeof obj.keepalive60s === "boolean" &&
        typeof obj.aiUnlocked === "boolean"
      ) {
        return {
          googleClean: obj.googleClean,
          keepalive60s: obj.keepalive60s,
          aiUnlocked: obj.aiUnlocked,
        };
      }
      return undefined;
    }
  );
  const [sortBy, setSortBy] = usePersistedState<NodeSortBy>(
    "nodes.sortBy",
    "default",
    oneOfPref(["default", "latency", "up", "down"] as const)
  );
  const [showMoreFilters, setShowMoreFilters] = usePersistedState<boolean>(
    "nodes.showMoreFilters",
    false,
    isBoolPref
  );
  const [pageSize, setPageSize] = usePersistedState<number>(
    "nodes.pageSize",
    30,
    oneOfPref([30, 50, 100] as const)
  );
  const [currentPage, setCurrentPage] = useState<number>(1);

  // Cross-subscription batch selection & target multi-group
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(
    () => new Set()
  );
  const [targetGroupId, setTargetGroupId] = useState<string>(
    () => storeGroups[0]?.id ?? "grp-ai"
  );

  useEffect(() => {
    if (groups.length > 0 && !groups.some((g) => g.id === targetGroupId)) {
      setTargetGroupId(groups[0].id);
    }
  }, [groups, targetGroupId]);

  useEffect(() => {
    if (!initialized || filterSubId === "all") return;
    if (
      !subscriptions.some((s) => s.id === filterSubId) &&
      !nodes.some((n) => n.sub_id === filterSubId)
    ) {
      setFilterSubId("all");
    }
  }, [initialized, filterSubId, subscriptions, nodes, setFilterSubId]);

  // Prune stale selected node IDs whenever the backing node list shrinks
  useEffect(() => {
    if (embeddedSubsOnly) return;
    setSelectedNodeIds((prev) => {
      if (prev.size === 0) return prev;
      const validIds = new Set(nodes.map((n) => n.id));
      let changed = false;
      const next = new Set<string>();
      for (const id of prev) {
        if (validIds.has(id)) {
          next.add(id);
        } else {
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [nodes, embeddedSubsOnly]);

  // Reset pagination to page 1 when filters or page size change
  useEffect(() => {
    if (embeddedSubsOnly) return;
    setCurrentPage(1);
  }, [
    embeddedSubsOnly,
    keyword,
    filterSubId,
    filterContinent,
    filterRegion,
    filterMultiplier,
    filterProtocol,
    filter443,
    healthFilters,
    sortBy,
    pageSize,
  ]);

  // Derived lookup maps
  const subNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) map.set(s.id, s.name);
    return map;
  }, [subscriptions]);

  const subNodeCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  const nodeGroupMembership = useMemo(() => {
    if (embeddedSubsOnly) return new Map<string, MultiGroup[]>();
    const map = new Map<string, MultiGroup[]>();
    for (const g of groups) {
      for (const nid of g.member_node_ids) {
        const list = map.get(nid);
        if (list) list.push(g);
        else map.set(nid, [g]);
      }
    }
    return map;
  }, [groups, embeddedSubsOnly]);

  const nodesForRegionStats = useMemo(
    () =>
      embeddedSubsOnly
        ? []
        : filterSubId === "all"
          ? nodes
          : nodes.filter((n) => n.sub_id === filterSubId),
    [nodes, filterSubId, embeddedSubsOnly]
  );

  const continentRegionStats = useMemo(
    () => buildContinentRegionStats(nodesForRegionStats),
    [nodesForRegionStats]
  );

  // Clear stale continent/region filter if switching source leaves zero nodes in that bucket
  useEffect(() => {
    if (embeddedSubsOnly || nodesForRegionStats.length === 0) return;
    if (
      filterContinent !== "all" &&
      continentRegionStats.continentCounts[filterContinent] === 0
    ) {
      setFilterContinent("all");
      if (filterRegion !== "all") setFilterRegion("all");
      return;
    }
    if (
      filterRegion !== "all" &&
      !continentRegionStats.allRegions.some((r) => r.code === filterRegion)
    ) {
      setFilterRegion("all");
    }
  }, [
    embeddedSubsOnly,
    nodesForRegionStats.length,
    continentRegionStats,
    filterContinent,
    filterRegion,
  ]);

  const protocolStats = useMemo(() => {
    if (embeddedSubsOnly) return [] as Array<[string, number]>;
    const counts = new Map<string, number>();
    for (const n of nodes) {
      const proto = n.protocol.toLowerCase();
      counts.set(proto, (counts.get(proto) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [nodes, embeddedSubsOnly]);

  const native443Count = useMemo(
    () => (embeddedSubsOnly ? 0 : nodes.filter((n) => n.is_443_native).length),
    [nodes, embeddedSubsOnly]
  );

  const filteredNodes = useMemo(() => {
    if (embeddedSubsOnly) return [] as ProxyNode[];
    const kw = keyword.trim().toLowerCase();
    const matched = nodes.filter((node) => {
      if (filterSubId !== "all" && node.sub_id !== filterSubId) return false;
      if (!nodeMatchesContinentAndRegion(node, filterContinent, filterRegion)) {
        return false;
      }
      if (
        filterProtocol !== "all" &&
        node.protocol.toLowerCase() !== filterProtocol
      ) {
        return false;
      }
      if (filterMultiplier === "le1" && node.multiplier > 1.0) return false;
      if (
        filterMultiplier === "1to2" &&
        (node.multiplier < 1.0 || node.multiplier > 2.0)
      ) {
        return false;
      }
      if (filterMultiplier === "ge3" && node.multiplier < 3.0) return false;

      if (filter443 === "only_443" && !node.is_443_native) return false;
      if (filter443 === "non_443" && node.is_443_native) return false;

      const probe = storeProbes[node.id];
      if (healthFilters.googleClean && probe?.google_clean !== true) {
        return false;
      }
      if (healthFilters.keepalive60s && probe?.keepalive_60s_ok !== true) {
        return false;
      }
      if (healthFilters.aiUnlocked && !isAiUnlocked(probe)) {
        return false;
      }

      if (kw) {
        const subName = (subNameMap.get(node.sub_id) ?? "").toLowerCase();
        const regionCode = resolveNodeRegionCode(node);
        const regionLabel = getRegionLabel(regionCode).toLowerCase();
        const hit =
          node.name.toLowerCase().includes(kw) ||
          node.server.toLowerCase().includes(kw) ||
          node.protocol.toLowerCase().includes(kw) ||
          regionCode.toLowerCase().includes(kw) ||
          regionLabel.includes(kw) ||
          subName.includes(kw) ||
          node.tags.some((t) => t.toLowerCase().includes(kw));
        if (!hit) return false;
      }

      return true;
    });

    if (sortBy === "default") return matched;

    const healthHints = runtime.node_health_hints;
    return [...matched].sort((a, b) => {
      const pa = storeProbes[a.id];
      const pb = storeProbes[b.id];
      if (sortBy === "latency") {
        const ra = resolveNodeDisplayLatency(pa, healthHints?.[a.id]);
        const rb = resolveNodeDisplayLatency(pb, healthHints?.[b.id]);
        const aOk = ra.ok && ra.latencyMs !== null;
        const bOk = rb.ok && rb.latencyMs !== null;
        if (aOk !== bOk) return aOk ? -1 : 1;
        if (aOk && bOk) return (ra.latencyMs ?? 99999) - (rb.latencyMs ?? 99999);
        return a.name.localeCompare(b.name);
      }
      if (sortBy === "up") {
        const aHas = hasValidUpMbps(pa);
        const bHas = hasValidUpMbps(pb);
        if (aHas !== bHas) return aHas ? -1 : 1;
        if (aHas && bHas) return (pb!.up_mbps ?? -1) - (pa!.up_mbps ?? -1);
        return a.name.localeCompare(b.name);
      }
      const aHas = hasValidDownMbps(pa);
      const bHas = hasValidDownMbps(pb);
      if (aHas !== bHas) return aHas ? -1 : 1;
      if (aHas && bHas) return (pb!.down_mbps ?? -1) - (pa!.down_mbps ?? -1);
      return a.name.localeCompare(b.name);
    });
  }, [
    nodes,
    keyword,
    filterSubId,
    filterContinent,
    filterRegion,
    filterProtocol,
    filterMultiplier,
    filter443,
    healthFilters,
    sortBy,
    storeProbes,
    runtime.node_health_hints,
    subNameMap,
    embeddedSubsOnly,
  ]);

  const selectedCrossSubCount = useMemo(() => {
    if (embeddedSubsOnly || selectedNodeIds.size === 0) return 0;
    const subSet = new Set<string>();
    for (const n of nodes) {
      if (selectedNodeIds.has(n.id)) subSet.add(n.sub_id);
    }
    return subSet.size;
  }, [nodes, selectedNodeIds, embeddedSubsOnly]);

  const targetGroup = useMemo(
    () => (embeddedSubsOnly ? null : groups.find((g) => g.id === targetGroupId) ?? null),
    [groups, targetGroupId, embeddedSubsOnly]
  );

  const targetGroupMemberSet = useMemo(
    () => new Set(embeddedSubsOnly ? [] : (targetGroup?.member_node_ids ?? [])),
    [targetGroup, embeddedSubsOnly]
  );

  const advancedFilterCount =
    (filterMultiplier !== "all" ? 1 : 0) +
    (filterProtocol !== "all" ? 1 : 0) +
    (filter443 !== "all" ? 1 : 0) +
    (healthFilters.keepalive60s ? 1 : 0);

  const hasActiveFilters =
    keyword.trim().length > 0 ||
    filterSubId !== "all" ||
    filterContinent !== "all" ||
    filterRegion !== "all" ||
    healthFilters.googleClean ||
    healthFilters.aiUnlocked ||
    sortBy !== "default" ||
    advancedFilterCount > 0;

  const totalPages = Math.max(1, Math.ceil(filteredNodes.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStartIndex = (safePage - 1) * pageSize;
  const pagedNodes = useMemo(
    () =>
      embeddedSubsOnly
        ? []
        : filteredNodes.slice(pageStartIndex, pageStartIndex + pageSize),
    [embeddedSubsOnly, filteredNodes, pageStartIndex, pageSize]
  );

  const allFilteredSelected =
    !embeddedSubsOnly &&
    filteredNodes.length > 0 &&
    filteredNodes.every((n) => selectedNodeIds.has(n.id));

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
    const removedIds = new Set(
      nodes.filter((n) => n.sub_id === sub.id).map((n) => n.id)
    );
    try {
      await appActions.deleteSubscription(sub.id);
      if (removedIds.size > 0) {
        setSelectedNodeIds((prev) => {
          const next = new Set(prev);
          for (const id of removedIds) next.delete(id);
          return next;
        });
      }
      if (filterSubId === sub.id) setFilterSubId("all");
      if (renamingSubId === sub.id) {
        setRenamingSubId(null);
        setRenamingSubName("");
      }
      if (importSuccessBanner?.subId === sub.id) {
        setImportSuccessBanner(null);
      }
      setPendingDeleteSub(null);
      void appActions.refreshDanglingRulesAudit();
      appActions.showToast(`已移除订阅：${sub.name}（同时移除 ${removedIds.size} 个节点）`, "info");
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
        if (importedSubId) {
          setFilterSubId(importedSubId);
        }
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
    setFilterSubId(subId);

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
      if (filterSubId === mergeSourceSubId) {
        setFilterSubId(mergeTargetSubId);
      }
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
        setFilterSubId(targetSubId);
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
          if (importedSubId) {
            setFilterSubId(importedSubId);
          }
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
        if (finalSubId) {
          setFilterSubId(finalSubId);
        }
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
    setFilterSubId(subId);
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

  /* ---------- Node Selection, Batch Group Join/Remove & PreAccel Override ---------- */

  const toggleSelectNode = (nodeId: string) => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  const toggleSelectAllFiltered = () => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (allFilteredSelected) {
        for (const n of filteredNodes) next.delete(n.id);
      } else {
        for (const n of filteredNodes) next.add(n.id);
      }
      return next;
    });
  };

  const handleBatchAddToGroup = async () => {
    if (selectedNodeIds.size === 0) return;
    if (!targetGroup) {
      appActions.showToast("请先选择目标多选组", "warn");
      return;
    }

    const toAdd: string[] = [];
    for (const nid of selectedNodeIds) {
      if (!targetGroupMemberSet.has(nid)) toAdd.push(nid);
    }

    if (toAdd.length === 0) {
      appActions.showToast(
        `所选 ${selectedNodeIds.size} 个节点均已在「${targetGroup.name}」中`,
        "info"
      );
      return;
    }

    const updatedMemberIds = [...targetGroup.member_node_ids, ...toAdd];
    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        updatedMemberIds
      );
      appActions.syncGroups(
        groups.map((g) => (g.id === updated.id ? updated : g))
      );
      appActions.showToast(
        `已将 ${toAdd.length} 个节点加入「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`加入多选组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleBatchRemoveFromGroup = async () => {
    if (selectedNodeIds.size === 0) return;
    if (!targetGroup) {
      appActions.showToast("请先选择目标多选组", "warn");
      return;
    }

    let removeCount = 0;
    for (const nid of selectedNodeIds) {
      if (targetGroupMemberSet.has(nid)) removeCount += 1;
    }

    if (removeCount === 0) {
      appActions.showToast(
        `所选节点都不在「${targetGroup.name}」中`,
        "info"
      );
      return;
    }

    const updatedMemberIds = targetGroup.member_node_ids.filter(
      (id) => !selectedNodeIds.has(id)
    );
    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        updatedMemberIds
      );
      appActions.syncGroups(
        groups.map((g) => (g.id === updated.id ? updated : g))
      );
      appActions.showToast(
        `已将 ${removeCount} 个节点移出「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`移出多选组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSetPreAccelOverride = async (
    nodeIds: string[],
    overrideValue: boolean | null
  ) => {
    const overrideMode: PreAccelOverrideMode =
      overrideValue === null
        ? "inherit"
        : overrideValue
          ? "force_on"
          : "force_off";
    const idSet = new Set(nodeIds);
    const prevNodes = nodes;
    const optimistic = nodes.map((n) =>
      idSet.has(n.id) ? { ...n, preaccel_override: overrideValue } : n
    );
    appActions.syncNodes(optimistic);
    try {
      await catcloudApi.setNodesPreAccelOverride(nodeIds, overrideMode);
      const label =
        overrideValue === null
          ? "自动跟随全局"
          : overrideValue
            ? "强制开启中转加速"
            : "强制关闭中转加速";
      appActions.showToast(
        nodeIds.length > 1
          ? `已将 ${nodeIds.length} 个节点的中转加速设为「${label}」`
          : `已更新中转加速方式：${label}`,
        "ok"
      );
    } catch (err) {
      appActions.syncNodes(prevNodes);
      appActions.showToast(`设置中转加速失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSelectSingleNode = async (nodeId: string) => {
    if (selectingSingleNodeId) return;
    setSelectingSingleNodeId(nodeId);
    try {
      await appActions.selectSingleNode(nodeId);
    } finally {
      setSelectingSingleNodeId(null);
    }
  };

  const resetAllFilters = () => {
    setKeyword("");
    setFilterSubId("all");
    setFilterContinent("all");
    setFilterRegion("all");
    setFilterMultiplier("all");
    setFilterProtocol("all");
    setFilter443("all");
    setHealthFilters({
      googleClean: false,
      keepalive60s: false,
      aiUnlocked: false,
    });
    setSortBy("default");
  };

  return (
    <div className="space-y-3">
      {/* ====================================================================
       * 1. Compact Header, Route Mode Guide Bar & Refresh All Bar
       * ==================================================================== */}
      {!embeddedSubsOnly && (
      <section className="cc-card cc-glass space-y-2.5 rounded-2xl px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                节点与测速
              </h1>
              <span className="rounded-full bg-[var(--accent-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                {subscriptions.length} 个订阅 · {nodes.length} 个节点 · {native443Count} 个直连 443
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--green)]">
                <ShieldCheck className="h-3.5 w-3.5" />
                刷新失败时自动保留原有节点，不会清空
              </span>
            </div>
          </div>

          <button
            type="button"
            disabled={refreshingAll || subscriptions.length === 0}
            onClick={() => void refreshAllSubscriptions()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-[var(--accent)] ${refreshingAll ? "animate-spin" : ""}`}
            />
            全部刷新
          </button>
        </div>

        {/* Active Route Mode Status Guide Bar */}
        <div
          className={`flex flex-wrap items-center justify-between gap-2.5 rounded-xl border px-3 py-2 text-xs ${
            isSingleMode
              ? "border-[var(--green)]/40 bg-[var(--bg-elevated)]/85"
              : "border-[var(--accent)]/40 bg-[var(--bg-elevated)]/85"
          }`}
        >
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {isSingleMode ? (
              <>
                <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--green)]/35 bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--green)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                  当前：单节点模式
                </span>
                <span className="truncate text-[11px] text-[var(--text-secondary)]">
                  正在使用：
                  <strong className="font-semibold text-[var(--text)]">
                    {runtime.active_node_name || "未选择"}
                  </strong>
                </span>
              </>
            ) : (
              <>
                <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--accent)]/35 bg-[var(--accent-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
                  当前：智能多选组（{runtime.active_group_name || "未启用"}）
                </span>
                <span className="text-[11px] text-[var(--text-secondary)]">
                  点下方任意节点的「用它」，可立刻切为单节点固定使用
                </span>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => appActions.setNav("overview")}
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <ArrowLeft className="h-3 w-3 shrink-0" />
            <span>返回总览</span>
          </button>
        </div>
      </section>
      )}

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
       * 2. Beginner-Friendly 3-Card Quick Import Hub
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
       * 3. Adaptive Subscription Cards Grid
       * ==================================================================== */}
      <section aria-label="已导入订阅卡片" className="space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-xs font-semibold text-[var(--text)]">
              已导入订阅（{subscriptions.length}）
            </h2>
            <span className="inline-flex items-center gap-1 text-[11px] text-[var(--green)]">
              <ShieldCheck className="h-3.5 w-3.5" />
              刷新失败时自动保留原有节点
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={openShareImport}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              title={dict.share.importZipTooltip}
            >
              <Package className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{dict.common.importShareBundle} (.zip)</span>
            </button>

            <button
              type="button"
              onClick={() => openShareExport(undefined, dict.share.defaultPackName)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              title={dict.share.exportZipTooltip}
            >
              <Upload className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{dict.common.exportShareBundle} (.zip)</span>
            </button>

            <button
              type="button"
              onClick={() => openShareExport(undefined, undefined, "lan_send")}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--accent)]/45 bg-[var(--accent-soft)]/50 px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
              title={dict.sync.entryBtn}
            >
              <QrCode className="h-3.5 w-3.5" />
              <span>{dict.sync.entryBtn}</span>
            </button>

            <button
              type="button"
              disabled={subscriptions.length < 2}
              onClick={openMergeModal}
              title={
                subscriptions.length < 2
                  ? dict.nodes.mergeSubsNeedTwoTip
                  : dict.nodes.mergeSubsTooltip
              }
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            >
              <GitMerge className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>{dict.nodes.mergeSubsBtn}</span>
            </button>

            {embeddedSubsOnly && (
              <button
                type="button"
                disabled={refreshingAll || subscriptions.length === 0}
                onClick={() => void refreshAllSubscriptions()}
                title={dict.nodes.refreshAllBtn}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:opacity-50"
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 text-[var(--accent)] ${refreshingAll ? "animate-spin" : ""}`}
                />
                {dict.nodes.refreshAllBtn}
              </button>
            )}
          </div>
        </div>

        {subscriptions.length === 0 ? (
          <div className="cc-card cc-glass rounded-2xl px-4 py-6 text-center text-xs text-[var(--muted)]">
            还没有导入订阅来源，请先在上方任选一种方式添加节点
          </div>
        ) : (
        <div
          className={
            subscriptions.length >= 3
              ? "grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3"
              : "grid grid-cols-1 gap-3 md:grid-cols-2"
          }
        >
          {subscriptions.map((sub) => {
            const hasQuota = sub.traffic_total_bytes > 0;
            const usedBytes = Math.max(0, sub.traffic_used_bytes);
            const remainingBytes = hasQuota
              ? Math.max(0, sub.traffic_total_bytes - usedBytes)
              : 0;
            const usagePct = hasQuota
              ? Math.min(100, Math.round((usedBytes / sub.traffic_total_bytes) * 100))
              : 0;
            const barColor =
              usagePct >= 90
                ? "var(--red)"
                : usagePct >= 75
                  ? "var(--amber)"
                  : "var(--accent)";
            const expire = formatExpireInfo(sub.expires_at);
            const nodeCount = subNodeCountMap.get(sub.id) ?? 0;
            const isSelectedFilter = !embeddedSubsOnly && filterSubId === sub.id;
            const isRefreshing = refreshingIdSet.has(sub.id) || refreshingAll;
            const maskedSource = maskSubscriptionSource(getSubSource(sub));
            const isRenamingThis = renamingSubId === sub.id;

            return (
              <article
                key={sub.id}
                className={`cc-card cc-glass flex min-w-0 flex-col justify-between rounded-2xl p-3.5 ${
                  isSelectedFilter ? "border-[var(--accent)]" : ""
                }`}
              >
                <div>
                  {/* Card Top Header */}
                  <div className="flex items-start justify-between gap-2">
                    {isRenamingThis ? (
                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        <input
                          type="text"
                          autoFocus
                          disabled={renamingBusy}
                          value={renamingSubName}
                          onChange={(e) => setRenamingSubName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              void handleSubmitRenameSub(sub);
                            } else if (e.key === "Escape") {
                              e.preventDefault();
                              handleCancelRenameSub();
                            }
                          }}
                          aria-label={dict.nodes.renameSubTitle}
                          className="min-w-0 flex-1 rounded-lg border border-[var(--accent)] bg-[var(--card)] px-2 py-1 text-xs font-semibold text-[var(--text)] outline-none"
                        />
                        <button
                          type="button"
                          disabled={renamingBusy}
                          onClick={() => void handleSubmitRenameSub(sub)}
                          title={dict.common.confirm}
                          aria-label="确认修改分组名"
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                        >
                          <Check className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={renamingBusy}
                          onClick={handleCancelRenameSub}
                          title={dict.common.cancel}
                          aria-label="取消修改分组名"
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          if (onViewSubNodes) {
                            onViewSubNodes(sub.id);
                          } else {
                            setFilterSubId(isSelectedFilter ? "all" : sub.id);
                          }
                        }}
                        className="min-w-0 text-left"
                        title={onViewSubNodes ? "查看这个订阅下的节点" : "点击只看这个订阅的节点"}
                      >
                        <div className="flex items-center gap-1.5">
                          <span className="truncate text-sm font-semibold text-[var(--text)]">
                            {sub.name}
                          </span>
                          <span className="shrink-0 rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            {SUB_KIND_LABELS[sub.kind]}
                          </span>
                        </div>
                        <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                          {maskedSource}
                        </div>
                      </button>
                    )}

                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        disabled={isRefreshing}
                        onClick={() => void refreshSingleSubscription(sub, false)}
                        className="inline-flex h-7 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                        title="刷新节点列表（失败自动保留原有节点）"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${isRefreshing ? "animate-spin" : ""}`}
                        />
                        刷新
                      </button>
                      <button
                        type="button"
                        disabled={renamingBusy}
                        onClick={() => handleStartRenameSub(sub)}
                        className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                        title={dict.nodes.renameSubTitle}
                        aria-label={`改名：${sub.name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          openShareExport(
                            nodes.filter((n) => n.sub_id === sub.id).map((n) => n.id),
                            `${sub.name} 分享包`
                          )
                        }
                        className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        title="导出该组节点为 .zip 分享包"
                        aria-label={`导出分组：${sub.name}`}
                      >
                        <Upload className="h-3.5 w-3.5" />
                      </button>
                      {!inTauri && (
                        <button
                          type="button"
                          disabled={isRefreshing}
                          onClick={() => void refreshSingleSubscription(sub, true)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--amber)] hover:text-[var(--amber)] disabled:opacity-50"
                          title="演示刷新失败保护效果"
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                        </button>
                      )}
                      {(inTauri || subscriptions.length > 1) && (
                        <button
                          type="button"
                          onClick={() => setPendingDeleteSub(sub)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
                          title="删除此订阅"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Traffic Progress Bar */}
                  <div className="mt-3">
                    {hasQuota ? (
                      <>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-[var(--muted)]">
                            已用{" "}
                            <span className="cc-mono text-[var(--text)]">
                              {formatQuotaBytes(usedBytes)}
                            </span>{" "}
                            / {formatQuotaBytes(sub.traffic_total_bytes)}
                          </span>
                          <span className="cc-mono font-medium text-[var(--text-secondary)]">
                            余 {formatQuotaBytes(remainingBytes)} ({100 - usagePct}%)
                          </span>
                        </div>
                        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-elevated)]">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${usagePct}%`,
                              backgroundColor: barColor,
                            }}
                          />
                        </div>
                      </>
                    ) : (
                      <div className="rounded-lg bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] text-[var(--muted)]">
                        暂未提供流量统计 · 当前共{" "}
                        <span className="cc-mono text-[var(--text)]">
                          {nodeCount}
                        </span>{" "}
                        个节点
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Bottom Meta & Error Protection Status */}
                <div className="mt-3 space-y-1.5 border-t border-[var(--line)] pt-2.5 text-[11px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">到期时间</span>
                    <span
                      className="cc-mono"
                      style={{
                        color:
                          expire.tone === "danger"
                            ? "var(--red)"
                            : expire.tone === "warn"
                              ? "var(--amber)"
                              : "var(--text-secondary)",
                      }}
                    >
                      {expire.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">
                      最近刷新 · {nodeCount} 节点
                    </span>
                    <span className="cc-mono text-[var(--text-secondary)]">
                      {formatTimeShort(sub.last_ok_at)}
                    </span>
                  </div>

                  {sub.last_error && (
                    <div className="flex items-start gap-1.5 rounded-lg bg-[var(--amber-soft)] px-2 py-1.5 text-[10px] leading-snug text-[var(--amber)]">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>{formatErrorMessage(sub.last_error)}</span>
                    </div>
                  )}

                  {onViewSubNodes && (
                    <div className="flex items-center justify-end pt-1">
                      <button
                        type="button"
                        onClick={() => onViewSubNodes(sub.id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                      >
                        <span>查看节点（{nodeCount}）</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    </div>
                  )}
                </div>
              </article>
            );
          })}
        </div>
        )}
      </section>

      {!embeddedSubsOnly && (
      <>

      {/* ====================================================================
       * 4. Compact Node Filter Bar (Primary: Search + Source + Region; More Filters Collapsible)
       * ==================================================================== */}
      <section className="cc-card cc-glass space-y-2.5 rounded-2xl p-3.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-xs font-semibold text-[var(--text)]">
              筛选节点
            </h2>
            <span className="cc-mono text-[11px] text-[var(--muted)]">
              显示 {filteredNodes.length} / {nodes.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-56">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder="搜节点名称、地区、协议或地址..."
                className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </div>

            <button
              type="button"
              onClick={() =>
                setHealthFilters((prev) => ({ ...prev, googleClean: !prev.googleClean }))
              }
              className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                healthFilters.googleClean
                  ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              {healthFilters.googleClean && <Check className="h-3 w-3" />}
              <span>仅看谷歌正常</span>
            </button>

            <button
              type="button"
              onClick={() =>
                setHealthFilters((prev) => ({ ...prev, aiUnlocked: !prev.aiUnlocked }))
              }
              className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                healthFilters.aiUnlocked
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              {healthFilters.aiUnlocked && <Check className="h-3 w-3" />}
              <span>仅看 AI 可用</span>
            </button>

            <div className="inline-flex items-center gap-1.5">
              <ArrowUpDown className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <AppSelect
                aria-label="节点排序方式"
                size="sm"
                value={sortBy}
                onChange={(v) => setSortBy(v as NodeSortBy)}
                options={[
                  { value: "default", label: "排序：默认" },
                  { value: "latency", label: "排序：延迟最低" },
                  { value: "up", label: "排序：上传最快" },
                  { value: "down", label: "排序：下载最快" },
                ]}
                className="min-w-[132px]"
              />
            </div>

            <button
              type="button"
              onClick={() => setShowMoreFilters((v) => !v)}
              className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                showMoreFilters || advancedFilterCount > 0
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              <span>更多筛选</span>
              {advancedFilterCount > 0 && (
                <span className="cc-mono rounded-full bg-[var(--accent)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--accent-ink)]">
                  {advancedFilterCount}
                </span>
              )}
              {showMoreFilters ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5" />
              )}
            </button>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetAllFilters}
                className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
              >
                <RotateCcw className="h-3 w-3" />
                重置筛选
              </button>
            )}
          </div>
        </div>

        {/* Filter Rows */}
        <div className="space-y-2 text-[11px]">
          {/* Row A: Subscription Source */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[var(--muted)]">来源</span>
            <button
              type="button"
              onClick={() => setFilterSubId("all")}
              className={`rounded-lg border px-2 py-0.5 transition-colors ${
                filterSubId === "all"
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
              }`}
            >
              全部
            </button>
            {subscriptions.map((sub) => (
              <button
                key={sub.id}
                type="button"
                onClick={() => setFilterSubId(sub.id)}
                className={`rounded-lg border px-2 py-0.5 transition-colors ${
                  filterSubId === sub.id
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                {sub.name} ({subNodeCountMap.get(sub.id) ?? 0})
              </button>
            ))}
          </div>

          {/* Row A2: Two-Tier Continent -> Country/Region Filter */}
          <ContinentRegionFilter
            variant="pills"
            stats={continentRegionStats}
            continent={filterContinent}
            region={filterRegion}
            onContinentChange={(c) => {
              setFilterContinent(c);
              setCurrentPage(1);
            }}
            onRegionChange={(r) => {
              setFilterRegion(r);
              setCurrentPage(1);
            }}
          />

          {/* Collapsible Row B: Multiplier Range, Protocol, Direct 443 & Health Checks */}
          {showMoreFilters && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-[var(--line)]/70 pt-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[var(--muted)]">流量倍率</span>
                {(
                  [
                    { id: "all", label: "全部" },
                    { id: "le1", label: "<= 1x" },
                    { id: "1to2", label: "1x..2x" },
                    { id: "ge3", label: "3x+" },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setFilterMultiplier(opt.id)}
                    className={`rounded-lg border px-2 py-0.5 cc-mono transition-colors ${
                      filterMultiplier === opt.id
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[var(--muted)]">协议</span>
                <button
                  type="button"
                  onClick={() => setFilterProtocol("all")}
                  className={`rounded-lg border px-2 py-0.5 transition-colors ${
                    filterProtocol === "all"
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  全部
                </button>
                {protocolStats.map(([proto, count]) => (
                  <button
                    key={proto}
                    type="button"
                    onClick={() => setFilterProtocol(proto)}
                    className={`rounded-lg border px-2 py-0.5 cc-mono uppercase transition-colors ${
                      filterProtocol === proto
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    {proto} ({count})
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[var(--muted)]">端口类型</span>
                {(
                  [
                    { id: "all", label: "全部" },
                    { id: "only_443", label: "仅直连 443" },
                    { id: "non_443", label: "其他端口" },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setFilter443(opt.id)}
                    className={`rounded-lg border px-2 py-0.5 transition-colors ${
                      filter443 === opt.id
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[var(--muted)]">长连接</span>
                <button
                  type="button"
                  onClick={() =>
                    setHealthFilters((prev) => ({
                      ...prev,
                      keepalive60s: !prev.keepalive60s,
                    }))
                  }
                  className={`inline-flex items-center gap-1 rounded-lg border px-2 py-0.5 transition-colors ${
                    healthFilters.keepalive60s
                      ? "border-[var(--green)] bg-[var(--green-soft)] font-medium text-[var(--green)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {healthFilters.keepalive60s && <Check className="h-3 w-3" />}
                  60 秒长连接稳定
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ====================================================================
       * 5. Batch Group Add/Remove & Relay Override Bar
       * ==================================================================== */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3">
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <button
            type="button"
            onClick={toggleSelectAllFiltered}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
          >
            <Check className="h-3 w-3 text-[var(--accent)]" />
            {allFilteredSelected
              ? "取消全选筛选结果"
              : `全选当前筛选 (${filteredNodes.length})`}
          </button>

          {selectedNodeIds.size > 0 ? (
            <>
              <span className="rounded-full bg-[var(--accent-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                已勾选 {selectedNodeIds.size} 个节点
                {selectedCrossSubCount > 1
                  ? `（来自 ${selectedCrossSubCount} 个订阅）`
                  : ""}
              </span>
              <button
                type="button"
                onClick={() => setSelectedNodeIds(new Set())}
                className="text-[11px] text-[var(--muted)] hover:text-[var(--text)]"
              >
                清空勾选
              </button>
            </>
          ) : (
            <span className="text-[11px] text-[var(--muted)]">
              勾选下方节点，可批量加入或移出指定多选组
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs">
            <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            <AppSelect
              aria-label="目标智能多选组"
              size="sm"
              value={targetGroupId}
              onChange={setTargetGroupId}
              options={groups.map((g) => ({
                value: g.id,
                label: `${g.name}（${g.member_node_ids.length} 节点）`,
              }))}
              placeholder="暂无多选组"
              disabled={groups.length === 0}
              className="min-w-[160px]"
            />
          </div>

          <button
            type="button"
            disabled={selectedNodeIds.size === 0 || groups.length === 0}
            onClick={() => void handleBatchAddToGroup()}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-3 py-1.5 text-xs font-semibold transition-colors ${
              selectedNodeIds.size === 0 || groups.length === 0
                ? "cursor-not-allowed border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                : "bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90"
            }`}
          >
            <Plus className="h-3.5 w-3.5 shrink-0" />
            加入多选组
          </button>

          <button
            type="button"
            disabled={selectedNodeIds.size === 0 || groups.length === 0}
            onClick={() => void handleBatchRemoveFromGroup()}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
              selectedNodeIds.size === 0 || groups.length === 0
                ? "cursor-not-allowed border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)]"
                : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--red)] hover:text-[var(--red)]"
            }`}
          >
            <Minus className="h-3.5 w-3.5 shrink-0" />
            移出多选组
          </button>

          {selectedNodeIds.size > 0 && (
            <div className="inline-flex items-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), true)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--accent)]"
                title="让所选节点强制走中转加速"
              >
                中转开
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), false)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--red)]"
                title="让所选节点强制直连不走中转"
              >
                中转关
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), null)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                title="恢复为自动跟随全局设置"
              >
                自动
              </button>
            </div>
          )}
        </div>
      </section>

      {/* ====================================================================
       * 6. Node List Table (Paginated + Fixed-Width Right Controls)
       * ==================================================================== */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        {filteredNodes.length > 0 && (
          <PaginationBar
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={filteredNodes.length}
            pageSize={pageSize}
            pageSizeOptions={[30, 50, 100]}
            onPageChange={setCurrentPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setCurrentPage(1);
            }}
            className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-4 py-2"
          />
        )}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] table-fixed border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)] text-[11px] font-medium text-[var(--muted)]">
                <th className="w-8 px-2 py-2.5 text-center">
                  <input
                    type="checkbox"
                    checked={allFilteredSelected}
                    onChange={toggleSelectAllFiltered}
                    aria-label="全选当前筛选节点"
                    className="accent-[var(--accent)]"
                  />
                </th>
                <th className="w-[260px] min-w-[240px] whitespace-nowrap px-2 py-2.5">
                  节点名称 / 来源 / 分组
                </th>
                <th className="w-[122px] whitespace-nowrap px-1.5 py-2.5">
                  地区 · 倍率 · 协议
                </th>
                <th className="w-[194px] whitespace-nowrap px-1.5 py-2.5">
                  延迟 · 上下行 · 解锁
                </th>
                <th className="w-[134px] whitespace-nowrap px-1.5 py-2.5">
                  <div className="inline-flex items-center gap-1 whitespace-nowrap">
                    <Zap className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    国内提速
                  </div>
                </th>
                <th className="w-[138px] whitespace-nowrap px-1.5 py-2.5 text-right">
                  使用 / 分组
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]/70">
              {pagedNodes.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-6 py-10 text-center text-xs text-[var(--muted)]"
                  >
                    <Globe className="mx-auto mb-2 h-6 w-6 opacity-50" />
                    暂无符合条件的节点，可以在上方导入订阅链接或放宽筛选条件。
                  </td>
                </tr>
              ) : (
                pagedNodes.map((node) => {
                  const selected = selectedNodeIds.has(node.id);
                  const probe = storeProbes[node.id];
                  const aiInfo = getNodeAiInfo(probe);
                  const subName = subNameMap.get(node.sub_id) ?? node.sub_id;
                  const memberGroups = nodeGroupMembership.get(node.id) ?? [];
                  const regionCode = resolveNodeRegionCode(node);
                  const regionLabel = getRegionLabel(regionCode);
                  const isSingleActive =
                    isSingleMode && runtime.active_node_id === node.id;
                  const isSwitchingSingle = selectingSingleNodeId === node.id;

                  const effectiveGlobalPreAccel =
                    globalPreAccel.enabled &&
                    !(globalPreAccel.skip_443_native && node.is_443_native);

                  return (
                    <tr
                      key={node.id}
                      className={`transition-colors ${
                        isSingleActive
                          ? "bg-[var(--green-soft)]/35"
                          : selected
                            ? "bg-[var(--accent-soft)]/60"
                            : "hover:bg-[var(--card-hover)]"
                      }`}
                    >
                      {/* Checkbox */}
                      <td className="w-8 px-2 py-2.5 text-center align-middle">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => toggleSelectNode(node.id)}
                          aria-label={`选择节点 ${node.name}`}
                          className="accent-[var(--accent)]"
                        />
                      </td>

                      {/* Node Name, Source Sub & Group Membership */}
                      <td className="px-2 py-2.5 align-middle">
                        <div className="flex min-w-0 items-center gap-1.5">
                          <Server className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                          <span
                            title={node.name}
                            className="block min-w-0 flex-1 truncate font-semibold text-[var(--text)]"
                          >
                            {node.name}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px]">
                          <span
                            title={subName}
                            className="max-w-[110px] truncate rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                          >
                            {subName}
                          </span>
                          <span
                            title={`${node.server}:${node.port}`}
                            className="max-w-[100px] truncate cc-mono text-[var(--muted)]"
                          >
                            {node.server}:{node.port}
                          </span>
                          {memberGroups.map((g) => (
                            <span
                              key={g.id}
                              title={g.name}
                              className="max-w-[96px] truncate rounded-full bg-[var(--sky-soft)] px-1.5 py-0.5 font-medium text-[var(--sky)]"
                            >
                              {g.name}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Region, Multiplier, Protocol & Direct 443 */}
                      <td className="w-[122px] px-1.5 py-2.5 align-middle">
                        <div className="flex flex-col gap-1 cc-mono text-[10px]">
                          <div className="flex items-center gap-1">
                            <span
                              title={regionLabel}
                              className="shrink-0 rounded border border-[var(--line)] bg-[var(--bg-elevated)] px-1 py-0.5 font-semibold text-[var(--text)]"
                            >
                              {regionCode}
                            </span>
                            <span
                              className={`shrink-0 rounded px-1 py-0.5 font-medium ${
                                node.multiplier >= 3
                                  ? "bg-[var(--coral-soft)] text-[var(--coral)]"
                                  : node.multiplier <= 1
                                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                                    : "bg-[var(--amber-soft)] text-[var(--amber)]"
                              }`}
                            >
                              {node.multiplier}x
                            </span>
                            <span className="truncate rounded bg-[var(--bg-elevated)] px-1 py-0.5 uppercase text-[var(--text-secondary)]">
                              {node.protocol}
                            </span>
                          </div>
                          <div>
                            {node.is_443_native ? (
                              <span className="inline-block whitespace-nowrap rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                                直连 443
                              </span>
                            ) : (
                              <span className="inline-block rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                                :{node.port}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Health Snapshot Badges: Latency, Up/Down Speed, Google Clean/CN & AI Unlocks */}
                      <td className="w-[194px] px-1.5 py-2.5 align-middle">
                        {(() => {
                          const healthHint = runtime.node_health_hints?.[node.id];
                          const resolvedLat = resolveNodeDisplayLatency(probe, healthHint);
                          const tipKey = getLatencyTooltipKey(resolvedLat);
                          const latBaseTip =
                            tipKey === "probeHot"
                              ? dict.latency.probeHotTooltip
                              : tipKey === "healthCold"
                                ? dict.latency.healthColdTooltip
                                : tipKey === "failed"
                                  ? dict.latency.failedTooltip
                                  : dict.latency.untestedTooltip;
                          const tipTags: string[] = [];
                          if (resolvedLat.isProbation) tipTags.push(dict.latency.probationBadge);
                          if (resolvedLat.isDegraded) tipTags.push(dict.latency.degradedBadge);
                          if (healthHint?.status === "cooldown") {
                            tipTags.push(
                              healthHint.cooldown_remaining_sec > 0
                                ? formatI18nTemplate(dict.latency.cooldownSec, {
                                    sec: Math.ceil(healthHint.cooldown_remaining_sec),
                                  })
                                : dict.latency.cooldownActive
                            );
                          }
                          if (healthHint?.reason?.trim()) {
                            tipTags.push(`${dict.latency.reasonPrefix}${healthHint.reason.trim()}`);
                          }
                          const latTooltip =
                            tipTags.length > 0 ? `${latBaseTip} · ${tipTags.join(" · ")}` : latBaseTip;
                          const isCooldown =
                            healthHint?.status === "cooldown" && resolvedLat.state === "failed";
                          const latDotColor = isCooldown
                            ? "var(--amber)"
                            : resolvedLat.state === "failed"
                              ? "var(--red)"
                              : resolvedLat.latencyMs !== null
                                ? resolvedLat.latencyMs <= 140
                                  ? "var(--green)"
                                  : resolvedLat.latencyMs <= 300
                                    ? "var(--amber)"
                                    : "var(--red)"
                                : "var(--muted)";
                          const hasUp = hasValidUpMbps(probe);
                          const hasDown = hasValidDownMbps(probe);
                          return (
                        <div className="flex flex-col gap-1 text-[10px]">
                          <div className="flex flex-wrap items-center gap-1.5 cc-mono">
                            <span
                              title={latTooltip}
                              className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-1.5 py-0.5 font-semibold ${
                                isCooldown
                                  ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                                  : resolvedLat.state === "failed"
                                    ? "bg-[var(--red-soft)] text-[var(--red)]"
                                    : resolvedLat.latencyMs !== null
                                      ? resolvedLat.latencyMs <= 140
                                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                                        : resolvedLat.latencyMs <= 300
                                          ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                                          : "bg-[var(--red-soft)] text-[var(--red)]"
                                      : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                              }`}
                            >
                              <span
                                className="h-1.5 w-1.5 shrink-0 rounded-full"
                                style={{ backgroundColor: latDotColor }}
                                aria-hidden="true"
                              />
                              <span>
                                {resolvedLat.latencyMs !== null
                                  ? `${Math.round(resolvedLat.latencyMs)} ms`
                                  : isCooldown
                                    ? healthHint && healthHint.cooldown_remaining_sec > 0
                                      ? formatI18nTemplate(dict.latency.cooldownSec, {
                                          sec: Math.ceil(healthHint.cooldown_remaining_sec),
                                        })
                                      : dict.latency.cooldownActive
                                    : resolvedLat.state === "failed"
                                      ? dict.latency.timeoutShort
                                      : dict.latency.untestedShort}
                              </span>
                            </span>
                            {(hasUp || hasDown) && (
                              <div
                                className="flex flex-col leading-tight text-[11px]"
                                title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
                              >
                                {hasUp && (
                                  <span className="whitespace-nowrap font-medium text-[var(--coral)]">
                                    ↑{probe!.up_mbps!.toFixed(1)} Mbps
                                  </span>
                                )}
                                {hasDown && (
                                  <span className="whitespace-nowrap font-medium text-[var(--sky)]">
                                    ↓
                                    {probe!.down_mbps! >= 100
                                      ? Math.round(probe!.down_mbps!)
                                      : probe!.down_mbps!.toFixed(1)}{" "}
                                    Mbps
                                  </span>
                                )}
                              </div>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-1">
                            <span
                              title={formatGoogleRegionTooltip(probe)}
                              className={`whitespace-nowrap rounded-md px-1.5 py-0.5 font-medium ${
                                probe?.google_clean === true
                                  ? "bg-[var(--green-soft)] text-[var(--green)]"
                                  : probe?.google_clean === false
                                    ? "bg-[var(--red-soft)] text-[var(--red)]"
                                    : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                              }`}
                            >
                              {probe?.google_clean === true
                                ? "谷歌正常"
                                : probe?.google_clean === false
                                  ? "谷歌送中"
                                  : "未测地区"}
                            </span>

                            {probe?.google_risk_mismatch && (
                              <span
                                className="whitespace-nowrap rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 font-medium text-[var(--amber)]"
                                title={formatGoogleRegionTooltip(probe)}
                              >
                                地区有偏差
                              </span>
                            )}

                            {aiInfo.badges.length > 0 ? (
                              <span className="inline-flex flex-wrap items-center gap-1">
                                {aiInfo.badges.map((badge) => {
                                  const isLegacy = badge.windsurfState === "legacy_retest";
                                  const toneCls = isLegacy
                                    ? getAiBadgeToneClass("muted", "legacy")
                                    : badge.tone === "green"
                                      ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                                      : getAiBadgeToneClass(badge.tone, "soft");
                                  return (
                                    <span
                                      key={badge.id}
                                      title={badge.tooltip}
                                      className={`whitespace-nowrap rounded-md px-1.5 py-0.5 font-medium ${toneCls}`}
                                    >
                                      {badge.shortLabel}
                                    </span>
                                  );
                                })}
                              </span>
                            ) : aiInfo.unlockedLabels.length > 0 ? (
                              <span
                                title={aiInfo.detail}
                                className="inline-flex flex-wrap items-center gap-1"
                              >
                                {aiInfo.unlockedLabels.map((lbl) => (
                                  <span
                                    key={lbl}
                                    className="whitespace-nowrap rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 font-medium text-[var(--accent)]"
                                  >
                                    {lbl}
                                  </span>
                                ))}
                              </span>
                            ) : (
                              <span
                                title={aiInfo.detail}
                                className="whitespace-nowrap rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]"
                              >
                                {aiInfo.total > 0 ? "AI 受限" : "AI 未测"}
                              </span>
                            )}

                            {probe?.keepalive_60s_ok !== null &&
                              probe?.keepalive_60s_ok !== undefined && (
                                <span
                                  className={`whitespace-nowrap rounded-md px-1.5 py-0.5 font-medium ${
                                    probe.keepalive_60s_ok
                                      ? "bg-[var(--green-soft)] text-[var(--green)]"
                                      : "bg-[var(--red-soft)] text-[var(--red)]"
                                  }`}
                                >
                                  {probe.keepalive_60s_ok ? "长连接稳" : "易断连"}
                                </span>
                              )}
                          </div>
                        </div>
                          );
                        })()}
                      </td>

                      {/* Single-Node Relay 3-State Override */}
                      <td className="w-[134px] whitespace-nowrap px-1.5 py-2.5 align-middle">
                        <div className="flex flex-col gap-1">
                          <div className="inline-flex w-fit shrink-0 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[10px]">
                            {(
                              [
                                { value: null, label: "自动" },
                                { value: true, label: "强制开" },
                                { value: false, label: "强制关" },
                              ] as const
                            ).map((opt) => {
                              const active = node.preaccel_override === opt.value;
                              const activeClass =
                                opt.value === true
                                  ? "bg-[var(--accent)] text-[var(--accent-ink)] font-semibold"
                                  : opt.value === false
                                    ? "bg-[var(--red-soft)] text-[var(--red)] font-semibold"
                                    : "bg-[var(--card)] text-[var(--text)] font-semibold";
                              return (
                                <button
                                  key={String(opt.value)}
                                  type="button"
                                  onClick={() =>
                                    void handleSetPreAccelOverride([node.id], opt.value)
                                  }
                                  className={`shrink-0 whitespace-nowrap rounded-md px-1 py-0.5 transition-colors ${
                                    active
                                      ? activeClass
                                      : "text-[var(--muted)] hover:text-[var(--text)]"
                                  }`}
                                >
                                  {opt.label}
                                </button>
                              );
                            })}
                          </div>
                          {node.preaccel_override === null && (
                            <span className="whitespace-nowrap text-[10px] text-[var(--muted)]">
                              当前：
                              {effectiveGlobalPreAccel
                                ? "自动走中转"
                                : node.is_443_native &&
                                    globalPreAccel.skip_443_native
                                  ? "直连免中转"
                                  : "全局中转已关"}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Single-Node Use & Quick Group Actions */}
                      <td className="w-[138px] whitespace-nowrap px-1.5 py-2.5 text-right align-middle">
                        <div className="inline-flex flex-nowrap items-center justify-end gap-1">
                          <button
                            type="button"
                            disabled={isSingleActive || isSwitchingSingle}
                            onClick={() => void handleSelectSingleNode(node.id)}
                            title={
                              isSingleActive
                                ? "当前正处于单节点模式并使用此节点"
                                : "切换为单节点模式，固定使用此节点"
                            }
                            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border px-2 py-1 text-[11px] font-semibold transition-colors disabled:cursor-default ${
                              isSingleActive
                                ? "border-[var(--green)] bg-[var(--green)] text-[var(--accent-ink)]"
                                : "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:opacity-60"
                            }`}
                          >
                            {isSingleActive ? (
                              <>
                                <Check className="h-3 w-3 shrink-0" />
                                <span>在用</span>
                              </>
                            ) : (
                              <>
                                <Play className="h-2.5 w-2.5 shrink-0 fill-current" />
                                <span>{isSwitchingSingle ? "切换中" : "用它"}</span>
                              </>
                            )}
                          </button>

                          <GroupMembershipPopover node={node} variant="pill" />
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {filteredNodes.length > 0 && (
          <PaginationBar
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={filteredNodes.length}
            pageSize={pageSize}
            pageSizeOptions={[30, 50, 100]}
            onPageChange={setCurrentPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setCurrentPage(1);
            }}
            className="border-t border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-2.5"
          />
        )}
      </section>
      </>
      )}

      {/* ====================================================================
       * 7. Slide-Over Drawers: Legacy Read-Only Migration & Live Capture Wizard
       * ==================================================================== */}
      <MigrationDrawer
        open={migrationOpen}
        initialTab={migrationInitialTab}
        initialPasteText={migrationInitialPaste}
        onClose={closeMigration}
        onImport={handleMigrationImport}
      />

      <ProcessAttachDrawer
        open={processAttachOpen}
        onClose={closeProcessAttach}
        onConfirmCapture={handleLiveCaptureImport}
        onGoToSubUrl={handleFocusSubUrlInput}
      />

      {/* Share Bundle Export / Import Modal */}
      <ShareBundleModal
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

      {/* Merge Two Subscriptions Portal Modal */}
      {mergeModalOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!mergingSubs) setMergeModalOpen(false);
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label={dict.nodes.mergeSubsTitle}
              onClick={(e) => e.stopPropagation()}
              className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                    <GitMerge className="h-4 w-4" />
                  </span>
                  <div>
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      {dict.nodes.mergeSubsTitle}
                    </h3>
                    <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                      把源分组中的节点安全整合进目标分组，便于统一管理
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={mergingSubs}
                  onClick={() => setMergeModalOpen(false)}
                  aria-label="关闭合并分组弹窗"
                  className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-4 space-y-3">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <span className="block text-[11px] font-medium text-[var(--text-secondary)]">
                      源分组（将被合并移入）
                    </span>
                    <AppSelect
                      aria-label="选择源分组"
                      size="sm"
                      disabled={mergingSubs}
                      value={mergeSourceSubId}
                      onChange={(nextSource) => {
                        setMergeSourceSubId(nextSource);
                        setMergeError(null);
                        if (nextSource === mergeTargetSubId) {
                          const altTarget = subscriptions.find((s) => s.id !== nextSource);
                          if (altTarget) {
                            setMergeTargetSubId(altTarget.id);
                            setMergeNewName(altTarget.name);
                          }
                        }
                      }}
                      options={subscriptions.map((s) => ({
                        value: s.id,
                        label: `${s.name}（${subNodeCountMap.get(s.id) ?? 0} 节点）`,
                      }))}
                      className="w-full"
                      buttonClassName="bg-[var(--card)]"
                    />
                  </div>

                  <div className="space-y-1">
                    <span className="block text-[11px] font-medium text-[var(--text-secondary)]">
                      目标分组（合并后保留）
                    </span>
                    <AppSelect
                      aria-label="选择目标分组"
                      size="sm"
                      disabled={mergingSubs}
                      value={mergeTargetSubId}
                      onChange={(nextTarget) => {
                        setMergeTargetSubId(nextTarget);
                        setMergeError(null);
                        const found = subscriptions.find((s) => s.id === nextTarget);
                        if (found) setMergeNewName(found.name);
                        if (nextTarget === mergeSourceSubId) {
                          const altSource = subscriptions.find((s) => s.id !== nextTarget);
                          if (altSource) setMergeSourceSubId(altSource.id);
                        }
                      }}
                      options={subscriptions.map((s) => ({
                        value: s.id,
                        label: `${s.name}（${subNodeCountMap.get(s.id) ?? 0} 节点）`,
                      }))}
                      className="w-full"
                      buttonClassName="bg-[var(--card)]"
                    />
                  </div>
                </div>

                <label className="block text-[11px] font-medium text-[var(--text-secondary)]">
                  合并后的分组名称
                  <input
                    type="text"
                    disabled={mergingSubs}
                    value={mergeNewName}
                    onChange={(e) => setMergeNewName(e.target.value)}
                    placeholder="留空则沿用目标分组原名"
                    className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <label className="flex cursor-pointer items-start gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 px-3 py-2 text-xs">
                  <input
                    type="checkbox"
                    checked={mergeDedup}
                    disabled={mergingSubs}
                    onChange={(e) => setMergeDedup(e.target.checked)}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                  />
                  <div className="min-w-0">
                    <div className="font-medium text-[var(--text)]">
                      按节点物理指纹自动去重（推荐）
                    </div>
                    <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                      自动过滤协议、地址与端口完全一致的重复线路，避免合并后出现重复条目
                    </div>
                  </div>
                </label>

                <div className="flex items-start gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/55 px-3 py-2.5 text-[11px] leading-relaxed text-[var(--amber)]">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>
                    合并后，源分组中的节点将安全整合进目标分组并移除源分组外壳；原有的测速记录与智能多选组中的节点引用均会自动保留，不会丢失。
                  </span>
                </div>

                {mergeError && (
                  <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{mergeError}</span>
                  </div>
                )}
              </div>

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={mergingSubs}
                  onClick={() => setMergeModalOpen(false)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  取消
                </button>
                <button
                  type="button"
                  disabled={
                    mergingSubs ||
                    !mergeSourceSubId ||
                    !mergeTargetSubId ||
                    mergeSourceSubId === mergeTargetSubId
                  }
                  onClick={() => void handleConfirmMergeSubs()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {mergingSubs ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <GitMerge className="h-3.5 w-3.5" />
                  )}
                  <span>{mergingSubs ? "正在合并…" : "确认合并分组"}</span>
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}

      {/* Delete Subscription Two-Step Confirmation Modal */}
      {pendingDeleteSub &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!deletingSub) setPendingDeleteSub(null);
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label="确认删除订阅"
              onClick={(e) => e.stopPropagation()}
              className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--red-soft)] text-[var(--red)]">
                    <AlertTriangle className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      确认删除整条订阅？
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      即将删除订阅「
                      <span className="font-semibold text-[var(--text)]">
                        {pendingDeleteSub.name}
                      </span>
                      」，并同时移除该订阅下的{" "}
                      <strong className="cc-mono text-[var(--red)]">
                        {subNodeCountMap.get(pendingDeleteSub.id) ?? 0} 个节点
                      </strong>
                      。此操作无法撤销，请确认后再继续。
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={deletingSub}
                  onClick={() => setPendingDeleteSub(null)}
                  className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                  aria-label="关闭弹窗"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={deletingSub}
                  onClick={() => setPendingDeleteSub(null)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  取消
                </button>
                <button
                  type="button"
                  disabled={deletingSub}
                  onClick={() => void handleConfirmRemoveSubscription()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--red)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  <span>{deletingSub ? "删除中…" : "确认删除"}</span>
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
}
