import {
  type DesktopAppCandidate,
  type LiveCaptureOutcomeDto,
  type LiveCaptureStatusDto,
  type MigrationPreviewDto,
  type ProxyNode,
  type SubscriptionRecord,
  type SubscriptionUpdateMode,
} from "../../api/tauri";

/* ============================================================================
 * Domain Types & Constants
 * ============================================================================ */

export type MigrationSourceKind =
  | "clash_verge"
  | "flclash"
  | "v2rayn"
  | "local_file"
  | "clipboard_text";

export interface MigrationPreviewItem {
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

export interface CaptureConfirmPayload {
  name: string;
  outcome: LiveCaptureOutcomeDto;
  selectedNodes: ProxyNode[];
  targetMode: "new" | "existing";
  targetSubId?: string;
  updateMode?: SubscriptionUpdateMode;
}

export const SUB_KIND_LABELS: Record<SubscriptionRecord["kind"], string> = {
  url: "订阅链接",
  file: "本地文件",
  migrated: "已有软件导入",
  process_adapter: "软件抓取",
};

export const KNOWN_CLIENT_SPECS: Array<{
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

export const SINGLE_NODE_URI_RE =
  /^(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls):\/\//i;

export const KNOWN_MIGRATION_CLIENT_KINDS = new Set<MigrationSourceKind>([
  "clash_verge",
  "flclash",
  "v2rayn",
]);

export const UNSUPPORTED_CAPTURE_NOTICE =
  "该软件暂不支持直接抓取，建议尝试其它支持的软件或前往官网查看是否提供标准订阅链接";

/* ============================================================================
 * Helpers: Subscription Masking, Clash URI & Formatting
 * ============================================================================ */

export function getSubSource(sub: SubscriptionRecord): string {
  return sub.url_or_cmd || "";
}

export function maskSubscriptionSource(raw: string): string {
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

export function formatQuotaBytes(bytes: number): string {
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

export function inferSubNameFromUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.replace(/^www\./i, "");
    if (host) return host;
  } catch {
    /* use fallback */
  }
  return "我的订阅";
}

export function isSingleNodeShareUri(raw: string): boolean {
  const firstLine = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0 && !line.startsWith("#"));
  if (!firstLine) return false;
  return SINGLE_NODE_URI_RE.test(firstLine);
}

export function containsSingleNodeShareUriLine(raw: string): boolean {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .some((line) => line.length > 0 && !line.startsWith("#") && SINGLE_NODE_URI_RE.test(line));
}

export function normalizeSubSourceForCompare(kind: "url" | "file", raw: string): string {
  const trimmed = raw.trim();
  if (kind !== "url") return trimmed;
  return trimmed.replace(/^(https?:\/\/[^/?#]+)/i, (prefix) => prefix.toLowerCase());
}

export function parseClashInstallConfigUrl(
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

export function hasPausedCaptureSession(cap: {
  active: boolean;
  timedOut?: boolean;
  sessionId: string | null;
  status: LiveCaptureStatusDto | null;
}): boolean {
  const hasSessionRef = Boolean(cap.sessionId || cap.status?.session_id);
  if (!hasSessionRef || cap.active) return false;
  return Boolean(cap.timedOut || (cap.status && !cap.status.active));
}

/* ============================================================================
 * Helpers: Migration Path Normalization, Dedup & Merge
 * ============================================================================ */

export function migrationClientLabel(kind: string): string {
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

export function normalizeMigrationKind(kind: string): MigrationSourceKind {
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

export function extractPathBasename(path: string | null | undefined): string | null {
  const trimmed = path?.trim();
  if (!trimmed) return null;
  const withoutTrailing = trimmed.replace(/[\\/]+$/, "");
  if (!withoutTrailing) return null;
  const segs = withoutTrailing.split(/[\\/]/).filter(Boolean);
  return segs[segs.length - 1] ?? null;
}

export function normalizeMigrationSourcePath(path: string | null | undefined): string | null {
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

export function getMigrationDedupeKey(item: MigrationPreviewItem): string {
  const norm = normalizeMigrationSourcePath(item.source_path);
  return norm ? `path:${norm}` : `id:${item.id}`;
}

export function isNormalizedPathInDir(candidateNorm: string, dirNorm: string): boolean {
  if (candidateNorm === dirNorm) return true;
  const prefix = dirNorm.endsWith("/") ? dirNorm : `${dirNorm}/`;
  return candidateNorm.startsWith(prefix);
}

export function defaultMigrationSubName(item: MigrationPreviewItem): string {
  const customDisplay = item.display_name?.trim();
  if (customDisplay) return customDisplay;
  const basename = extractPathBasename(item.source_path);
  if (basename) return basename;
  return `导入 · ${item.client_label}`;
}

export function mapMigrationDtoToPreview(
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

export function mergeSingleMigrationItem(
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

export function mergeScannedMigrationItems(
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

export function formatTimeShort(iso: string | null): string {
  if (!iso) return "尚未刷新";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${mm}-${dd} ${hh}:${mi}`;
}

export function formatExpireInfo(expiresAt: string | null): {
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

/* ============================================================================
 * Pure Client-Side Pasted Config Preview Parser & Live Capture Helpers
 * ============================================================================ */

export function detectRegionFromName(name: string): string {
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

export function extractMultiplierFromName(name: string): number {
  const m =
    /(?:^|[\s[\]()·|-])(\d+(?:\.\d+)?)\s*(?:x|倍|倍率)(?:$|[\s[\]()·|-])/i.exec(
      name
    ) ?? /(?:^|[\s[\]()·|-])x(\d+(?:\.\d+)?)(?:$|[\s[\]()·|-])/i.exec(name);
  if (!m) return 1.0;
  const val = Number(m[1]);
  return Number.isFinite(val) && val >= 0 ? val : 1.0;
}

export function parsePastedConfigPreview(rawInput: string): MigrationPreviewItem {
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

export function isSelfCatCloudCandidate(cand: DesktopAppCandidate): boolean {
  const joined = `${cand.friendly_name} ${cand.window_title} ${cand.process_name}`.toLowerCase();
  return joined.includes("catcloud") || joined.includes("猫猫云梯");
}

export function formatCaptureEventTime(tsMs: number): string {
  const d = new Date(tsMs);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}
