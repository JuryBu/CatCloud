import {
  ArrowDownToLine,
  BookOpen,
  Check,
  Copy,
  Download,
  Loader2,
  MessageSquareWarning,
  Network,
  Pause,
  Play,
  ScrollText,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { catcloudApi, isTauriEnv } from "../api/tauri";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";
import { isBoolPref, usePersistedState } from "../utils/uiPrefs";

export type LogLevel = "debug" | "info" | "warning" | "error";

interface CoreLogEntry {
  id: number;
  time: string;
  level: LogLevel;
  module: string;
  message: string;
}

interface LogBufferState {
  entries: CoreLogEntry[];
  truncatedCount: number;
}

const MAX_LOG_LINES = 2000;
const DEFAULT_RENDER_LIMIT = 300;
const RENDER_STEP = 300;

const LEVEL_META: Record<
  LogLevel,
  { label: string; color: string; softBg: string }
> = {
  debug: {
    label: "调试",
    color: "var(--muted)",
    softBg: "var(--bg-elevated)",
  },
  info: {
    label: "普通",
    color: "var(--sky)",
    softBg: "var(--sky-soft)",
  },
  warning: {
    label: "提醒",
    color: "var(--amber)",
    softBg: "var(--amber-soft)",
  },
  error: {
    label: "错误",
    color: "var(--red)",
    softBg: "var(--red-soft)",
  },
};

const ALL_LEVELS: readonly LogLevel[] = ["debug", "info", "warning", "error"] as const;

const DEFAULT_ENABLED_LEVELS: Record<LogLevel, boolean> = {
  debug: true,
  info: true,
  warning: true,
  error: true,
};

function validateEnabledLevels(raw: unknown): Record<LogLevel, boolean> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return undefined;
  }
  const rec = raw as Record<string, unknown>;
  if (
    typeof rec.debug !== "boolean" ||
    typeof rec.info !== "boolean" ||
    typeof rec.warning !== "boolean" ||
    typeof rec.error !== "boolean"
  ) {
    return undefined;
  }
  return {
    debug: rec.debug,
    info: rec.info,
    warning: rec.warning,
    error: rec.error,
  };
}

function formatNowClock(date: Date = new Date()): string {
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  const ss = String(date.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function normalizeLogLevel(raw?: string): LogLevel {
  const lower = (raw ?? "info").toLowerCase();
  if (lower === "debug" || lower === "info" || lower === "warning" || lower === "error") {
    return lower;
  }
  if (lower === "warn") return "warning";
  return "info";
}

interface RawLogPayload {
  time: string;
  level: LogLevel;
  module: string;
  message: string;
}

const RAW_CORE_MODULE_RE = /^(mihomo|clash|meta|core|kernel|engine|unknown)$/i;

const APP_LOG_MODULE_MAP: Record<string, string> = {
  应用: "应用",
  通用: "应用",
  核心: "内核",
  内核: "内核",
  热重载: "内核",
  配置: "配置",
  系统代理: "代理",
  代理: "代理",
  代理模式: "代理",
  虚拟网卡: "虚拟网卡",
  tun: "虚拟网卡",
  提速: "提速",
  国内提速: "提速",
  预加速: "提速",
  中转: "提速",
  多选组: "多选组",
  分组: "多选组",
  策略择优: "多选组",
  节点切换: "多选组",
  单节点: "单节点",
  订阅: "订阅",
  测速: "测速",
  探针: "测速",
  分流: "分流",
  规则: "分流",
  更新: "更新",
};

function classifyAppLogTag(rawTag: string): string {
  const trimmed = rawTag.trim();
  if (!trimmed) return "应用";
  const exact = APP_LOG_MODULE_MAP[trimmed] ?? APP_LOG_MODULE_MAP[trimmed.toLowerCase()];
  if (exact) return exact;
  if (/(提速|预加速|中转|preaccel)/i.test(trimmed)) return "提速";
  if (/(单节点|single)/i.test(trimmed)) return "单节点";
  if (/(多选组|分组|策略|择优|切换|group)/i.test(trimmed)) return "多选组";
  if (/(核心|内核|重载|mihomo|core)/i.test(trimmed)) return "内核";
  if (/(虚拟网卡|\btun\b)/i.test(trimmed)) return "虚拟网卡";
  if (/(代理|proxy)/i.test(trimmed)) return "代理";
  if (/(订阅|sub)/i.test(trimmed)) return "订阅";
  if (/(测速|探针|probe)/i.test(trimmed)) return "测速";
  if (/(分流|规则|rule)/i.test(trimmed)) return "分流";
  return trimmed;
}

function classifyLogModule(message: string, rawModule?: string): string {
  const text = message.trim();
  const appMatch = /^\[应用\/([^\]]+)\]/.exec(text);
  if (appMatch) {
    return classifyAppLogTag(appMatch[1]);
  }
  const cleanedModule = rawModule?.trim() ?? "";
  if (cleanedModule && !RAW_CORE_MODULE_RE.test(cleanedModule)) {
    const modAppMatch = /^应用\/(.+)$/.exec(cleanedModule);
    if (modAppMatch) {
      return classifyAppLogTag(modAppMatch[1]);
    }
    return cleanedModule;
  }
  if (/(\btun\b|wintun|gvisor|utun|sing-tun|虚拟网卡|网卡)/i.test(text)) {
    return "虚拟网卡";
  }
  if (/(\bdns\b|fake-?ip|nameserver|resolver|\bdoh\b|\bdot\b|lookup|hosts|域名解析|域名)/i.test(text)) {
    return "域名解析";
  }
  if (/(url-?test|health\s*check|delay|latency|probe|connectivity|keepalive|\bping\b|timeout|测速|连通|检测|心跳|延迟)/i.test(text)) {
    return "网络检测";
  }
  if (/(\[tcp\]|\[udp\]|\bmatch\b|\brule\b|geosite|geoip|using\s|-->|\bdirect\b|\breject\b|dialer|proxy-?group|分流|路由|命中)/i.test(text)) {
    return "分流";
  }
  return "代理核心";
}

function logEntryKey(item: Pick<RawLogPayload, "time" | "level" | "message">): string {
  return `${item.time}\u0000${item.level}\u0000${item.message}`;
}

/**
 * Deduplicate real-time logs buffered while `getRecentLogs` was in flight against
 * the tail of the returned history snapshot using `(time, level, message)`.
 */
function dedupeEarlyQueueAgainstHistory(
  history: RawLogPayload[],
  earlyQueue: RawLogPayload[]
): RawLogPayload[] {
  if (history.length === 0 || earlyQueue.length === 0) {
    return earlyQueue;
  }

  const historyKeys = history.map(logEntryKey);
  const earlyKeys = earlyQueue.map(logEntryKey);

  // Case 1: entire earlyQueue is already contained inside the tail window of history
  const searchStart = Math.max(0, historyKeys.length - earlyKeys.length - 64);
  const maxStart = historyKeys.length - earlyKeys.length;
  for (let start = maxStart; start >= searchStart; start--) {
    let allMatch = true;
    for (let i = 0; i < earlyKeys.length; i++) {
      if (historyKeys[start + i] !== earlyKeys[i]) {
        allMatch = false;
        break;
      }
    }
    if (allMatch) {
      return [];
    }
  }

  // Case 2: longest suffix of history matching prefix of earlyQueue
  const maxOverlap = Math.min(historyKeys.length, earlyKeys.length);
  for (let k = maxOverlap; k >= 1; k--) {
    let matched = true;
    const offset = historyKeys.length - k;
    for (let i = 0; i < k; i++) {
      if (historyKeys[offset + i] !== earlyKeys[i]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return earlyQueue.slice(k);
    }
  }

  return earlyQueue;
}

function mergeBackfilledLogEntries(
  prevEntries: CoreLogEntry[],
  snapshot: RawLogPayload[],
  allocId: () => number
): { entries: CoreLogEntry[]; overflow: number } {
  if (snapshot.length === 0) {
    return { entries: prevEntries, overflow: 0 };
  }
  const toEntries = (raws: RawLogPayload[]): CoreLogEntry[] =>
    raws.map((raw) => ({
      id: allocId(),
      time: raw.time,
      level: raw.level,
      module: raw.module,
      message: raw.message,
    }));

  if (prevEntries.length === 0) {
    const next = toEntries(snapshot);
    if (next.length > MAX_LOG_LINES) {
      const overflow = next.length - MAX_LOG_LINES;
      return { entries: next.slice(overflow), overflow };
    }
    return { entries: next, overflow: 0 };
  }

  const dedupedStandard = dedupeEarlyQueueAgainstHistory(prevEntries, snapshot);
  if (dedupedStandard.length === 0) {
    return { entries: prevEntries, overflow: 0 };
  }

  let baseEntries = prevEntries;
  let toAppend = dedupedStandard;

  if (dedupedStandard.length === snapshot.length) {
    const prevKeys = prevEntries.map(logEntryKey);
    const snapKeySet = new Set(snapshot.map(logEntryKey));
    const maxSkip = Math.min(prevEntries.length, 64);
    let aligned = false;
    for (let skip = 1; skip <= maxSkip; skip++) {
      if (!snapKeySet.has(prevKeys[prevKeys.length - skip])) {
        break;
      }
      const trimmedPrev = prevEntries.slice(0, prevEntries.length - skip);
      const remainder = dedupeEarlyQueueAgainstHistory(trimmedPrev, snapshot);
      if (remainder.length < snapshot.length) {
        baseEntries = trimmedPrev;
        toAppend = remainder;
        aligned = true;
        break;
      }
    }
    if (!aligned && prevEntries.length <= snapshot.length) {
      let allInSnap = true;
      for (let i = 0; i < prevKeys.length; i++) {
        if (!snapKeySet.has(prevKeys[i])) {
          allInSnap = false;
          break;
        }
      }
      if (allInSnap) {
        baseEntries = [];
        toAppend = snapshot;
      }
    }
  }

  if (toAppend.length === 0 && baseEntries === prevEntries) {
    return { entries: prevEntries, overflow: 0 };
  }

  const merged = baseEntries.concat(toEntries(toAppend));
  if (merged.length > MAX_LOG_LINES) {
    const overflow = merged.length - MAX_LOG_LINES;
    return { entries: merged.slice(overflow), overflow };
  }
  return { entries: merged, overflow: 0 };
}

function formatLogTimestamp(ts?: string): string {
  if (!ts) return formatNowClock();
  const parsed = new Date(ts);
  if (!Number.isNaN(parsed.getTime())) {
    return formatNowClock(parsed);
  }
  return ts.slice(0, 12);
}

const SENSITIVE_LOG_KEY_ALT =
  "(?:controller_secret|obfs[-_]?password|authorization|refresh[-_]?token|client[-_]?secret|access[-_]?token|private[-_]?key|public[-_]?key|passphrase|set[-_]?cookie|auth[-_]?token|sub[-_]?token|user[-_]?uuid|short[-_]?id|password|auth[-_]?str|api[-_]?key|apikey|passwd|secret|cookie|token|auth|uuid|pwd|key|psk|pbk|sid|username)";

const SENSITIVE_QUERY_PARAM_RE = new RegExp(
  `([?&](?:[A-Za-z0-9_-]*[-_])?${SENSITIVE_LOG_KEY_ALT}=)([^&#\\s"'<>]+)`,
  "gi"
);

const SENSITIVE_KV_RE = new RegExp(
  `((?<![A-Za-z0-9])${SENSITIVE_LOG_KEY_ALT}["']?[ \\t]*(?:=|:(?!//))[ \\t]*)(Bearer[ \\t]+)?(?:<REDACTED>|"(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|(?![{\\[\\r\\n])[^\\s&#"'\\x60,;\\)\\]\\}<>]+)`,
  "gi"
);

/**
 * Strict frontend log sanitizer aligned 1:1 with `crates/catcloud-core/src/sanitize.rs`:
 * - Only loopback/unspecified (`127.0.0.1`, `0.0.0.0`, `::1`, `::`) are preserved verbatim.
 * - Redacts sensitive query params & key-value pairs (`token`, `uuid`, `pwd`, `auth`, `auth_str`,
 *   `auth-str`, `psk`, `pbk`, `sid`, `cookie`, `set-cookie`, `apikey`, `public_key`, `public-key`,
 *   `short_id`, `short-id`, `username`, and `_`/`-` prefixed compound keys) while preserving JSON quotes.
 * - ALL other IPv4 addresses (including private RFC1918, TUN `198.18.*`, link-local, and public DNS)
 *   are masked as `A.B.C.*` while protecting version strings (`v1.2.3.4`) and 5-part OIDs.
 * - ALL other IPv6 literals (including `fe80:`, `fc/fd`, `ff`, `2001:db8:`, `::ffff:`) are masked as `a:b::*`.
 */
function sanitizeLogLine(raw: string): string {
  let out = raw
    // Redact custom CatCloud relay import tokens (`mmrelay://v1/...`) and opaque `vmess://` base64 payloads
    .replace(/(mmrelay:\/\/(?:v\d+\/)?)[^\s"'<>]+/gi, "$1<REDACTED>")
    .replace(/(vmess:\/\/)[^\s"'<>#]+/gi, "$1<REDACTED>")
    // Redact userinfo credentials in proxy & HTTP(S) URLs (`scheme://user:pass@host`)
    .replace(
      /((?:https?|socks5h?|trojan|vless|vmess|ssr?|hysteria2|hy2|tuic|anytls):\/\/)([^/\s"'<>?#]+)@/gi,
      "$1<REDACTED>@"
    )
    // Redact opaque base64-only Shadowsocks/SSR payloads (`ss://<base64>#tag`)
    .replace(/(ssr?:\/\/)(?!<REDACTED>@)[^\s"'<>#]+/gi, "$1<REDACTED>")
    .replace(/(?<![A-Za-z0-9])(Bearer[ \t]+)(?:<REDACTED>|[^\s&#"'`,;)\]}<>]+)/gi, "$1<REDACTED>")
    .replace(SENSITIVE_QUERY_PARAM_RE, "$1<REDACTED>")
    .replace(SENSITIVE_KV_RE, (full, prefix: string, bearer: string | undefined) => {
      const valStart = prefix.length + (bearer?.length ?? 0);
      const val = full.slice(valStart);
      if (!val || val === "<REDACTED>" || val === '"<REDACTED>"' || val === "'<REDACTED>'") {
        return full;
      }
      if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
        return `${prefix}${bearer ?? ""}"<REDACTED>"`;
      }
      if (val.startsWith("'") && val.endsWith("'") && val.length >= 2) {
        return `${prefix}${bearer ?? ""}'<REDACTED>'`;
      }
      return `${prefix}${bearer ?? ""}<REDACTED>`;
    })
    // Redact Windows & Unix user directories (supporting CJK and other non-ASCII usernames)
    .replace(/[A-Za-z]:([\\/])Users([\\/])[^\\/\s"'<>|:*?\r\n]+/gi, "C:$1Users$2<USER>")
    .replace(/\/(Users|home)\/[^\\/\s"'<>|:*?\r\n]+/g, "/$1/<USER>");

  // Strictly mask all non-loopback/non-unspecified IPv4 addresses to `A.B.C.*`
  // Protects version strings (`v1.2.3.4`, `version=1.2.3.4`) and multi-segment OIDs (`1.3.6.1.5`).
  out = out.replace(
    /(?<![A-Za-z0-9.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\.\d)(?![0-9A-Za-z])/g,
    (full, a, b, c, d, offset: number, source: string) => {
      const nums = [Number(a), Number(b), Number(c), Number(d)];
      if (nums.some((n) => n > 255)) return full;
      // Preserve explicit loopback and unspecified addresses only
      if (full === "127.0.0.1" || full === "0.0.0.0") return full;
      // Guard version prefixes immediately preceding the match (e.g. `v1_1.2.3.4`, `version: 1.2.3.4`)
      const before = source.slice(Math.max(0, offset - 12), offset);
      if (/(?:^|[^a-zA-Z])(?:v\d+_|version[\s:=_-]*)$/i.test(before)) {
        return full;
      }
      return `${a}.${b}.${c}.*`;
    }
  );

  // Strictly mask all non-loopback/non-unspecified IPv6 literals to `a:b::*` (without touching HH:MM:SS or MACs)
  out = out.replace(
    /(?<![0-9a-fA-F:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::)(?![0-9a-fA-F:])/g,
    (full) => {
      const lower = full.toLowerCase();
      if (lower === "::" || lower === "::1") return full;
      if (lower.includes("::")) {
        const parts = lower.split("::");
        if (parts.length > 2) return full;
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        if (left.length + right.length > 7) return full;
        if (left.length >= 2) return `${left[0]}:${left[1]}::*`;
        if (left.length === 1) return `${left[0]}::*`;
        return "<REDACTED_IPV6>";
      }
      const segments = lower.split(":");
      if (segments.length !== 8) return full;
      return `${segments[0]}:${segments[1]}::*`;
    }
  );

  return out;
}

function buildSeedLogs(): CoreLogEntry[] {
  const now = Date.now();
  const templates: Array<{ level: LogLevel; module: string; message: string }> = [
    {
      level: "info",
      module: "代理核心",
      message: "代理内核已启动，本地代理端口 17890 就绪（省内存模式）",
    },
    {
      level: "info",
      module: "域名解析",
      message: "本地域名解析服务已就绪（127.0.0.1:11053，智能分流已开启）",
    },
    {
      level: "info",
      module: "国内提速",
      message: "国内连通检测正常，中转通道延迟 18 ms",
    },
    {
      level: "debug",
      module: "分流路由",
      message:
        "访问 generativelanguage.googleapis.com:443，按域名匹配走「AI 专线粘性组 → JP-Tokyo-01 · 1x」",
    },
    {
      level: "warning",
      module: "智能选路",
      message: "「影音下载均衡组」检测到 SG-Edge-02 延迟波动（19.4 ms），进入 60 秒观察冷却",
    },
    {
      level: "info",
      module: "配置更新",
      message: "配置检查通过（42 ms），已平滑应用最新设置且未中断现有连接",
    },
  ];

  return templates.map((item, idx) => ({
    id: idx + 1,
    time: formatNowClock(new Date(now - (templates.length - idx) * 3500)),
    level: item.level,
    module: item.module,
    message: item.message,
  }));
}

const STREAM_SAMPLES: Array<{ level: LogLevel; module: string; message: string }> = [
  {
    level: "debug",
    module: "分流路由",
    message: "访问 chatgpt.com:443，按域名匹配走「AI 专线粘性组 → JP-Tokyo-01 · 1x」",
  },
  {
    level: "info",
    module: "国内提速",
    message: "主力中转线路心跳正常（华东 443 主力线路，延迟 19 ms）",
  },
  {
    level: "info",
    module: "资源占用",
    message: "当前内核内存占用 35.4 MB，处于省内存运行区间",
  },
];

export function LogsPage() {
  const inTauri = isTauriEnv();
  const runtime = useAppSelector((s) => s.runtime);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const [logState, setLogState] = useState<LogBufferState>(() => ({
    entries: inTauri ? [] : buildSeedLogs(),
    truncatedCount: 0,
  }));
  const [paused, setPaused] = useState<boolean>(false);
  const [bufferedWhilePaused, setBufferedWhilePaused] = useState<number>(0);
  const [autoScroll, setAutoScroll] = usePersistedState<boolean>(
    "logs.autoScroll",
    true,
    isBoolPref
  );
  const [keyword, setKeyword] = useState<string>("");
  const [renderLimit, setRenderLimit] = useState<number>(DEFAULT_RENDER_LIMIT);
  const [enabledLevels, setEnabledLevels] = usePersistedState<Record<LogLevel, boolean>>(
    "logs.enabledLevels",
    DEFAULT_ENABLED_LEVELS,
    validateEnabledLevels
  );
  const [copied, setCopied] = useState<boolean>(false);
  const [copyingAiDiag, setCopyingAiDiag] = useState<boolean>(false);
  const [copiedAiDiag, setCopiedAiDiag] = useState<boolean>(false);
  const [openingIssue, setOpeningIssue] = useState<boolean>(false);

  const nextIdRef = useRef<number>(100);
  const sampleCursorRef = useRef<number>(0);
  const pausedRef = useRef<boolean>(paused);
  const entriesRef = useRef<CoreLogEntry[]>(logState.entries);
  const pendingBufferRef = useRef<CoreLogEntry[]>([]);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const copiedTimerRef = useRef<number | null>(null);
  const copiedAiTimerRef = useRef<number | null>(null);

  pausedRef.current = paused;
  entriesRef.current = logState.entries;

  const { entries, truncatedCount } = logState;

  // Pure functional state transition: never nests another setState inside a state updater
  const appendBatch = (incoming: CoreLogEntry[]) => {
    if (incoming.length === 0) return;
    setLogState((prev) => {
      const merged = prev.entries.concat(incoming);
      if (merged.length > MAX_LOG_LINES) {
        const overflow = merged.length - MAX_LOG_LINES;
        return {
          entries: merged.slice(overflow),
          truncatedCount: prev.truncatedCount + overflow,
        };
      }
      return {
        entries: merged,
        truncatedCount: prev.truncatedCount,
      };
    });
  };

  useEffect(() => {
    return () => {
      if (copiedTimerRef.current !== null) {
        window.clearTimeout(copiedTimerRef.current);
      }
      if (copiedAiTimerRef.current !== null) {
        window.clearTimeout(copiedAiTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let mockTimer: number | null = null;

    const enqueueEntries = (rawItems: RawLogPayload[]) => {
      if (rawItems.length === 0) return;
      const items: CoreLogEntry[] = rawItems.map((raw) => {
        nextIdRef.current += 1;
        return {
          id: nextIdRef.current,
          time: raw.time,
          level: raw.level,
          module: raw.module,
          message: raw.message,
        };
      });

      if (pausedRef.current) {
        pendingBufferRef.current.push(...items);
        if (pendingBufferRef.current.length > MAX_LOG_LINES) {
          pendingBufferRef.current = pendingBufferRef.current.slice(-MAX_LOG_LINES);
        }
        setBufferedWhilePaused(pendingBufferRef.current.length);
        return;
      }

      appendBatch(items);
    };

    const pushIncoming = (level: LogLevel, module: string, message: string, time?: string) => {
      enqueueEntries([
        {
          time: time ?? formatNowClock(),
          level,
          module,
          message,
        },
      ]);
    };

    const startMockStream = () => {
      if (disposed || mockTimer !== null) return;
      mockTimer = window.setInterval(() => {
        if (disposed || document.visibilityState !== "visible") return;
        const sample = STREAM_SAMPLES[sampleCursorRef.current % STREAM_SAMPLES.length];
        sampleCursorRef.current += 1;
        pushIncoming(sample.level, sample.module, sample.message);
      }, 2800);
    };

    let removeVisibilityListener: (() => void) | null = null;

    if (inTauri) {
      let historyLoaded = false;
      let earlyQueue: RawLogPayload[] = [];
      let backfilling = false;
      let backfillQueuedAgain = false;
      let backfillEarlyQueue: RawLogPayload[] = [];

      const mapRecentLines = (
        lines: Array<{ level?: string; payload?: string; timestamp?: string }>
      ): RawLogPayload[] =>
        lines.map((line) => {
          const message = line.payload ?? "";
          return {
            time: formatLogTimestamp(line.timestamp),
            level: normalizeLogLevel(line.level),
            module: classifyLogModule(message),
            message,
          };
        });

      const backfillOnResume = async () => {
        if (disposed || !historyLoaded) return;
        if (backfilling) {
          backfillQueuedAgain = true;
          return;
        }
        backfilling = true;
        backfillEarlyQueue = [];
        try {
          const lines = await catcloudApi.getRecentLogs(500);
          if (disposed) return;
          const snapshotBatch = mapRecentLines(lines);
          const dedupedLive = dedupeEarlyQueueAgainstHistory(snapshotBatch, backfillEarlyQueue);
          backfillEarlyQueue = [];
          const authoritative = snapshotBatch.concat(dedupedLive);
          if (authoritative.length === 0) return;

          if (pausedRef.current) {
            const combinedExisting = entriesRef.current.concat(pendingBufferRef.current);
            const netNew = dedupeEarlyQueueAgainstHistory(combinedExisting, authoritative);
            if (netNew.length > 0) {
              enqueueEntries(netNew);
            }
            return;
          }

          setLogState((prev) => {
            const res = mergeBackfilledLogEntries(prev.entries, authoritative, () => {
              nextIdRef.current += 1;
              return nextIdRef.current;
            });
            if (res.entries === prev.entries) return prev;
            return {
              entries: res.entries,
              truncatedCount: prev.truncatedCount + res.overflow,
            };
          });
        } catch {
          if (!disposed && backfillEarlyQueue.length > 0) {
            const pendingLive = backfillEarlyQueue;
            backfillEarlyQueue = [];
            enqueueEntries(pendingLive);
          }
        } finally {
          backfilling = false;
          if (!disposed && backfillQueuedAgain) {
            backfillQueuedAgain = false;
            void backfillOnResume();
          }
        }
      };

      const handleVisibilityChange = () => {
        if (document.visibilityState === "visible") {
          void backfillOnResume();
        }
      };
      if (typeof document !== "undefined") {
        document.addEventListener("visibilitychange", handleVisibilityChange);
        removeVisibilityListener = () =>
          document.removeEventListener("visibilitychange", handleVisibilityChange);
      }

      const bootRealLogStream = async () => {
        // 1. Register real-time listener FIRST so no lines are missed while fetching history.
        try {
          const { listen } = await import("@tauri-apps/api/event");
          const fn = await listen<{
            level?: string;
            module?: string;
            payload?: string;
            message?: string;
            time?: string;
            timestamp?: string;
          }>("catcloud://core-log", (ev) => {
            if (disposed) return;
            const message = ev.payload.message ?? ev.payload.payload ?? "";
            const item: RawLogPayload = {
              time: ev.payload.time ?? formatLogTimestamp(ev.payload.timestamp),
              level: normalizeLogLevel(ev.payload.level),
              module: classifyLogModule(message, ev.payload.module),
              message,
            };
            if (!historyLoaded) {
              earlyQueue.push(item);
              if (earlyQueue.length > MAX_LOG_LINES) {
                earlyQueue = earlyQueue.slice(-MAX_LOG_LINES);
              }
              return;
            }
            if (backfilling) {
              backfillEarlyQueue.push(item);
              if (backfillEarlyQueue.length > MAX_LOG_LINES) {
                backfillEarlyQueue = backfillEarlyQueue.slice(-MAX_LOG_LINES);
              }
              return;
            }
            enqueueEntries([item]);
          });

          if (disposed) {
            fn();
            return;
          }
          unlisten = fn;
        } catch {
          /* never inject mock stream in Tauri runtime */
        }

        // 2. Fetch recent history snapshot and merge with deduplicated earlyQueue.
        let historyBatch: RawLogPayload[] = [];
        try {
          const lines = await catcloudApi.getRecentLogs(500);
          if (disposed) return;
          historyBatch = mapRecentLines(lines);
        } catch {
          /* core may not have emitted logs yet */
        }

        if (disposed) return;
        const dedupedEarly = dedupeEarlyQueueAgainstHistory(historyBatch, earlyQueue);
        earlyQueue = [];
        historyLoaded = true;
        enqueueEntries(historyBatch.concat(dedupedEarly));
      };

      void bootRealLogStream();
    } else {
      startMockStream();
    }

    return () => {
      disposed = true;
      removeVisibilityListener?.();
      unlisten?.();
      if (mockTimer !== null) {
        window.clearInterval(mockTimer);
        mockTimer = null;
      }
    };
  }, [inTauri]);

  const levelCounts = useMemo(() => {
    const counts: Record<LogLevel, number> = {
      debug: 0,
      info: 0,
      warning: 0,
      error: 0,
    };
    for (const item of entries) {
      counts[item.level] += 1;
    }
    return counts;
  }, [entries]);

  const filteredEntries = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return entries.filter((item) => {
      if (!enabledLevels[item.level]) return false;
      if (!kw) return true;
      return (
        item.message.toLowerCase().includes(kw) ||
        item.module.toLowerCase().includes(kw) ||
        item.time.includes(kw) ||
        item.level.includes(kw) ||
        LEVEL_META[item.level].label.includes(kw)
      );
    });
  }, [enabledLevels, entries, keyword]);

  const hiddenOlderCount = Math.max(0, filteredEntries.length - renderLimit);
  const visibleEntries = useMemo(
    () => (hiddenOlderCount > 0 ? filteredEntries.slice(-renderLimit) : filteredEntries),
    [filteredEntries, hiddenOlderCount, renderLimit]
  );

  useEffect(() => {
    if (!autoScroll || paused) return;
    const el = scrollContainerRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [autoScroll, visibleEntries.length, paused]);

  const handleTogglePause = () => {
    if (paused) {
      const flushed = pendingBufferRef.current;
      pendingBufferRef.current = [];
      setBufferedWhilePaused(0);
      setPaused(false);
      if (flushed.length > 0) {
        appendBatch(flushed);
      }
      setAutoScroll(true);
    } else {
      setPaused(true);
    }
  };

  const handleClear = () => {
    pendingBufferRef.current = [];
    setBufferedWhilePaused(0);
    setLogState({ entries: [], truncatedCount: 0 });
    setRenderLimit(DEFAULT_RENDER_LIMIT);
    appActions.showToast("已清空运行日志", "info");
  };

  const toggleLevel = (lvl: LogLevel) => {
    setEnabledLevels((prev) => ({ ...prev, [lvl]: !prev[lvl] }));
  };

  const formatSanitizedLogText = (): string => {
    const header = [
      `# 猫猫云梯运行日志导出`,
      `# 导出条数：${filteredEntries.length}（最多保留 ${MAX_LOG_LINES} 条，已清理早期记录 ${truncatedCount} 条）`,
      `# 隐私保护：已自动隐藏密钥、本机用户名及公网 IP`,
      "",
    ];
    const body = filteredEntries.map((item) =>
      sanitizeLogLine(
        `[${item.time}] [${LEVEL_META[item.level].label}] [${item.module}] ${item.message}`
      )
    );
    return header.concat(body).join("\n");
  };

  const handleCopyAiDiagnosticBundle = async () => {
    if (copyingAiDiag) return;
    setCopyingAiDiag(true);
    try {
      const recentViewLines = filteredEntries
        .slice(-40)
        .map((item) =>
          sanitizeLogLine(
            `[${item.time}] [${LEVEL_META[item.level].label}] [${item.module}] ${item.message}`
          )
        )
        .join("\n");
      const ok = await appActions.copySanitizedDiagnosticsForAi(
        recentViewLines || undefined
      );
      if (ok) {
        setCopiedAiDiag(true);
        if (copiedAiTimerRef.current !== null) {
          window.clearTimeout(copiedAiTimerRef.current);
        }
        copiedAiTimerRef.current = window.setTimeout(() => {
          copiedAiTimerRef.current = null;
          setCopiedAiDiag(false);
        }, 2000);
      }
    } finally {
      setCopyingAiDiag(false);
    }
  };

  const handleCopySanitized = async () => {
    const text = formatSanitizedLogText();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      appActions.showToast(`已复制 ${filteredEntries.length} 条日志（隐私已自动打码）`, "ok");
      if (copiedTimerRef.current !== null) {
        window.clearTimeout(copiedTimerRef.current);
      }
      copiedTimerRef.current = window.setTimeout(() => {
        copiedTimerRef.current = null;
        setCopied(false);
      }, 1800);
    } catch {
      appActions.showToast("无法写入剪贴板，请改用「导出」保存为日志文件", "warn");
    }
  };

  const handleExportSanitized = () => {
    const text = formatSanitizedLogText();
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = url;
    a.download = `catcloud-logs-${stamp}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    appActions.showToast(`已导出日志文件（${filteredEntries.length} 条，隐私已自动打码）`, "ok");
  };

  const handleScroll = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const distanceToBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    const nearBottom = distanceToBottom < 32;
    if (nearBottom !== autoScroll) {
      setAutoScroll(nearBottom);
    }
  };

  const jumpToBottom = () => {
    setAutoScroll(true);
    const el = scrollContainerRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  };

  return (
    <div className="space-y-4">
      {/* 顶部标题与操作栏 */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--accent)]">
            <ScrollText className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-sm font-semibold text-[var(--text)]">{dict.nav.logs}</h1>
              <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
                {entries.length} / {MAX_LOG_LINES} 条
              </span>
              {paused ? (
                <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--amber)]">
                  已暂停{bufferedWhilePaused > 0 ? `（新增 +${bufferedWhilePaused} 条）` : ""}
                </span>
              ) : !runtime.running ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--muted)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--muted)] opacity-60" />
                  代理核心未启动（开启代理后自动接收日志）
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--green)]">
                  <span className="cc-pulse-dot h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                  实时更新中
                </span>
              )}
            </div>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              最多保留最近 {MAX_LOG_LINES} 条记录，默认先展示最新 {DEFAULT_RENDER_LIMIT} 条保持流畅；复制和导出时会自动隐藏隐私信息。
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={copyingAiDiag}
            onClick={() => void handleCopyAiDiagnosticBundle()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
            title="一键打包当前代理状态与脱敏日志，直接粘给 AI 助手排查"
          >
            {copiedAiDiag ? (
              <>
                <Check className="h-3.5 w-3.5" />
                <span>已复制诊断包</span>
              </>
            ) : (
              <span>{copyingAiDiag ? "正在打包…" : "🤖 复制诊断包发给 AI"}</span>
            )}
          </button>

          <button
            type="button"
            onClick={() => appActions.setNav("rules")}
            className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
          >
            <Network className="h-3.5 w-3.5 text-[var(--muted)]" />
            <span>{dict.nav.rules}</span>
          </button>

          <button
            type="button"
            onClick={() => appActions.openAiAssistant("troubleshooting")}
            title={
              uiLang === "zh-CN"
                ? "前往 AI 助手查看通用排障总纲与只读诊断命令"
                : dict.aiHub.subtitle
            }
            className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
          >
            <BookOpen className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{uiLang === "zh-CN" ? "AI 协作指南" : dict.nav.ai}</span>
          </button>

          <button
            type="button"
            disabled={openingIssue}
            onClick={() => {
              if (openingIssue) return;
              setOpeningIssue(true);
              void appActions.openGithubIssueFeedback().finally(() => {
                setOpeningIssue(false);
              });
            }}
            title={dict.common.openIssue}
            className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--amber)] hover:text-[var(--text)] disabled:opacity-60"
          >
            {openingIssue ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--amber)]" />
            ) : (
              <MessageSquareWarning className="h-3.5 w-3.5 text-[var(--amber)]" />
            )}
            <span>{uiLang === "zh-CN" ? "反馈 Issue" : "Issue"}</span>
          </button>

          <button
            type="button"
            onClick={handleTogglePause}
            className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
              paused
                ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--line-strong)]"
            }`}
          >
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {paused ? "继续滚动" : "暂停滚动"}
          </button>

          <button
            type="button"
            onClick={() => void handleCopySanitized()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-[var(--green)]" />
            ) : (
              <Copy className="h-3.5 w-3.5 text-[var(--accent)]" />
            )}
            {copied ? "已复制" : "仅复制日志"}
          </button>

          <button
            type="button"
            onClick={handleExportSanitized}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
          >
            <Download className="h-3.5 w-3.5 text-[var(--sky)]" />
            导出
          </button>

          <button
            type="button"
            onClick={handleClear}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
          >
            <Trash2 className="h-3.5 w-3.5" />
            清空
          </button>
        </div>
      </section>

      {/* 超出上限自动清理提示 */}
      {truncatedCount > 0 && (
        <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)] px-3.5 py-2 text-xs text-[var(--amber)]">
          <span>
            日志已超过 {MAX_LOG_LINES} 条上限，已自动清理较早的 {truncatedCount} 条记录以保持省内存。
          </span>
        </div>
      )}

      {/* 筛选工具栏 */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-3.5">
        <div className="flex flex-wrap items-center gap-1.5">
          {ALL_LEVELS.map((lvl) => {
            const active = enabledLevels[lvl];
            const meta = LEVEL_META[lvl];
            return (
              <button
                key={lvl}
                type="button"
                onClick={() => toggleLevel(lvl)}
                className="inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1 text-xs font-medium transition-colors"
                style={{
                  borderColor: active ? meta.color : "var(--line)",
                  backgroundColor: active ? meta.softBg : "var(--bg-elevated)",
                  color: active ? meta.color : "var(--muted)",
                  opacity: active ? 1 : 0.65,
                }}
              >
                <span>{meta.label}</span>
                <span className="cc-mono text-[10px] opacity-80">{levelCounts[lvl]}</span>
              </button>
            );
          })}
        </div>

        <div className="relative min-w-[240px] flex-1 max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
          <input
            type="text"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索网址、分组、模块或关键词..."
            className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-8 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
          />
          {keyword && (
            <button
              type="button"
              onClick={() => setKeyword("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
              aria-label="清除搜索关键词"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </section>

      {/* 日志内容区 */}
      <section className="cc-card cc-glass relative overflow-hidden rounded-2xl">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-4 py-2 text-[11px] text-[var(--muted)]">
          <div className="flex flex-wrap items-center gap-2">
            <span>
              当前显示 {visibleEntries.length} / {filteredEntries.length} 条记录
            </span>
            <span>·</span>
            <span className="inline-flex items-center gap-1 text-[var(--green)]">
              <ShieldCheck className="h-3 w-3" />
              复制与导出会自动隐藏密钥、用户名和公网 IP
            </span>
          </div>
          <div className="flex items-center gap-2">
            {renderLimit > DEFAULT_RENDER_LIMIT && filteredEntries.length > DEFAULT_RENDER_LIMIT && (
              <button
                type="button"
                onClick={() => setRenderLimit(DEFAULT_RENDER_LIMIT)}
                className="text-[10px] text-[var(--accent)] hover:underline"
              >
                收起至最新 {DEFAULT_RENDER_LIMIT} 条
              </button>
            )}
            <span className="text-[10px]">
              {!runtime.running
                ? "等待核心启动"
                : autoScroll && !paused
                  ? "自动跟随最新"
                  : "手动浏览中"}
            </span>
          </div>
        </div>

        <div
          ref={scrollContainerRef}
          onScroll={handleScroll}
          className="cc-selectable cc-mono h-[520px] overflow-y-auto px-3 py-2 text-[11.5px] leading-relaxed"
        >
          {filteredEntries.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-xs text-[var(--muted)]">
              <ScrollText className="h-6 w-6 opacity-50" />
              <span>
                {entries.length === 0 && !runtime.running
                  ? "代理核心未启动，开启代理后将自动接收实时运行日志"
                  : "暂无符合条件的运行日志"}
              </span>
            </div>
          ) : (
            <div className="space-y-0.5">
              {hiddenOlderCount > 0 && (
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-[11px] text-[var(--muted)]">
                  <span>已折叠较早的 {hiddenOlderCount} 条日志（当前仅展示最新 {visibleEntries.length} 条）</span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setRenderLimit((n) => Math.min(MAX_LOG_LINES, n + RENDER_STEP))}
                      className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    >
                      显示更多 +{RENDER_STEP}
                    </button>
                    <button
                      type="button"
                      onClick={() => setRenderLimit(MAX_LOG_LINES)}
                      className="rounded-md border border-[var(--accent)] bg-[var(--accent-soft)] px-2 py-0.5 text-[var(--accent)]"
                    >
                      全部 {filteredEntries.length} 条
                    </button>
                  </div>
                </div>
              )}
              {visibleEntries.map((item) => {
                const meta = LEVEL_META[item.level];
                return (
                  <div
                    key={item.id}
                    className="flex items-start gap-2 rounded-lg px-2 py-1 hover:bg-[var(--card-hover)]"
                  >
                    <span className="shrink-0 text-[var(--muted)]">{item.time}</span>
                    <span
                      className="inline-block w-[46px] shrink-0 rounded px-1.5 py-0.5 text-center text-[10px] font-semibold leading-none"
                      style={{
                        color: meta.color,
                        backgroundColor: meta.softBg,
                      }}
                    >
                      {meta.label}
                    </span>
                    <span className="w-[118px] shrink-0 truncate text-[var(--accent)]">
                      {item.module}
                    </span>
                    <span className="min-w-0 flex-1 break-all text-[var(--text-secondary)]">
                      {item.message}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {!autoScroll && filteredEntries.length > 0 && (
          <button
            type="button"
            onClick={jumpToBottom}
            className="absolute bottom-4 right-5 inline-flex items-center gap-1.5 rounded-full border border-[var(--accent)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--accent)]"
            style={{ boxShadow: "var(--shadow-popover)" }}
          >
            <ArrowDownToLine className="h-3.5 w-3.5" />
            回到最新日志
          </button>
        )}
      </section>
    </div>
  );
}
