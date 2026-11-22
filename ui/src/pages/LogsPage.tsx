import {
  ArrowDownToLine,
  Check,
  Copy,
  Download,
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
import { appActions } from "../store/appStore";

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
    label: "Debug",
    color: "var(--muted)",
    softBg: "var(--bg-elevated)",
  },
  info: {
    label: "Info",
    color: "var(--sky)",
    softBg: "var(--sky-soft)",
  },
  warning: {
    label: "Warning",
    color: "var(--amber)",
    softBg: "var(--amber-soft)",
  },
  error: {
    label: "Error",
    color: "var(--red)",
    softBg: "var(--red-soft)",
  },
};

const ALL_LEVELS: readonly LogLevel[] = ["debug", "info", "warning", "error"] as const;

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

function formatLogTimestamp(ts?: string): string {
  if (!ts) return formatNowClock();
  const parsed = new Date(ts);
  if (!Number.isNaN(parsed.getTime())) {
    return formatNowClock(parsed);
  }
  return ts.slice(0, 12);
}

/**
 * Sanitize exported or copied logs so credentials, bearer secrets, user paths,
 * and unexpected non-documentation public IPv4 addresses are never leaked.
 */
function sanitizeLogLine(raw: string): string {
  const safeDnsIps = new Set([
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "114.114.114.114",
  ]);
  const safePrefixes = [
    "0.",
    "10.",
    "127.",
    "169.254.",
    "192.168.",
    "198.18.",
    "198.19.",
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "224.",
    "255.",
  ];

  let out = raw
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1<REDACTED>")
    .replace(/((?:password|secret|token|key)\s*[=:]\s*)([^\s,&"']+)/gi, "$1<REDACTED>")
    .replace(/[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9_.-]+/gi, "C:\\Users\\<USER>")
    .replace(/\/(?:Users|home)\/[A-Za-z0-9_.-]+/g, "/home/<USER>");

  out = out.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (full, a, b, c, d) => {
    const nums = [Number(a), Number(b), Number(c), Number(d)];
    if (nums.some((n) => n > 255)) return full;
    if (safeDnsIps.has(full)) return full;
    if (safePrefixes.some((p) => full.startsWith(p))) return full;
    if (nums[0] === 172 && nums[1] >= 16 && nums[1] <= 31) return full;
    return `${a}.${b}.***.***`;
  });

  return out;
}

function buildSeedLogs(): CoreLogEntry[] {
  const now = Date.now();
  const templates: Array<{ level: LogLevel; module: string; message: string }> = [
    {
      level: "info",
      module: "core.boot",
      message: "Mihomo Meta v1.19.12-alpha started (GOMEMLIMIT=48MiB, GOGC=35, mixed-port=17890)",
    },
    {
      level: "info",
      module: "dns.server",
      message: "DNS listener active on 127.0.0.1:11053 (mode=fake-ip, range=198.18.0.1/16, ipv6=false)",
    },
    {
      level: "info",
      module: "preaccel.probe",
      message: "Domestic probe http://connectivitycheck.platform.hicloud.com/generate_204 -> 204 OK (18ms)",
    },
    {
      level: "debug",
      module: "router.match",
      message: "[TCP] 127.0.0.1:53120 --> generativelanguage.googleapis.com:443 match DomainSuffix(googleapis.com) using AI 专线粘性组[JP-Tokyo-01 · 1x]",
    },
    {
      level: "warning",
      module: "strategy.arbiter",
      message: "Group '流媒体与下载受控均衡' observed jitter spike on SG-Edge-02 (19.4ms), cooldown 60s active",
    },
    {
      level: "info",
      module: "hotreload.l2",
      message: "Config preflight (syntax + anti-loop + mihomo -t) passed in 42ms; zero active connections dropped",
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
    module: "router.match",
    message: "[TCP] 127.0.0.1:54012 --> chatgpt.com:443 match DomainSuffix(chatgpt.com) using AI 专线粘性组[JP-Tokyo-01 · 1x]",
  },
  {
    level: "info",
    module: "preaccel.probe",
    message: "Domestic 204 heartbeat OK on CN-East-443 Primary (198.51.100.10:443, 19ms)",
  },
  {
    level: "info",
    module: "memory.gc",
    message: "Mihomo RSS 35.4 MiB / budget 48 MiB (within low-memory envelope)",
  },
];

export function LogsPage() {
  const inTauri = isTauriEnv();
  const [logState, setLogState] = useState<LogBufferState>(() => ({
    entries: inTauri ? [] : buildSeedLogs(),
    truncatedCount: 0,
  }));
  const [paused, setPaused] = useState<boolean>(false);
  const [bufferedWhilePaused, setBufferedWhilePaused] = useState<number>(0);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [keyword, setKeyword] = useState<string>("");
  const [renderLimit, setRenderLimit] = useState<number>(DEFAULT_RENDER_LIMIT);
  const [enabledLevels, setEnabledLevels] = useState<Record<LogLevel, boolean>>({
    debug: true,
    info: true,
    warning: true,
    error: true,
  });
  const [copied, setCopied] = useState<boolean>(false);

  const nextIdRef = useRef<number>(100);
  const sampleCursorRef = useRef<number>(0);
  const pausedRef = useRef<boolean>(paused);
  const pendingBufferRef = useRef<CoreLogEntry[]>([]);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const copiedTimerRef = useRef<number | null>(null);

  pausedRef.current = paused;

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
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let mockTimer: number | null = null;

    const pushIncoming = (level: LogLevel, module: string, message: string, time?: string) => {
      nextIdRef.current += 1;
      const item: CoreLogEntry = {
        id: nextIdRef.current,
        time: time ?? formatNowClock(),
        level,
        module,
        message,
      };

      if (pausedRef.current) {
        pendingBufferRef.current.push(item);
        if (pendingBufferRef.current.length > MAX_LOG_LINES) {
          pendingBufferRef.current = pendingBufferRef.current.slice(-MAX_LOG_LINES);
        }
        setBufferedWhilePaused(pendingBufferRef.current.length);
        return;
      }

      appendBatch([item]);
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

    if (inTauri) {
      // Load recent buffered backend logs first
      void catcloudApi
        .getRecentLogs(500)
        .then((lines) => {
          if (disposed || lines.length === 0) return;
          const batch: CoreLogEntry[] = lines.map((line) => {
            nextIdRef.current += 1;
            return {
              id: nextIdRef.current,
              time: formatLogTimestamp(line.timestamp),
              level: normalizeLogLevel(line.level),
              module: "mihomo",
              message: line.payload ?? "",
            };
          });
          appendBatch(batch);
        })
        .catch(() => {
          /* core may not have emitted logs yet */
        });

      void import("@tauri-apps/api/event")
        .then(({ listen }) =>
          listen<{ level?: string; module?: string; payload?: string; message?: string; time?: string; timestamp?: string }>(
            "catcloud://core-log",
            (ev) => {
              if (disposed) return;
              pushIncoming(
                normalizeLogLevel(ev.payload.level),
                ev.payload.module ?? "mihomo",
                ev.payload.message ?? ev.payload.payload ?? "",
                ev.payload.time ?? formatLogTimestamp(ev.payload.timestamp)
              );
            }
          )
        )
        .then((fn) => {
          if (disposed) {
            fn();
          } else {
            unlisten = fn;
          }
        })
        .catch(() => {
          /* never inject mock stream in Tauri runtime */
        });
    } else {
      startMockStream();
    }

    return () => {
      disposed = true;
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
        item.level.includes(kw)
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
    appActions.showToast("已清空实时日志环形缓冲", "info");
  };

  const toggleLevel = (lvl: LogLevel) => {
    setEnabledLevels((prev) => ({ ...prev, [lvl]: !prev[lvl] }));
  };

  const formatSanitizedLogText = (): string => {
    const header = [
      `# CatCloud Sanitized Core Log Export`,
      `# Exported Lines: ${filteredEntries.length} (Ring Capacity: ${MAX_LOG_LINES}, Truncated: ${truncatedCount})`,
      `# Sanitization: Sensitive tokens, user paths, and non-RFC5737 public IPs masked automatically`,
      "",
    ];
    const body = filteredEntries.map((item) =>
      sanitizeLogLine(
        `[${item.time}] [${item.level.toUpperCase().padEnd(7, " ")}] [${item.module}] ${item.message}`
      )
    );
    return header.concat(body).join("\n");
  };

  const handleCopySanitized = async () => {
    const text = formatSanitizedLogText();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      appActions.showToast(`已复制 ${filteredEntries.length} 行脱敏日志到剪贴板`, "ok");
      if (copiedTimerRef.current !== null) {
        window.clearTimeout(copiedTimerRef.current);
      }
      copiedTimerRef.current = window.setTimeout(() => {
        copiedTimerRef.current = null;
        setCopied(false);
      }, 1800);
    } catch {
      appActions.showToast("剪贴板写入受限，请改用导出 .log 文件", "warn");
    }
  };

  const handleExportSanitized = () => {
    const text = formatSanitizedLogText();
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = url;
    a.download = `catcloud-core-sanitized-${stamp}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    appActions.showToast(`已导出脱敏日志文件（${filteredEntries.length} 行）`, "ok");
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
      {/* Header & Ring Buffer Capacity Banner */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--accent)]">
            <ScrollText className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-sm font-semibold text-[var(--text)]">独立实时内核日志</h1>
              <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
                {entries.length} / {MAX_LOG_LINES} 行
              </span>
              {paused ? (
                <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--amber)]">
                  已暂停{bufferedWhilePaused > 0 ? `（待追齐 +${bufferedWhilePaused}）` : ""}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--green)]">
                  <span className="cc-pulse-dot h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                  实时流订阅中
                </span>
              )}
            </div>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              固定 2000 行环形缓冲，默认渲染最新 300 条以保持低内存与丝滑滚动；复制与导出自动执行脱敏掩码。
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
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
            {paused ? "恢复流与滚动" : "暂停滚动"}
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
            复制脱敏日志
          </button>

          <button
            type="button"
            onClick={handleExportSanitized}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
          >
            <Download className="h-3.5 w-3.5 text-[var(--sky)]" />
            导出 .log
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

      {/* Ring Buffer Truncation Notice */}
      {truncatedCount > 0 && (
        <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)] px-3.5 py-2 text-xs text-[var(--amber)]">
          <span>
            已触发 {MAX_LOG_LINES} 行环形缓冲上限截断，已自动回收 {truncatedCount} 条早期日志以保障常驻低内存。
          </span>
          <span className="cc-mono text-[11px]">Ring FIFO</span>
        </div>
      )}

      {/* Filter Toolbar */}
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
            placeholder="检索域名、策略组、模块名或错误关键词..."
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

      {/* Streaming Log Console */}
      <section className="cc-card cc-glass relative overflow-hidden rounded-2xl">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-4 py-2 text-[11px] text-[var(--muted)]">
          <div className="flex flex-wrap items-center gap-2">
            <span>
              当前渲染 {visibleEntries.length} / {filteredEntries.length} 条记录
            </span>
            <span>·</span>
            <span className="inline-flex items-center gap-1 text-[var(--green)]">
              <ShieldCheck className="h-3 w-3" />
              导出自动脱敏（密钥 / 用户名 / 非白名单公网 IP 掩码）
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
            <span className="cc-mono text-[10px]">
              {autoScroll && !paused ? "自动贴底" : "手动浏览模式"}
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
              <span>暂无符合当前级别与关键词条件的内核日志</span>
            </div>
          ) : (
            <div className="space-y-0.5">
              {hiddenOlderCount > 0 && (
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-[11px] text-[var(--muted)]">
                  <span>已折叠较早的 {hiddenOlderCount} 条日志（仅渲染最新 {visibleEntries.length} 条）</span>
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
                      className="inline-block w-[58px] shrink-0 rounded px-1.5 py-0.5 text-center text-[10px] font-semibold uppercase leading-none"
                      style={{
                        color: meta.color,
                        backgroundColor: meta.softBg,
                      }}
                    >
                      {item.level}
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
