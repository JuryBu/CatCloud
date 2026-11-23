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
              <h1 className="text-sm font-semibold text-[var(--text)]">运行日志</h1>
              <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
                {entries.length} / {MAX_LOG_LINES} 条
              </span>
              {paused ? (
                <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--amber)]">
                  已暂停{bufferedWhilePaused > 0 ? `（新增 +${bufferedWhilePaused} 条）` : ""}
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
            {copied ? "已复制" : "复制（已自动打码隐私）"}
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
              {autoScroll && !paused ? "自动跟随最新" : "手动浏览中"}
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
              <span>暂无符合条件的运行日志</span>
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
