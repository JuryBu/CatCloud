import {
  BookOpen,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  FileText,
  Loader2,
  MessageSquareWarning,
  RefreshCw,
  Sparkles,
  Stethoscope,
  Terminal,
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type AgentBootstrapPromptDto,
  type AgentModuleDoc,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect } from "../components/AppSelect";
import {
  UI_LANGUAGE_OPTIONS,
  type UiLanguage,
  normalizeUiLanguage,
  useUiDict,
} from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";

interface ReadonlyCliItem {
  cmd: string;
  descZh: string;
  descEn: string;
}

const READONLY_CLI_ITEMS: readonly ReadonlyCliItem[] = [
  {
    cmd: "catcloud status --json",
    descZh: "查看代理核心运行状态、当前节点、模式与本地端口",
    descEn: "Inspect core status, active node, proxy mode, and local ports",
  },
  {
    cmd: "catcloud net doctor --json",
    descZh: "六层只读网络诊断（端口、代理、DNS、规则、提速与外网）",
    descEn: "6-layer read-only network diagnostics (ports, proxy, DNS, rules, boost)",
  },
  {
    cmd: "catcloud net connections --json",
    descZh: "查看当前活跃连接与命中的分流规则",
    descEn: "List active connections and matched routing rules",
  },
  {
    cmd: "catcloud net match example.com --json",
    descZh: "测试指定域名命中的分流规则与实际出口",
    descEn: "Test which routing rule and outbound a domain matches",
  },
  {
    cmd: "catcloud logs tail --lines 80 --since 30m --json",
    descZh: "读取近 30 分钟最近 80 条自动脱敏运行日志（支持时间窗过滤）",
    descEn: "Read the latest 80 sanitized log lines within a time window",
  },
  {
    cmd: "catcloud group members --id <id> add --nodes <node_id> --json",
    descZh: "向已有智能多选组安全增删节点（不影响策略与分流规则）",
    descEn: "Safely add/remove nodes in a smart group without resetting policies",
  },
  {
    cmd: "catcloud sub list --json",
    descZh: "查看已导入订阅与节点分组概览（自动脱敏链接）",
    descEn: "List imported subscriptions and node groups (URLs sanitized)",
  },
  {
    cmd: "catcloud config diag --json",
    descZh: "导出完整脱敏环境与排障诊断快照",
    descEn: "Export full sanitized diagnostic snapshot",
  },
  {
    cmd: "catcloud share inspect <pack.zip> --json",
    descZh: "只读检查好友分享包（.zip）内的节点与中转清单",
    descEn: "Read-only inspection of a friend share bundle (.zip)",
  },
] as const;

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fallback below */
  }
  if (typeof document === "undefined") return false;
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "");
    el.style.position = "fixed";
    el.style.left = "-9999px";
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

function downloadMarkdownFallback(fileName: string, content: string): void {
  if (typeof document === "undefined") return;
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function renderInlineMarkdown(text: string): ReactNode[] {
  const tokens = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return tokens.map((part, idx) => {
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      return (
        <code
          key={idx}
          className="cc-mono rounded bg-[var(--bg-elevated)] px-1 py-0.5 text-[11px] text-[var(--accent)]"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
      return (
        <strong key={idx} className="font-semibold text-[var(--text)]">
          {part.slice(2, -2)}
        </strong>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

function CompactMarkdownView({ content }: { content: string }) {
  const blocks = useMemo(() => {
    const lines = content.replace(/\r\n/g, "\n").split("\n");
    const out: Array<
      | { type: "h1" | "h2" | "h3" | "p" | "quote"; text: string }
      | { type: "code"; lang: string; code: string }
      | { type: "list"; items: string[]; ordered: boolean }
    > = [];

    let i = 0;
    while (i < lines.length) {
      const raw = lines[i];
      const trimmed = raw.trim();

      if (!trimmed) {
        i += 1;
        continue;
      }

      if (trimmed.startsWith("```")) {
        const lang = trimmed.slice(3).trim();
        const codeLines: string[] = [];
        i += 1;
        while (i < lines.length && !lines[i].trim().startsWith("```")) {
          codeLines.push(lines[i]);
          i += 1;
        }
        if (i < lines.length) i += 1;
        out.push({ type: "code", lang, code: codeLines.join("\n") });
        continue;
      }

      if (trimmed.startsWith("### ")) {
        out.push({ type: "h3", text: trimmed.slice(4).trim() });
        i += 1;
        continue;
      }
      if (trimmed.startsWith("## ")) {
        out.push({ type: "h2", text: trimmed.slice(3).trim() });
        i += 1;
        continue;
      }
      if (trimmed.startsWith("# ")) {
        out.push({ type: "h1", text: trimmed.slice(2).trim() });
        i += 1;
        continue;
      }
      if (trimmed.startsWith("> ")) {
        const quoteLines: string[] = [];
        while (i < lines.length && lines[i].trim().startsWith("> ")) {
          quoteLines.push(lines[i].trim().slice(2).trim());
          i += 1;
        }
        out.push({ type: "quote", text: quoteLines.join(" ") });
        continue;
      }
      if (/^[-*]\s+/.test(trimmed)) {
        const items: string[] = [];
        while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
          items.push(lines[i].trim().replace(/^[-*]\s+/, ""));
          i += 1;
        }
        out.push({ type: "list", items, ordered: false });
        continue;
      }
      if (/^\d+\.\s+/.test(trimmed)) {
        const items: string[] = [];
        while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
          items.push(lines[i].trim().replace(/^\d+\.\s+/, ""));
          i += 1;
        }
        out.push({ type: "list", items, ordered: true });
        continue;
      }

      const paraLines: string[] = [trimmed];
      i += 1;
      while (
        i < lines.length &&
        lines[i].trim() !== "" &&
        !/^(#{1,3}\s|```|>\s|[-*]\s|\d+\.\s)/.test(lines[i].trim())
      ) {
        paraLines.push(lines[i].trim());
        i += 1;
      }
      out.push({ type: "p", text: paraLines.join(" ") });
    }
    return out;
  }, [content]);

  return (
    <div className="min-w-0 space-y-2.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
      {blocks.map((block, idx) => {
        if (block.type === "h1") {
          return (
            <h3 key={idx} className="pt-0.5 text-sm font-semibold text-[var(--text)]">
              {renderInlineMarkdown(block.text)}
            </h3>
          );
        }
        if (block.type === "h2") {
          return (
            <h4
              key={idx}
              className="border-t border-[var(--line)]/60 pt-2 text-[13px] font-semibold text-[var(--text)] first:border-t-0 first:pt-0"
            >
              {renderInlineMarkdown(block.text)}
            </h4>
          );
        }
        if (block.type === "h3") {
          return (
            <h5 key={idx} className="pt-1 text-xs font-semibold text-[var(--accent)]">
              {renderInlineMarkdown(block.text)}
            </h5>
          );
        }
        if (block.type === "quote") {
          return (
            <blockquote
              key={idx}
              className="rounded-r-lg border-l-2 border-[var(--accent)] bg-[var(--bg-elevated)]/70 px-3 py-1.5 text-[11.5px] text-[var(--text-secondary)]"
            >
              {renderInlineMarkdown(block.text)}
            </blockquote>
          );
        }
        if (block.type === "code") {
          return (
            <pre
              key={idx}
              className="cc-mono max-w-full overflow-x-auto rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text)]"
            >
              {block.code}
            </pre>
          );
        }
        if (block.type === "list") {
          const Tag = block.ordered ? "ol" : "ul";
          return (
            <Tag
              key={idx}
              className={`space-y-1 pl-4 ${block.ordered ? "list-decimal" : "list-disc"}`}
            >
              {block.items.map((item, itemIdx) => (
                <li key={itemIdx} className="pl-0.5">
                  {renderInlineMarkdown(item)}
                </li>
              ))}
            </Tag>
          );
        }
        return <p key={idx}>{renderInlineMarkdown(block.text)}</p>;
      })}
    </div>
  );
}

export function AiAssistantPage() {
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const aiRouteHint = useAppSelector((s) => s.aiRouteHint);
  const dict = useUiDict(uiLang);
  const isZh = uiLang === "zh-CN";
  const inTauri = isTauriEnv();

  const [docLang, setDocLang] = useState<UiLanguage>(uiLang);
  const prevUiLangRef = useRef<UiLanguage>(uiLang);

  useEffect(() => {
    if (prevUiLangRef.current !== uiLang) {
      const wasFollowingUi = docLang === prevUiLangRef.current;
      prevUiLangRef.current = uiLang;
      if (wasFollowingUi) {
        setDocLang(uiLang);
      }
    }
  }, [docLang, uiLang]);

  const [docs, setDocs] = useState<AgentModuleDoc[]>([]);
  const [docsLoading, setDocsLoading] = useState<boolean>(true);
  const [docsError, setDocsError] = useState<string | null>(null);
  const [catalogReloadTick, setCatalogReloadTick] = useState<number>(0);
  const [selectedDocId, setSelectedDocId] = useState<string>(
    () => aiRouteHint?.moduleId || "troubleshooting"
  );

  const [docContent, setDocContent] = useState<string>("");
  const [docLoading, setDocLoading] = useState<boolean>(false);
  const [docError, setDocError] = useState<string | null>(null);

  const [bootstrapInfo, setBootstrapInfo] = useState<AgentBootstrapPromptDto | null>(null);
  const [highlightAgentCard, setHighlightAgentCard] = useState<boolean>(false);
  const [showAgentPaths, setShowAgentPaths] = useState<boolean>(false);

  const [manualsAccordionOpen, setManualsAccordionOpen] = useState<boolean>(() =>
    Boolean(aiRouteHint?.moduleId)
  );
  const [cliAccordionOpen, setCliAccordionOpen] = useState<boolean>(false);
  const [issueAccordionOpen, setIssueAccordionOpen] = useState<boolean>(false);
  const [issueSummary, setIssueSummary] = useState<string>("");

  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const docCacheRef = useRef<Map<string, string>>(new Map());
  const copyTimerRef = useRef<number | null>(null);
  const highlightTimerRef = useRef<number | null>(null);
  const pendingHintModuleRef = useRef<string | null>(aiRouteHint?.moduleId ?? null);

  const flashCopied = useCallback((key: string) => {
    setCopiedKey(key);
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      copyTimerRef.current = null;
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 2000);
  }, []);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      if (highlightTimerRef.current !== null) {
        window.clearTimeout(highlightTimerRef.current);
      }
    };
  }, []);

  // Consume external route hints (e.g. from LogsPage -> troubleshooting)
  useEffect(() => {
    if (!aiRouteHint) return;
    if (aiRouteHint.moduleId) {
      pendingHintModuleRef.current = aiRouteHint.moduleId;
      setSelectedDocId(aiRouteHint.moduleId);
      setManualsAccordionOpen(true);
    }
    if (aiRouteHint.tab === "agent") {
      setHighlightAgentCard(true);
      if (highlightTimerRef.current !== null) {
        window.clearTimeout(highlightTimerRef.current);
      }
      highlightTimerRef.current = window.setTimeout(() => {
        highlightTimerRef.current = null;
        setHighlightAgentCard(false);
      }, 1800);
    }
    appActions.consumeAiRouteHint();
  }, [aiRouteHint]);

  // Load lightweight 8-doc catalog + local agent paths whenever docLang changes
  useEffect(() => {
    let cancelled = false;
    setDocsLoading(true);
    setDocsError(null);

    void Promise.allSettled([
      catcloudApi.listAgentDocs(docLang),
      catcloudApi.buildAgentBootstrapPrompt(docLang, "ai", "autopilot"),
    ]).then(([docsRes, bootRes]) => {
      if (cancelled) return;
      if (docsRes.status === "fulfilled") {
        const list = Array.isArray(docsRes.value) ? docsRes.value : [];
        setDocs(list);
        if (list.length > 0) {
          const hintId = pendingHintModuleRef.current;
          setSelectedDocId((prev) => {
            if (hintId && list.some((d) => d.id === hintId)) {
              pendingHintModuleRef.current = null;
              return hintId;
            }
            if (list.some((d) => d.id === prev)) {
              return prev;
            }
            return list[0].id;
          });
        }
      } else {
        setDocsError(formatErrorMessage(docsRes.reason) || "加载手册目录失败");
      }
      if (bootRes.status === "fulfilled") {
        setBootstrapInfo(bootRes.value);
      }
      setDocsLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [docLang, catalogReloadTick]);

  // On-demand single manual fetch (cached per lang:docId)
  const loadSingleDoc = useCallback(
    async (docId: string, lang: UiLanguage, force = false) => {
      if (!docId) return;
      const cacheKey = `${lang}:${docId}`;
      const cached = docCacheRef.current.get(cacheKey);
      if (!force && cached !== undefined) {
        setDocContent(cached);
        setDocError(null);
        setDocLoading(false);
        return;
      }
      setDocLoading(true);
      setDocError(null);
      try {
        const md = await catcloudApi.exportAgentDocs(docId, false, lang);
        docCacheRef.current.set(cacheKey, md);
        setDocContent(md);
      } catch (err) {
        setDocError(formatErrorMessage(err) || "加载手册正文失败");
      } finally {
        setDocLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (!selectedDocId) return;
    let cancelled = false;
    const cacheKey = `${docLang}:${selectedDocId}`;
    const cached = docCacheRef.current.get(cacheKey);
    if (cached !== undefined) {
      setDocContent(cached);
      setDocError(null);
      setDocLoading(false);
      return;
    }

    setDocLoading(true);
    setDocError(null);
    void catcloudApi
      .exportAgentDocs(selectedDocId, false, docLang)
      .then((md) => {
        if (cancelled) return;
        docCacheRef.current.set(cacheKey, md);
        setDocContent(md);
      })
      .catch((err) => {
        if (cancelled) return;
        setDocError(formatErrorMessage(err) || "加载手册正文失败");
      })
      .finally(() => {
        if (!cancelled) {
          setDocLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [docLang, selectedDocId]);

  const activeDocMeta = useMemo(
    () => docs.find((d) => d.id === selectedDocId) ?? docs[0] ?? null,
    [docs, selectedDocId]
  );

  const handleCopyWebGuide = async () => {
    if (busyAction) return;
    setBusyAction("web-guide");
    try {
      const ok = await appActions.copyAiOnboardingForUser(docLang, selectedDocId);
      if (ok) flashCopied("web-guide");
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopyDiag = async (sourceKey: "web-diag" | "agent-diag") => {
    if (busyAction) return;
    setBusyAction(sourceKey);
    try {
      const ok = await appActions.copySanitizedDiagnosticsForAi();
      if (ok) flashCopied(sourceKey);
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopyAgentBootstrap = async (mode: "autopilot" | "readonly" = "autopilot") => {
    if (busyAction) return;
    const actionKey = mode === "readonly" ? "agent-readonly" : "agent-autopilot";
    setBusyAction(actionKey);
    try {
      const ok = await appActions.copyAgentBootstrapPrompt(docLang, mode);
      if (ok) flashCopied(actionKey);
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportSingleDoc = async (docId: string) => {
    if (busyAction || !docId) return;
    setBusyAction("export-md");
    try {
      const outcome = await catcloudApi.exportAgentDocFileDialog(docId, docLang);
      if (outcome.cancelled) return;
      if (!inTauri) {
        const md =
          docCacheRef.current.get(`${docLang}:${docId}`) ||
          (await catcloudApi.exportAgentDocs(docId, false, docLang));
        downloadMarkdownFallback(
          outcome.path || `catcloud-guide-${docId}-${docLang}.md`,
          md
        );
      }
      appActions.showToast(
        isZh
          ? `已导出手册文件：${outcome.path ?? `${docId}.md`}`
          : `Exported manual: ${outcome.path ?? `${docId}.md`}`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(
        `${isZh ? "导出手册失败" : "Failed to export manual"}: ${formatErrorMessage(err)}`,
        "warn"
      );
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopyCurrentDoc = async () => {
    const content = docContent.trim();
    if (!content) return;
    const ok = await copyToClipboard(content);
    if (ok) {
      flashCopied("doc-copy");
      appActions.showToast(
        isZh
          ? `已复制手册「${activeDocMeta?.title ?? selectedDocId}」`
          : `Copied manual: ${activeDocMeta?.title ?? selectedDocId}`,
        "ok"
      );
    } else {
      appActions.showToast(
        isZh ? "无法写入剪贴板，请改用「导出 .md」" : "Clipboard unavailable; use Export .md instead",
        "warn"
      );
    }
  };

  const handleCopyCli = async (cmd: string, key: string) => {
    const ok = await copyToClipboard(cmd);
    if (ok) {
      flashCopied(key);
      appActions.showToast(isZh ? "已复制只读诊断命令" : "Copied read-only CLI command", "ok");
    } else {
      appActions.showToast(isZh ? "无法写入剪贴板" : "Clipboard unavailable", "warn");
    }
  };

  const handleOpenIssue = async (summaryText?: string) => {
    if (busyAction) return;
    setBusyAction("github-issue");
    try {
      await appActions.openGithubIssueFeedback(summaryText);
    } finally {
      setBusyAction(null);
    }
  };

  const languageSelectOptions = useMemo(
    () =>
      UI_LANGUAGE_OPTIONS.map((item) => ({
        value: item.value,
        label: item.optionLabel,
      })),
    []
  );

  const cliPathPreview = bootstrapInfo?.cli_path || "catcloud";
  const docsIndexPreview =
    bootstrapInfo?.docs_index_path || `<data_dir>/agent_docs/${docLang}/INDEX.md`;

  return (
    <div className="space-y-4 pb-3">
      {/* Top Compact Header Bar */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3.5">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <Bot className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-[var(--text)]">
              {dict.aiHub.title}
            </h1>
            <p className="mt-0.5 truncate text-xs text-[var(--muted)]">
              {dict.aiHub.subtitle}
            </p>
          </div>
        </div>

        <div className="flex max-w-full flex-wrap items-center gap-2">
          <div className="flex max-w-full flex-wrap items-center gap-2">
            <span className="whitespace-nowrap text-[11px] font-medium text-[var(--muted)]">
              {dict.aiHub.docLanguageLabel}
            </span>
            <AppSelect
              aria-label={dict.aiHub.docLanguageLabel}
              size="sm"
              value={docLang}
              onChange={(v) => setDocLang(normalizeUiLanguage(v))}
              options={languageSelectOptions}
              className="min-w-[168px] max-w-full"
            />
          </div>

          <button
            type="button"
            onClick={() => appActions.openOnboardingModal()}
            className="inline-flex h-8 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--accent)]/45 bg-[var(--accent-soft)]/70 px-3 text-xs font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
          >
            <Sparkles className="h-3.5 w-3.5 shrink-0" />
            <span>{dict.aiHub.reopenOnboardingBtn}</span>
          </button>

          <button
            type="button"
            disabled={busyAction === "github-issue"}
            onClick={() => void handleOpenIssue()}
            className="inline-flex h-8 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
          >
            {busyAction === "github-issue" ? (
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
            ) : (
              <MessageSquareWarning className="h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
            )}
            <span>{dict.aiHub.reportIssueBtn}</span>
          </button>
        </div>
      </section>

      {/* Dual Audience Equal-Height Cards: Left Hero = Local AI Agent Autopilot | Right = Web AI Walkthrough */}
      <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-2">
        {/* Left Hero Card: Local AI Agent Full Autopilot */}
        <section
          className={`cc-card cc-glass flex flex-col justify-between gap-3.5 rounded-2xl border-[var(--accent)]/60 p-4 transition-colors ${
            highlightAgentCard ? "border-[var(--accent)] ring-2 ring-[var(--accent)]/40" : ""
          }`}
          style={{
            background:
              "linear-gradient(135deg, color-mix(in srgb, var(--accent-soft) 55%, var(--card)) 0%, var(--card) 100%)",
          }}
        >
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent)] text-[var(--accent-ink)]">
                  <Cpu className="h-4 w-4" />
                </span>
                <h2 className="text-sm font-bold text-[var(--text)]">
                  {dict.aiHub.agentTitle}
                </h2>
              </div>
              <span className="rounded-full border border-[var(--accent)]/45 bg-[var(--surface)]/90 px-2.5 py-0.5 text-[10.5px] font-semibold text-[var(--accent)]">
                {dict.aiHub.agentCardBadge}
              </span>
            </div>

            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              {dict.aiHub.agentDesc}
            </p>

            {/* Collapsible single-line CLI & Manual Path Disclosure (no terminal wall on first glance) */}
            <div className="rounded-xl border border-[var(--line)]/80 bg-[var(--bg-elevated)]/75">
              <button
                type="button"
                onClick={() => setShowAgentPaths((v) => !v)}
                aria-expanded={showAgentPaths}
                className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:text-[var(--text)]"
              >
                <span className="inline-flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span>
                    {showAgentPaths ? dict.aiHub.agentHidePaths : dict.aiHub.agentShowPaths}
                  </span>
                </span>
                {showAgentPaths ? (
                  <ChevronDown className="h-3.5 w-3.5 text-[var(--muted)]" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5 text-[var(--muted)]" />
                )}
              </button>
              {showAgentPaths && (
                <div className="space-y-1 border-t border-[var(--line)]/70 px-3 py-2 text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="w-12 shrink-0 font-medium text-[var(--muted)]">CLI</span>
                    <code
                      title={cliPathPreview}
                      className="cc-mono cc-selectable min-w-0 flex-1 truncate text-[var(--text)]"
                    >
                      {cliPathPreview}
                    </code>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-12 shrink-0 font-medium text-[var(--muted)]">
                      {isZh ? "手册树" : "Manuals"}
                    </span>
                    <code
                      title={docsIndexPreview}
                      className="cc-mono cc-selectable min-w-0 flex-1 truncate text-[var(--text-secondary)]"
                    >
                      {docsIndexPreview}
                    </code>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyAgentBootstrap("autopilot")}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {copiedKey === "agent-autopilot" ? (
                <Check className="h-3.5 w-3.5" />
              ) : busyAction === "agent-autopilot" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Terminal className="h-3.5 w-3.5" />
              )}
              <span>
                {copiedKey === "agent-autopilot"
                  ? dict.common.copied
                  : dict.aiHub.agentCopyBootstrap}
              </span>
            </button>

            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyAgentBootstrap("readonly")}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] px-3 py-2 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
            >
              {copiedKey === "agent-readonly" ? (
                <Check className="h-3.5 w-3.5 text-[var(--green)]" />
              ) : busyAction === "agent-readonly" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Stethoscope className="h-3.5 w-3.5 text-[var(--sky)]" />
              )}
              <span>
                {copiedKey === "agent-readonly"
                  ? dict.common.copied
                  : dict.aiHub.agentCopyReadonly}
              </span>
            </button>

            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyDiag("agent-diag")}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-2.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
            >
              {copiedKey === "agent-diag" ? (
                <Check className="h-3.5 w-3.5 text-[var(--green)]" />
              ) : busyAction === "agent-diag" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-[var(--accent)]" />
              )}
              <span>
                {copiedKey === "agent-diag"
                  ? dict.common.copied
                  : dict.aiHub.webAiCopyDiag}
              </span>
            </button>
          </div>
        </section>

        {/* Right Card: Web AI Step-by-Step Guide */}
        <section className="cc-card cc-glass flex flex-col justify-between gap-4 rounded-2xl p-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--sky-soft)] text-[var(--sky)]">
                  <Sparkles className="h-4 w-4" />
                </span>
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  {dict.aiHub.webAiTitle}
                </h2>
              </div>
              <span className="rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10px] font-medium text-[var(--muted)]">
                {dict.onboarding.aiSupportWebNames}
              </span>
            </div>

            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              {dict.aiHub.webAiDesc}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyWebGuide()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--accent)]/60 bg-[var(--accent-soft)] px-3.5 py-2 text-xs font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:opacity-60"
            >
              {copiedKey === "web-guide" ? (
                <Check className="h-3.5 w-3.5" />
              ) : busyAction === "web-guide" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              <span>
                {copiedKey === "web-guide" ? dict.common.copied : dict.aiHub.webAiCopyGuide}
              </span>
            </button>

            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyDiag("web-diag")}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
            >
              {copiedKey === "web-diag" ? (
                <Check className="h-3.5 w-3.5 text-[var(--green)]" />
              ) : busyAction === "web-diag" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Stethoscope className="h-3.5 w-3.5 text-[var(--sky)]" />
              )}
              <span>
                {copiedKey === "web-diag" ? dict.common.copied : dict.aiHub.webAiCopyDiag}
              </span>
            </button>

            <button
              type="button"
              disabled={busyAction !== null || !selectedDocId}
              onClick={() => void handleExportSingleDoc(selectedDocId)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
            >
              {busyAction === "export-md" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5 text-[var(--muted)]" />
              )}
              <span>{dict.aiHub.webAiExportMd}</span>
            </button>
          </div>
        </section>
      </div>

      {/* Collapsible Bundled Manuals (8 docs): Collapsed by Default with Chapter Preview Chips */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <button
          type="button"
          onClick={() => setManualsAccordionOpen((open) => !open)}
          aria-expanded={manualsAccordionOpen}
          className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
        >
          <div className="flex min-w-0 items-center gap-2.5">
            <BookOpen className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="truncate text-xs font-semibold text-[var(--text)]">
                  {dict.aiHub.tabManuals}
                </span>
                <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10px] text-[var(--muted)]">
                  {isZh ? `${docs.length || 8} 篇` : `${docs.length || 8} docs`}
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-[var(--muted)]">
                {dict.aiHub.manualsExpandHint}
              </p>
            </div>
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            {manualsAccordionOpen ? dict.aiHub.manualsCollapseBtn : dict.aiHub.manualsExpandBtn}
            {manualsAccordionOpen ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </span>
        </button>

        {/* Compact module catalog overview chips when collapsed */}
        {!manualsAccordionOpen && docs.length > 0 && (
          <div className="flex flex-wrap gap-1.5 border-t border-[var(--line)]/65 bg-[var(--bg-elevated)]/40 px-4 py-2.5">
            {docs.map((doc) => (
              <button
                key={doc.id}
                type="button"
                onClick={() => {
                  setSelectedDocId(doc.id);
                  setManualsAccordionOpen(true);
                }}
                title={doc.summary || doc.title}
                className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
              >
                {doc.title}
              </button>
            ))}
          </div>
        )}

        {manualsAccordionOpen && (
          <div className="border-t border-[var(--line)] p-4">
            <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-12">
          {/* Left Column: Lightweight 8-doc Index */}
          <div className="min-w-0 space-y-1 min-[1160px]:col-span-4">
            {docsLoading ? (
              <div className="flex items-center justify-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/60 py-10 text-xs text-[var(--muted)]">
                <Loader2 className="h-4 w-4 animate-spin text-[var(--accent)]" />
                <span>{dict.common.loading}</span>
              </div>
            ) : docsError ? (
              <div className="space-y-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/50 p-3 text-xs text-[var(--amber)]">
                <div>{docsError}</div>
                <button
                  type="button"
                  onClick={() => setCatalogReloadTick((n) => n + 1)}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--amber)]/50 bg-[var(--surface)] px-2.5 py-1 text-[11px] text-[var(--text)]"
                >
                  <RefreshCw className="h-3 w-3" />
                  <span>{dict.common.refresh}</span>
                </button>
              </div>
            ) : (
              docs.map((doc) => {
                const active = doc.id === selectedDocId;
                return (
                  <button
                    key={doc.id}
                    type="button"
                    onClick={() => setSelectedDocId(doc.id)}
                    aria-current={active ? "true" : undefined}
                    className={`group relative flex w-full flex-col gap-0.5 rounded-xl border px-3 py-2 text-left transition-colors ${
                      active
                        ? "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--text)]"
                        : "border-transparent bg-[var(--surface)]/55 text-[var(--text-secondary)] hover:border-[var(--line)] hover:bg-[var(--card-hover)] hover:text-[var(--text)]"
                    }`}
                  >
                    {active && (
                      <span
                        className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--accent)]"
                        aria-hidden="true"
                      />
                    )}
                    <span className="truncate text-xs font-semibold">
                      {doc.title}
                    </span>
                    {doc.summary && (
                      <span className="truncate text-[11px] text-[var(--muted)]">
                        {doc.summary}
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>

          {/* Right Column: On-Demand Single Manual Preview Card */}
          <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-[var(--line)] bg-[var(--surface)]/70 min-[1160px]:col-span-8">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] px-3.5 py-2.5">
              <div className="flex min-w-0 items-center gap-2">
                <FileText className="h-4 w-4 shrink-0 text-[var(--accent)]" />
                <span className="truncate text-xs font-semibold text-[var(--text)]">
                  {activeDocMeta?.title ?? selectedDocId}
                </span>
                {activeDocMeta?.file_name && (
                  <span className="hidden shrink-0 rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 cc-mono text-[10px] text-[var(--muted)] sm:inline-block">
                    {activeDocMeta.file_name}
                  </span>
                )}
              </div>

              <div className="flex shrink-0 items-center gap-1.5">
                <button
                  type="button"
                  disabled={docLoading || !docContent.trim()}
                  onClick={() => void handleCopyCurrentDoc()}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                >
                  {copiedKey === "doc-copy" ? (
                    <Check className="h-3 w-3 text-[var(--green)]" />
                  ) : (
                    <Copy className="h-3 w-3 text-[var(--accent)]" />
                  )}
                  <span>
                    {copiedKey === "doc-copy"
                      ? dict.common.copied
                      : isZh
                        ? "复制本篇"
                        : dict.common.copy}
                  </span>
                </button>

                <button
                  type="button"
                  disabled={busyAction !== null || !selectedDocId}
                  onClick={() => void handleExportSingleDoc(selectedDocId)}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  <Download className="h-3 w-3" />
                  <span>{isZh ? "导出 .md" : `${dict.common.export} .md`}</span>
                </button>
              </div>
            </div>

            <div className="cc-selectable min-w-0 max-h-[clamp(220px,calc(100vh-300px),440px)] min-h-[200px] overflow-y-auto px-4 py-3.5">
              {docLoading ? (
                <div className="flex h-[220px] items-center justify-center gap-2 text-xs text-[var(--muted)]">
                  <Loader2 className="h-4 w-4 animate-spin text-[var(--accent)]" />
                  <span>{dict.common.loading}</span>
                </div>
              ) : docError ? (
                <div className="flex h-[220px] flex-col items-center justify-center gap-2 text-center text-xs text-[var(--amber)]">
                  <span>{docError}</span>
                  <button
                    type="button"
                    onClick={() => void loadSingleDoc(selectedDocId, docLang, true)}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1 text-xs text-[var(--text)] hover:border-[var(--accent)]"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    <span>{dict.common.refresh}</span>
                  </button>
                </div>
              ) : docContent.trim() ? (
                <CompactMarkdownView content={docContent} />
              ) : (
                <div className="flex h-[220px] items-center justify-center text-xs text-[var(--muted)]">
                  {isZh ? "从左侧任选一篇手册即可展开预览" : "Pick any manual on the left to preview"}
                </div>
              )}
            </div>
          </div>
        </div>
          </div>
        )}
      </section>

      {/* Bottom Collapsed Accordion 1: Read-Only Diagnostic CLI Quick Reference */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <button
          type="button"
          onClick={() => setCliAccordionOpen((open) => !open)}
          aria-expanded={cliAccordionOpen}
          className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
        >
          <div className="flex min-w-0 items-center gap-2.5">
            <Terminal className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            <div className="min-w-0">
              <div className="truncate text-xs font-semibold text-[var(--text)]">
                {isZh ? "本机只读听诊 CLI 命令速查" : dict.aiHub.tabCli}
              </div>
              <p className="truncate text-[11px] text-[var(--muted)]">
                {isZh
                  ? "仅查询状态、诊断链路、查连接/分流与读取脱敏日志，不改动你的配置"
                  : "Read-only commands for status, network doctor, connections, rule match, and sanitized logs"}
              </p>
            </div>
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            {cliAccordionOpen ? (isZh ? "收起" : "Hide") : isZh ? "展开" : "Show"}
            {cliAccordionOpen ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </span>
        </button>

        {cliAccordionOpen && (
          <div className="space-y-2 border-t border-[var(--line)] p-4">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] text-[var(--muted)]">
                {isZh
                  ? "点击任意行右侧即可一键复制命令（所有输出均带 --json 且自动脱敏）"
                  : "Click copy on any row (all outputs are structured --json and sanitized)"}
              </span>
              <button
                type="button"
                onClick={() =>
                  void handleCopyCli(
                    READONLY_CLI_ITEMS.map((item) => item.cmd).join("\n"),
                    "cli-all"
                  )
                }
                className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
              >
                {copiedKey === "cli-all" ? (
                  <Check className="h-3 w-3 text-[var(--green)]" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
                <span>{copiedKey === "cli-all" ? dict.common.copied : isZh ? "复制全部" : "Copy All"}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 gap-1.5 min-[1160px]:grid-cols-2">
              {READONLY_CLI_ITEMS.map((item) => {
                const key = `cli:${item.cmd}`;
                return (
                  <div
                    key={item.cmd}
                    className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="break-all cc-mono cc-selectable text-[11px] leading-snug text-[var(--text)]">
                        {item.cmd}
                      </div>
                      <div className="mt-0.5 truncate text-[11px] text-[var(--muted)]">
                        {isZh ? item.descZh : item.descEn}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleCopyCli(item.cmd, key)}
                      title={dict.common.copy}
                      aria-label={`${dict.common.copy} ${item.cmd}`}
                      className="shrink-0 rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    >
                      {copiedKey === key ? (
                        <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* Bottom Collapsed Accordion 2: One-Click GitHub Issue Feedback */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <button
          type="button"
          onClick={() => setIssueAccordionOpen((open) => !open)}
          aria-expanded={issueAccordionOpen}
          className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
        >
          <div className="flex min-w-0 items-center gap-2.5">
            <MessageSquareWarning className="h-4 w-4 shrink-0 text-[var(--amber)]" />
            <div className="min-w-0">
              <div className="truncate text-xs font-semibold text-[var(--text)]">
                {dict.aiHub.issueCardTitle}
              </div>
              <p className="truncate text-[11px] text-[var(--muted)]">
                {isZh
                  ? "自动复制脱敏环境与异常摘要并拉起 GitHub Issue 新建页"
                  : "Copies sanitized diagnostics automatically and opens a pre-filled GitHub Issue"}
              </p>
            </div>
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            {issueAccordionOpen ? (isZh ? "收起" : "Hide") : isZh ? "展开" : "Show"}
            {issueAccordionOpen ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </span>
        </button>

        {issueAccordionOpen && (
          <div className="space-y-3 border-t border-[var(--line)] p-4">
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              {dict.aiHub.issueCardDesc}
            </p>
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <input
                type="text"
                value={issueSummary}
                onChange={(e) => setIssueSummary(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void handleOpenIssue(issueSummary);
                  }
                }}
                placeholder={
                  isZh
                    ? "可选：用一句话描述遇到的问题（例如：开启虚拟网卡后无法访问某网站）"
                    : "Optional: one-line summary of the issue you encountered"
                }
                className="min-w-0 flex-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs text-[var(--text)] placeholder:text-[var(--muted)] outline-none focus:border-[var(--accent)]"
              />
              <button
                type="button"
                disabled={busyAction === "github-issue"}
                onClick={() => void handleOpenIssue(issueSummary)}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                {busyAction === "github-issue" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <ExternalLink className="h-3.5 w-3.5" />
                )}
                <span>{dict.aiHub.issueButton}</span>
              </button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
