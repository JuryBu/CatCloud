import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  FileCode2,
  Filter,
  Layers,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  type DynamicFilterSpec,
  type FallbackPolicy,
  type GroupEvaluationReport,
  type MultiGroup,
  type MultiGroupMode,
  type ProbeSnapshot,
  type ProxyNode,
  type TriggerRule,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { ContinentRegionFilter, PaginationBar } from "../components/ContinentRegionFilter";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import {
  type ContinentId,
  buildContinentRegionStats,
  getRegionLabel,
  nodeMatchesContinentAndRegion,
  resolveNodeRegionCode,
} from "../utils/regions";

/* ============================================================================
 * Constants & Human-Friendly Presets
 * ============================================================================ */

const FORMULA_COST_EFFECTIVE =
  "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)";

const FORMULA_MAX_PERF =
  "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1";

const DEFAULT_MISSING_PING_MS = 9999;
const EPSILON_ZERO = 1e-12;
const EPSILON_EQ = 1e-9;
const NODE_PAGE_SIZE_OPTIONS = [24, 48, 96] as const;

const FRIENDLY_GROUP_NAME_MAP: Record<string, string> = {
  流媒体与下载受控均衡: "影音下载均衡组",
  高优家宽备援池: "备用精选组",
};

function formatGroupDisplayName(name: string): string {
  return FRIENDLY_GROUP_NAME_MAP[name] ?? name;
}

type CreateTemplateId = "manual" | "ai" | "download";

interface CreateTemplateMeta {
  id: CreateTemplateId;
  title: string;
  desc: string;
  mode: MultiGroupMode;
  switchMode: "force_close_old" | "graceful_new_only";
  formula: string;
  matchRules: string[];
}

const CREATE_TEMPLATES: readonly CreateTemplateMeta[] = [
  {
    id: "manual",
    title: "通用手动组",
    desc: "零门槛，挑喜欢的节点随时用",
    mode: "sticky_best",
    switchMode: "graceful_new_only",
    formula: FORMULA_COST_EFFECTIVE,
    matchRules: [],
  },
  {
    id: "ai",
    title: "AI 专线组",
    desc: "稳选最好防跳 IP，切线断旧连接",
    mode: "sticky_best",
    switchMode: "force_close_old",
    formula: FORMULA_COST_EFFECTIVE,
    matchRules: [
      "DOMAIN-SUFFIX,chatgpt.com",
      "DOMAIN-SUFFIX,ab.chatgpt.com",
      "DOMAIN-SUFFIX,openai.com",
      "DOMAIN-SUFFIX,anthropic.com",
      "DOMAIN-SUFFIX,claude.ai",
      "DOMAIN-SUFFIX,googleapis.com",
    ],
  },
  {
    id: "download",
    title: "均衡下载组",
    desc: "多条线路轮流分摊，下载更稳",
    mode: "load_balance_round_robin",
    switchMode: "graceful_new_only",
    formula: FORMULA_MAX_PERF,
    matchRules: [],
  },
];

interface ModeMeta {
  id: MultiGroupMode;
  title: string;
  shortLabel: string;
  desc: string;
}

const GROUP_MODES: readonly ModeMeta[] = [
  {
    id: "sticky_best",
    title: "平时稳选最好（推荐 · 防跳 IP）",
    shortLabel: "稳选最好",
    desc: "一直稳用综合表现最好的一条线，不乱跳地区，减少网站风控。",
  },
  {
    id: "load_balance_consistent_hash",
    title: "同网站固定、多路分摊",
    shortLabel: "同站分摊",
    desc: "同一个网站走固定线路，不同网站自动分摊到组内多条线路。",
  },
  {
    id: "load_balance_round_robin",
    title: "多线路轮流分摊（下载提速）",
    shortLabel: "轮流分摊",
    desc: "多个连接轮流走不同线路，适合并发下载和大流量拉取。",
  },
  {
    id: "conditional_pool",
    title: "按条件自动吸纳节点",
    shortLabel: "自动吸纳",
    desc: "订阅更新后，按倍率或谷歌地区条件自动把达标新节点收进本组。",
  },
];

interface GatePreset {
  expr: string;
  label: string;
  failText: string;
}

const GEMINI_GATE_EXPR = 'site_unlocked("gemini") == 1';
const LEGACY_GEMINI_GATE_EXPR = 'site_unlocked("google_ai") == 1';

const HARD_GATE_PRESETS: readonly GatePreset[] = [
  { expr: "google_clean == 1", label: "谷歌地区正常", failText: "谷歌地区异常" },
  { expr: "keepalive_ok == 1", label: "长连接稳定(60秒)", failText: "60秒长连接未通过" },
  { expr: 'site_unlocked("chatgpt") == 1', label: "ChatGPT 可用", failText: "ChatGPT 未解锁" },
  { expr: GEMINI_GATE_EXPR, label: "Gemini 可用", failText: "Gemini 未解锁" },
  { expr: 'site_unlocked("claude") == 1', label: "Claude 可用", failText: "Claude 未解锁" },
  { expr: 'site_unlocked("windsurf") == 1', label: "Windsurf 可用", failText: "Windsurf 未解锁" },
];

const SITE_FRIENDLY_NAMES: Record<string, string> = {
  chatgpt: "ChatGPT",
  google_ai: "Gemini",
  gemini: "Gemini",
  gemini_aistudio: "Gemini",
  claude: "Claude",
  windsurf: "Windsurf",
};

interface FallbackMeta {
  id: FallbackPolicy;
  title: string;
  desc: string;
  tone: "amber" | "accent" | "red";
}

const FALLBACK_POLICIES: readonly FallbackMeta[] = [
  {
    id: "degrade_best_warn",
    title: "先挑最好的顶着，提醒我（推荐）",
    desc: "即使暂时都不达标也不断网，挑相对最好的一条继续用并提醒你。",
    tone: "amber",
  },
  {
    id: "cross_pool_escalate",
    title: "临时借用备用组",
    desc: "主组撑不住时先借用下面选好的备用组，主组恢复后自动切回。",
    tone: "accent",
  },
  {
    id: "strict_circuit_break",
    title: "暂停连接，防止走错线路",
    desc: "严格防风控模式：没有符合要求的节点时宁可断开也不乱走出口。",
    tone: "red",
  },
];

const FORMULA_VARIABLES: ReadonlyArray<{ token: string; label: string }> = [
  { token: "up_mbps", label: "上行 Mbps" },
  { token: "down_mbps", label: "下行 Mbps" },
  { token: "ping_ms", label: "延迟 ms" },
  { token: "jitter_ms", label: "抖动 ms" },
  { token: "loss_pct", label: "丢包 %" },
  { token: "multiplier", label: "倍率" },
  { token: "keepalive_ok", label: "60秒保活" },
  { token: "google_clean", label: "谷歌地区正常" },
  { token: "unlocked", label: "全站点解锁" },
];

const PROBE_ADDRESS_SNIPPETS: ReadonlyArray<{ token: string; desc: string }> = [
  { token: 'probe_up("antigravity")', desc: "指定探针上行 Mbps" },
  { token: 'probe_down("dl")', desc: "指定探针下行 Mbps" },
  { token: 'probe_ping("chatgpt")', desc: "指定探针延迟 ms" },
  { token: 'probe_ok("builtin_unlock_windsurf")', desc: "指定探针通过 (1/0)" },
  { token: 'site_unlocked("chatgpt")', desc: "ChatGPT 解锁 (1/0)" },
  { token: 'site_unlocked("gemini")', desc: "Gemini 解锁 (1/0)" },
];

interface TriggerMeta {
  consecutiveFailures: number;
  bypassCooldownOnDisconnect: boolean;
}

type NodeViewMode = "all" | "members";
type NodeSortMode = "default" | "up_desc" | "down_desc" | "latency_asc";

/* ============================================================================
 * Safe Formatting Helpers for dynamic_filter, trigger_rules & match_rules
 * ============================================================================ */

function formatDynamicFilter(filter: MultiGroup["dynamic_filter"]): string {
  if (filter == null) return "";
  if (typeof filter === "string") return filter;
  if (typeof filter !== "object") return "";

  const spec = filter as DynamicFilterSpec;
  if (typeof spec.expr === "string" && spec.expr.trim().length > 0) {
    return spec.expr;
  }

  const parts: string[] = [];
  if (typeof spec.max_multiplier === "number" && Number.isFinite(spec.max_multiplier)) {
    parts.push(`multiplier <= ${spec.max_multiplier}`);
  }
  if (spec.require_google_clean) {
    parts.push("google_clean == 1");
  }
  if (spec.require_443_native === true) {
    parts.push("is_443_native == 1");
  } else if (spec.require_443_native === false) {
    parts.push("is_443_native == 0");
  }
  if (Array.isArray(spec.region_codes) && spec.region_codes.length > 0) {
    parts.push(`region: ${spec.region_codes.join("/")}`);
  }
  if (Array.isArray(spec.protocols) && spec.protocols.length > 0) {
    parts.push(`protocol: ${spec.protocols.join("/")}`);
  }
  if (Array.isArray(spec.sub_ids) && spec.sub_ids.length > 0) {
    parts.push(`sub: ${spec.sub_ids.join(",")}`);
  }
  return parts.join(" && ");
}

function buildDynamicFilterUpdate(
  rawText: string,
  prev: MultiGroup["dynamic_filter"]
): DynamicFilterSpec | null {
  const trimmed = rawText.trim();
  const baseObj: DynamicFilterSpec =
    prev && typeof prev === "object" ? { ...(prev as DynamicFilterSpec) } : {};
  if (!trimmed) {
    const hasOther =
      (baseObj.sub_ids && baseObj.sub_ids.length > 0) ||
      (baseObj.region_codes && baseObj.region_codes.length > 0) ||
      (baseObj.protocols && baseObj.protocols.length > 0) ||
      baseObj.max_multiplier != null ||
      Boolean(baseObj.require_google_clean) ||
      baseObj.require_443_native != null;
    if (!hasOther) return null;
    return { ...baseObj, expr: null };
  }
  return {
    sub_ids: baseObj.sub_ids ?? [],
    region_codes: baseObj.region_codes ?? [],
    max_multiplier: baseObj.max_multiplier ?? null,
    protocols: baseObj.protocols ?? [],
    require_google_clean: baseObj.require_google_clean ?? false,
    require_443_native: baseObj.require_443_native ?? null,
    expr: rawText,
  };
}

function getPrimaryTriggerExpr(group: MultiGroup): string {
  if (Array.isArray(group.trigger_rules) && group.trigger_rules.length > 0) {
    return group.trigger_rules[0].expr ?? "";
  }
  return group.trigger_expr ?? "";
}

function getPrimaryTriggerMeta(group: MultiGroup): TriggerMeta {
  if (Array.isArray(group.trigger_rules) && group.trigger_rules.length > 0) {
    const first = group.trigger_rules[0];
    return {
      consecutiveFailures: first.consecutive_failures ?? 2,
      bypassCooldownOnDisconnect: first.bypass_cooldown_on_disconnect ?? true,
    };
  }
  return {
    consecutiveFailures: 2,
    bypassCooldownOnDisconnect: true,
  };
}

function parseUploadTriggerInfo(expr: string): {
  enabled: boolean;
  threshold: number;
  prefix: string;
  isSimple: boolean;
} {
  const trimmed = expr.trim();
  if (!trimmed) {
    return { enabled: false, threshold: 2.0, prefix: "up_mbps", isSimple: true };
  }
  const simpleMatch = /^(up_mbps|probe_up\(\s*["'][^"']+["']\s*\))\s*<\s*(\d+(?:\.\d+)?)$/.exec(
    trimmed
  );
  if (simpleMatch) {
    return {
      enabled: true,
      threshold: Number(simpleMatch[2]) || 2.0,
      prefix: simpleMatch[1],
      isSimple: true,
    };
  }
  const partialMatch = /(up_mbps|probe_up\(\s*["'][^"']+["']\s*\))\s*<\s*(\d+(?:\.\d+)?)/.exec(
    trimmed
  );
  if (partialMatch) {
    return {
      enabled: true,
      threshold: Number(partialMatch[2]) || 2.0,
      prefix: partialMatch[1],
      isSimple: false,
    };
  }
  return { enabled: false, threshold: 2.0, prefix: "up_mbps", isSimple: false };
}

function formatMatchRuleChip(rule: string): { display: string; tag: string | null } {
  const trimmed = rule.trim();
  const upper = trimmed.toUpperCase();
  if (upper.startsWith("DOMAIN-SUFFIX,")) {
    return { display: trimmed.slice("DOMAIN-SUFFIX,".length).trim(), tag: null };
  }
  if (upper.startsWith("DOMAIN,")) {
    return { display: trimmed.slice("DOMAIN,".length).trim(), tag: "精确" };
  }
  if (upper.startsWith("DOMAIN-KEYWORD,")) {
    return { display: trimmed.slice("DOMAIN-KEYWORD,".length).trim(), tag: "关键词" };
  }
  if (upper.startsWith("PROCESS-NAME,")) {
    return { display: trimmed.slice("PROCESS-NAME,".length).trim(), tag: "程序" };
  }
  if (upper.startsWith("IP-CIDR,") || upper.startsWith("IP-CIDR6,")) {
    const idx = trimmed.indexOf(",");
    return { display: trimmed.slice(idx + 1).trim(), tag: "IP" };
  }
  return { display: trimmed, tag: null };
}

const KNOWN_MATCH_RULE_TYPES = new Set<string>([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-REGEX",
  "DOMAIN-WILDCARD",
  "GEOSITE",
  "GEOIP",
  "IP-CIDR",
  "IP-CIDR6",
  "IP-SUFFIX",
  "IP-ASN",
  "SRC-IP-CIDR",
  "SRC-PORT",
  "DST-PORT",
  "PROCESS-NAME",
  "PROCESS-NAME-REGEX",
  "PROCESS-PATH",
  "PROCESS-PATH-REGEX",
  "RULE-SET",
  "NETWORK",
  "UID",
  "IN-TYPE",
  "IN-USER",
  "IN-NAME",
  "SUB-RULE",
  "AND",
  "OR",
  "NOT",
]);

const BARE_RULE_KEYWORDS = new Set<string>([
  ...KNOWN_MATCH_RULE_TYPES,
  "MATCH",
  "FINAL",
  "DIRECT",
  "REJECT",
  "PROXY",
]);

const DOMAIN_LIKE_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;

const INVALID_MATCH_RULE_MSG = "请输入域名或完整规则（如 anthropic.com）";

function normalizeSingleMatchRule(raw: string): { rule: string | null; invalid: boolean } {
  const trimmed = raw.trim();
  if (!trimmed) return { rule: null, invalid: false };

  const commaIdx = trimmed.indexOf(",");
  if (commaIdx !== -1) {
    const ruleType = trimmed.slice(0, commaIdx).trim().toUpperCase();
    const restRaw = trimmed.slice(commaIdx + 1).trim();
    if (!KNOWN_MATCH_RULE_TYPES.has(ruleType) || !restRaw) {
      return { rule: null, invalid: true };
    }
    if (ruleType === "AND" || ruleType === "OR" || ruleType === "NOT") {
      return { rule: `${ruleType},${restRaw}`, invalid: false };
    }
    const restParts = restRaw
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    if (restParts.length === 0) {
      return { rule: null, invalid: true };
    }
    const primaryVal = restParts[0];
    if (BARE_RULE_KEYWORDS.has(primaryVal.toUpperCase())) {
      return { rule: null, invalid: true };
    }
    if (
      (ruleType === "DOMAIN" || ruleType === "DOMAIN-SUFFIX") &&
      !DOMAIN_LIKE_RE.test(primaryVal)
    ) {
      return { rule: null, invalid: true };
    }
    return { rule: `${ruleType},${restParts.join(",")}`, invalid: false };
  }

  if (BARE_RULE_KEYWORDS.has(trimmed.toUpperCase())) {
    return { rule: null, invalid: true };
  }

  const cleaned = trimmed
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/^\.+/, "")
    .replace(/\.+$/, "")
    .trim();

  if (!cleaned || BARE_RULE_KEYWORDS.has(cleaned.toUpperCase()) || !DOMAIN_LIKE_RE.test(cleaned)) {
    return { rule: null, invalid: true };
  }

  return { rule: `DOMAIN-SUFFIX,${cleaned.toLowerCase()}`, invalid: false };
}

function parseUserMatchRules(rawInput: string): { rules: string[]; invalidTokens: string[] } {
  // Never split by comma `,` — rules like "DOMAIN-SUFFIX,anthropic.com" contain commas.
  const segments = rawInput
    .split(/[\r\n;；]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const rules: string[] = [];
  const invalidTokens: string[] = [];
  const seen = new Set<string>();

  for (const seg of segments) {
    const { rule, invalid } = normalizeSingleMatchRule(seg);
    if (invalid || !rule) {
      invalidTokens.push(seg);
      continue;
    }
    if (!seen.has(rule)) {
      seen.add(rule);
      rules.push(rule);
    }
  }

  return { rules, invalidTokens };
}

function normalizeGroupForBackend(group: MultiGroup, meta: TriggerMeta): MultiGroup {
  const expr = getPrimaryTriggerExpr(group).trim();
  const triggerRules: TriggerRule[] = expr
    ? [
        {
          expr,
          consecutive_failures: Math.max(1, Math.round(meta.consecutiveFailures)),
          bypass_cooldown_on_disconnect: meta.bypassCooldownOnDisconnect,
        },
        ...(Array.isArray(group.trigger_rules) ? group.trigger_rules.slice(1) : []),
      ]
    : [];

  let dynamicFilter: DynamicFilterSpec | null = null;
  if (typeof group.dynamic_filter === "string") {
    dynamicFilter = group.dynamic_filter.trim()
      ? {
          expr: group.dynamic_filter.trim(),
          sub_ids: [],
          region_codes: [],
          max_multiplier: null,
          protocols: [],
          require_google_clean: false,
          require_443_native: null,
        }
      : null;
  } else if (group.dynamic_filter && typeof group.dynamic_filter === "object") {
    const f = group.dynamic_filter as DynamicFilterSpec;
    dynamicFilter = {
      expr: typeof f.expr === "string" && f.expr.trim() ? f.expr.trim() : null,
      sub_ids: Array.isArray(f.sub_ids) ? f.sub_ids : [],
      region_codes: Array.isArray(f.region_codes) ? f.region_codes : [],
      max_multiplier: typeof f.max_multiplier === "number" ? f.max_multiplier : null,
      protocols: Array.isArray(f.protocols) ? f.protocols : [],
      require_google_clean: Boolean(f.require_google_clean),
      require_443_native: typeof f.require_443_native === "boolean" ? f.require_443_native : null,
    };
  }

  return {
    ...group,
    independent_routing: Boolean(group.independent_routing),
    dynamic_filter: dynamicFilter,
    trigger_rules: triggerRules,
    trigger_expr: expr || null,
  };
}

/* ============================================================================
 * Zero-eval Safe Recursive-Descent AST Formula Parser & Evaluator
 * 100% semantically aligned with Rust `crates/catcloud-core/src/strategy/formula.rs`
 * ============================================================================ */

type OpValue =
  | "+"
  | "-"
  | "*"
  | "/"
  | "("
  | ")"
  | ","
  | "!"
  | "=="
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "&&"
  | "||";

type Token =
  | { kind: "num"; value: number }
  | { kind: "ident"; value: string }
  | { kind: "str"; value: string }
  | { kind: "op"; value: OpValue };

interface EvalContext {
  vars: Record<string, number>;
  probeUp: Record<string, number>;
  probeDown: Record<string, number>;
  probePing: Record<string, number>;
  probeOk: Record<string, boolean>;
  unlockedSites: Record<string, boolean>;
}

interface EvalOutcome {
  ok: boolean;
  value: number;
  error: string | null;
}

function sanitizeNumber(v: number): number {
  return Number.isFinite(v) && v !== 0 ? v : 0;
}

function isTruthy(v: number): boolean {
  return Number.isFinite(v) && Math.abs(v) > EPSILON_ZERO;
}

function tokenizeFormula(input: string): { tokens: Token[]; error: string | null } {
  const tokens: Token[] = [];
  let i = 0;
  const len = input.length;

  while (i < len) {
    const ch = input[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    const two = input.slice(i, i + 2);
    if (
      two === "==" ||
      two === "!=" ||
      two === "<=" ||
      two === ">=" ||
      two === "&&" ||
      two === "||"
    ) {
      tokens.push({ kind: "op", value: two });
      i += 2;
      continue;
    }
    if (
      ch === "+" ||
      ch === "-" ||
      ch === "*" ||
      ch === "/" ||
      ch === "(" ||
      ch === ")" ||
      ch === "," ||
      ch === "!" ||
      ch === "<" ||
      ch === ">"
    ) {
      tokens.push({ kind: "op", value: ch });
      i += 1;
      continue;
    }
    if (ch === "=" || ch === "&" || ch === "|") {
      return {
        tokens: [],
        error: `无效运算符「${ch}」（请使用 ==、&& 或 ||）`,
      };
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      i += 1;
      let str = "";
      while (i < len && input[i] !== quote) {
        if (input[i] === "\\" && i + 1 < len) {
          str += input[i + 1];
          i += 2;
          continue;
        }
        str += input[i];
        i += 1;
      }
      if (i >= len) {
        return { tokens: [], error: "字符串字面量缺少闭合引号" };
      }
      i += 1;
      tokens.push({ kind: "str", value: str });
      continue;
    }
    if (ch >= "0" && ch <= "9") {
      let numText = "";
      while (i < len && input[i] >= "0" && input[i] <= "9") {
        numText += input[i];
        i += 1;
      }
      if (i < len && input[i] === ".") {
        numText += ".";
        i += 1;
        if (i >= len || input[i] < "0" || input[i] > "9") {
          return { tokens: [], error: `无效数值：${numText}` };
        }
        while (i < len && input[i] >= "0" && input[i] <= "9") {
          numText += input[i];
          i += 1;
        }
      }
      const parsed = Number(numText);
      if (!Number.isFinite(parsed)) {
        return { tokens: [], error: `无效数值：${numText}` };
      }
      tokens.push({ kind: "num", value: parsed });
      continue;
    }
    if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch === "_") {
      let ident = "";
      while (
        i < len &&
        ((input[i] >= "a" && input[i] <= "z") ||
          (input[i] >= "A" && input[i] <= "Z") ||
          (input[i] >= "0" && input[i] <= "9") ||
          input[i] === "_")
      ) {
        ident += input[i];
        i += 1;
      }
      tokens.push({ kind: "ident", value: ident });
      continue;
    }
    return { tokens: [], error: `非法字符：「${ch}」` };
  }

  return { tokens, error: null };
}

function lookupSiteUnlockedRaw(
  unlockedSites: Record<string, boolean>,
  siteName: string
): boolean | null {
  const findKey = (target: string): boolean | null => {
    if (target in unlockedSites) {
      return unlockedSites[target];
    }
    const targetLower = target.toLowerCase();
    for (const [k, v] of Object.entries(unlockedSites)) {
      if (k.toLowerCase() === targetLower) {
        return v;
      }
    }
    return null;
  };

  const direct = findKey(siteName);
  if (direct !== null) return direct;

  const lower = siteName.toLowerCase();
  if (lower === "google_ai" || lower === "gemini" || lower === "gemini_aistudio") {
    for (const alias of ["gemini", "gemini_aistudio", "google_ai"]) {
      if (alias === lower) continue;
      const hit = findKey(alias);
      if (hit !== null) return hit;
    }
  }
  return null;
}

function evaluateFormulaSafely(expr: string, ctx: EvalContext): EvalOutcome {
  const trimmed = expr.trim();
  if (!trimmed) {
    return { ok: false, value: 0, error: "公式不能为空" };
  }
  const lexed = tokenizeFormula(trimmed);
  if (lexed.error) {
    return { ok: false, value: 0, error: lexed.error };
  }
  const tokens = lexed.tokens;
  let pos = 0;

  const peek = (): Token | undefined => tokens[pos];
  const consume = (): Token | undefined => {
    const t = tokens[pos];
    pos += 1;
    return t;
  };

  const parseOr = (): number => {
    let left = parseAnd();
    while (true) {
      const t = peek();
      if (t && t.kind === "op" && t.value === "||") {
        consume();
        const right = parseAnd();
        left = isTruthy(left) || isTruthy(right) ? 1 : 0;
      } else {
        break;
      }
    }
    return left;
  };

  const parseAnd = (): number => {
    let left = parseEquality();
    while (true) {
      const t = peek();
      if (t && t.kind === "op" && t.value === "&&") {
        consume();
        const right = parseEquality();
        left = isTruthy(left) && isTruthy(right) ? 1 : 0;
      } else {
        break;
      }
    }
    return left;
  };

  const parseEquality = (): number => {
    let left = parseComparison();
    while (true) {
      const t = peek();
      if (t && t.kind === "op" && (t.value === "==" || t.value === "!=")) {
        consume();
        const right = parseComparison();
        left =
          t.value === "=="
            ? Math.abs(left - right) <= EPSILON_EQ
              ? 1
              : 0
            : Math.abs(left - right) > EPSILON_EQ
              ? 1
              : 0;
      } else {
        break;
      }
    }
    return left;
  };

  const parseComparison = (): number => {
    let left = parseAdditive();
    while (true) {
      const t = peek();
      if (
        t &&
        t.kind === "op" &&
        (t.value === "<" || t.value === "<=" || t.value === ">" || t.value === ">=")
      ) {
        consume();
        const right = parseAdditive();
        if (t.value === "<") left = left < right - EPSILON_EQ ? 1 : 0;
        else if (t.value === "<=") left = left <= right + EPSILON_EQ ? 1 : 0;
        else if (t.value === ">") left = left > right + EPSILON_EQ ? 1 : 0;
        else left = left >= right - EPSILON_EQ ? 1 : 0;
      } else {
        break;
      }
    }
    return left;
  };

  const parseAdditive = (): number => {
    let left = parseMultiplicative();
    while (true) {
      const t = peek();
      if (t && t.kind === "op" && (t.value === "+" || t.value === "-")) {
        consume();
        const right = parseMultiplicative();
        left = sanitizeNumber(t.value === "+" ? left + right : left - right);
      } else {
        break;
      }
    }
    return left;
  };

  const parseMultiplicative = (): number => {
    let left = parseUnary();
    while (true) {
      const t = peek();
      if (t && t.kind === "op" && (t.value === "*" || t.value === "/")) {
        consume();
        const right = parseUnary();
        if (t.value === "/") {
          left =
            !Number.isFinite(right) || Math.abs(right) <= EPSILON_ZERO
              ? 0
              : sanitizeNumber(left / right);
        } else {
          left = sanitizeNumber(left * right);
        }
      } else {
        break;
      }
    }
    return left;
  };

  const parseUnary = (): number => {
    const t = peek();
    if (t && t.kind === "op" && t.value === "-") {
      consume();
      return sanitizeNumber(-parseUnary());
    }
    if (t && t.kind === "op" && t.value === "!") {
      consume();
      return isTruthy(parseUnary()) ? 0 : 1;
    }
    return parsePrimary();
  };

  const parsePrimary = (): number => {
    const t = peek();
    if (!t) {
      throw new Error("表达式提前结束");
    }
    if (t.kind === "num") {
      consume();
      return sanitizeNumber(t.value);
    }
    if (t.kind === "op" && t.value === "(") {
      consume();
      const val = parseOr();
      const closing = consume();
      if (!closing || closing.kind !== "op" || closing.value !== ")") {
        throw new Error("缺少右括号 )");
      }
      return val;
    }
    if (t.kind === "ident") {
      consume();
      const name = t.value;
      const next = peek();
      if (next && next.kind === "op" && next.value === "(") {
        consume(); // '('
        if (
          name === "probe_up" ||
          name === "probe_down" ||
          name === "probe_ping" ||
          name === "probe_ok" ||
          name === "site_unlocked"
        ) {
          const arg = consume();
          if (!arg || arg.kind !== "str" || !arg.value.trim()) {
            throw new Error(`${name} 需要非空字符串参数`);
          }
          const close = consume();
          if (!close || close.kind !== "op" || close.value !== ")") {
            throw new Error(`${name} 缺少闭合括号`);
          }
          if (name === "probe_up") {
            const v = ctx.probeUp[arg.value];
            return sanitizeNumber(typeof v === "number" && Number.isFinite(v) ? v : (ctx.vars.up_mbps ?? 0));
          }
          if (name === "probe_down") {
            const v = ctx.probeDown[arg.value];
            return sanitizeNumber(typeof v === "number" && Number.isFinite(v) ? v : (ctx.vars.down_mbps ?? 0));
          }
          if (name === "probe_ping") {
            const p = ctx.probePing[arg.value];
            if (typeof p === "number" && Number.isFinite(p)) return p;
            const fallbackPing = ctx.vars.ping_ms;
            return typeof fallbackPing === "number" && Number.isFinite(fallbackPing)
              ? fallbackPing
              : DEFAULT_MISSING_PING_MS;
          }
          if (name === "probe_ok") {
            return ctx.probeOk[arg.value] === true ? 1 : 0;
          }
          return lookupSiteUnlockedRaw(ctx.unlockedSites, arg.value) === true ? 1 : 0;
        }

        const args: number[] = [];
        const afterOpen = peek();
        if (!(afterOpen && afterOpen.kind === "op" && afterOpen.value === ")")) {
          args.push(parseOr());
          while (true) {
            const sep = peek();
            if (sep && sep.kind === "op" && sep.value === ",") {
              consume();
              args.push(parseOr());
            } else {
              break;
            }
          }
        }
        const close = consume();
        if (!close || close.kind !== "op" || close.value !== ")") {
          throw new Error(`函数 ${name} 缺少闭合括号`);
        }
        if (name === "min" && args.length === 2) return sanitizeNumber(Math.min(args[0], args[1]));
        if (name === "max" && args.length === 2) return sanitizeNumber(Math.max(args[0], args[1]));
        if (name === "abs" && args.length === 1) return sanitizeNumber(Math.abs(args[0]));
        if (name === "clamp" && args.length === 3) {
          const lo = Math.min(args[1], args[2]);
          const hi = Math.max(args[1], args[2]);
          return sanitizeNumber(Math.min(hi, Math.max(lo, args[0])));
        }
        if (name === "if" && args.length === 3) {
          return isTruthy(args[0]) ? args[1] : args[2];
        }
        throw new Error(`不支持的函数或参数数量错误：${name}`);
      }

      if (name === "true") return 1;
      if (name === "false") return 0;
      if (name in ctx.vars) {
        return sanitizeNumber(ctx.vars[name]);
      }
      throw new Error(`未知变量：${name}`);
    }
    throw new Error("公式语法结构不合法");
  };

  try {
    const val = parseOr();
    if (pos < tokens.length) {
      return { ok: false, value: 0, error: "公式末尾存在多余标记" };
    }
    if (!Number.isFinite(val)) {
      return { ok: false, value: 0, error: "计算结果溢出或非有限数" };
    }
    return { ok: true, value: sanitizeNumber(val), error: null };
  } catch (err) {
    return {
      ok: false,
      value: 0,
      error: err instanceof Error ? err.message : "公式解析失败",
    };
  }
}

function buildEvalContextForNode(node: ProxyNode, snap: ProbeSnapshot | undefined): EvalContext {
  const unlockedEntries = snap ? Object.values(snap.unlocked_sites) : [];
  const allUnlocked = unlockedEntries.length > 0 && unlockedEntries.every(Boolean);
  const ok = snap?.ok ?? false;

  return {
    vars: {
      up_mbps: snap?.up_mbps ?? 0,
      down_mbps: snap?.down_mbps ?? 0,
      ping_ms: snap?.latency_ms ?? (ok ? 0 : DEFAULT_MISSING_PING_MS),
      latency_ms: snap?.latency_ms ?? (ok ? 0 : DEFAULT_MISSING_PING_MS),
      jitter_ms: snap?.jitter_ms ?? 0,
      loss_pct: snap?.loss_pct ?? (ok ? 0 : 100),
      multiplier: Number.isFinite(node.multiplier) && node.multiplier >= 0 ? node.multiplier : 1,
      keepalive_ok: snap?.keepalive_60s_ok === true ? 1 : 0,
      google_clean: snap?.google_clean === true ? 1 : 0,
      unlocked: allUnlocked ? 1 : 0,
      is_443_native: node.is_443_native ? 1 : 0,
      ok: ok ? 1 : 0,
    },
    probeUp: snap?.per_probe_up_mbps ?? {},
    probeDown: snap?.per_probe_down_mbps ?? {},
    probePing: snap?.per_probe_ping_ms ?? {},
    probeOk: snap?.per_probe_ok ?? {},
    unlockedSites: snap?.unlocked_sites ?? {},
  };
}

function checkHardGate(gate: string, ctx: EvalContext): boolean {
  const res = evaluateFormulaSafely(gate, ctx);
  return res.ok && isTruthy(res.value);
}

/**
 * Human-friendly gate check:
 * - Never marks untested nodes as "failed" or "rejected"!
 * - Only returns `failedReasons` when the node has an actual measured value that violates a gate.
 */
interface NodeGateAssessment {
  hasMeasuredFailure: boolean;
  failedReasons: string[];
  allMeasuredAndPassed: boolean;
}

function assessNodeAgainstGates(
  node: ProxyNode,
  snap: ProbeSnapshot | undefined,
  hardGates: string[]
): NodeGateAssessment {
  if (hardGates.length === 0 || !snap) {
    return { hasMeasuredFailure: false, failedReasons: [], allMeasuredAndPassed: false };
  }

  const failedReasons: string[] = [];
  let untestedCount = 0;
  let lazyCtx: EvalContext | null = null;

  for (const gate of hardGates) {
    const compact = gate.replace(/\s+/g, "");
    if (compact === "google_clean==1") {
      if (snap.google_clean === null || snap.google_clean === undefined) {
        untestedCount += 1;
      } else if (snap.google_clean === false) {
        failedReasons.push("谷歌地区异常");
      }
      continue;
    }
    if (compact === "keepalive_ok==1") {
      if (snap.keepalive_60s_ok === null || snap.keepalive_60s_ok === undefined) {
        untestedCount += 1;
      } else if (snap.keepalive_60s_ok === false) {
        failedReasons.push("60秒长连接未通过");
      }
      continue;
    }
    const siteMatch = /^site_unlocked\(["']([^"']+)["']\)==1$/.exec(compact);
    if (siteMatch) {
      const siteKey = siteMatch[1];
      const measured = lookupSiteUnlockedRaw(snap.unlocked_sites ?? {}, siteKey);
      if (measured === null) {
        untestedCount += 1;
      } else if (measured === false) {
        const label = SITE_FRIENDLY_NAMES[siteKey.toLowerCase()] ?? siteKey;
        failedReasons.push(`${label} 未解锁`);
      }
      continue;
    }
    // Custom / compound gate expression: neutrally allow untested keepalive_ok (matching Rust evaluator)
    if (!lazyCtx) {
      lazyCtx = buildEvalContextForNode(node, snap);
    }
    const evalCtx =
      (snap.keepalive_60s_ok === null || snap.keepalive_60s_ok === undefined) &&
      gate.includes("keepalive_ok")
        ? { ...lazyCtx, vars: { ...lazyCtx.vars, keepalive_ok: 1 } }
        : lazyCtx;
    if (!checkHardGate(gate, evalCtx)) {
      failedReasons.push(gate);
    }
  }

  return {
    hasMeasuredFailure: failedReasons.length > 0,
    failedReasons,
    allMeasuredAndPassed: failedReasons.length === 0 && untestedCount === 0,
  };
}

function formatLatencyTone(ms: number): string {
  if (ms <= 140) return "var(--green)";
  if (ms <= 300) return "var(--amber)";
  return "var(--red)";
}

function formatMultiplierLabel(multiplier: number): string {
  if (!Number.isFinite(multiplier)) return "1x";
  return Number.isInteger(multiplier) ? `${multiplier}x` : `${Number(multiplier.toFixed(2))}x`;
}

function extractCardAiDots(snap: ProbeSnapshot | undefined): Array<{
  id: string;
  label: string;
  short: string;
}> {
  if (!snap) return [];
  const sites = snap.unlocked_sites ?? {};
  const list: Array<{ id: string; label: string; short: string }> = [];
  if (sites.claude === true) list.push({ id: "claude", label: "Claude 可用", short: "C" });
  if ((sites.gemini ?? sites.gemini_aistudio ?? sites.google_ai) === true) {
    list.push({ id: "gemini", label: "Gemini 可用", short: "G" });
  }
  if (sites.chatgpt === true) list.push({ id: "chatgpt", label: "ChatGPT 可用", short: "GPT" });
  return list;
}

function isNodeAiReady(snap: ProbeSnapshot | undefined): boolean {
  if (!snap) return false;
  const sites = snap.unlocked_sites ?? {};
  return (
    sites.claude === true ||
    sites.chatgpt === true ||
    sites.windsurf === true ||
    (sites.gemini ?? sites.gemini_aistudio ?? sites.google_ai) === true
  );
}

function buildMultiGroupAgentMarkdown(group: MultiGroup, meta: TriggerMeta): string {
  const normalized = normalizeGroupForBackend(group, meta);
  const snippet = JSON.stringify(
    {
      id: normalized.id,
      name: normalized.name,
      mode: normalized.mode,
      independent_routing: Boolean(normalized.independent_routing),
      match_rules: normalized.match_rules,
      hard_gates: normalized.hard_gates,
      trigger_rules: normalized.trigger_rules,
      formula_expr: normalized.formula_expr,
      fallback_policy: normalized.fallback_policy,
      fallback_pool_id: normalized.fallback_pool_id,
      recover_probe_interval_sec: normalized.recover_probe_interval_sec,
      switch_mode: normalized.switch_mode,
      cooldown_sec: normalized.cooldown_sec,
      hysteresis_pct: normalized.hysteresis_pct,
    },
    null,
    2
  );

  return [
    `# CatCloud Agent Guide: Smart Multi-Group (${group.name})`,
    "",
    "> 按站点粘性优选、受控均衡、安全 AST 自定义加权公式与三选一兜底策略协同规范。",
    "",
    "## 1. 适用场景与量化触发信号",
    "- AI / 编程客户端（OpenAI、Claude、Gemini、Windsurf）因随机切节点导致 IP 漂移风控或静默区域受限时，应启用 `sticky_best` 并开启 `google_clean == 1` 与 `keepalive_ok == 1` 硬门禁。",
    "- 需混合多家订阅并优先消耗 0.5x/1x 低倍率节点，仅在主池全员不达标时短暂借调高优备援池，并按回切间隔自动恢复。",
    "- 流媒体与并发下载站点可使用 `load_balance_consistent_hash` 或 `load_balance_round_robin`，所有入池节点均须先通过硬门禁过滤。",
    "",
    "## 2. 外部前提与安全 AST 公式规范",
    "- 节点库至少导入 2 条可用节点，并完成一次零干扰隔离测速以生成最新 `ProbeSnapshot`。",
    "- 加权公式由纯 AST 解释器求值（零 `eval`），可用变量：`up_mbps`, `down_mbps`, `ping_ms`, `jitter_ms`, `loss_pct`, `multiplier`, `keepalive_ok`, `google_clean`, `unlocked`, `is_443_native`, `ok`。",
    '- 支持按探针/站点寻址：`probe_up("id")`, `probe_down("id")`, `probe_ping("id")`, `probe_ok("id")`, `site_unlocked("chatgpt")`；内置函数：`min`, `max`, `clamp`, `abs`, `if`。',
    "- 兜底策略三选一：`degrade_best_warn` / `cross_pool_escalate` / `strict_circuit_break`。",
    "",
    "## 3. GUI 路径与 Headless CLI 热写入验收命令",
    "- GUI 路径：左侧「智能多选组」→ 选择多选组 → 点击节点加入/切换 → 展开右侧「策略与标准」微调并应用。",
    "- 查看全部策略组：`catcloud group list --json`",
    `- 一键切换次优节点并核验连接清理：\`catcloud group switch --group ${group.id} --json\``,
    "- 热重载生效配置：`catcloud config reload --json`",
    "",
    "## 4. 安全回退与排障清单",
    `- 公式编辑异常导致 0 候选时，可一键复位为默认低倍率性价比模板：\`${FORMULA_COST_EFFECTIVE}\`。`,
    "- 若策略组长期处于 `REJECT` 熔断态，请先核查 `hard_gates` 与最新测速快照，或临时切为 `degrade_best_warn` 保障连通。",
    "- 若切节点后旧 HTTP/2 / gRPC 长连接仍卡住，请将该组 `switch_mode` 设为 `force_close_old`。",
    "",
    "## 当前策略组参考配置（已脱敏）",
    "```json",
    snippet,
    "```",
  ].join("\n");
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fallback below */
  }
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}

/* ============================================================================
 * Main Component: Three-Column Human-Friendly Smart Multi-Group Workbench
 * ============================================================================ */

export function MultiGroupPage() {
  const storeGroups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const probeProgress = useAppSelector((s) => s.probeProgress);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const runtime = useAppSelector((s) => s.runtime);
  const isGroupMode = runtime.route_mode !== "single";
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  // Local group drafts (keeps unsaved strategy edits per group while syncing live active_node_id & members)
  const [groups, setGroups] = useState<MultiGroup[]>(storeGroups);
  const [selectedId, setSelectedId] = useState<string>(
    runtime.active_group_id || storeGroups[0]?.id || ""
  );
  const [triggerMetas, setTriggerMetas] = useState<Record<string, TriggerMeta>>({});
  const [dirtyGroupIds, setDirtyGroupIds] = useState<Record<string, boolean>>({});

  // Left sidebar: create form & two-step delete confirmation
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupTemplate, setNewGroupTemplate] = useState<CreateTemplateId>("manual");
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingGroupId, setDeletingGroupId] = useState<string | null>(null);

  // Center pane: inline rename, filters, pagination, batch clear confirm, single-node actions
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [selectedSubId, setSelectedSubId] = useState<string>("all");
  const [filterContinent, setFilterContinent] = useState<ContinentId>("all");
  const [filterRegion, setFilterRegion] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<NodeViewMode>("all");
  const [sortMode, setSortMode] = useState<NodeSortMode>("default");
  const [filterGoogleClean, setFilterGoogleClean] = useState(false);
  const [filterAiReady, setFilterAiReady] = useState(false);
  const [nodePage, setNodePage] = useState(1);
  const [nodePageSize, setNodePageSize] = useState(24);
  const [confirmClearMembers, setConfirmClearMembers] = useState(false);
  const [switchingNext, setSwitchingNext] = useState(false);
  const [selectingNodeId, setSelectingNodeId] = useState<string | null>(null);
  const [probingNodeIds, setProbingNodeIds] = useState<Record<string, boolean>>({});

  // Right strategy drawer: collapsed by default so node grid gets huge breathing room
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [savingGroup, setSavingGroup] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [evalReport, setEvalReport] = useState<GroupEvaluationReport | null>(null);
  const [newRuleInput, setNewRuleInput] = useState("");
  const [customGateInput, setCustomGateInput] = useState("");
  const [copiedGuide, setCopiedGuide] = useState(false);
  const [backendFormulaValidation, setBackendFormulaValidation] = useState<{
    checkedExpr: string;
    ok: boolean;
    error: string | null;
  } | null>(null);

  // Stable order snapshot so clicking node cards in "all" view toggles colors in-place without jumping!
  const [pinnedOrder, setPinnedOrder] = useState<{
    groupId: string;
    activeId: string | null;
    memberIds: Set<string>;
  }>({
    groupId: "",
    activeId: null,
    memberIds: new Set<string>(),
  });

  const dirtyGroupIdsRef = useRef(dirtyGroupIds);
  dirtyGroupIdsRef.current = dirtyGroupIds;
  const latestMembersRef = useRef<Record<string, string[]>>({});
  const memberReqSeqRef = useRef<Record<string, number>>({});
  const copyTimerRef = useRef<number | null>(null);
  const deleteConfirmTimerRef = useRef<number | null>(null);
  const clearConfirmTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      if (deleteConfirmTimerRef.current !== null) window.clearTimeout(deleteConfirmTimerRef.current);
      if (clearConfirmTimerRef.current !== null) window.clearTimeout(clearConfirmTimerRef.current);
    };
  }, []);

  // Sync store groups smoothly without wiping unsaved strategy drafts
  useEffect(() => {
    if (!initialized && storeGroups.length === 0) return;
    setGroups((prev) => {
      const prevById = new Map(prev.map((g) => [g.id, g]));
      return storeGroups.map((sg) => {
        const local = prevById.get(sg.id);
        if (local && dirtyGroupIdsRef.current[sg.id]) {
          return {
            ...local,
            member_node_ids: latestMembersRef.current[sg.id] ?? sg.member_node_ids,
            active_node_id: sg.active_node_id,
          };
        }
        return sg;
      });
    });
    setSelectedId((prev) => {
      if (prev && storeGroups.some((g) => g.id === prev)) return prev;
      if (runtime.active_group_id && storeGroups.some((g) => g.id === runtime.active_group_id)) {
        return runtime.active_group_id;
      }
      return storeGroups[0]?.id ?? "";
    });
  }, [storeGroups, initialized, runtime.active_group_id]);

  const selectedGroup = useMemo(
    () => groups.find((g) => g.id === selectedId) ?? groups[0] ?? null,
    [groups, selectedId]
  );
  const selectedGroupId = selectedGroup?.id ?? null;

  // Refresh pinned display ordering when switching groups or changing view/filters
  useEffect(() => {
    if (!selectedGroup) return;
    setPinnedOrder({
      groupId: selectedGroup.id,
      activeId: selectedGroup.active_node_id,
      memberIds: new Set(selectedGroup.member_node_ids),
    });
    setEditingName(false);
    setConfirmClearMembers(false);
    setEvalReport(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedGroup?.id, viewMode]);

  useEffect(() => {
    setNodePage(1);
  }, [
    selectedGroupId,
    viewMode,
    searchQuery,
    selectedSubId,
    filterContinent,
    filterRegion,
    sortMode,
    filterGoogleClean,
    filterAiReady,
  ]);

  // Debounced backend authoritative formula validation in Tauri runtime (only when advanced panel is open or dirty)
  const currentFormulaExpr = selectedGroup?.formula_expr ?? "";
  useEffect(() => {
    if (!inTauri || !selectedGroup || !advancedOpen) {
      setBackendFormulaValidation(null);
      return;
    }
    const expr = currentFormulaExpr.trim();
    if (!expr) {
      setBackendFormulaValidation({
        checkedExpr: currentFormulaExpr,
        ok: false,
        error: "公式不能为空",
      });
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void catcloudApi
        .validateFormulaExpr(expr)
        .then((ok) => {
          if (!cancelled) {
            setBackendFormulaValidation({
              checkedExpr: currentFormulaExpr,
              ok,
              error: ok ? null : "后端公式校验未通过",
            });
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setBackendFormulaValidation({
              checkedExpr: currentFormulaExpr,
              ok: false,
              error: formatErrorMessage(err),
            });
          }
        });
    }, 280);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [currentFormulaExpr, inTauri, selectedGroup?.id, advancedOpen]);

  // Fast lookup maps for 430+ nodes (zero O(N^2) loops)
  const nodeById = useMemo(() => {
    const map = new Map<string, ProxyNode>();
    for (const n of nodes) map.set(n.id, n);
    return map;
  }, [nodes]);

  const subNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) map.set(s.id, s.name);
    return map;
  }, [subscriptions]);

  const providerTabs = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      if (!n.enabled) continue;
      const sid = n.sub_id || "__unknown__";
      counts.set(sid, (counts.get(sid) ?? 0) + 1);
    }
    const items: Array<{ id: string; name: string; count: number }> = [];
    const seen = new Set<string>();
    for (const sub of subscriptions) {
      const cnt = counts.get(sub.id) ?? 0;
      if (cnt > 0) {
        items.push({ id: sub.id, name: sub.name, count: cnt });
        seen.add(sub.id);
      }
    }
    for (const [sid, cnt] of counts.entries()) {
      if (!seen.has(sid)) {
        items.push({
          id: sid,
          name: sid === "__unknown__" ? "其他来源" : sid,
          count: cnt,
        });
      }
    }
    return items;
  }, [nodes, subscriptions]);

  const enabledNodes = useMemo(() => nodes.filter((n) => n.enabled), [nodes]);

  const subScopedNodes = useMemo(() => {
    if (selectedSubId === "all") return enabledNodes;
    return enabledNodes.filter((n) => (n.sub_id || "__unknown__") === selectedSubId);
  }, [enabledNodes, selectedSubId]);

  const regionStats = useMemo(
    () => buildContinentRegionStats(subScopedNodes),
    [subScopedNodes]
  );

  useEffect(() => {
    if (filterContinent !== "all" && regionStats.continentCounts[filterContinent] === 0) {
      setFilterContinent("all");
    }
    if (
      filterRegion !== "all" &&
      !regionStats.allRegions.some((r) => r.code === filterRegion)
    ) {
      setFilterRegion("all");
    }
  }, [regionStats, filterContinent, filterRegion]);

  const memberIdSet = useMemo(
    () => new Set(selectedGroup?.member_node_ids ?? []),
    [selectedGroup?.member_node_ids]
  );

  // Only bind live probe/member/active dependencies when needed (members view, metric sort, or health filters)
  // so streaming probe updates never re-filter/re-sort all 430+ nodes in default "all" view.
  const memberFilterSet = viewMode === "members" ? memberIdSet : null;
  const memberActiveId =
    viewMode === "members" ? (selectedGroup?.active_node_id ?? null) : null;
  const needsLiveProbes =
    viewMode === "members" || sortMode !== "default" || filterGoogleClean || filterAiReady;
  const activeFilterProbes = needsLiveProbes ? probes : null;

  // Filter & stably sort nodes for the main grid
  const filteredNodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = enabledNodes.filter((node) => {
      if (memberFilterSet && !memberFilterSet.has(node.id)) return false;
      if (selectedSubId !== "all" && (node.sub_id || "__unknown__") !== selectedSubId) return false;
      if (!nodeMatchesContinentAndRegion(node, filterContinent, filterRegion)) {
        return false;
      }
      if (filterGoogleClean && activeFilterProbes?.[node.id]?.google_clean !== true) {
        return false;
      }
      if (filterAiReady && !isNodeAiReady(activeFilterProbes?.[node.id])) {
        return false;
      }
      if (q) {
        const subName = (subNameById.get(node.sub_id) ?? "").toLowerCase();
        const resolvedCode = resolveNodeRegionCode(node);
        const regionCn = getRegionLabel(resolvedCode).toLowerCase();
        const hay =
          `${node.name} ${node.region_code} ${resolvedCode} ${regionCn} ${node.protocol} ${subName}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const usePinned = pinnedOrder.groupId === selectedGroupId;
    const pinnedActive = usePinned ? pinnedOrder.activeId : null;
    const pinnedMembers = usePinned ? pinnedOrder.memberIds : null;

    const getMetricRank = (
      snap: ProbeSnapshot | undefined
    ): { tier: number; primary: number; secondary: number } => {
      if (!snap) return { tier: 2, primary: 0, secondary: 99999 };
      if (!snap.ok) return { tier: 3, primary: 0, secondary: 99999 };
      const lat =
        typeof snap.latency_ms === "number" && Number.isFinite(snap.latency_ms)
          ? snap.latency_ms
          : 99999;
      if (sortMode === "up_desc") {
        if (typeof snap.up_mbps === "number" && Number.isFinite(snap.up_mbps)) {
          return { tier: 0, primary: -snap.up_mbps, secondary: lat };
        }
        return { tier: 1, primary: lat, secondary: 0 };
      }
      if (sortMode === "down_desc") {
        if (typeof snap.down_mbps === "number" && Number.isFinite(snap.down_mbps)) {
          return { tier: 0, primary: -snap.down_mbps, secondary: lat };
        }
        return { tier: 1, primary: lat, secondary: 0 };
      }
      // latency_asc
      if (typeof snap.latency_ms === "number" && Number.isFinite(snap.latency_ms)) {
        const up =
          typeof snap.up_mbps === "number" && Number.isFinite(snap.up_mbps) ? snap.up_mbps : -1;
        return { tier: 0, primary: snap.latency_ms, secondary: -up };
      }
      return { tier: 1, primary: 99999, secondary: 0 };
    };

    const sorted = [...list];
    sorted.sort((a, b) => {
      if (sortMode !== "default") {
        const ra = getMetricRank(activeFilterProbes?.[a.id]);
        const rb = getMetricRank(activeFilterProbes?.[b.id]);
        if (ra.tier !== rb.tier) return ra.tier - rb.tier;
        if (ra.primary !== rb.primary) return ra.primary - rb.primary;
        if (ra.secondary !== rb.secondary) return ra.secondary - rb.secondary;
        return a.name.localeCompare(b.name);
      }
      if (viewMode === "members") {
        const aAct = memberActiveId === a.id ? 1 : 0;
        const bAct = memberActiveId === b.id ? 1 : 0;
        if (aAct !== bAct) return bAct - aAct;
        const aSnap = activeFilterProbes?.[a.id];
        const bSnap = activeFilterProbes?.[b.id];
        const aLat = aSnap?.ok ? (aSnap.latency_ms ?? 99999) : 99999;
        const bLat = bSnap?.ok ? (bSnap.latency_ms ?? 99999) : 99999;
        if (aLat !== bLat) return aLat - bLat;
        return a.name.localeCompare(b.name);
      }
      // In "all" view, keep active/initial members upfront without jumping mid-click
      if (!pinnedMembers) return 0;
      const aWeight = a.id === pinnedActive ? 2 : pinnedMembers.has(a.id) ? 1 : 0;
      const bWeight = b.id === pinnedActive ? 2 : pinnedMembers.has(b.id) ? 1 : 0;
      if (aWeight !== bWeight) return bWeight - aWeight;
      return 0;
    });

    return sorted;
  }, [
    enabledNodes,
    viewMode,
    sortMode,
    filterGoogleClean,
    filterAiReady,
    memberFilterSet,
    selectedSubId,
    filterContinent,
    filterRegion,
    searchQuery,
    subNameById,
    pinnedOrder,
    selectedGroupId,
    memberActiveId,
    activeFilterProbes,
  ]);

  const totalNodePages = Math.max(1, Math.ceil(filteredNodes.length / nodePageSize));
  const safeNodePage = Math.min(Math.max(1, nodePage), totalNodePages);

  const pagedFilteredNodes = useMemo(
    () =>
      filteredNodes.slice(
        (safeNodePage - 1) * nodePageSize,
        safeNodePage * nodePageSize
      ),
    [filteredNodes, safeNodePage, nodePageSize]
  );

  // Count how many nodes in current filter are not yet in the active group
  const unjoinedInFilterIds = useMemo(() => {
    const ids: string[] = [];
    for (const n of filteredNodes) {
      if (!memberIdSet.has(n.id)) ids.push(n.id);
    }
    return ids;
  }, [filteredNodes, memberIdSet]);

  // Gentle group-level health notice: ONLY warn if gates exist AND tested members exist AND all tested members failed
  const measuredMemberNotice = useMemo(() => {
    if (!selectedGroup || selectedGroup.hard_gates.length === 0) return null;
    let testedMemberCount = 0;
    let failedTestedCount = 0;
    for (const id of selectedGroup.member_node_ids) {
      const node = nodeById.get(id);
      const snap = probes[id];
      if (!node || !snap) continue;
      testedMemberCount += 1;
      const res = assessNodeAgainstGates(node, snap, selectedGroup.hard_gates);
      if (res.hasMeasuredFailure) failedTestedCount += 1;
    }
    if (testedMemberCount > 0 && failedTestedCount === testedMemberCount) {
      return "组内已测速的节点暂未满足右侧勾选的要求，建议测速其他节点或放宽右侧标准";
    }
    return null;
  }, [selectedGroup, nodeById, probes]);

  // Derived strategy values for right drawer
  const currentTriggerMeta: TriggerMeta = selectedGroup
    ? triggerMetas[selectedGroup.id] ?? getPrimaryTriggerMeta(selectedGroup)
    : { consecutiveFailures: 2, bypassCooldownOnDisconnect: true };

  const currentTriggerExpr = selectedGroup ? getPrimaryTriggerExpr(selectedGroup) : "";
  const uploadTriggerInfo = useMemo(
    () => parseUploadTriggerInfo(currentTriggerExpr),
    [currentTriggerExpr]
  );
  const isSelectedDirty = selectedGroup ? Boolean(dirtyGroupIds[selectedGroup.id]) : false;

  const activeRuleCount = useMemo(() => {
    if (!selectedGroup) return 0;
    let count = selectedGroup.hard_gates.length;
    if (currentTriggerExpr.trim()) count += 1;
    if (selectedGroup.match_rules.length > 0) count += 1;
    return count;
  }, [selectedGroup, currentTriggerExpr]);

  const otherGroups = useMemo(
    () => groups.filter((g) => g.id !== selectedGroup?.id),
    [groups, selectedGroup]
  );

  // Formula syntax check (only needed for advanced section)
  const formulaSyntaxCheck = useMemo(() => {
    if (!selectedGroup) return { ok: true, error: null as string | null, source: "local" as const };
    if (
      inTauri &&
      backendFormulaValidation &&
      backendFormulaValidation.checkedExpr === selectedGroup.formula_expr
    ) {
      return {
        ok: backendFormulaValidation.ok,
        error: backendFormulaValidation.error,
        source: "backend" as const,
      };
    }
    const sampleOutcome = evaluateFormulaSafely(selectedGroup.formula_expr, {
      vars: {
        up_mbps: 12,
        down_mbps: 150,
        ping_ms: 80,
        latency_ms: 80,
        jitter_ms: 5,
        loss_pct: 0,
        multiplier: 1,
        keepalive_ok: 1,
        google_clean: 1,
        unlocked: 1,
        is_443_native: 1,
        ok: 1,
      },
      probeUp: { antigravity: 12 },
      probeDown: { dl: 150 },
      probePing: { chatgpt: 80 },
      probeOk: { builtin_unlock_windsurf: true },
      unlockedSites: { chatgpt: true, google_ai: true, claude: true, windsurf: true },
    });
    return { ok: sampleOutcome.ok, error: sampleOutcome.error, source: "local" as const };
  }, [selectedGroup, inTauri, backendFormulaValidation]);

  const formattedDynamicFilter = selectedGroup
    ? formatDynamicFilter(selectedGroup.dynamic_filter)
    : "";

  /* ============================================================================
   * Action Handlers
   * ============================================================================ */

  const updateSelectedGroup = (updater: (group: MultiGroup) => MultiGroup) => {
    if (!selectedGroup) return;
    setGroups((prev) => prev.map((g) => (g.id === selectedGroup.id ? updater(g) : g)));
    setDirtyGroupIds((prev) => ({ ...prev, [selectedGroup.id]: true }));
  };

  const updateTriggerMeta = (patch: Partial<TriggerMeta>) => {
    if (!selectedGroup) return;
    const nextMeta = { ...currentTriggerMeta, ...patch };
    setTriggerMetas((prev) => ({
      ...prev,
      [selectedGroup.id]: nextMeta,
    }));
    updateSelectedGroup((g) => {
      const expr = getPrimaryTriggerExpr(g).trim();
      if (!expr) return g;
      const rest = Array.isArray(g.trigger_rules) ? g.trigger_rules.slice(1) : [];
      return {
        ...g,
        trigger_rules: [
          {
            expr,
            consecutive_failures: nextMeta.consecutiveFailures,
            bypass_cooldown_on_disconnect: nextMeta.bypassCooldownOnDisconnect,
          },
          ...rest,
        ],
      };
    });
  };

  /** Optimistically update member_node_ids with sequence guard to survive rapid multi-clicks */
  const persistGroupMembers = async (
    groupId: string,
    nextMemberIds: string[],
    toastText?: string
  ): Promise<boolean> => {
    const prevIds =
      latestMembersRef.current[groupId] ??
      groups.find((g) => g.id === groupId)?.member_node_ids ??
      [];
    const uniqueNext = Array.from(new Set(nextMemberIds));
    latestMembersRef.current[groupId] = uniqueNext;

    const seq = (memberReqSeqRef.current[groupId] ?? 0) + 1;
    memberReqSeqRef.current[groupId] = seq;

    // Optimistic state + store sync
    setGroups((prev) =>
      prev.map((g) => (g.id === groupId ? { ...g, member_node_ids: uniqueNext } : g))
    );
    appActions.syncGroups(
      appStore
        .getState()
        .groups.map((g) => (g.id === groupId ? { ...g, member_node_ids: uniqueNext } : g))
    );

    try {
      const saved = await catcloudApi.updateMultiGroupMembers(groupId, uniqueNext);
      if (memberReqSeqRef.current[groupId] === seq) {
        latestMembersRef.current[groupId] = saved.member_node_ids;
        setGroups((prev) =>
          prev.map((g) =>
            g.id === groupId
              ? {
                  ...g,
                  member_node_ids: saved.member_node_ids,
                  active_node_id: saved.active_node_id,
                }
              : g
          )
        );
        appActions.syncGroups(
          appStore.getState().groups.map((g) =>
            g.id === groupId
              ? {
                  ...g,
                  member_node_ids: saved.member_node_ids,
                  active_node_id: saved.active_node_id,
                }
              : g
          )
        );
        if (toastText) appActions.showToast(toastText, "ok");
      }
      return true;
    } catch (err) {
      if (memberReqSeqRef.current[groupId] === seq) {
        latestMembersRef.current[groupId] = prevIds;
        setGroups((prev) =>
          prev.map((g) => (g.id === groupId ? { ...g, member_node_ids: prevIds } : g))
        );
        appActions.syncGroups(
          appStore
            .getState()
            .groups.map((g) => (g.id === groupId ? { ...g, member_node_ids: prevIds } : g))
        );
        appActions.showToast(`更新组成员失败：${formatErrorMessage(err)}`, "warn");
      }
      return false;
    }
  };

  const handleToggleNodeMembership = (node: ProxyNode) => {
    if (!selectedGroup) return;
    const currentIds =
      latestMembersRef.current[selectedGroup.id] ?? selectedGroup.member_node_ids;
    const exists = currentIds.includes(node.id);
    if (exists && selectedGroup.active_node_id === node.id) {
      appActions.showToast("当前正在使用这个节点，请先切到其它节点再移出", "info");
      return;
    }
    const nextIds = exists
      ? currentIds.filter((id) => id !== node.id)
      : [...currentIds, node.id];
    void persistGroupMembers(selectedGroup.id, nextIds);
  };

  const handleUseNode = async (node: ProxyNode) => {
    if (!selectedGroup || selectingNodeId === node.id) return;
    setSelectingNodeId(node.id);
    try {
      const currentIds =
        latestMembersRef.current[selectedGroup.id] ?? selectedGroup.member_node_ids;
      if (!currentIds.includes(node.id)) {
        const joined = await persistGroupMembers(selectedGroup.id, [...currentIds, node.id]);
        if (!joined) return;
      }
      const closeOld = selectedGroup.switch_mode === "force_close_old";
      await appActions.selectGroupNode(selectedGroup.id, node.id, closeOld);
      setGroups((prev) =>
        prev.map((g) => (g.id === selectedGroup.id ? { ...g, active_node_id: node.id } : g))
      );
    } finally {
      setSelectingNodeId(null);
    }
  };

  const handleProbeSingleNode = async (node: ProxyNode) => {
    if (probingNodeIds[node.id] || probeProgress.running) return;
    setProbingNodeIds((prev) => ({ ...prev, [node.id]: true }));
    try {
      const res = await catcloudApi.runIsolatedProbes([node.id], [], "unlock", false);
      if (res.snapshots && Object.keys(res.snapshots).length > 0) {
        const merged = { ...appStore.getState().probes, ...res.snapshots };
        appActions.syncProbes(merged);
      }
      const snap = res.snapshots?.[node.id];
      if (snap && snap.ok && snap.latency_ms !== null) {
        appActions.showToast(`测速完成：${node.name} · ${Math.round(snap.latency_ms)} ms`, "ok");
      } else if (res.errors.length > 0) {
        appActions.showToast(`测速提示：${res.errors[0]}`, "warn");
      } else {
        appActions.showToast(`${node.name} 暂时连接超时，可稍后再试`, "warn");
      }
    } catch (err) {
      appActions.showToast(`测速失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setProbingNodeIds((prev) => {
        const next = { ...prev };
        delete next[node.id];
        return next;
      });
    }
  };

  const handleAddFilteredToGroup = () => {
    if (!selectedGroup || unjoinedInFilterIds.length === 0) return;
    const currentIds =
      latestMembersRef.current[selectedGroup.id] ?? selectedGroup.member_node_ids;
    const nextIds = [...currentIds, ...unjoinedInFilterIds];
    void persistGroupMembers(
      selectedGroup.id,
      nextIds,
      `已将 ${unjoinedInFilterIds.length} 个节点加入「${formatGroupDisplayName(selectedGroup.name)}」`
    );
  };

  const handleClearGroupMembers = () => {
    if (!selectedGroup || selectedGroup.member_node_ids.length === 0) return;
    if (!confirmClearMembers) {
      setConfirmClearMembers(true);
      if (clearConfirmTimerRef.current !== null) {
        window.clearTimeout(clearConfirmTimerRef.current);
      }
      clearConfirmTimerRef.current = window.setTimeout(() => {
        setConfirmClearMembers(false);
        clearConfirmTimerRef.current = null;
      }, 3500);
      return;
    }
    setConfirmClearMembers(false);
    void persistGroupMembers(
      selectedGroup.id,
      [],
      `已清空「${formatGroupDisplayName(selectedGroup.name)}」中的节点`
    );
  };

  const handleSwitchNextBestInGroup = async () => {
    if (!selectedGroup || switchingNext) return;
    if (selectedGroup.member_node_ids.length === 0 && selectedGroup.mode !== "conditional_pool") {
      appActions.showToast("当前组里还没有节点，请先点击下方节点卡片加入本组", "warn");
      return;
    }
    setSwitchingNext(true);
    try {
      const res = await catcloudApi.switchNextBestNode(selectedGroup.id);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime({
        ...rt,
        route_mode: "group",
        active_group_id: rt.active_group_id || selectedGroup.id,
        active_group_name: rt.active_group_name || selectedGroup.name,
      });
      setGroups((prev) => {
        const next = prev.map((g) =>
          g.id === selectedGroup.id ? { ...g, active_node_id: res.active_node_id } : g
        );
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(`已切至下一个最快节点：${res.active_node_name}`, "ok");
    } catch (err) {
      appActions.showToast(`切换失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSwitchingNext(false);
    }
  };

  const handleCreateGroup = async (ev: FormEvent) => {
    ev.preventDefault();
    const name = newGroupName.trim();
    if (!name) {
      appActions.showToast("请先给新多选组起个名字", "warn");
      return;
    }
    if (creatingGroup) return;
    setCreatingGroup(true);

    const tpl = CREATE_TEMPLATES.find((t) => t.id === newGroupTemplate) ?? CREATE_TEMPLATES[0];
    // Always start clean: zero hard_gates, zero trigger_rules, zero member_node_ids!
    const created: MultiGroup = {
      id: `grp-${Date.now().toString(36)}`,
      name,
      mode: tpl.mode,
      independent_routing: false,
      match_rules: [...tpl.matchRules],
      member_node_ids: [],
      dynamic_filter: null,
      primary_probe_id: null,
      hard_gates: [],
      trigger_rules: [],
      trigger_expr: null,
      formula_expr: tpl.formula,
      fallback_policy: "degrade_best_warn",
      fallback_pool_id: null,
      escalated_since: null,
      recover_probe_interval_sec: 120,
      switch_mode: tpl.switchMode,
      cooldown_sec: 60,
      hysteresis_pct: 20,
      active_node_id: null,
    };

    try {
      const saved = await catcloudApi.upsertMultiGroup(created);
      latestMembersRef.current[saved.id] = saved.member_node_ids;
      setGroups((prev) => {
        const next = [...prev, saved];
        appActions.syncGroups(next);
        return next;
      });
      setSelectedId(saved.id);
      setNewGroupName("");
      setShowCreateForm(false);
      setViewMode("all");
      appActions.showToast(`已新建「${saved.name}」，点击中间节点卡片即可加入`, "ok");
    } catch (err) {
      appActions.showToast(`新建失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCreatingGroup(false);
    }
  };

  const handleRequestDeleteGroup = (groupId: string) => {
    if (groups.length <= 1) return;
    setConfirmDeleteId(groupId);
    if (deleteConfirmTimerRef.current !== null) {
      window.clearTimeout(deleteConfirmTimerRef.current);
    }
    deleteConfirmTimerRef.current = window.setTimeout(() => {
      setConfirmDeleteId(null);
      deleteConfirmTimerRef.current = null;
    }, 4000);
  };

  const handleConfirmDeleteGroup = async (group: MultiGroup) => {
    if (deletingGroupId || groups.length <= 1) return;
    setDeletingGroupId(group.id);
    try {
      await catcloudApi.deleteMultiGroup(group.id);
      const next = groups.filter((g) => g.id !== group.id);
      delete latestMembersRef.current[group.id];
      setGroups(next);
      appActions.syncGroups(next);
      if (selectedGroup?.id === group.id) {
        setSelectedId(next[0]?.id ?? "");
      }
      setConfirmDeleteId(null);
      appActions.showToast(`已删除多选组：${formatGroupDisplayName(group.name)}`, "info");
    } catch (err) {
      appActions.showToast(`删除失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingGroupId(null);
    }
  };

  const handleCommitRename = async () => {
    if (!selectedGroup) return;
    const trimmed = nameDraft.trim();
    setEditingName(false);
    if (
      !trimmed ||
      trimmed === selectedGroup.name ||
      trimmed === formatGroupDisplayName(selectedGroup.name)
    ) {
      return;
    }

    const updated: MultiGroup = { ...selectedGroup, name: trimmed };
    try {
      const payload = normalizeGroupForBackend(updated, currentTriggerMeta);
      const saved = await catcloudApi.upsertMultiGroup(payload);
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === saved.id ? saved : g));
        appActions.syncGroups(next);
        return next;
      });
      setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      appActions.showToast(`已重命名为：${formatGroupDisplayName(saved.name)}`, "ok");
    } catch (err) {
      appActions.showToast(`重命名失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSaveSelectedGroup = async () => {
    if (!selectedGroup || savingGroup) return;
    setSavingGroup(true);
    try {
      const payload = normalizeGroupForBackend(selectedGroup, currentTriggerMeta);
      const saved = await catcloudApi.upsertMultiGroup(payload);
      latestMembersRef.current[saved.id] = saved.member_node_ids;
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === saved.id ? saved : g));
        appActions.syncGroups(next);
        return next;
      });
      setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      appActions.showToast(`策略已保存并生效：${formatGroupDisplayName(saved.name)}`, "ok");
    } catch (err) {
      appActions.showToast(`保存策略失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingGroup(false);
    }
  };

  const handleToggleGate = (expr: string) => {
    updateSelectedGroup((g) => {
      if (expr === GEMINI_GATE_EXPR) {
        const hasAnyGemini =
          g.hard_gates.includes(GEMINI_GATE_EXPR) ||
          g.hard_gates.includes(LEGACY_GEMINI_GATE_EXPR);
        const cleaned = g.hard_gates.filter(
          (item) => item !== GEMINI_GATE_EXPR && item !== LEGACY_GEMINI_GATE_EXPR
        );
        return {
          ...g,
          hard_gates: hasAnyGemini ? cleaned : [...cleaned, GEMINI_GATE_EXPR],
        };
      }
      const exists = g.hard_gates.includes(expr);
      return {
        ...g,
        hard_gates: exists
          ? g.hard_gates.filter((item) => item !== expr)
          : [...g.hard_gates, expr],
      };
    });
  };

  const handleAddCustomGate = (ev: FormEvent) => {
    ev.preventDefault();
    const expr = customGateInput.trim();
    if (!expr || !selectedGroup) return;
    if (!selectedGroup.hard_gates.includes(expr)) {
      updateSelectedGroup((g) => ({ ...g, hard_gates: [...g.hard_gates, expr] }));
    }
    setCustomGateInput("");
  };

  const setPrimaryTriggerExpr = (nextExpr: string) => {
    updateSelectedGroup((g) => {
      const rest = Array.isArray(g.trigger_rules) ? g.trigger_rules.slice(1) : [];
      const trimmed = nextExpr.trim();
      return {
        ...g,
        trigger_expr: trimmed ? nextExpr : null,
        trigger_rules: trimmed
          ? [
              {
                expr: nextExpr,
                consecutive_failures: currentTriggerMeta.consecutiveFailures,
                bypass_cooldown_on_disconnect: currentTriggerMeta.bypassCooldownOnDisconnect,
              },
              ...rest,
            ]
          : rest,
      };
    });
  };

  const handleToggleUploadTrigger = () => {
    if (!selectedGroup) return;
    if (uploadTriggerInfo.enabled) {
      if (uploadTriggerInfo.isSimple) {
        setPrimaryTriggerExpr("");
      } else {
        setPrimaryTriggerExpr("");
      }
    } else {
      const val = Number.isFinite(uploadTriggerInfo.threshold) ? uploadTriggerInfo.threshold : 2.0;
      setPrimaryTriggerExpr(`${uploadTriggerInfo.prefix} < ${val}`);
    }
  };

  const handleUploadThresholdChange = (raw: string) => {
    const num = Number(raw);
    if (!Number.isFinite(num) || num < 0) return;
    if (uploadTriggerInfo.isSimple || !currentTriggerExpr.trim()) {
      setPrimaryTriggerExpr(`${uploadTriggerInfo.prefix} < ${num}`);
    } else {
      const replaced = currentTriggerExpr.replace(
        /(up_mbps|probe_up\(\s*["'][^"']+["']\s*\))\s*<\s*\d+(?:\.\d+)?/,
        `$1 < ${num}`
      );
      setPrimaryTriggerExpr(replaced);
    }
  };

  const handleAddMatchRule = (ev: FormEvent) => {
    ev.preventDefault();
    if (!selectedGroup) return;
    const raw = newRuleInput.trim();
    if (!raw) return;

    const { rules, invalidTokens } = parseUserMatchRules(raw);
    if (rules.length === 0) {
      appActions.showToast(INVALID_MATCH_RULE_MSG, "warn");
      return;
    }

    const existing = new Set(selectedGroup.match_rules);
    const toAdd = rules.filter((r) => !existing.has(r));
    if (toAdd.length > 0) {
      updateSelectedGroup((g) => ({
        ...g,
        match_rules: [...g.match_rules, ...toAdd],
      }));
    }

    if (invalidTokens.length > 0) {
      appActions.showToast(
        `已忽略无效条目（${invalidTokens.join("、")}），${INVALID_MATCH_RULE_MSG}`,
        "warn"
      );
      setNewRuleInput(invalidTokens.join("; "));
      return;
    }

    setNewRuleInput("");
  };

  const handleInsertFormulaToken = (snippet: string) => {
    if (!selectedGroup) return;
    updateSelectedGroup((g) => {
      const base = g.formula_expr.trim();
      return {
        ...g,
        formula_expr: base ? `${base} + ${snippet}` : snippet,
      };
    });
  };

  const handleEvaluateBackend = async () => {
    if (!selectedGroup || evaluating) return;
    setEvaluating(true);
    try {
      if (isSelectedDirty) {
        const payload = normalizeGroupForBackend(selectedGroup, currentTriggerMeta);
        const saved = await catcloudApi.upsertMultiGroup(payload);
        setGroups((prev) => {
          const next = prev.map((g) => (g.id === saved.id ? saved : g));
          appActions.syncGroups(next);
          return next;
        });
        setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      }
      const report = await catcloudApi.evaluateMultiGroup(selectedGroup.id);
      setEvalReport(report);
      const latestProbes = appStore.getState().probes;
      const evalIds = new Set<string>();
      for (const c of report.gate_passed) evalIds.add(c.node_id);
      for (const c of report.gate_rejected) evalIds.add(c.node_id);
      if (evalIds.size === 0) {
        for (const id of selectedGroup.member_node_ids) evalIds.add(id);
      }
      let untestedCnt = 0;
      for (const id of evalIds) {
        if (!latestProbes[id]) untestedCnt += 1;
      }
      appActions.showToast(
        untestedCnt > 0
          ? `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个（其中 ${untestedCnt} 个尚未测速）`
          : `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`后端评估失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setEvaluating(false);
    }
  };

  const handleCopyAgentGuide = async () => {
    if (!selectedGroup) return;
    let md = buildMultiGroupAgentMarkdown(selectedGroup, currentTriggerMeta);
    if (inTauri) {
      try {
        const exported = await catcloudApi.exportAgentDocs("multi_group", false);
        if (exported && exported.trim()) {
          md = exported;
        }
      } catch {
        /* fallback to local markdown */
      }
    }
    const ok = await copyToClipboard(md);
    if (ok) {
      setCopiedGuide(true);
      appActions.showToast("已复制 AI 助手协同指南（Markdown）", "ok");
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedGuide(false);
        copyTimerRef.current = null;
      }, 2200);
    } else {
      appActions.showToast("复制失败，请检查剪贴板权限", "warn");
    }
  };

  const handleCardKeyDown = (ev: KeyboardEvent<HTMLDivElement>, onTrigger: () => void) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      onTrigger();
    }
  };

  const activeNodeInSelectedGroup = selectedGroup?.active_node_id
    ? nodeById.get(selectedGroup.active_node_id) ?? null
    : null;

  const isRuntimeActiveGroup =
    isGroupMode &&
    Boolean(selectedGroup) &&
    runtime.active_group_id === selectedGroup?.id;

  const customHardGates = useMemo(() => {
    if (!selectedGroup) return [];
    const presetSet = new Set([
      ...HARD_GATE_PRESETS.map((p) => p.expr),
      LEGACY_GEMINI_GATE_EXPR,
    ]);
    return selectedGroup.hard_gates.filter((expr) => !presetSet.has(expr));
  }, [selectedGroup]);

  const evalUntestedCount = useMemo(() => {
    if (!evalReport) return 0;
    const candidateIds = new Set<string>();
    for (const c of evalReport.gate_passed) candidateIds.add(c.node_id);
    for (const c of evalReport.gate_rejected) candidateIds.add(c.node_id);
    if (candidateIds.size === 0 && selectedGroup) {
      for (const id of selectedGroup.member_node_ids) candidateIds.add(id);
    }
    let untested = 0;
    for (const id of candidateIds) {
      if (!probes[id]) untested += 1;
    }
    return untested;
  }, [evalReport, selectedGroup, probes]);

  const selectedGroupDisplayName = selectedGroup
    ? formatGroupDisplayName(selectedGroup.name)
    : "";

  /* ============================================================================
   * Render: Three-Column Workbench (Left Groups | Center Nodes | Right Drawer)
   * ============================================================================ */

  return (
    <div className="flex min-h-[calc(100vh-2rem)] flex-col gap-3.5 lg:flex-row lg:items-stretch">
      {/* =====================================================================
          COLUMN 1: LEFT SIDEBAR (232px) — Create Group & Existing Groups List
         ===================================================================== */}
      <aside className="flex w-full shrink-0 flex-col lg:w-[232px]">
        <div className="cc-card cc-glass flex flex-1 flex-col rounded-2xl p-3">
          {/* Prominent "+ 新建多选组" primary button */}
          <button
            type="button"
            onClick={() => setShowCreateForm((v) => !v)}
            className={`flex w-full items-center justify-center gap-1.5 rounded-xl px-3.5 py-2.5 text-xs font-semibold transition-opacity ${
              showCreateForm
                ? "border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                : "bg-[var(--accent)] text-[var(--accent-ink)] shadow-sm hover:opacity-90"
            }`}
          >
            {showCreateForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            <span>{showCreateForm ? "取消新建" : "新建多选组"}</span>
          </button>

          {/* Ultra-simple inline create form */}
          {showCreateForm && (
            <form
              onSubmit={(ev) => void handleCreateGroup(ev)}
              className="mt-3 space-y-2.5 rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] p-2.5"
            >
              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  多选组名称
                </label>
                <input
                  type="text"
                  autoFocus
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  placeholder="例如：日常主力、AI 专线"
                  className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </div>

              <div>
                <div className="mb-1 text-[11px] font-medium text-[var(--text-secondary)]">
                  快捷场景（可选）
                </div>
                <div className="space-y-1.5">
                  {CREATE_TEMPLATES.map((tpl) => {
                    const picked = newGroupTemplate === tpl.id;
                    return (
                      <button
                        key={tpl.id}
                        type="button"
                        onClick={() => setNewGroupTemplate(tpl.id)}
                        className={`w-full rounded-lg border px-2.5 py-1.5 text-left transition-colors ${
                          picked
                            ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                            : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        <div className="text-[11px] font-semibold text-[var(--text)]">
                          {tpl.title}
                        </div>
                        <div className="mt-0.5 text-[10px] text-[var(--muted)]">{tpl.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="text-[10px] leading-relaxed text-[var(--muted)]">
                新建后不设限制门槛，直接去中间点选节点加入即可。
              </div>

              <button
                type="submit"
                disabled={creatingGroup}
                className="w-full rounded-lg bg-[var(--accent)] py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                {creatingGroup ? "创建中..." : "确认创建"}
              </button>
            </form>
          )}

          {/* Section heading */}
          <div className="mt-3.5 mb-2 flex items-center justify-between px-0.5">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-[var(--text-secondary)]">
              <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>我的多选组</span>
            </div>
            <span className="cc-mono text-[10px] text-[var(--muted)]">{groups.length} 组</span>
          </div>

          {/* Gentle Guide Banner when Home is Currently in Single-Node Mode */}
          {!isGroupMode && (
            <div className="mb-2.5 rounded-xl border border-[var(--green)]/35 bg-[var(--green-soft)]/55 px-2.5 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
              <div className="flex items-start gap-1.5">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--green)]" />
                <span>
                  当前首页正在使用单节点（
                  <span className="font-semibold text-[var(--text)]">
                    {runtime.active_node_name || "单节点"}
                  </span>
                  ），点下方组的「使用此组」可切回智能多选组
                </span>
              </div>
              <button
                type="button"
                onClick={() => appActions.setNav("overview")}
                className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-[var(--green)] hover:underline"
              >
                <ArrowLeft className="h-3 w-3 shrink-0" />
                <span>返回总览</span>
              </button>
            </div>
          )}

          {/* Existing multi-groups list */}
          <div className="space-y-1.5">
            {groups.map((g) => {
              const isSelected = selectedGroup?.id === g.id;
              const isSystemActive = isGroupMode && runtime.active_group_id === g.id;
              const isIndependentActive = !isSystemActive && Boolean(g.independent_routing);
              const activeNode = g.active_node_id ? nodeById.get(g.active_node_id) : null;
              const modeMeta = GROUP_MODES.find((m) => m.id === g.mode) ?? GROUP_MODES[0];
              const isDirty = Boolean(dirtyGroupIds[g.id]);
              const isConfirmingDel = confirmDeleteId === g.id;
              const displayName = formatGroupDisplayName(g.name);

              return (
                <div
                  key={g.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelectedId(g.id)}
                  onKeyDown={(ev) => handleCardKeyDown(ev, () => setSelectedId(g.id))}
                  className={`group relative cursor-pointer rounded-xl border p-2.5 transition-colors ${
                    isSystemActive && isSelected
                      ? "border-[var(--green)] bg-[var(--green-soft)]/55 shadow-xs"
                      : isSystemActive
                        ? "border-[var(--green)]/65 bg-[var(--green-soft)]/30 hover:border-[var(--green)]"
                        : isSelected
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] shadow-xs"
                          : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-1.5">
                    <div className="flex min-w-0 items-center gap-1.5">
                      {isSystemActive && (
                        <span
                          className="h-2 w-2 shrink-0 rounded-full bg-[var(--green)]"
                          title="当前系统正在使用此组"
                        />
                      )}
                      <span className="truncate text-xs font-semibold text-[var(--text)]">
                        {displayName}
                      </span>
                      {isDirty && (
                        <span
                          className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                          title="右侧策略尚未点应用"
                        />
                      )}
                    </div>

                    {groups.length > 1 && !isConfirmingDel && (
                      <button
                        type="button"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          handleRequestDeleteGroup(g.id);
                        }}
                        className="shrink-0 rounded-md p-0.5 text-[var(--muted)] opacity-0 transition-opacity hover:bg-[var(--red-soft)] hover:text-[var(--red)] group-hover:opacity-100 focus:opacity-100"
                        title="删除此多选组"
                        aria-label={`删除多选组 ${displayName}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>

                  {isConfirmingDel ? (
                    <div
                      className="mt-2 flex items-center justify-between gap-1.5 rounded-lg border border-[var(--red)]/40 bg-[var(--red-soft)] px-2 py-1"
                      onClick={(ev) => ev.stopPropagation()}
                    >
                      <span className="text-[10px] font-medium text-[var(--red)]">确认删除？</span>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          disabled={deletingGroupId === g.id}
                          onClick={() => void handleConfirmDeleteGroup(g)}
                          className="rounded bg-[var(--red)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                        >
                          {deletingGroupId === g.id ? "..." : "删"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(null)}
                          className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] hover:text-[var(--text)]"
                        >
                          取消
                        </button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="mt-1.5 flex flex-wrap items-center justify-between gap-1.5 text-[11px]">
                        <span className="cc-mono font-medium text-[var(--text-secondary)]">
                          {g.member_node_ids.length} 个节点
                        </span>
                        <div className="flex flex-wrap items-center gap-1">
                          {isIndependentActive && (
                            <span
                              title={
                                g.match_rules.length > 0
                                  ? `已开启独立分流：即使首页在用其它组，命中本组 ${g.match_rules.length} 条适用网站规则的流量也会单独走此组`
                                  : "已开启独立分流开关（在右侧添加适用网站域名后将单独接管对应流量）"
                              }
                              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--amber)]"
                            >
                              <span className="h-1.5 w-1.5 rounded-full bg-[var(--amber)]" />
                              <span>分站生效中</span>
                            </span>
                          )}
                          <span className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            {modeMeta.shortLabel}
                          </span>
                        </div>
                      </div>
                      <div className="mt-1.5 flex items-center justify-between gap-1.5">
                        <span className="min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">
                          {activeNode
                            ? `${isSystemActive ? "正在用" : "组内选定"}：${activeNode.name}`
                            : "尚未选定节点"}
                        </span>
                        {isSystemActive ? (
                          <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                            当前使用中
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setSelectedId(g.id);
                              void appActions.setActiveGroup(g.id);
                            }}
                            className="shrink-0 whitespace-nowrap rounded-md border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                          >
                            使用此组
                          </button>
                        )}
                      </div>
                    </>
                  )}
                </div>
              );
            })}

            {groups.length === 0 && (
              <div className="rounded-xl border border-dashed border-[var(--line)] px-3 py-5 text-center text-[11px] text-[var(--muted)]">
                还没有多选组，点上方按钮新建一个吧
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* =====================================================================
          COLUMN 2: CENTER MAIN STAGE — Huge, Airy Node Grid & Instant Actions
         ===================================================================== */}
      {selectedGroup ? (
        <section className="flex min-w-0 flex-1 flex-col gap-3">
          {/* Compact Top Header Bar */}
          <div className="cc-card cc-glass rounded-2xl px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-3">
                  {editingName ? (
                    <form
                      onSubmit={(ev) => {
                        ev.preventDefault();
                        void handleCommitRename();
                      }}
                      className="flex items-center gap-1.5"
                    >
                      <input
                        type="text"
                        autoFocus
                        value={nameDraft}
                        onChange={(e) => setNameDraft(e.target.value)}
                        onBlur={() => void handleCommitRename()}
                        onKeyDown={(e) => {
                          if (e.key === "Escape") {
                            setEditingName(false);
                          }
                        }}
                        className="rounded-lg border border-[var(--accent)] bg-[var(--bg-elevated)] px-2.5 py-1 text-sm font-semibold text-[var(--text)] outline-none"
                      />
                    </form>
                  ) : (
                    <div className="inline-flex min-w-0 max-w-full items-center gap-2">
                      <h1 className="truncate text-base font-semibold tracking-tight text-[var(--text)]">
                        {selectedGroupDisplayName}
                      </h1>
                      <button
                        type="button"
                        onClick={() => {
                          setNameDraft(selectedGroupDisplayName);
                          setEditingName(true);
                        }}
                        title="点击修改多选组名称"
                        aria-label="修改多选组名称"
                        className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-lg text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--accent)]"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  )}

                  {isRuntimeActiveGroup ? (
                    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--green)]/40 bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--green)]">
                      <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                      当前使用中
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void appActions.setActiveGroup(selectedGroup.id)}
                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--accent)] px-3 py-1 text-[11px] font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                    >
                      <Play className="h-2.5 w-2.5 fill-current" />
                      <span>使用此组</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => appActions.setNav("overview")}
                    className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <ArrowLeft className="h-3 w-3 shrink-0" />
                    <span>返回总览</span>
                  </button>
                </div>

                {/* Plain-language status summary */}
                <p className="mt-1 truncate text-xs text-[var(--muted)]">
                  {selectedGroup.member_node_ids.length > 0 ? (
                    <>
                      已加入{" "}
                      <span className="cc-mono font-semibold text-[var(--text)]">
                        {selectedGroup.member_node_ids.length}
                      </span>{" "}
                      个节点
                      <span className="mx-1.5 opacity-50">·</span>
                      {isRuntimeActiveGroup ? "正在用：" : "组内选定："}
                      <span
                        className={`font-medium ${
                          isRuntimeActiveGroup ? "text-[var(--green)]" : "text-[var(--text-secondary)]"
                        }`}
                      >
                        {activeNodeInSelectedGroup ? activeNodeInSelectedGroup.name : "尚未选定"}
                      </span>
                    </>
                  ) : (
                    <span>本组还没有节点 · 直接点击下方任意节点卡片即可加入</span>
                  )}
                </p>
              </div>

              {/* Two prominent top-right action buttons */}
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={switchingNext}
                  onClick={() => void handleSwitchNextBestInGroup()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  {switchingNext ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Zap className="h-3.5 w-3.5" />
                  )}
                  <span>{switchingNext ? "切换中..." : "换下一个最快"}</span>
                </button>

                <button
                  type="button"
                  onClick={() => setDrawerOpen((v) => !v)}
                  className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition-colors ${
                    drawerOpen
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  }`}
                >
                  <Settings2 className="h-3.5 w-3.5" />
                  <span>{drawerOpen ? "收起策略与标准" : "策略与标准"}</span>
                  {activeRuleCount > 0 && (
                    <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--accent)]">
                      {activeRuleCount}
                    </span>
                  )}
                  {isSelectedDirty && (
                    <span
                      className="h-1.5 w-1.5 rounded-full bg-[var(--amber)]"
                      title="有未应用的策略改动"
                    />
                  )}
                </button>
              </div>
            </div>

            {measuredMemberNotice && (
              <div className="mt-2.5 flex items-center gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)] px-3 py-1.5 text-[11px] text-[var(--amber)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span>{measuredMemberNotice}</span>
              </div>
            )}
          </div>

          {/* Spacious Two-Row Filter, Sort, Quick Health Pills & Batch Action Bar */}
          <div className="cc-card cc-glass space-y-2.5 rounded-2xl px-4 py-3">
            {/* Row 1: Wide Search Box + Source + Continent/Region + Sort Dropdown */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[160px] flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="搜索节点名、地区或来源..."
                  className="h-9 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery("")}
                    aria-label="清空搜索"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              {/* Source (Subscription) dropdown */}
              <div className="relative shrink-0">
                <Filter className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                <select
                  value={selectedSubId}
                  onChange={(e) => setSelectedSubId(e.target.value)}
                  aria-label="按来源筛选"
                  className="h-9 max-w-[175px] rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                >
                  <option value="all">全部来源 ({enabledNodes.length})</option>
                  {providerTabs.map((sub) => (
                    <option key={sub.id} value={sub.id}>
                      {sub.name} ({sub.count})
                    </option>
                  ))}
                </select>
              </div>

              {/* TAG-style two-tier Continent -> Country/Region filter */}
              <ContinentRegionFilter
                variant="select"
                stats={regionStats}
                continent={filterContinent}
                region={filterRegion}
                onContinentChange={(c) => {
                  setFilterContinent(c);
                  setNodePage(1);
                }}
                onRegionChange={(r) => {
                  setFilterRegion(r);
                  setNodePage(1);
                }}
              />

              {/* Metric Sort Dropdown */}
              <div className="relative shrink-0">
                <ArrowUpDown
                  className={`pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 ${
                    sortMode !== "default" ? "text-[var(--accent)]" : "text-[var(--muted)]"
                  }`}
                />
                <select
                  value={sortMode}
                  onChange={(e) => setSortMode(e.target.value as NodeSortMode)}
                  aria-label="节点排序方式"
                  className={`h-9 max-w-[200px] cursor-pointer appearance-none rounded-xl border bg-[var(--bg-elevated)] pl-8 pr-7 text-xs font-medium text-[var(--text)] outline-none transition-colors hover:border-[var(--line-strong)] focus:border-[var(--accent)] ${
                    sortMode !== "default"
                      ? "border-[var(--accent)]/60"
                      : "border-[var(--line)]"
                  }`}
                >
                  <option value="default">排序：默认（在用优先）</option>
                  <option value="up_desc">排序：上传最快</option>
                  <option value="down_desc">排序：下载最快</option>
                  <option value="latency_asc">排序：延迟最低</option>
                </select>
                <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              </div>
            </div>

            {/* Row 2: View Mode Switch + Quick Health Filter Pills + Batch Actions */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)]/60 pt-2.5">
              <div className="flex flex-wrap items-center gap-2">
                {/* View mode segmented switch */}
                <div className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-xs">
                  <button
                    type="button"
                    onClick={() => setViewMode("all")}
                    className={`rounded-lg px-2.5 py-1 font-medium transition-colors ${
                      viewMode === "all"
                        ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                        : "text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    全部节点
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewMode("members")}
                    className={`rounded-lg px-2.5 py-1 font-medium transition-colors ${
                      viewMode === "members"
                        ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                        : "text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    仅看本组 ({selectedGroup.member_node_ids.length})
                  </button>
                </div>

                {/* Quick Health Filter Pills */}
                <button
                  type="button"
                  aria-pressed={filterGoogleClean}
                  onClick={() => setFilterGoogleClean((v) => !v)}
                  title="仅看已测出谷歌地区正常的节点（不送中）"
                  className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1 text-xs font-medium transition-colors ${
                    filterGoogleClean
                      ? "border-[var(--green)]/60 bg-[var(--green-soft)] text-[var(--green)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--green)]/50 hover:text-[var(--text)]"
                  }`}
                >
                  <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                  <span>谷歌正常</span>
                </button>

                <button
                  type="button"
                  aria-pressed={filterAiReady}
                  onClick={() => setFilterAiReady((v) => !v)}
                  title="仅看已测出支持 ChatGPT / Gemini / Claude / Windsurf 任一 AI 的节点"
                  className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1 text-xs font-medium transition-colors ${
                    filterAiReady
                      ? "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)]/50 hover:text-[var(--text)]"
                  }`}
                >
                  <Sparkles className="h-3.5 w-3.5 shrink-0" />
                  <span>AI 可用</span>
                </button>
              </div>

              {/* Batch quick actions */}
              <div className="flex flex-wrap items-center gap-1.5">
                {viewMode === "all" && unjoinedInFilterIds.length > 0 && (
                  <button
                    type="button"
                    onClick={handleAddFilteredToGroup}
                    className="inline-flex items-center gap-1 rounded-xl border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>当前筛选全加入 ({unjoinedInFilterIds.length})</span>
                  </button>
                )}

                {selectedGroup.member_node_ids.length > 0 && (
                  <button
                    type="button"
                    onClick={handleClearGroupMembers}
                    className={`rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                      confirmClearMembers
                        ? "border-[var(--red)] bg-[var(--red-soft)] text-[var(--red)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--red)]/50 hover:text-[var(--red)]"
                    }`}
                  >
                    {confirmClearMembers ? "再点一次确认清空" : "清空本组"}
                  </button>
                )}
              </div>
            </div>

            {/* Compact Legend & Match Count Row */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
              <div className="flex flex-wrap items-center gap-3">
                <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
                  <span className="h-3 w-3 shrink-0 rounded-[4px] bg-[var(--green)] shadow-xs" />
                  <span className="font-medium">正在用</span>
                </span>
                <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
                  <span className="h-3 w-3 shrink-0 rounded-[4px] bg-[var(--accent)] shadow-xs" />
                  <span className="font-medium">已在本组</span>
                </span>
                <span className="inline-flex items-center gap-1.5 text-[var(--muted)]">
                  <span className="h-3 w-3 shrink-0 rounded-[4px] border-2 border-[var(--line-strong)] bg-[var(--card)]" />
                  <span>未加入</span>
                </span>
                <span className="cc-mono text-[11px] text-[var(--muted)]">
                  · 匹配 {filteredNodes.length} 个
                  {totalNodePages > 1 ? `（第 ${safeNodePage}/${totalNodePages} 页）` : ""}
                </span>
              </div>

              {(searchQuery ||
                selectedSubId !== "all" ||
                filterContinent !== "all" ||
                filterRegion !== "all" ||
                filterGoogleClean ||
                filterAiReady ||
                sortMode !== "default") && (
                <button
                  type="button"
                  onClick={() => {
                    setSearchQuery("");
                    setSelectedSubId("all");
                    setFilterContinent("all");
                    setFilterRegion("all");
                    setFilterGoogleClean(false);
                    setFilterAiReady(false);
                    setSortMode("default");
                    setNodePage(1);
                  }}
                  className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)] transition-colors hover:text-[var(--accent)]"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>重置筛选</span>
                </button>
              )}
            </div>
          </div>

          {/* Responsive Node Card Grid Container (Stretches to align bottom edge with left & right columns) */}
          <div className="cc-card cc-glass flex flex-1 flex-col rounded-2xl p-3">
          {totalNodePages > 1 && (
            <PaginationBar
              currentPage={safeNodePage}
              totalPages={totalNodePages}
              totalItems={filteredNodes.length}
              pageSize={nodePageSize}
              pageSizeOptions={NODE_PAGE_SIZE_OPTIONS}
              onPageChange={setNodePage}
              onPageSizeChange={(s) => {
                setNodePageSize(s);
                setNodePage(1);
              }}
              compact
              className="mb-2.5 border-b border-[var(--line)]/60 pb-2"
            />
          )}

          {pagedFilteredNodes.length > 0 ? (
            <div
              className={`grid grid-cols-1 gap-2.5 sm:grid-cols-2 ${
                drawerOpen ? "2xl:grid-cols-3" : "xl:grid-cols-3 2xl:grid-cols-4"
              }`}
            >
              {pagedFilteredNodes.map((node) => {
                const isActive = selectedGroup.active_node_id === node.id;
                const isLiveActive = isActive && isRuntimeActiveGroup;
                const isMember = memberIdSet.has(node.id);
                const snap = probes[node.id];
                const subName = subNameById.get(node.sub_id) ?? "订阅节点";
                const isProbing = Boolean(probingNodeIds[node.id]);
                const isSelecting = selectingNodeId === node.id;
                const gateEval = assessNodeAgainstGates(node, snap, selectedGroup.hard_gates);
                const regionCode = resolveNodeRegionCode(node);
                const isHighMult = node.multiplier > 1.05;
                const isLowMult = node.multiplier < 0.95;

                // Distinct visual framing: Live active (emerald thick border) > Group-selected (soft emerald) > Member (warm-gold thick border) > Non-member (subtle gray)
                const cardClass = isLiveActive
                  ? "border-2 border-[var(--green)] bg-[var(--green-soft)] shadow-sm"
                  : isActive
                    ? "border-2 border-[var(--green)]/60 bg-[var(--green-soft)]/45"
                    : isMember
                      ? "border-2 border-[var(--accent)] bg-[var(--accent-soft)]"
                      : "border border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)] hover:bg-[var(--card-hover)]";

                return (
                  <div
                    key={node.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => handleToggleNodeMembership(node)}
                    onKeyDown={(ev) =>
                      handleCardKeyDown(ev, () => handleToggleNodeMembership(node))
                    }
                    className={`group relative flex cursor-pointer flex-col justify-between gap-2.5 rounded-xl p-3 transition-all ${cardClass}`}
                  >
                    {/* Top row: region badge + node name + membership badge */}
                    <div className="flex items-center justify-between gap-1.5">
                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        <span
                          title={getRegionLabel(regionCode)}
                          className="cc-mono shrink-0 rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-secondary)]"
                        >
                          {regionCode}
                        </span>
                        <span
                          title={node.name}
                          className="min-w-0 flex-1 truncate text-xs font-semibold text-[var(--text)]"
                        >
                          {node.name}
                        </span>
                      </div>

                      {isLiveActive ? (
                        <span className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--green)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                          <Star className="h-2.5 w-2.5 fill-current" />
                          <span>正在用</span>
                        </span>
                      ) : isActive ? (
                        <span className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-full border border-[var(--green)]/50 bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                          <Star className="h-2.5 w-2.5" />
                          <span>组内选定</span>
                        </span>
                      ) : isMember ? (
                        <span className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-full border border-[var(--accent)]/50 bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                          <Check className="h-2.5 w-2.5" />
                          <span>在组内</span>
                        </span>
                      ) : (
                        <span className="pointer-events-none absolute right-2.5 top-2.5 rounded-full border border-[var(--accent)]/40 bg-[var(--card)]/95 px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)] opacity-0 shadow-xs transition-opacity group-hover:opacity-100">
                          + 加入本组
                        </span>
                      )}
                    </div>

                    {/* Middle row: provider + multiplier + Google clean/CN & AI unlock dots */}
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span
                        title={subName}
                        className="max-w-[128px] truncate rounded-md bg-[var(--bg-elevated)]/90 px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                      >
                        {subName}
                      </span>

                      {isLowMult ? (
                        <span className="cc-mono rounded-md bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                          {formatMultiplierLabel(node.multiplier)}
                        </span>
                      ) : isHighMult ? (
                        <span className="cc-mono rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--amber)]">
                          {formatMultiplierLabel(node.multiplier)}
                        </span>
                      ) : (
                        <span className="cc-mono text-[10px] text-[var(--muted)]/80">1x</span>
                      )}

                      {snap?.google_clean === true && (
                        <span className="rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                          谷歌正常
                        </span>
                      )}
                      {snap?.google_clean === false && (
                        <span className="rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]">
                          送中
                        </span>
                      )}
                      {snap?.google_risk_mismatch && (
                        <span
                          className="rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                          title="不同网站识别出的地区存在差异，仅供参考"
                        >
                          地区有偏差
                        </span>
                      )}

                      {(() => {
                        const aiDots = extractCardAiDots(snap);
                        if (aiDots.length === 0) return null;
                        return (
                          <span
                            className="inline-flex items-center gap-1"
                            title={`AI 解锁：${aiDots.map((d) => d.label).join(" · ")}`}
                          >
                            {aiDots.map((dot) => (
                              <span
                                key={dot.id}
                                title={dot.label}
                                aria-label={dot.label}
                                className="inline-flex items-center gap-0.5 rounded bg-[var(--accent-soft)] px-1 py-0.5 text-[9px] font-medium text-[var(--accent)]"
                              >
                                <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                                {dot.short}
                              </span>
                            ))}
                          </span>
                        );
                      })()}
                    </div>

                    {/* Bottom row: gentle probe status + 2 quick actions ("测" & "用它") */}
                    <div className="flex items-center justify-between gap-2 pt-0.5">
                      <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px]">
                        {!snap ? (
                          <span className="rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            待测
                          </span>
                        ) : !snap.ok ? (
                          <span
                            title="最近一次测速未连通，可点右侧「测」重测"
                            className="rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]"
                          >
                            暂不可达
                          </span>
                        ) : (
                          <>
                            {snap.latency_ms !== null && (
                              <span
                                className="cc-mono cc-tabular font-semibold"
                                style={{ color: formatLatencyTone(snap.latency_ms) }}
                              >
                                {Math.round(snap.latency_ms)} ms
                              </span>
                            )}
                            {snap.up_mbps !== null && (
                              <span className="cc-mono cc-tabular text-[10px] text-[var(--coral)]">
                                ↑{snap.up_mbps.toFixed(1)}M
                              </span>
                            )}
                            {snap.down_mbps !== null && (
                              <span className="cc-mono cc-tabular text-[10px] text-[var(--sky)]">
                                ↓{snap.down_mbps >= 100 ? Math.round(snap.down_mbps) : snap.down_mbps.toFixed(1)}M
                              </span>
                            )}
                            {gateEval.hasMeasuredFailure && (
                              <span
                                title={`实测未达标：${gateEval.failedReasons.join("、")}`}
                                className="rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                              >
                                实测未达标
                              </span>
                            )}
                          </>
                        )}
                      </div>

                      <div
                        className="flex shrink-0 items-center gap-1"
                        onClick={(ev) => ev.stopPropagation()}
                      >
                        <button
                          type="button"
                          disabled={isProbing || probeProgress.running}
                          onClick={() => void handleProbeSingleNode(node)}
                          title={
                            probeProgress.running
                              ? "测速任务进行中，请等待当前测速完成"
                              : "快速测一下这个节点的延迟与解锁"
                          }
                          className="inline-flex items-center gap-0.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {isProbing ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Activity className="h-3 w-3" />
                          )}
                          <span>测</span>
                        </button>

                        <button
                          type="button"
                          disabled={isLiveActive || isSelecting}
                          onClick={() => void handleUseNode(node)}
                          title={
                            isLiveActive
                              ? "当前正在使用此节点"
                              : isActive
                                ? "启用此组并立即切换为当前使用节点"
                                : isMember
                                  ? "立即切换为当前使用节点"
                                  : "加入本组并立即切换为当前使用节点"
                          }
                          className={`inline-flex items-center gap-0.5 rounded-lg px-2 py-1 text-[11px] font-semibold transition-colors ${
                            isLiveActive
                              ? "border border-[var(--green)]/40 bg-[var(--card)] text-[var(--green)] opacity-85"
                              : "bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                          }`}
                        >
                          {isSelecting ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : isLiveActive ? (
                            <Check className="h-3 w-3" />
                          ) : (
                            <Play className="h-2.5 w-2.5 fill-current" />
                          )}
                          <span>{isLiveActive ? "在用" : "用它"}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center px-6 py-12 text-center">
              <p className="text-xs font-medium text-[var(--text-secondary)]">
                {viewMode === "members" && selectedGroup.member_node_ids.length === 0
                  ? "当前多选组里还没有节点"
                  : enabledNodes.length === 0
                    ? "节点库里还没有节点，请先去「节点与订阅」导入订阅"
                    : "没有找到符合当前筛选条件的节点"}
              </p>
              {viewMode === "members" &&
                selectedGroup.member_node_ids.length === 0 &&
                enabledNodes.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setViewMode("all")}
                    className="mt-3 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                  >
                    切到「全部节点」挑选加入
                  </button>
                )}
              {(searchQuery ||
                selectedSubId !== "all" ||
                filterContinent !== "all" ||
                filterRegion !== "all" ||
                filterGoogleClean ||
                filterAiReady) && (
                <button
                  type="button"
                  onClick={() => {
                    setSearchQuery("");
                    setSelectedSubId("all");
                    setFilterContinent("all");
                    setFilterRegion("all");
                    setFilterGoogleClean(false);
                    setFilterAiReady(false);
                    setSortMode("default");
                    setNodePage(1);
                  }}
                  className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                >
                  重置全部筛选
                </button>
              )}
            </div>
          )}

          {/* Pagination bar with page-size switcher & direct page jump */}
          {filteredNodes.length > 0 && (
            <PaginationBar
              currentPage={safeNodePage}
              totalPages={totalNodePages}
              totalItems={filteredNodes.length}
              pageSize={nodePageSize}
              pageSizeOptions={NODE_PAGE_SIZE_OPTIONS}
              onPageChange={setNodePage}
              onPageSizeChange={(s) => {
                setNodePageSize(s);
                setNodePage(1);
              }}
              className="mt-3 border-t border-[var(--line)]/60 pt-2.5"
            />
          )}
          </div>
        </section>
      ) : (
        <section className="cc-card cc-glass flex flex-1 items-center justify-center rounded-2xl p-10 text-center text-xs text-[var(--muted)]">
          暂无多选组，请点击左侧「+ 新建多选组」创建首个分组。
        </section>
      )}

      {/* =====================================================================
          COLUMN 3: RIGHT COLLAPSIBLE STRATEGY DRAWER (Collapsed strip / 332px)
         ===================================================================== */}
      {selectedGroup && !drawerOpen && (
        <aside className="hidden lg:flex lg:shrink-0 lg:flex-col">
          <button
            type="button"
            onClick={() => setDrawerOpen(true)}
            title="点击展开右侧策略与标准设置"
            className="cc-card cc-glass flex w-[44px] flex-1 flex-col items-center justify-start gap-3 rounded-2xl py-4 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <span className="flex flex-col items-center gap-3 lg:sticky lg:top-4">
              <Settings2 className="h-4 w-4 text-[var(--accent)]" />
              <span
                className="text-xs font-medium tracking-widest"
                style={{ writingMode: "vertical-rl" }}
              >
                点击展开策略与标准
              </span>
              {activeRuleCount > 0 && (
                <span className="cc-mono flex h-5 w-5 items-center justify-center rounded-full bg-[var(--accent-soft)] text-[10px] font-semibold text-[var(--accent)]">
                  {activeRuleCount}
                </span>
              )}
            </span>
          </button>
        </aside>
      )}

      {selectedGroup && drawerOpen && (
        <aside className="flex w-full shrink-0 flex-col lg:w-[332px]">
          <div className="cc-card cc-glass flex flex-1 flex-col rounded-2xl">
            {/* Drawer Header */}
            <div className="flex items-center justify-between gap-2 border-b border-[var(--line)] px-4 py-3">
              <div className="flex items-center gap-2">
                <Settings2 className="h-4 w-4 text-[var(--accent)]" />
                <div>
                  <h2 className="text-xs font-semibold text-[var(--text)]">策略与标准</h2>
                  <p className="text-[10px] text-[var(--muted)]">
                    针对「{selectedGroupDisplayName}」的选点规则
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
                title="收起策略面板"
                aria-label="收起策略面板"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-5 p-4">
              {/* 1. 选点模式 */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-[var(--text)]">1. 选点模式</div>
                <div className="space-y-1.5">
                  {GROUP_MODES.map((m) => {
                    const active = selectedGroup.mode === m.id;
                    return (
                      <button
                        key={m.id}
                        type="button"
                        onClick={() => updateSelectedGroup((g) => ({ ...g, mode: m.id }))}
                        className={`w-full rounded-xl border px-3 py-2.5 text-left transition-colors ${
                          active
                            ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-[var(--text)]">
                            {m.title}
                          </span>
                          {active && <Check className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />}
                        </div>
                        <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                          {m.desc}
                        </p>
                      </button>
                    );
                  })}
                </div>

                {selectedGroup.mode === "conditional_pool" && (
                  <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-[11px]">
                    <span className="text-[var(--text-secondary)]">
                      {formattedDynamicFilter
                        ? "已配置自动吸纳筛选条件，订阅更新时自动生效"
                        : "订阅更新后将按条件自动吸纳达标节点"}
                    </span>
                    <button
                      type="button"
                      onClick={() => setAdvancedOpen(true)}
                      className="shrink-0 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[10px] font-medium text-[var(--accent)] hover:border-[var(--accent)]"
                    >
                      去高级设置编辑
                    </button>
                  </div>
                )}
              </div>

              {/* 2. 必须满足的要求（门槛） */}
              <div className="space-y-2 border-t border-[var(--line)]/70 pt-4">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    2. 必须满足的要求（门槛）
                  </div>
                  {selectedGroup.hard_gates.length > 0 && (
                    <button
                      type="button"
                      onClick={() => updateSelectedGroup((g) => ({ ...g, hard_gates: [] }))}
                      className="text-[10px] text-[var(--muted)] hover:text-[var(--accent)]"
                    >
                      全部取消
                    </button>
                  )}
                </div>

                <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-[11px] leading-relaxed text-[var(--muted)]">
                  勾选后，自动选点时只优先挑满足下面条件的节点；
                  <span className="font-medium text-[var(--text-secondary)]">
                    还没测过速的节点标「待测」，不会直接判淘汰
                  </span>
                  。
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {HARD_GATE_PRESETS.map((preset) => {
                    const enabled =
                      selectedGroup.hard_gates.includes(preset.expr) ||
                      (preset.expr === GEMINI_GATE_EXPR &&
                        selectedGroup.hard_gates.includes(LEGACY_GEMINI_GATE_EXPR));
                    return (
                      <button
                        key={preset.expr}
                        type="button"
                        onClick={() => handleToggleGate(preset.expr)}
                        className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                          enabled
                            ? "border-[var(--green)]/60 bg-[var(--green-soft)] text-[var(--green)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        {enabled ? (
                          <ShieldCheck className="h-3 w-3 shrink-0" />
                        ) : (
                          <Plus className="h-3 w-3 shrink-0 opacity-60" />
                        )}
                        <span>{preset.label}</span>
                      </button>
                    );
                  })}
                </div>

                {customHardGates.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {customHardGates.map((expr) => (
                      <span
                        key={expr}
                        className="cc-mono inline-flex items-center gap-1 rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                      >
                        {expr}
                        <button
                          type="button"
                          onClick={() => handleToggleGate(expr)}
                          aria-label={`移除条件 ${expr}`}
                          className="text-[var(--muted)] hover:text-[var(--red)]"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* 3. 什么时候自动换节点 */}
              <div className="space-y-2.5 border-t border-[var(--line)]/70 pt-4">
                <div className="text-xs font-semibold text-[var(--text)]">
                  3. 什么时候自动换节点
                </div>

                {/* Upload speed threshold switch + inline number */}
                <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                      上行速度太慢时自动切
                    </span>
                    <button
                      type="button"
                      onClick={handleToggleUploadTrigger}
                      className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold transition-colors ${
                        uploadTriggerInfo.enabled
                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                          : "bg-[var(--card)] text-[var(--muted)]"
                      }`}
                    >
                      {uploadTriggerInfo.enabled ? "已开启" : "未开启"}
                    </button>
                  </div>

                  {uploadTriggerInfo.enabled && (
                    <div className="mt-2 space-y-1">
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-[var(--text-secondary)]">
                        <span>上行低于</span>
                        <input
                          type="number"
                          step="0.5"
                          min="0.1"
                          max="500"
                          value={uploadTriggerInfo.threshold}
                          onChange={(e) => handleUploadThresholdChange(e.target.value)}
                          className="cc-mono w-16 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-center text-xs font-semibold text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                        <span>Mbps 自动切换</span>
                      </div>
                      <div className="text-[10px] text-[var(--muted)]">
                        约{" "}
                        {uploadTriggerInfo.threshold / 8 >= 1
                          ? (uploadTriggerInfo.threshold / 8).toFixed(1)
                          : (uploadTriggerInfo.threshold / 8).toFixed(2)}{" "}
                        MB/s（8 Mbps ≈ 1 MB/s）
                      </div>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <label className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2">
                    <span className="block text-[10px] text-[var(--muted)]">连续失败几次换</span>
                    <div className="mt-1 flex items-baseline gap-1">
                      <input
                        type="number"
                        min={1}
                        max={10}
                        value={currentTriggerMeta.consecutiveFailures}
                        onChange={(e) =>
                          updateTriggerMeta({
                            consecutiveFailures: Math.max(1, Number(e.target.value) || 1),
                          })
                        }
                        className="cc-mono w-full bg-transparent text-sm font-semibold text-[var(--text)] outline-none"
                      />
                      <span className="text-[10px] text-[var(--muted)]">次</span>
                    </div>
                  </label>

                  <label className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2">
                    <span className="block text-[10px] text-[var(--muted)]">换完冷静多久</span>
                    <div className="mt-1 flex items-baseline gap-1">
                      <input
                        type="number"
                        min={10}
                        max={600}
                        value={selectedGroup.cooldown_sec}
                        onChange={(e) =>
                          updateSelectedGroup((g) => ({
                            ...g,
                            cooldown_sec: Math.max(10, Number(e.target.value) || 60),
                          }))
                        }
                        className="cc-mono w-full bg-transparent text-sm font-semibold text-[var(--text)] outline-none"
                      />
                      <span className="text-[10px] text-[var(--muted)]">秒</span>
                    </div>
                  </label>
                </div>

                <button
                  type="button"
                  onClick={() =>
                    updateSelectedGroup((g) => ({
                      ...g,
                      switch_mode:
                        g.switch_mode === "force_close_old"
                          ? "graceful_new_only"
                          : "force_close_old",
                    }))
                  }
                  className="flex w-full items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-left text-[11px] hover:border-[var(--line-strong)]"
                >
                  <div>
                    <div className="font-medium text-[var(--text-secondary)]">
                      切节点时立即断开旧连接
                    </div>
                    <div className="text-[10px] text-[var(--muted)]">
                      AI 聊天推荐开启，防止卡死在旧线路
                    </div>
                  </div>
                  <span
                    className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                      selectedGroup.switch_mode === "force_close_old"
                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                        : "bg-[var(--card)] text-[var(--muted)]"
                    }`}
                  >
                    {selectedGroup.switch_mode === "force_close_old" ? "开启" : "温和"}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() =>
                    updateTriggerMeta({
                      bypassCooldownOnDisconnect: !currentTriggerMeta.bypassCooldownOnDisconnect,
                    })
                  }
                  className="flex w-full items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-left text-[11px] hover:border-[var(--line-strong)]"
                >
                  <span className="text-[var(--text-secondary)]">彻底断连时跳过冷却立刻换</span>
                  <span
                    className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                      currentTriggerMeta.bypassCooldownOnDisconnect
                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                        : "bg-[var(--card)] text-[var(--muted)]"
                    }`}
                  >
                    {currentTriggerMeta.bypassCooldownOnDisconnect ? "开启" : "关闭"}
                  </span>
                </button>
              </div>

              {/* 4. 全部不达标怎么办 */}
              <div className="space-y-2 border-t border-[var(--line)]/70 pt-4">
                <div className="text-xs font-semibold text-[var(--text)]">4. 全部不达标怎么办</div>
                <div className="space-y-1.5">
                  {FALLBACK_POLICIES.map((pol) => {
                    const selected = selectedGroup.fallback_policy === pol.id;
                    return (
                      <button
                        key={pol.id}
                        type="button"
                        onClick={() =>
                          updateSelectedGroup((g) => ({
                            ...g,
                            fallback_policy: pol.id,
                            fallback_pool_id:
                              pol.id === "cross_pool_escalate"
                                ? g.fallback_pool_id ?? otherGroups[0]?.id ?? null
                                : g.fallback_pool_id,
                          }))
                        }
                        className={`w-full rounded-xl border px-3 py-2 text-left transition-colors ${
                          selected
                            ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-[var(--text)]">
                            {pol.title}
                          </span>
                          {selected && (
                            <Check className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                          )}
                        </div>
                        <p className="mt-0.5 text-[10px] leading-relaxed text-[var(--muted)]">
                          {pol.desc}
                        </p>
                      </button>
                    );
                  })}
                </div>

                {selectedGroup.fallback_policy === "cross_pool_escalate" && (
                  <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 text-xs">
                    <label className="block">
                      <span className="text-[11px] text-[var(--muted)]">选择备用组</span>
                      <select
                        value={selectedGroup.fallback_pool_id ?? ""}
                        onChange={(e) =>
                          updateSelectedGroup((g) => ({
                            ...g,
                            fallback_pool_id: e.target.value || null,
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                      >
                        <option value="">请选择一个备用多选组</option>
                        {otherGroups.map((og) => (
                          <option key={og.id} value={og.id}>
                            {formatGroupDisplayName(og.name)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="block">
                      <span className="text-[11px] text-[var(--muted)]">
                        每隔多久探测主组恢复（秒）
                      </span>
                      <input
                        type="number"
                        min={30}
                        max={1800}
                        value={selectedGroup.recover_probe_interval_sec}
                        onChange={(e) =>
                          updateSelectedGroup((g) => ({
                            ...g,
                            recover_probe_interval_sec: Math.max(
                              30,
                              Number(e.target.value) || 120
                            ),
                          }))
                        }
                        className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                      />
                    </label>
                  </div>
                )}
              </div>

              {/* 5. 适用网站 */}
              <div className="space-y-2.5 border-t border-[var(--line)]/70 pt-4">
                <div className="text-xs font-semibold text-[var(--text)]">
                  5. 适用网站（哪些网站走这个组）
                </div>

                {/* Independent site routing switch (default off so inactive groups never steal traffic) */}
                <button
                  type="button"
                  role="switch"
                  aria-checked={Boolean(selectedGroup.independent_routing)}
                  onClick={() =>
                    updateSelectedGroup((g) => ({
                      ...g,
                      independent_routing: !Boolean(g.independent_routing),
                    }))
                  }
                  className={`w-full rounded-xl border p-2.5 text-left transition-colors ${
                    selectedGroup.independent_routing
                      ? "border-[var(--amber)]/55 bg-[var(--amber-soft)]/50"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-semibold text-[var(--text)]">
                      独立接管专属网站分流
                    </span>
                    <span
                      className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold transition-colors ${
                        selectedGroup.independent_routing
                          ? "bg-[var(--amber)] text-[var(--accent-ink)]"
                          : "bg-[var(--card)] text-[var(--muted)]"
                      }`}
                    >
                      {selectedGroup.independent_routing ? "已开启" : "已关闭"}
                    </span>
                  </div>
                  <p className="mt-1.5 text-[10px] leading-relaxed text-[var(--muted)]">
                    关闭时，只有首页选中本组才会走这里，绝不抢其它组的流量；打开后，即使首页在用别的组，命中下方域名的网站也会单独走本组
                  </p>
                  {selectedGroup.independent_routing && selectedGroup.match_rules.length === 0 && (
                    <p className="mt-1 text-[10px] font-medium text-[var(--amber)]">
                      提示：请在下方添加至少一条网站域名，独立分流才会匹配生效
                    </p>
                  )}
                </button>

                <div className="flex flex-wrap gap-1.5">
                  {selectedGroup.match_rules.length > 0 ? (
                    selectedGroup.match_rules.map((rule) => {
                      const chip = formatMatchRuleChip(rule);
                      return (
                        <span
                          key={rule}
                          title={rule}
                          className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--text-secondary)]"
                        >
                          {chip.tag && (
                            <span className="rounded bg-[var(--card)] px-1 text-[9px] text-[var(--muted)]">
                              {chip.tag}
                            </span>
                          )}
                          <span className="cc-mono">{chip.display}</span>
                          <button
                            type="button"
                            onClick={() =>
                              updateSelectedGroup((g) => ({
                                ...g,
                                match_rules: g.match_rules.filter((r) => r !== rule),
                              }))
                            }
                            aria-label={`移除网站 ${chip.display}`}
                            className="text-[var(--muted)] hover:text-[var(--red)]"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      );
                    })
                  ) : (
                    <span className="text-[11px] text-[var(--muted)]">
                      暂未限定网站（可作手动主力组或备用组）
                    </span>
                  )}
                </div>

                <form onSubmit={handleAddMatchRule} className="flex gap-1.5">
                  <input
                    type="text"
                    value={newRuleInput}
                    onChange={(e) => setNewRuleInput(e.target.value)}
                    placeholder="输入域名，如 openai.com"
                    className="min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                  <button
                    type="submit"
                    className="shrink-0 rounded-lg border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    添加
                  </button>
                </form>
                <div className="text-[10px] text-[var(--muted)]">
                  直接填域名会自动匹配子域名；完整规则（如 DOMAIN-SUFFIX,anthropic.com）会原样保留，多条请用分号或换行分隔。
                </div>
              </div>

              {/* 6. 高级设置（默认折叠：自定义 AST 公式、后端校验与 AI 协同） */}
              <div className="border-t border-[var(--line)]/70 pt-3">
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((v) => !v)}
                  className="flex w-full items-center justify-between rounded-xl px-1 py-1.5 text-left text-xs font-medium text-[var(--muted)] transition-colors hover:text-[var(--text)]"
                >
                  <span className="inline-flex items-center gap-1.5">
                    {advancedOpen ? (
                      <ChevronDown className="h-3.5 w-3.5 text-[var(--accent)]" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5" />
                    )}
                    <span>高级：自定义评分公式与 AI 协同</span>
                  </span>
                </button>

                {advancedOpen && (
                  <div className="mt-2.5 space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3">
                    {/* Formula presets */}
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-1.5">
                        <span className="text-[11px] font-semibold text-[var(--text-secondary)]">
                          节点评分公式（安全公式校验）
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            updateSelectedGroup((g) => ({
                              ...g,
                              formula_expr: FORMULA_COST_EFFECTIVE,
                            }))
                          }
                          className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          <RotateCcw className="h-3 w-3" />
                          <span>重置</span>
                        </button>
                      </div>

                      <div className="flex flex-wrap gap-1.5">
                        <button
                          type="button"
                          onClick={() =>
                            updateSelectedGroup((g) => ({
                              ...g,
                              formula_expr: FORMULA_COST_EFFECTIVE,
                            }))
                          }
                          className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-[10px] font-medium ${
                            selectedGroup.formula_expr.trim() === FORMULA_COST_EFFECTIVE
                              ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
                          }`}
                        >
                          <Sparkles className="h-3 w-3" />
                          <span>低倍率性价比</span>
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            updateSelectedGroup((g) => ({ ...g, formula_expr: FORMULA_MAX_PERF }))
                          }
                          className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-[10px] font-medium ${
                            selectedGroup.formula_expr.trim() === FORMULA_MAX_PERF
                              ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
                          }`}
                        >
                          <Zap className="h-3 w-3" />
                          <span>纯性能最快</span>
                        </button>
                      </div>

                      <textarea
                        rows={3}
                        value={selectedGroup.formula_expr}
                        onChange={(e) =>
                          updateSelectedGroup((g) => ({ ...g, formula_expr: e.target.value }))
                        }
                        spellCheck={false}
                        className="cc-mono cc-selectable w-full rounded-lg border border-[var(--line)] bg-[var(--card)] p-2 text-[11px] leading-relaxed text-[var(--text)] outline-none focus:border-[var(--accent)]"
                      />

                      <div className="text-[10px]">
                        {formulaSyntaxCheck.ok ? (
                          <span className="inline-flex items-center gap-1 text-[var(--green)]">
                            <CheckCircle2 className="h-3 w-3 shrink-0" />
                            <span>
                              {formulaSyntaxCheck.source === "backend"
                                ? "后端公式校验通过"
                                : "公式语法校验通过"}
                            </span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[var(--red)]">
                            <AlertTriangle className="h-3 w-3 shrink-0" />
                            <span>{formulaSyntaxCheck.error}</span>
                          </span>
                        )}
                      </div>

                      {/* Quick insert variable & probe snippets */}
                      <div className="flex flex-wrap gap-1 pt-1">
                        {FORMULA_VARIABLES.map((v) => (
                          <button
                            key={v.token}
                            type="button"
                            onClick={() => handleInsertFormulaToken(v.token)}
                            title={`点击插入 ${v.label}`}
                            className="cc-mono rounded border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                          >
                            {v.token}
                          </button>
                        ))}
                        {PROBE_ADDRESS_SNIPPETS.map((p) => (
                          <button
                            key={p.token}
                            type="button"
                            onClick={() => handleInsertFormulaToken(p.token)}
                            title={p.desc}
                            className="cc-mono rounded border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--accent)] hover:border-[var(--accent)]"
                          >
                            {p.token}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Advanced trigger expr, dynamic filter, hysteresis & custom gate */}
                    <div className="space-y-2 border-t border-[var(--line)]/70 pt-2.5">
                      {selectedGroup.mode === "conditional_pool" && (
                        <label className="block">
                          <span className="text-[10px] text-[var(--muted)]">
                            自动吸纳筛选条件（留空则不限）
                          </span>
                          <input
                            type="text"
                            value={formattedDynamicFilter}
                            onChange={(e) =>
                              updateSelectedGroup((g) => ({
                                ...g,
                                dynamic_filter: buildDynamicFilterUpdate(
                                  e.target.value,
                                  g.dynamic_filter
                                ),
                              }))
                            }
                            placeholder="例如：限制倍率上限或要求谷歌地区正常"
                            className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                          />
                        </label>
                      )}

                      <label className="block">
                        <span className="text-[10px] text-[var(--muted)]">
                          自定义切换触发表达式
                        </span>
                        <input
                          type="text"
                          value={currentTriggerExpr}
                          onChange={(e) => setPrimaryTriggerExpr(e.target.value)}
                          placeholder="留空或输入自定义触发规则"
                          className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                      </label>

                      <label className="block">
                        <span className="text-[10px] text-[var(--muted)]">
                          防频繁切换缓冲幅度 (%)
                        </span>
                        <input
                          type="number"
                          min={0}
                          max={100}
                          value={selectedGroup.hysteresis_pct}
                          onChange={(e) =>
                            updateSelectedGroup((g) => ({
                              ...g,
                              hysteresis_pct: Math.max(
                                0,
                                Math.min(100, Number(e.target.value) || 0)
                              ),
                            }))
                          }
                          className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                      </label>

                      <form onSubmit={handleAddCustomGate} className="flex gap-1">
                        <input
                          type="text"
                          value={customGateInput}
                          onChange={(e) => setCustomGateInput(e.target.value)}
                          placeholder="添加自定义门槛表达式..."
                          className="cc-mono min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[10px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                        <button
                          type="submit"
                          className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[10px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                        >
                          加门槛
                        </button>
                      </form>
                    </div>

                    {/* Backend evaluation & AI assistant collaboration guide */}
                    <div className="space-y-2 border-t border-[var(--line)]/70 pt-2.5">
                      <button
                        type="button"
                        disabled={evaluating}
                        onClick={() => void handleEvaluateBackend()}
                        className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                      >
                        <RefreshCw className={`h-3 w-3 ${evaluating ? "animate-spin" : ""}`} />
                        <span>{evaluating ? "模拟打分中..." : "立即模拟打分排序"}</span>
                      </button>

                      {evalReport && (
                        <div className="space-y-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-2 text-[10px] text-[var(--text-secondary)]">
                          <div className="cc-mono">
                            候选 {evalReport.pool_size} · 过门槛 {evalReport.gate_passed.length} ·
                            健康 {evalReport.healthy_candidates.length}
                          </div>
                          {evalUntestedCount > 0 && (
                            <div className="text-[var(--amber)]">
                              其中 {evalUntestedCount} 个尚未测速（先测速再按门槛筛）
                            </div>
                          )}
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={() => void handleCopyAgentGuide()}
                        className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                      >
                        {copiedGuide ? (
                          <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                        ) : (
                          <Copy className="h-3.5 w-3.5 text-[var(--accent)]" />
                        )}
                        <FileCode2 className="h-3 w-3 opacity-70" />
                        <span>{copiedGuide ? "已复制 AI 协同指南" : "复制 AI 助手协同指南"}</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Sticky Bottom Apply Strategy Bar */}
            <div className="sticky bottom-0 border-t border-[var(--line)] bg-[var(--card)]/95 px-4 py-3 backdrop-blur-xs rounded-b-2xl">
              <button
                type="button"
                disabled={savingGroup || !formulaSyntaxCheck.ok}
                onClick={() => void handleSaveSelectedGroup()}
                className={`inline-flex w-full items-center justify-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-semibold transition-opacity disabled:opacity-50 ${
                  isSelectedDirty
                    ? "bg-[var(--accent)] text-[var(--accent-ink)] shadow-xs hover:opacity-90"
                    : "border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                }`}
              >
                <Save className="h-3.5 w-3.5" />
                <span>
                  {savingGroup
                    ? "正在应用..."
                    : isSelectedDirty
                      ? "应用策略（有未保存改动）"
                      : "应用策略"}
                </span>
              </button>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}
