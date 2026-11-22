import {
  AlertTriangle,
  ArrowRightLeft,
  Check,
  CheckCircle2,
  Copy,
  FileCode2,
  Filter,
  Layers,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  type DynamicFilterSpec,
  type FallbackPolicy,
  type GroupEvaluationReport,
  type MultiGroup,
  type MultiGroupMode,
  type ProbeSnapshot,
  type ProxyNode,
  type SwitchMode,
  type TriggerRule,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { appActions, useAppSelector } from "../store/appStore";

const FORMULA_COST_EFFECTIVE =
  "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)";

const FORMULA_MAX_PERF =
  "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1";

const DEFAULT_MISSING_PING_MS = 9999;
const EPSILON_ZERO = 1e-12;
const EPSILON_EQ = 1e-9;

interface ModeMeta {
  id: MultiGroupMode;
  title: string;
  shortLabel: string;
  badge: string;
  desc: string;
}

const GROUP_MODES: readonly ModeMeta[] = [
  {
    id: "sticky_best",
    title: "AI 专线粘性优选",
    shortLabel: "粘性优选",
    badge: "硬门禁过滤 · 防 IP 漂移",
    desc: "锁定综合分最高的合规节点，维持会话稳定不乱跳；仅在触发门槛或断连时自动切至次优。",
  },
  {
    id: "conditional_pool",
    title: "动态条件池",
    shortLabel: "动态条件池",
    badge: "硬门禁过滤 · 跨订阅动态入池",
    desc: "按倍率、地区与探针条件动态计算候选节点集合，订阅更新后自动吸纳达标新节点。",
  },
  {
    id: "load_balance_consistent_hash",
    title: "一致性哈希受控均衡",
    shortLabel: "哈希均衡",
    badge: "硬门禁过滤 · 同域会话粘性",
    desc: "先经硬门禁剔除送中与高抖动节点，再按目标域名哈希分摊至多条合规线路。",
  },
  {
    id: "load_balance_round_robin",
    title: "轮询受控均衡",
    shortLabel: "轮询均衡",
    badge: "硬门禁过滤 · 并发轮询分发",
    desc: "仅在通过全部硬门禁的高分节点间轮询分发并发连接，适合大文件下载与高频抓取。",
  },
];

interface GatePreset {
  expr: string;
  label: string;
  desc: string;
}

const HARD_GATE_PRESETS: readonly GatePreset[] = [
  { expr: "google_clean == 1", label: "Google 零送中", desc: "仅保留 Google 侧真值洁净节点" },
  { expr: "keepalive_ok == 1", label: "60s 保活通过", desc: "排除静默长连接黑洞节点" },
  { expr: 'site_unlocked("chatgpt") == 1', label: "ChatGPT 解锁", desc: "要求 ChatGPT 站点探针通过" },
  { expr: 'site_unlocked("google_ai") == 1', label: "Google AI 解锁", desc: "要求 Gemini / Google AI 可达" },
  { expr: 'site_unlocked("claude") == 1', label: "Claude 解锁", desc: "要求 Anthropic / Claude 解锁" },
  { expr: 'site_unlocked("windsurf") == 1', label: "Windsurf 解锁", desc: "要求 Windsurf / Codeium 可达" },
];

const FORMULA_VARIABLES: ReadonlyArray<{ token: string; label: string }> = [
  { token: "up_mbps", label: "上行 Mbps" },
  { token: "down_mbps", label: "下行 Mbps" },
  { token: "ping_ms", label: "延迟 ms" },
  { token: "jitter_ms", label: "抖动 ms" },
  { token: "loss_pct", label: "丢包 %" },
  { token: "multiplier", label: "倍率" },
  { token: "keepalive_ok", label: "60s 保活" },
  { token: "google_clean", label: "Google 洁净" },
  { token: "unlocked", label: "全站点解锁" },
];

const PROBE_ADDRESS_SNIPPETS: ReadonlyArray<{ token: string; desc: string }> = [
  { token: 'probe_up("antigravity")', desc: "指定探针上行 Mbps" },
  { token: 'probe_down("dl")', desc: "指定探针下行 Mbps" },
  { token: 'probe_ping("chatgpt")', desc: "指定探针延迟 ms" },
  { token: 'probe_ok("builtin_unlock_windsurf")', desc: "指定探针通过 (1/0)" },
  { token: 'site_unlocked("chatgpt")', desc: "ChatGPT 解锁 (1/0)" },
  { token: 'site_unlocked("google_ai")', desc: "Google AI 解锁 (1/0)" },
];

interface FallbackMeta {
  id: FallbackPolicy;
  title: string;
  badge: string;
  desc: string;
  tone: "amber" | "accent" | "red";
}

const FALLBACK_POLICIES: readonly FallbackMeta[] = [
  {
    id: "degrade_best_warn",
    title: "降级择优预警",
    badge: "默认稳妥 · 不断网",
    desc: "全员未达门槛时仍择当前综合分最高者维持连通，并在主界面与托盘标记降级预警。",
    tone: "amber",
  },
  {
    id: "cross_pool_escalate",
    title: "跨池求助（自动回切）",
    badge: "借调高优备援池",
    desc: "临时借调指定备援池节点承接流量，后台按设定间隔探活主池，恢复后带滞回自动切回。",
    tone: "accent",
  },
  {
    id: "strict_circuit_break",
    title: "红线熔断至 REJECT",
    badge: "零妥协防风控",
    desc: "所有候选均不满足硬门禁或门槛时立即切换为 REJECT 并断开连接，杜绝误走不合规出口。",
    tone: "red",
  },
];

interface TriggerMeta {
  consecutiveFailures: number;
  bypassCooldownOnDisconnect: boolean;
}

/* ============================================================================
 * Safe Formatting Helpers for dynamic_filter & trigger_rules
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
    dynamic_filter: dynamicFilter,
    trigger_rules: triggerRules,
    trigger_expr: expr || null,
  };
}

/* ============================================================================
 * Zero-eval Safe Recursive-Descent AST Formula Parser & Evaluator
 * 100% semantically aligned with Rust `crates/catcloud-core/src/strategy/formula.rs`
 * - Division by zero returns 0
 * - Missing probe_up / probe_down / probe_ok / site_unlocked returns 0
 * - Missing probe_ping returns 9999
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

function lookupSiteUnlocked(unlockedSites: Record<string, boolean>, siteName: string): number {
  if (siteName in unlockedSites) {
    return unlockedSites[siteName] ? 1 : 0;
  }
  const lower = siteName.toLowerCase();
  for (const [k, v] of Object.entries(unlockedSites)) {
    if (k.toLowerCase() === lower) {
      return v ? 1 : 0;
    }
  }
  return 0;
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
          left = !Number.isFinite(right) || Math.abs(right) <= EPSILON_ZERO ? 0 : sanitizeNumber(left / right);
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
          if (name === "probe_up") return sanitizeNumber(ctx.probeUp[arg.value] ?? 0);
          if (name === "probe_down") return sanitizeNumber(ctx.probeDown[arg.value] ?? 0);
          if (name === "probe_ping") {
            const p = ctx.probePing[arg.value];
            return typeof p === "number" && Number.isFinite(p) ? p : DEFAULT_MISSING_PING_MS;
          }
          if (name === "probe_ok") {
            return ctx.probeOk[arg.value] === true ? 1 : 0;
          }
          return lookupSiteUnlocked(ctx.unlockedSites, arg.value);
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

function buildMultiGroupAgentMarkdown(group: MultiGroup, meta: TriggerMeta): string {
  const normalized = normalizeGroupForBackend(group, meta);
  const snippet = JSON.stringify(
    {
      id: normalized.id,
      name: normalized.name,
      mode: normalized.mode,
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
    "- 需混合多家订阅并优先消耗 0.5x/1x 低倍率节点，仅在主池全员不达标时短暂借调 3x 高优备援池，并按回切间隔自动恢复。",
    "- 流媒体与并发下载站点可使用 `load_balance_consistent_hash` 或 `load_balance_round_robin`，所有入池节点均须先通过硬门禁过滤。",
    "",
    "## 2. 外部前提与安全 AST 公式规范",
    "- 节点库至少导入 2 条可用节点，并完成一次零干扰隔离测速以生成最新 `ProbeSnapshot`。",
    "- 加权公式由纯 AST 解释器求值（零 `eval`），可用变量：`up_mbps`, `down_mbps`, `ping_ms`, `jitter_ms`, `loss_pct`, `multiplier`, `keepalive_ok`, `google_clean`, `unlocked`, `is_443_native`, `ok`。",
    '- 支持按探针/站点寻址：`probe_up("id")`, `probe_down("id")`, `probe_ping("id")`, `probe_ok("id")`, `site_unlocked("chatgpt")`；内置函数：`min`, `max`, `clamp`, `abs`, `if`。',
    "- 兜底策略三选一：`degrade_best_warn`（降级择优预警）/ `cross_pool_escalate`（跨池求助自动回切）/ `strict_circuit_break`（红线熔断至 `REJECT`）。",
    "",
    "## 3. GUI 路径与 Headless CLI 热写入验收命令",
    "- GUI 路径：左侧「智能多选组」→ 选择策略组 → 配置模式、AST 公式、硬门禁、兜底与旧连接切换模式 → 保存策略组。",
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

export function MultiGroupPage() {
  const storeGroups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  const [groups, setGroups] = useState<MultiGroup[]>(storeGroups);
  const [selectedId, setSelectedId] = useState<string>(storeGroups[0]?.id ?? "");
  const [triggerMetas, setTriggerMetas] = useState<Record<string, TriggerMeta>>({});
  const [dirtyGroupIds, setDirtyGroupIds] = useState<Record<string, boolean>>({});
  const [savingGroup, setSavingGroup] = useState(false);
  const [deletingGroup, setDeletingGroup] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [evalReport, setEvalReport] = useState<GroupEvaluationReport | null>(null);
  const [backendFormulaValidation, setBackendFormulaValidation] = useState<{
    checkedExpr: string;
    ok: boolean;
    error: string | null;
  } | null>(null);

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupMode, setNewGroupMode] = useState<MultiGroupMode>("sticky_best");
  const [newGroupDomains, setNewGroupDomains] = useState("DOMAIN-SUFFIX,anthropic.com");
  const [customGateInput, setCustomGateInput] = useState("");
  const [newRuleInput, setNewRuleInput] = useState("");
  const [copiedGuide, setCopiedGuide] = useState(false);
  const [switchingNext, setSwitchingNext] = useState(false);

  const syncedRef = useRef(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (initialized && !syncedRef.current) {
      syncedRef.current = true;
      setGroups(storeGroups);
      setSelectedId((prev) => prev || storeGroups[0]?.id || "");
    }
  }, [storeGroups, initialized]);

  const selectedGroup = useMemo(
    () => groups.find((g) => g.id === selectedId) ?? groups[0] ?? null,
    [groups, selectedId]
  );

  // Reset backend evaluation report when switching groups
  useEffect(() => {
    setEvalReport(null);
  }, [selectedGroup?.id]);

  // Debounced backend authoritative formula validation in Tauri runtime
  const currentFormulaExpr = selectedGroup?.formula_expr ?? "";
  useEffect(() => {
    if (!inTauri || !selectedGroup) {
      setBackendFormulaValidation(null);
      return;
    }
    const expr = currentFormulaExpr.trim();
    if (!expr) {
      setBackendFormulaValidation({ checkedExpr: currentFormulaExpr, ok: false, error: "公式不能为空" });
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
              error: ok ? null : "后端 AST 校验未通过",
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
    }, 260);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [currentFormulaExpr, inTauri, selectedGroup?.id]);

  const currentTriggerMeta: TriggerMeta = selectedGroup
    ? triggerMetas[selectedGroup.id] ?? getPrimaryTriggerMeta(selectedGroup)
    : { consecutiveFailures: 2, bypassCooldownOnDisconnect: true };

  const currentTriggerExpr = selectedGroup ? getPrimaryTriggerExpr(selectedGroup) : "";
  const isSelectedDirty = selectedGroup ? Boolean(dirtyGroupIds[selectedGroup.id]) : false;

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

  const handleSaveSelectedGroup = async () => {
    if (!selectedGroup || savingGroup) return;
    setSavingGroup(true);
    try {
      const payload = normalizeGroupForBackend(selectedGroup, currentTriggerMeta);
      const saved = await catcloudApi.upsertMultiGroup(payload);
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === saved.id ? saved : g));
        appActions.syncGroups(next);
        return next;
      });
      setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      appActions.showToast(`已保存策略组：${saved.name}`, "ok");
    } catch (err) {
      appActions.showToast(`保存策略组失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingGroup(false);
    }
  };

  const handleDeleteSelectedGroup = async () => {
    if (!selectedGroup || deletingGroup) return;
    setDeletingGroup(true);
    try {
      await catcloudApi.deleteMultiGroup(selectedGroup.id);
      const next = groups.filter((g) => g.id !== selectedGroup.id);
      setGroups(next);
      appActions.syncGroups(next);
      setSelectedId(next[0]?.id ?? "");
      appActions.showToast(`已删除策略组：${selectedGroup.name}`, "info");
    } catch (err) {
      appActions.showToast(`删除策略组失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingGroup(false);
    }
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
      appActions.showToast(
        `后端评估完成：候选池 ${report.pool_size} / 过门禁 ${report.gate_passed.length} / 健康 ${report.healthy_candidates.length}`,
        report.all_failed_hard_gates ? "warn" : "ok"
      );
    } catch (err) {
      appActions.showToast(`评估策略组失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setEvaluating(false);
    }
  };

  const handleCreateGroup = async (ev: FormEvent) => {
    ev.preventDefault();
    const name = newGroupName.trim();
    if (!name) {
      appActions.showToast("请填写多选组名称", "warn");
      return;
    }
    const id = `grp-${Date.now().toString(36)}`;
    const parsedRules = newGroupDomains
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    const defaultMemberIds = nodes.filter((n) => n.enabled).map((n) => n.id);
    const created: MultiGroup = {
      id,
      name,
      mode: newGroupMode,
      match_rules: parsedRules,
      member_node_ids: defaultMemberIds,
      dynamic_filter:
        newGroupMode === "conditional_pool"
          ? {
              expr: "multiplier <= 1.5 && google_clean == 1",
              sub_ids: [],
              region_codes: [],
              max_multiplier: null,
              protocols: [],
              require_google_clean: true,
              require_443_native: null,
            }
          : null,
      primary_probe_id: "antigravity",
      hard_gates: ["google_clean == 1", "keepalive_ok == 1"],
      trigger_rules: [
        {
          expr: 'probe_up("antigravity") < 2.0',
          consecutive_failures: 2,
          bypass_cooldown_on_disconnect: true,
        },
      ],
      trigger_expr: 'probe_up("antigravity") < 2.0',
      formula_expr: FORMULA_COST_EFFECTIVE,
      fallback_policy: "degrade_best_warn",
      fallback_pool_id: null,
      escalated_since: null,
      recover_probe_interval_sec: 120,
      switch_mode: newGroupMode === "sticky_best" ? "force_close_old" : "graceful_new_only",
      cooldown_sec: 60,
      hysteresis_pct: 20,
      active_node_id: defaultMemberIds[0] ?? null,
    };

    try {
      const saved = await catcloudApi.upsertMultiGroup(created);
      setGroups((prev) => {
        const next = [...prev, saved];
        appActions.syncGroups(next);
        return next;
      });
      setSelectedId(saved.id);
      setNewGroupName("");
      setShowCreateForm(false);
      appActions.showToast(`已新建智能多选组：${saved.name}`, "ok");
    } catch (err) {
      appActions.showToast(`创建策略组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  // Offline syntax check synchronized with Rust `strategy/formula.rs`, superseded by backend result when fresh
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

  // Real-time candidate node scoring queue
  const scoredCandidates = useMemo(() => {
    if (!selectedGroup) return [];
    const candidateNodes =
      selectedGroup.member_node_ids.length > 0
        ? nodes.filter((n) => selectedGroup.member_node_ids.includes(n.id))
        : nodes;

    const evaluated = candidateNodes.map((node) => {
      const snap = probes[node.id];
      const ctx = buildEvalContextForNode(node, snap);
      const failedGates = selectedGroup.hard_gates.filter((gate) => !checkHardGate(gate, ctx));
      const passedAllGates = failedGates.length === 0;
      const scoreResult = evaluateFormulaSafely(selectedGroup.formula_expr, ctx);
      return {
        node,
        snap,
        passedAllGates,
        failedGates,
        score: scoreResult.ok ? scoreResult.value : 0,
      };
    });

    evaluated.sort((a, b) => {
      if (a.passedAllGates !== b.passedAllGates) return a.passedAllGates ? -1 : 1;
      return b.score - a.score;
    });
    return evaluated;
  }, [nodes, probes, selectedGroup]);

  const maxScore = useMemo(() => {
    let peak = 1;
    for (const item of scoredCandidates) {
      if (item.score > peak) peak = item.score;
    }
    return peak;
  }, [scoredCandidates]);

  const handleSwitchNextBestInGroup = async () => {
    if (!selectedGroup || switchingNext) return;
    setSwitchingNext(true);
    try {
      const res = await catcloudApi.switchNextBestNode(selectedGroup.id);
      setGroups((prev) => {
        const next = prev.map((g) =>
          g.id === selectedGroup.id ? { ...g, active_node_id: res.active_node_id } : g
        );
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(
        `${selectedGroup.name} 已切至次优：${res.active_node_name}（清理 ${res.closed_connections} 条旧连接）`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`切换次优节点失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSwitchingNext(false);
    }
  };

  const handleManualSelectNode = async (node: ProxyNode) => {
    if (!selectedGroup) return;
    const closeOld = selectedGroup.switch_mode === "force_close_old";
    try {
      const res = await catcloudApi.selectGroupNode(selectedGroup.id, node.id, closeOld);
      setGroups((prev) => {
        const next = prev.map((g) =>
          g.id === selectedGroup.id ? { ...g, active_node_id: res.active_node_id } : g
        );
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(
        `已切换 ${selectedGroup.name} → ${res.active_node_name}（${
          closeOld ? `踢断 ${res.closed_connections} 条旧连接` : "温和切换"
        }）`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`手动切换节点失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleGate = (expr: string) => {
    updateSelectedGroup((g) => {
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

  const handleAddMatchRule = (ev: FormEvent) => {
    ev.preventDefault();
    const rule = newRuleInput.trim();
    if (!rule || !selectedGroup) return;
    if (!selectedGroup.match_rules.includes(rule)) {
      updateSelectedGroup((g) => ({ ...g, match_rules: [...g.match_rules, rule] }));
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
        /* fallback to local guide markdown */
      }
    }
    const ok = await copyToClipboard(md);
    if (ok) {
      setCopiedGuide(true);
      appActions.showToast("已复制智能多选组四段式 Agent 指南（Markdown）", "ok");
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedGuide(false);
        copyTimerRef.current = null;
      }, 2200);
    } else {
      appActions.showToast("复制失败，请检查剪贴板权限", "warn");
    }
  };

  const otherGroups = useMemo(
    () => groups.filter((g) => g.id !== selectedGroup?.id),
    [groups, selectedGroup]
  );

  const passingCount = scoredCandidates.filter((c) => c.passedAllGates).length;
  const formattedDynamicFilter = selectedGroup ? formatDynamicFilter(selectedGroup.dynamic_filter) : "";

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      {/* Left / Top Multi-Group Selector Sidebar + Create Form */}
      <aside className="space-y-3 xl:col-span-3">
        <div className="cc-card cc-glass rounded-2xl p-3.5">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-[var(--accent)]" />
              <h1 className="text-sm font-semibold text-[var(--text)]">多选组列表</h1>
            </div>
            <button
              type="button"
              onClick={() => setShowCreateForm((v) => !v)}
              className="inline-flex items-center gap-1 rounded-lg bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
            >
              {showCreateForm ? <X className="h-3 w-3" /> : <Plus className="h-3 w-3" />}
              <span>{showCreateForm ? "取消" : "新建组"}</span>
            </button>
          </div>

          {showCreateForm && (
            <form
              onSubmit={(ev) => void handleCreateGroup(ev)}
              className="mb-3 space-y-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 text-xs"
            >
              <input
                type="text"
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                placeholder="策略组名称（如 Claude 专用池）"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
              />
              <select
                value={newGroupMode}
                onChange={(e) => setNewGroupMode(e.target.value as MultiGroupMode)}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
              >
                {GROUP_MODES.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.title}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={newGroupDomains}
                onChange={(e) => setNewGroupDomains(e.target.value)}
                placeholder="匹配规则（逗号分隔）"
                className="cc-mono w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
              />
              <button
                type="submit"
                className="w-full rounded-lg bg-[var(--accent)] py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                创建多选组
              </button>
            </form>
          )}

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-1">
            {groups.map((g) => {
              const active = selectedGroup?.id === g.id;
              const modeMeta = GROUP_MODES.find((m) => m.id === g.mode) ?? GROUP_MODES[0];
              const activeNode = nodes.find((n) => n.id === g.active_node_id);
              const filterSummary = formatDynamicFilter(g.dynamic_filter);
              return (
                <button
                  key={g.id}
                  type="button"
                  onClick={() => setSelectedId(g.id)}
                  className={`w-full rounded-xl border p-3 text-left transition-colors ${
                    active
                      ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-semibold text-[var(--text)]">
                      {g.name}
                    </span>
                    <span className="shrink-0 rounded-full bg-[var(--card)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                      {modeMeta.shortLabel}
                    </span>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between gap-2 text-[11px] text-[var(--muted)]">
                    <span className="truncate cc-mono">
                      {activeNode ? activeNode.name : "待择优"}
                    </span>
                    <span className="shrink-0 cc-mono">{g.member_node_ids.length} 节点</span>
                  </div>
                  {filterSummary && (
                    <div className="mt-1 truncate cc-mono text-[10px] text-[var(--muted)]">
                      {filterSummary}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Agent Four-Section Guide Copy Card */}
        {selectedGroup && (
          <div className="cc-card cc-glass rounded-2xl p-3.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text)]">
              <FileCode2 className="h-4 w-4 text-[var(--accent)]" />
              <span>AI Agent 协同配置</span>
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--muted)]">
              导出包含触发信号、AST 公式字段、CLI 热写入验收与回退清单的四段式指南，直接交付任意 AI Agent 协助调参。
            </p>
            <button
              type="button"
              onClick={() => void handleCopyAgentGuide()}
              className="mt-3 inline-flex w-full items-center justify-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              {copiedGuide ? (
                <Check className="h-3.5 w-3.5 text-[var(--green)]" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-[var(--accent)]" />
              )}
              <span>{copiedGuide ? "已复制四段式指南" : "复制给 AI Agent 四段式指南"}</span>
            </button>
          </div>
        )}
      </aside>

      {/* Right Main Configuration & Live Ranking Workbench */}
      {selectedGroup ? (
        <div className="space-y-4 xl:col-span-9">
          {/* Header Banner: Active Group Summary, Save/Delete & One-Click Next Best */}
          <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold tracking-tight text-[var(--text)]">
                  {selectedGroup.name}
                </h2>
                <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                  硬门禁通过 {passingCount}/{scoredCandidates.length}
                </span>
                {selectedGroup.escalated_since && (
                  <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                    已跨池借调中
                  </span>
                )}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
                <span>规则：</span>
                {selectedGroup.match_rules.length > 0 ? (
                  selectedGroup.match_rules.map((rule) => (
                    <span
                      key={rule}
                      className="inline-flex items-center gap-1 rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 cc-mono text-[11px] text-[var(--text-secondary)]"
                    >
                      {rule}
                      <button
                        type="button"
                        onClick={() =>
                          updateSelectedGroup((g) => ({
                            ...g,
                            match_rules: g.match_rules.filter((r) => r !== rule),
                          }))
                        }
                        className="text-[var(--muted)] hover:text-[var(--red)]"
                        aria-label={`移除规则 ${rule}`}
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))
                ) : (
                  <span className="text-[11px]">作为备援池（无直接分流规则）</span>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <form onSubmit={handleAddMatchRule} className="flex items-center gap-1">
                <input
                  type="text"
                  value={newRuleInput}
                  onChange={(e) => setNewRuleInput(e.target.value)}
                  placeholder="DOMAIN-SUFFIX,..."
                  className="cc-mono w-40 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
                <button
                  type="submit"
                  className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1.5 text-[11px] text-[var(--muted)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                >
                  加规则
                </button>
              </form>
              <button
                type="button"
                disabled={savingGroup}
                onClick={() => void handleSaveSelectedGroup()}
                className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-semibold transition-colors disabled:opacity-60 ${
                  isSelectedDirty
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                }`}
              >
                <Save className="h-3.5 w-3.5" />
                <span>{savingGroup ? "保存中..." : isSelectedDirty ? "保存修改" : "已保存"}</span>
              </button>
              <button
                type="button"
                disabled={switchingNext}
                onClick={() => void handleSwitchNextBestInGroup()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Zap className="h-3.5 w-3.5" />
                <span>{switchingNext ? "切换中..." : "一键切至次优"}</span>
              </button>
              {groups.length > 1 && (
                <button
                  type="button"
                  disabled={deletingGroup}
                  onClick={() => void handleDeleteSelectedGroup()}
                  className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)] disabled:opacity-50"
                  title="删除当前策略组"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </section>

          {/* 4 Per-Site Independent Mode Selector Cards */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">
                  按站点独立调度模式（4 选 1）
                </h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  所有模式均在调度前执行硬门禁过滤，杜绝送中或失活节点混入活跃池
                </p>
              </div>
              <span className="inline-flex items-center gap-1 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[11px] text-[var(--green)]">
                <ShieldCheck className="h-3.5 w-3.5" />
                前置硬门禁保护
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
              {GROUP_MODES.map((m) => {
                const selected = selectedGroup.mode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => updateSelectedGroup((g) => ({ ...g, mode: m.id }))}
                    className={`rounded-xl border p-3.5 text-left transition-colors ${
                      selected
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                      <span className="text-xs font-semibold text-[var(--text)]">{m.title}</span>
                      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--card)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                        <Filter className="h-2.5 w-2.5" />
                        {m.badge}
                      </span>
                    </div>
                    <div className="mt-1 cc-mono text-[10px] text-[var(--accent)]">{m.id}</div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--muted)]">
                      {m.desc}
                    </p>
                  </button>
                );
              })}
            </div>

            {selectedGroup.mode === "conditional_pool" && (
              <label className="mt-3 block rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 text-xs">
                <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                  动态条件池入池过滤表达式（跨订阅自动匹配）
                </span>
                <input
                  type="text"
                  value={formattedDynamicFilter}
                  onChange={(e) =>
                    updateSelectedGroup((g) => ({
                      ...g,
                      dynamic_filter: buildDynamicFilterUpdate(e.target.value, g.dynamic_filter),
                    }))
                  }
                  placeholder="multiplier <= 1.5 && google_clean == 1"
                  className="cc-mono mt-1.5 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>
            )}
          </section>

          {/* Safe AST Custom Weighting Formula Editor */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">
                  安全自定义加权公式（纯 AST 解析 · 零 eval）
                </h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  编辑后立即校验语法并试算候选排名，支持按探针 ID 与站点解锁精确引用实测指标
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() =>
                    updateSelectedGroup((g) => ({ ...g, formula_expr: FORMULA_COST_EFFECTIVE }))
                  }
                  className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    selectedGroup.formula_expr.trim() === FORMULA_COST_EFFECTIVE
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                  }`}
                >
                  <Sparkles className="h-3 w-3" />
                  低倍率性价比优先
                </button>
                <button
                  type="button"
                  onClick={() =>
                    updateSelectedGroup((g) => ({ ...g, formula_expr: FORMULA_MAX_PERF }))
                  }
                  className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    selectedGroup.formula_expr.trim() === FORMULA_MAX_PERF
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                  }`}
                >
                  <Zap className="h-3 w-3" />
                  纯性能最快
                </button>
              </div>
            </div>

            <textarea
              rows={3}
              value={selectedGroup.formula_expr}
              onChange={(e) =>
                updateSelectedGroup((g) => ({ ...g, formula_expr: e.target.value }))
              }
              spellCheck={false}
              className="cc-mono cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 text-xs leading-relaxed text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />

            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px]">
              {formulaSyntaxCheck.ok ? (
                <span className="inline-flex items-center gap-1.5 text-[var(--green)]">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {formulaSyntaxCheck.source === "backend" ? "后端 AST 校验通过" : "AST 语法校验通过"} · 已实时计算{" "}
                  {scoredCandidates.length} 个候选节点得分
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-[var(--red)]">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  公式语法提示：{formulaSyntaxCheck.error}
                </span>
              )}
              <button
                type="button"
                onClick={() =>
                  updateSelectedGroup((g) => ({ ...g, formula_expr: FORMULA_COST_EFFECTIVE }))
                }
                className="inline-flex items-center gap-1 text-[var(--muted)] hover:text-[var(--text)]"
              >
                <RotateCcw className="h-3 w-3" />
                重置默认
              </button>
            </div>

            {/* Variables & Per-Probe Addressing Hints */}
            <div className="mt-3 space-y-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] font-medium text-[var(--muted)]">可用变量：</span>
                {FORMULA_VARIABLES.map((v) => (
                  <button
                    key={v.token}
                    type="button"
                    onClick={() => handleInsertFormulaToken(v.token)}
                    title={`点击追加 ${v.label}`}
                    className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 cc-mono text-[11px] text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    {v.token}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] font-medium text-[var(--muted)]">按探针 / 站点寻址：</span>
                {PROBE_ADDRESS_SNIPPETS.map((p) => (
                  <button
                    key={p.token}
                    type="button"
                    onClick={() => handleInsertFormulaToken(p.token)}
                    title={p.desc}
                    className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 cc-mono text-[11px] text-[var(--accent)] transition-colors hover:border-[var(--accent)]"
                  >
                    {p.token}
                  </button>
                ))}
              </div>
            </div>
          </section>

          {/* Hard Gates & Threshold Trigger Parameters */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex items-center gap-2">
              <SlidersHorizontal className="h-4 w-4 text-[var(--accent)]" />
              <h3 className="text-sm font-semibold text-[var(--text)]">硬门禁与阈值触发</h3>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {/* Hard Gates */}
              <div className="space-y-2.5">
                <div className="text-xs font-medium text-[var(--text-secondary)]">
                  硬门禁条件（任一不满足即剔除候选）
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {HARD_GATE_PRESETS.map((preset) => {
                    const enabled = selectedGroup.hard_gates.includes(preset.expr);
                    return (
                      <button
                        key={preset.expr}
                        type="button"
                        onClick={() => handleToggleGate(preset.expr)}
                        title={preset.desc}
                        className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                          enabled
                            ? "border-[var(--green)]/50 bg-[var(--green-soft)] text-[var(--green)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                        }`}
                      >
                        <Lock className="h-3 w-3" />
                        <span>{preset.label}</span>
                      </button>
                    );
                  })}
                </div>

                {/* Active gate expressions list + add custom */}
                <div className="flex flex-wrap gap-1.5">
                  {selectedGroup.hard_gates.map((expr) => (
                    <span
                      key={expr}
                      className="inline-flex items-center gap-1 rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 cc-mono text-[11px] text-[var(--text-secondary)]"
                    >
                      {expr}
                      <button
                        type="button"
                        onClick={() => handleToggleGate(expr)}
                        className="text-[var(--muted)] hover:text-[var(--red)]"
                        aria-label={`移除门禁 ${expr}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                </div>

                <form onSubmit={handleAddCustomGate} className="flex gap-1.5">
                  <input
                    type="text"
                    value={customGateInput}
                    onChange={(e) => setCustomGateInput(e.target.value)}
                    placeholder='自定义门禁（如 site_unlocked("chatgpt") == 1）'
                    className="cc-mono flex-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                  <button
                    type="submit"
                    className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                  >
                    添加
                  </button>
                </form>
              </div>

              {/* Threshold Trigger & Anti-Flapping Parameters */}
              <div className="space-y-2.5">
                <label className="block">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">
                    劣化触发表达式（满足条件时重新评优切换）
                  </span>
                  <input
                    type="text"
                    value={currentTriggerExpr}
                    onChange={(e) => {
                      const val = e.target.value;
                      updateSelectedGroup((g) => {
                        const rest = Array.isArray(g.trigger_rules) ? g.trigger_rules.slice(1) : [];
                        return {
                          ...g,
                          trigger_expr: val.trim() ? val : null,
                          trigger_rules: val.trim()
                            ? [
                                {
                                  expr: val,
                                  consecutive_failures: currentTriggerMeta.consecutiveFailures,
                                  bypass_cooldown_on_disconnect:
                                    currentTriggerMeta.bypassCooldownOnDisconnect,
                                },
                                ...rest,
                              ]
                            : rest,
                        };
                      });
                    }}
                    placeholder='probe_up("antigravity") < 2.0 || latency_ms > 1500'
                    className="cc-mono mt-1.5 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <div className="grid grid-cols-3 gap-2">
                  <label className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2">
                    <span className="block text-[10px] text-[var(--muted)]">连续失败次数</span>
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
                      className="cc-mono mt-1 w-full bg-transparent text-sm font-semibold text-[var(--text)] outline-none"
                    />
                  </label>
                  <label className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2">
                    <span className="block text-[10px] text-[var(--muted)]">冷却时间 (秒)</span>
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
                      className="cc-mono mt-1 w-full bg-transparent text-sm font-semibold text-[var(--text)] outline-none"
                    />
                  </label>
                  <label className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2">
                    <span className="block text-[10px] text-[var(--muted)]">滞回幅度 (%)</span>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={selectedGroup.hysteresis_pct}
                      onChange={(e) =>
                        updateSelectedGroup((g) => ({
                          ...g,
                          hysteresis_pct: Math.max(0, Math.min(100, Number(e.target.value) || 0)),
                        }))
                      }
                      className="cc-mono mt-1 w-full bg-transparent text-sm font-semibold text-[var(--text)] outline-none"
                    />
                  </label>
                </div>

                <button
                  type="button"
                  onClick={() =>
                    updateTriggerMeta({
                      bypassCooldownOnDisconnect: !currentTriggerMeta.bypassCooldownOnDisconnect,
                    })
                  }
                  className="flex w-full items-center justify-between rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs hover:border-[var(--line-strong)]"
                >
                  <span className="text-[var(--text-secondary)]">
                    节点彻底断连时跳过冷却立即切换
                  </span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                      currentTriggerMeta.bypassCooldownOnDisconnect
                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                        : "bg-[var(--card)] text-[var(--muted)]"
                    }`}
                  >
                    {currentTriggerMeta.bypassCooldownOnDisconnect ? "已开启" : "已关闭"}
                  </span>
                </button>
              </div>
            </div>
          </section>

          {/* 3-Way Fallback Policy + Per-Group Switch Mode */}
          <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            {/* Fallback Policy 3-in-1 */}
            <div className="cc-card cc-glass rounded-2xl p-4 lg:col-span-7">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-[var(--text)]">
                    全员低于门槛兜底策略（3 选 1）
                  </h3>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    当组内所有节点同时低于设定门槛或未通过硬门禁时的自动处置
                  </p>
                </div>
                <ShieldAlert className="h-4 w-4 text-[var(--amber)]" />
              </div>

              <div className="space-y-2">
                {FALLBACK_POLICIES.map((pol) => {
                  const selected = selectedGroup.fallback_policy === pol.id;
                  const toneVar =
                    pol.tone === "red"
                      ? "var(--red)"
                      : pol.tone === "amber"
                        ? "var(--amber)"
                        : "var(--accent)";
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
                      className={`w-full rounded-xl border p-3 text-left transition-colors ${
                        selected
                          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                          : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-[var(--text)]">
                          {pol.title}
                        </span>
                        <span
                          className="rounded-full bg-[var(--card)] px-2 py-0.5 text-[10px] font-medium"
                          style={{ color: toneVar }}
                        >
                          {pol.badge}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                        {pol.desc}
                      </p>
                    </button>
                  );
                })}
              </div>

              {/* Extra controls when cross_pool_escalate is active */}
              {selectedGroup.fallback_policy === "cross_pool_escalate" && (
                <div className="mt-3 grid grid-cols-1 gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 text-xs sm:grid-cols-2">
                  <label>
                    <span className="text-[11px] text-[var(--muted)]">目标备援池</span>
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
                      <option value="">选择备援策略组</option>
                      {otherGroups.map((og) => (
                        <option key={og.id} value={og.id}>
                          {og.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span className="text-[11px] text-[var(--muted)]">
                      主池自动回切探测间隔 (秒)
                    </span>
                    <input
                      type="number"
                      min={30}
                      max={1800}
                      value={selectedGroup.recover_probe_interval_sec}
                      onChange={(e) =>
                        updateSelectedGroup((g) => ({
                          ...g,
                          recover_probe_interval_sec: Math.max(30, Number(e.target.value) || 120),
                        }))
                      }
                      className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                    />
                  </label>
                </div>
              )}
            </div>

            {/* Per-Group Switch Mode (force_close_old vs graceful_new_only) */}
            <div className="cc-card cc-glass flex flex-col justify-between rounded-2xl p-4 lg:col-span-5">
              <div>
                <div className="mb-3 flex items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      本组旧连接切换模式
                    </h3>
                    <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                      按策略组独立生效，互不干扰其他分流组连接
                    </p>
                  </div>
                  <ArrowRightLeft className="h-4 w-4 text-[var(--accent)]" />
                </div>

                <div className="space-y-2.5">
                  {(
                    [
                      {
                        id: "force_close_old",
                        title: "强力踢断旧连接",
                        tag: "AI 专线推荐",
                        desc: "切节点后立刻通过核心 API 关闭本组旧节点存量 TCP/HTTP2 僵尸连接，消除长请求卡死。",
                      },
                      {
                        id: "graceful_new_only",
                        title: "温和切换（仅新连接）",
                        tag: "流媒体 / 下载推荐",
                        desc: "保留正在传输的旧连接直至自然结束，仅将后续新建连接路由至切换后的优选节点。",
                      },
                    ] as ReadonlyArray<{
                      id: SwitchMode;
                      title: string;
                      tag: string;
                      desc: string;
                    }>
                  ).map((mode) => {
                    const active = selectedGroup.switch_mode === mode.id;
                    return (
                      <button
                        key={mode.id}
                        type="button"
                        onClick={() =>
                          updateSelectedGroup((g) => ({ ...g, switch_mode: mode.id }))
                        }
                        className={`w-full rounded-xl border p-3 text-left transition-colors ${
                          active
                            ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-[var(--text)]">
                            {mode.title}
                          </span>
                          <span className="rounded-full bg-[var(--card)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                            {mode.tag}
                          </span>
                        </div>
                        <div className="mt-1 cc-mono text-[10px] text-[var(--muted)]">
                          {mode.id}
                        </div>
                        <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                          {mode.desc}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] text-[var(--muted)]">
                当前策略：
                <span className="cc-mono ml-1 font-medium text-[var(--text)]">
                  {selectedGroup.switch_mode === "force_close_old"
                    ? "仅精准清理本组旧连接（不影响其他组）"
                    : "零中断平滑过渡"}
                </span>
              </div>
            </div>
          </section>

          {/* Real-Time Candidate Scoring Queue */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">候选节点实时评分队列</h3>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  实时结合最新探针快照与当前 AST 公式动态排序，点击任意达标节点可立即切换
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {passingCount === 0 && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--red)]">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    当前无节点通过硬门禁 · 将触发「
                    {FALLBACK_POLICIES.find((p) => p.id === selectedGroup.fallback_policy)?.title}」
                  </span>
                )}
                <button
                  type="button"
                  disabled={evaluating}
                  onClick={() => void handleEvaluateBackend()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${evaluating ? "animate-spin" : ""}`} />
                  <span>{evaluating ? "评估中..." : "后端权威评估"}</span>
                </button>
              </div>
            </div>

            {evalReport && (
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] text-[var(--text-secondary)]">
                <span className="cc-mono">
                  后端评估结论：候选池 {evalReport.pool_size} · 门禁通过 {evalReport.gate_passed.length} · 健康候选{" "}
                  {evalReport.healthy_candidates.length} · 淘汰 {evalReport.gate_rejected.length}
                </span>
                {evalReport.all_below_threshold && (
                  <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                    全员低于门槛
                  </span>
                )}
              </div>
            )}

            <div className="space-y-2">
              {scoredCandidates.map((item, idx) => {
                const isActive = selectedGroup.active_node_id === item.node.id;
                const barWidth = Math.max(4, Math.min(100, (item.score / maxScore) * 100));
                return (
                  <div
                    key={item.node.id}
                    className={`rounded-xl border px-3.5 py-2.5 transition-colors ${
                      isActive
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)]"
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-[var(--card)] cc-mono text-[11px] font-semibold text-[var(--accent)]">
                          #{idx + 1}
                        </span>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="truncate text-xs font-semibold text-[var(--text)]">
                              {item.node.name}
                            </span>
                            {isActive && (
                              <span className="rounded-full bg-[var(--accent)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                                当前活跃
                              </span>
                            )}
                            {item.passedAllGates ? (
                              <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                                门禁通过
                              </span>
                            ) : (
                              <span className="rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--red)]">
                                淘汰：{item.failedGates.join(" / ")}
                              </span>
                            )}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-3 cc-mono text-[11px] text-[var(--muted)]">
                            <span>{item.node.region_code}</span>
                            <span>{item.node.multiplier.toFixed(1)}x</span>
                            <span>↑ {item.snap?.up_mbps?.toFixed(1) ?? "--"} Mbps</span>
                            <span>↓ {item.snap?.down_mbps?.toFixed(1) ?? "--"} Mbps</span>
                            <span>{item.snap?.latency_ms ?? "--"} ms</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="w-28 text-right">
                          <div className="cc-mono cc-tabular text-sm font-semibold text-[var(--text)]">
                            {item.score.toFixed(1)}
                          </div>
                          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${barWidth}%`,
                                backgroundColor: item.passedAllGates
                                  ? "var(--accent)"
                                  : "var(--muted)",
                              }}
                            />
                          </div>
                        </div>

                        <button
                          type="button"
                          disabled={isActive}
                          onClick={() => void handleManualSelectNode(item.node)}
                          className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                        >
                          {isActive ? "使用中" : "切换"}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}

              {scoredCandidates.length === 0 && (
                <div className="rounded-xl border border-dashed border-[var(--line)] py-6 text-center text-xs text-[var(--muted)]">
                  暂无候选节点，请先在「节点与订阅」页面导入节点。
                </div>
              )}
            </div>
          </section>
        </div>
      ) : (
        <div className="cc-card cc-glass rounded-2xl p-8 text-center text-xs text-[var(--muted)] xl:col-span-9">
          暂无智能多选组，请点击左侧「新建组」创建首个策略组。
        </div>
      )}
    </div>
  );
}
