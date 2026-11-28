/**
 * Zero-eval Safe Recursive-Descent AST Formula Parser, Variable Context Builder,
 * and Hard-Gate Evaluator.
 *
 * 100% semantically aligned with Rust `crates/catcloud-core/src/strategy/formula.rs`,
 * preserving `ip_clean`, Windsurf semantic unlock/proxy-risk classification,
 * and neutral allowance for untested metrics.
 */

import type { ProbeSnapshot, ProxyNode } from "../api/types.ts";
import { resolveWindsurfUnlockDisplay } from "./aiUnlockDisplay.ts";
import { MISSING_LATENCY_PENALTY_MS } from "./latencyDisplay.ts";

export const FORMULA_COST_EFFECTIVE =
  "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)";

export const FORMULA_MAX_PERF =
  "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1";

export const FORMULA_WSF_CLEAN = `${FORMULA_COST_EFFECTIVE} + ip_clean * 120`;

export const DEFAULT_MISSING_PING_MS = MISSING_LATENCY_PENALTY_MS;
export const EPSILON_ZERO = 1e-12;
export const EPSILON_EQ = 1e-9;

export const GEMINI_GATE_EXPR = 'site_unlocked("gemini") == 1';
export const LEGACY_GEMINI_GATE_EXPR = 'site_unlocked("google_ai") == 1';

export interface GatePreset {
  expr: string;
  label: string;
  failText: string;
}

export const HARD_GATE_PRESETS: readonly GatePreset[] = [
  { expr: "google_clean == 1", label: "谷歌地区正常", failText: "谷歌地区异常" },
  { expr: "ip_clean == 1", label: "纯净住宅 / 避开代理机房", failText: "非纯净住宅 IP" },
  { expr: "keepalive_ok == 1", label: "长连接稳定(60秒)", failText: "60秒长连接未通过" },
  { expr: 'site_unlocked("chatgpt") == 1', label: "ChatGPT 可用", failText: "ChatGPT 未解锁" },
  { expr: GEMINI_GATE_EXPR, label: "Gemini 可用", failText: "Gemini 未解锁" },
  { expr: 'site_unlocked("claude") == 1', label: "Claude 可用", failText: "Claude 未解锁" },
  { expr: 'site_unlocked("windsurf") == 1', label: "Windsurf 可用", failText: "Windsurf 未解锁" },
];

export const SITE_FRIENDLY_NAMES: Record<string, string> = {
  chatgpt: "ChatGPT",
  google_ai: "Gemini",
  gemini: "Gemini",
  gemini_aistudio: "Gemini",
  claude: "Claude",
  windsurf: "Windsurf",
};

export const FORMULA_VARIABLES: ReadonlyArray<{ token: string; label: string }> = [
  { token: "up_mbps", label: "上行 Mbps" },
  { token: "down_mbps", label: "下行 Mbps" },
  { token: "ping_ms", label: "延迟 ms" },
  { token: "jitter_ms", label: "抖动 ms" },
  { token: "loss_pct", label: "丢包 %" },
  { token: "multiplier", label: "倍率" },
  { token: "keepalive_ok", label: "60秒保活" },
  { token: "google_clean", label: "谷歌地区正常" },
  { token: "ip_clean", label: "纯净住宅 IP" },
  { token: "unlocked", label: "全站点解锁" },
];

export const PROBE_ADDRESS_SNIPPETS: ReadonlyArray<{ token: string; desc: string }> = [
  { token: 'probe_up("antigravity")', desc: "指定探针上行 Mbps" },
  { token: 'probe_down("dl")', desc: "指定探针下行 Mbps" },
  { token: 'probe_ping("chatgpt")', desc: "指定探针延迟 ms" },
  { token: 'probe_ok("builtin_unlock_windsurf")', desc: "指定探针通过 (1/0)" },
  { token: 'site_unlocked("chatgpt")', desc: "ChatGPT 解锁 (1/0)" },
  { token: 'site_unlocked("gemini")', desc: "Gemini 解锁 (1/0)" },
];

export type OpValue =
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

export type Token =
  | { kind: "num"; value: number }
  | { kind: "ident"; value: string }
  | { kind: "str"; value: string }
  | { kind: "op"; value: OpValue };

export interface EvalContext {
  vars: Record<string, number>;
  probeUp: Record<string, number>;
  probeDown: Record<string, number>;
  probePing: Record<string, number>;
  probeOk: Record<string, boolean>;
  unlockedSites: Record<string, boolean>;
}

export interface EvalOutcome {
  ok: boolean;
  value: number;
  error: string | null;
}

export interface NodeGateAssessment {
  hasMeasuredFailure: boolean;
  failedReasons: string[];
  allMeasuredAndPassed: boolean;
}

export function sanitizeNumber(v: number): number {
  return Number.isFinite(v) && v !== 0 ? v : 0;
}

export function isTruthy(v: number): boolean {
  return Number.isFinite(v) && Math.abs(v) > EPSILON_ZERO;
}

export function tokenizeFormula(input: string): { tokens: Token[]; error: string | null } {
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

export function lookupSiteUnlockedRaw(
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

export function evaluateFormulaSafely(expr: string, ctx: EvalContext): EvalOutcome {
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
            return sanitizeNumber(
              typeof v === "number" && Number.isFinite(v) ? v : (ctx.vars.up_mbps ?? 0)
            );
          }
          if (name === "probe_down") {
            const v = ctx.probeDown[arg.value];
            return sanitizeNumber(
              typeof v === "number" && Number.isFinite(v) ? v : (ctx.vars.down_mbps ?? 0)
            );
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

export function buildEvalContextForNode(
  node: ProxyNode,
  snap: ProbeSnapshot | undefined
): EvalContext {
  const unlockedEntries = snap ? Object.values(snap.unlocked_sites) : [];
  const allUnlocked = unlockedEntries.length > 0 && unlockedEntries.every(Boolean);
  const ok = snap?.ok ?? false;
  const validLatencyMs =
    typeof snap?.latency_ms === "number" &&
    Number.isFinite(snap.latency_ms) &&
    snap.latency_ms > 0
      ? snap.latency_ms
      : null;
  const effectivePingMs = validLatencyMs ?? MISSING_LATENCY_PENALTY_MS;

  return {
    vars: {
      up_mbps: snap?.up_mbps ?? 0,
      down_mbps: snap?.down_mbps ?? 0,
      ping_ms: effectivePingMs,
      latency_ms: effectivePingMs,
      jitter_ms: snap?.jitter_ms ?? 0,
      loss_pct: snap?.loss_pct ?? (ok ? 0 : 100),
      multiplier: Number.isFinite(node.multiplier) && node.multiplier >= 0 ? node.multiplier : 1,
      keepalive_ok: snap?.keepalive_60s_ok === true ? 1 : 0,
      google_clean: snap?.google_clean === true ? 1 : 0,
      ip_clean: snap?.ip_clean === true ? 1 : 0,
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

export function checkHardGate(gate: string, ctx: EvalContext): boolean {
  const res = evaluateFormulaSafely(gate, ctx);
  return res.ok && isTruthy(res.value);
}

/**
 * Human-friendly gate check:
 * - Never marks untested nodes as "failed" or "rejected"!
 * - Only returns `failedReasons` when the node has an actual measured value that violates a gate.
 */
export function assessNodeAgainstGates(
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
    if (compact === "ip_clean==1") {
      if (snap.ip_clean === null || snap.ip_clean === undefined) {
        untestedCount += 1;
      } else if (snap.ip_clean === false) {
        failedReasons.push(
          snap.ip_risk_level === "proxy_risk" ? "出口 IP 高危代理风控" : "非纯净住宅 IP"
        );
      }
      continue;
    }
    const siteMatch = /^site_unlocked\(["']([^"']+)["']\)==1$/.exec(compact);
    if (siteMatch) {
      const siteKey = siteMatch[1];
      if (
        siteKey.toLowerCase() === "windsurf" ||
        siteKey.toLowerCase() === "builtin_unlock_windsurf"
      ) {
        const ws = resolveWindsurfUnlockDisplay(snap);
        if (ws.state === "untested" || ws.state === "legacy_retest") {
          untestedCount += 1;
        } else if (!ws.unlocked) {
          failedReasons.push(
            ws.state === "proxy_risk" ? "Windsurf 出口代理风控" : "Windsurf 未解锁"
          );
        }
        continue;
      }
      const measured = lookupSiteUnlockedRaw(snap.unlocked_sites ?? {}, siteKey);
      if (measured === null) {
        untestedCount += 1;
      } else if (measured === false) {
        const label = SITE_FRIENDLY_NAMES[siteKey.toLowerCase()] ?? siteKey;
        failedReasons.push(`${label} 未解锁`);
      }
      continue;
    }
    // Custom / compound gate expression: neutrally allow untested keepalive_ok & ip_clean independently (matching Rust evaluator)
    if (!lazyCtx) {
      lazyCtx = buildEvalContextForNode(node, snap);
    }
    let patchedVars = lazyCtx.vars;
    let patched = false;
    if (
      (snap.keepalive_60s_ok === null || snap.keepalive_60s_ok === undefined) &&
      gate.includes("keepalive_ok")
    ) {
      patchedVars = { ...patchedVars, keepalive_ok: 1 };
      patched = true;
    }
    if (
      (snap.ip_clean === null || snap.ip_clean === undefined) &&
      gate.includes("ip_clean")
    ) {
      patchedVars = { ...patchedVars, ip_clean: 1 };
      patched = true;
    }
    const evalCtx = patched ? { ...lazyCtx, vars: patchedVars } : lazyCtx;
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
