/**
 * Unified Mihomo routing rule constants, balanced-parenthesis logical rule parser,
 * strict validator (enforcing nested-clause and anti-dirty-character guards),
 * and user rule normalizer shared across MultiGroupPage, RulesConnsPage, and preview fallback.
 */

export const LOGICAL_PAREN_RULE_TYPES = new Set<string>(["AND", "OR", "NOT", "SUB-RULE"]);

export const STRICT_LOGICAL_RULE_TYPES = new Set<string>(["AND", "OR", "NOT"]);

export const REGEX_RULE_TYPES = new Set<string>([
  "DOMAIN-REGEX",
  "PROCESS-NAME-REGEX",
  "PROCESS-PATH-REGEX",
]);

export const NO_COMMA_SPLIT_MATCH_RULE_TYPES = new Set<string>([
  "SUB-RULE",
  "DOMAIN-REGEX",
  "PROCESS-NAME-REGEX",
  "PROCESS-PATH-REGEX",
]);

export const KNOWN_MATCH_RULE_TYPES = new Set<string>([
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

export const KNOWN_MIHOMO_RULE_TYPES = new Set<string>([
  ...KNOWN_MATCH_RULE_TYPES,
  "SRC-GEOIP",
  "SRC-IP-SUFFIX",
  "SRC-IP-ASN",
  "IN-PORT",
  "DSCP",
  "MATCH",
  "FINAL",
]);

export const BARE_RULE_KEYWORDS = new Set<string>([
  ...KNOWN_MATCH_RULE_TYPES,
  "MATCH",
  "FINAL",
  "DIRECT",
  "REJECT",
  "PROXY",
]);

export const DOMAIN_LIKE_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;

export const INVALID_MATCH_RULE_MSG =
  "请输入域名或完整规则（如 codeium.com / PROCESS-NAME,QQ.exe / AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))）";

export interface LogicalRuleParts {
  ruleType: string;
  expr: string;
  target: string | null;
}

export interface MihomoRuleTargetSpan {
  target: string;
  start: number;
  end: number;
}

export function isRuleFlagToken(token: string): boolean {
  const lower = token.trim().toLowerCase();
  return lower === "no-resolve" || lower === "src";
}

export function findBalancedParenEnd(text: string, openIdx: number): number {
  if (openIdx < 0 || openIdx >= text.length || text[openIdx] !== "(") return -1;
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")") {
      depth -= 1;
      if (depth < 0) return -1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function hasStrictBalancedOuterParens(expr: string): boolean {
  const trimmed = expr.trim();
  if (trimmed.length < 3 || !trimmed.startsWith("(") || !trimmed.endsWith(")")) {
    return false;
  }
  if (findBalancedParenEnd(trimmed, 0) !== trimmed.length - 1) {
    return false;
  }
  const inner = trimmed.slice(1, -1).trim();
  return inner.length > 0 && inner.startsWith("(") && inner.endsWith(")");
}

function splitTopLevelLogicalClauses(inner: string): string[] | null {
  if (!inner || inner === "()") return null;
  let depth = 0;
  let clauseStart = 0;
  const clauses: string[] = [];
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")") {
      depth -= 1;
      if (depth < 0) return null;
    } else if (ch === "," && depth === 0) {
      clauses.push(inner.slice(clauseStart, i).trim());
      clauseStart = i + 1;
    }
  }
  if (depth !== 0) return null;
  clauses.push(inner.slice(clauseStart).trim());
  return clauses;
}

/**
 * Validate a logical rule expression (the parenthesized part of AND / OR / NOT).
 * Returns `null` when valid, or a descriptive error string when invalid.
 * Enforces strict double-paren, nested logical clause, and anti-dirty-character checks.
 */
export function validateLogicalRuleExpr(expr: string, ruleType: string): string | null {
  const normalizedType = ruleType.trim().toUpperCase();
  const trimmed = expr.trim();
  if (!trimmed) {
    return `${normalizedType} 规则条件不能为空，请填写双层括号表达式`;
  }
  if (!trimmed.startsWith("(") || !trimmed.endsWith(")")) {
    return `${normalizedType} 规则条件必须使用括号包裹，例如 ((PROCESS-NAME,QQ.exe),(DST-PORT,15000))`;
  }
  const endIdx = findBalancedParenEnd(trimmed, 0);
  if (endIdx !== trimmed.length - 1) {
    return `${normalizedType} 规则括号未正确闭合或存在并列外层括号，请确认外层仅有一对 (...)`;
  }
  const inner = trimmed.slice(1, -1).trim();
  if (!inner) {
    return `${normalizedType} 规则括号内不能为空条件`;
  }
  if (!inner.startsWith("(") || !inner.endsWith(")")) {
    return `${normalizedType} 规则需使用 Mihomo 双层括号写法，例如 ${
      normalizedType === "NOT"
        ? "((DOMAIN-SUFFIX,cn))"
        : "((PROCESS-NAME,QQ.exe),(DST-PORT,15000))"
    }`;
  }
  const clauses = splitTopLevelLogicalClauses(inner);
  if (!clauses || clauses.length === 0) {
    return `${normalizedType} 规则内部括号不匹配或未闭合`;
  }
  for (const clause of clauses) {
    if (
      !clause.startsWith("(") ||
      !clause.endsWith(")") ||
      findBalancedParenEnd(clause, 0) !== clause.length - 1
    ) {
      return `${normalizedType} 规则每个子条件都必须由独立括号包裹且仅以逗号分隔`;
    }
    const body = clause.slice(1, -1).trim();
    const commaIdx = body.indexOf(",");
    if (!body || commaIdx <= 0) {
      return `${normalizedType} 规则子条件不能为空，且需为合法规则格式如 (PROCESS-NAME,QQ.exe)`;
    }
    const subType = body.slice(0, commaIdx).trim().toUpperCase();
    const subRest = body.slice(commaIdx + 1).trim();
    if (!subType || !subRest) {
      return `${normalizedType} 规则子条件不能为空，且需为合法规则格式如 (PROCESS-NAME,QQ.exe)`;
    }
    if (STRICT_LOGICAL_RULE_TYPES.has(subType)) {
      const nestedErr = validateLogicalRuleExpr(subRest, subType);
      if (nestedErr) return nestedErr;
    }
  }
  if (normalizedType === "NOT" && clauses.length !== 1) {
    return "NOT 规则仅允许包含 1 个子条件，例如 ((DOMAIN-SUFFIX,cn))";
  }
  return null;
}

export function countTopLevelLogicalChildren(parenBlock: string): number {
  const trimmed = parenBlock.trim();
  if (!hasStrictBalancedOuterParens(trimmed)) return -1;
  const inner = trimmed.slice(1, -1).trim();
  if (!inner || inner === "()") return 0;
  const clauses = splitTopLevelLogicalClauses(inner);
  if (!clauses) return -1;
  for (const clause of clauses) {
    if (
      !clause.startsWith("(") ||
      !clause.endsWith(")") ||
      findBalancedParenEnd(clause, 0) !== clause.length - 1
    ) {
      return -1;
    }
    const body = clause.slice(1, -1).trim();
    const commaIdx = body.indexOf(",");
    if (!body || commaIdx <= 0) return -1;
    const subType = body.slice(0, commaIdx).trim().toUpperCase();
    const subRest = body.slice(commaIdx + 1).trim();
    if (!subType || !subRest) return -1;
    if (STRICT_LOGICAL_RULE_TYPES.has(subType)) {
      if (validateLogicalRuleExpr(subRest, subType) !== null) return -1;
    }
  }
  return clauses.length;
}

export function validateLogicalMatchRuleRest(restRaw: string, ruleType?: string): boolean {
  const trimmed = restRaw.trim();
  if (!trimmed.startsWith("(")) return false;
  const closeIdx = findBalancedParenEnd(trimmed, 0);
  if (closeIdx < 0) return false;
  const parenBlock = trimmed.slice(0, closeIdx + 1);
  if (validateLogicalRuleExpr(parenBlock, ruleType ?? "AND") !== null) {
    return false;
  }
  const tail = trimmed.slice(closeIdx + 1).trim();
  if (!tail) return true;
  // Allow explicit target after closing paren (e.g. AND,((...)),DIRECT),
  // but reject top-level trailing flags (no-resolve/src) or extra commas forbidden by Mihomo.
  if (!tail.startsWith(",")) return false;
  const target = tail.slice(1).trim();
  if (!target || target.includes(",")) return false;
  if (isRuleFlagToken(target)) return false;
  return true;
}

export function parseLogicalRuleParts(trimmed: string): LogicalRuleParts | null {
  const firstComma = trimmed.indexOf(",");
  if (firstComma < 0) return null;
  const ruleType = trimmed.slice(0, firstComma).trim().toUpperCase();
  if (!LOGICAL_PAREN_RULE_TYPES.has(ruleType)) return null;
  let openIdx = firstComma + 1;
  while (openIdx < trimmed.length && /\s/.test(trimmed[openIdx])) openIdx += 1;
  const closeIdx = findBalancedParenEnd(trimmed, openIdx);
  if (closeIdx < 0) return null;
  const expr = trimmed.slice(openIdx, closeIdx + 1).trim();
  const tail = trimmed.slice(closeIdx + 1).trim();
  if (!tail) {
    return { ruleType, expr, target: null };
  }
  if (!tail.startsWith(",")) return null;
  const target = tail.slice(1).trim();
  if (!target) return null;
  if (ruleType !== "SUB-RULE") {
    // Mihomo forbids top-level trailing flags (no-resolve/src) or extra commas after logical rule target.
    if (target.includes(",") || isRuleFlagToken(target)) return null;
  }
  return { ruleType, expr, target };
}

export function normalizeSingleMatchRule(raw: string): { rule: string | null; invalid: boolean } {
  const trimmed = raw.trim();
  if (!trimmed) return { rule: null, invalid: false };

  const commaIdx = trimmed.indexOf(",");
  if (commaIdx !== -1) {
    const ruleType = trimmed.slice(0, commaIdx).trim().toUpperCase();
    const restRaw = trimmed.slice(commaIdx + 1).trim();
    if (!KNOWN_MATCH_RULE_TYPES.has(ruleType) || !restRaw) {
      return { rule: null, invalid: true };
    }
    if (STRICT_LOGICAL_RULE_TYPES.has(ruleType)) {
      if (!validateLogicalMatchRuleRest(restRaw, ruleType)) {
        return { rule: null, invalid: true };
      }
      return { rule: `${ruleType},${restRaw}`, invalid: false };
    }
    if (NO_COMMA_SPLIT_MATCH_RULE_TYPES.has(ruleType)) {
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

export function parseUserMatchRules(rawInput: string): {
  rules: string[];
  invalidTokens: string[];
} {
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

export function formatMatchRuleChip(rule: string): { display: string; tag: string | null } {
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
  if (upper.startsWith("DOMAIN-REGEX,")) {
    return { display: trimmed.slice("DOMAIN-REGEX,".length).trim(), tag: "正则" };
  }
  if (upper.startsWith("PROCESS-NAME,") || upper.startsWith("PROCESS-NAME-REGEX,")) {
    const idx = trimmed.indexOf(",");
    return { display: trimmed.slice(idx + 1).trim(), tag: "程序" };
  }
  if (upper.startsWith("PROCESS-PATH,") || upper.startsWith("PROCESS-PATH-REGEX,")) {
    const idx = trimmed.indexOf(",");
    return { display: trimmed.slice(idx + 1).trim(), tag: "路径" };
  }
  if (upper.startsWith("DST-PORT,") || upper.startsWith("SRC-PORT,")) {
    const idx = trimmed.indexOf(",");
    return { display: trimmed.slice(idx + 1).trim(), tag: "端口" };
  }
  if (upper.startsWith("AND,")) {
    return { display: trimmed.slice("AND,".length).trim(), tag: "复合与" };
  }
  if (upper.startsWith("OR,")) {
    return { display: trimmed.slice("OR,".length).trim(), tag: "复合或" };
  }
  if (upper.startsWith("NOT,")) {
    return { display: trimmed.slice("NOT,".length).trim(), tag: "复合非" };
  }
  if (upper.startsWith("SUB-RULE,")) {
    return { display: trimmed.slice("SUB-RULE,".length).trim(), tag: "子规则" };
  }
  if (upper.startsWith("IP-CIDR,") || upper.startsWith("IP-CIDR6,")) {
    const idx = trimmed.indexOf(",");
    return { display: trimmed.slice(idx + 1).trim(), tag: "IP" };
  }
  return { display: trimmed, tag: null };
}

export function locateMihomoRuleTarget(trimmed: string): MihomoRuleTargetSpan | null {
  const firstComma = trimmed.indexOf(",");
  if (firstComma < 0) return null;
  const ruleType = trimmed.slice(0, firstComma).trim().toUpperCase();
  if (!ruleType || ruleType === "SUB-RULE") return null;

  if (ruleType === "MATCH" || ruleType === "FINAL") {
    let start = firstComma + 1;
    while (start < trimmed.length && /\s/.test(trimmed[start])) start += 1;
    const end = trimmed.length;
    const target = trimmed.slice(start, end).trim();
    return target ? { target, start, end } : null;
  }

  if (STRICT_LOGICAL_RULE_TYPES.has(ruleType)) {
    let openIdx = firstComma + 1;
    while (openIdx < trimmed.length && /\s/.test(trimmed[openIdx])) openIdx += 1;
    const closeIdx = findBalancedParenEnd(trimmed, openIdx);
    if (closeIdx < 0) return null;
    let after = closeIdx + 1;
    while (after < trimmed.length && /\s/.test(trimmed[after])) after += 1;
    if (after >= trimmed.length || trimmed[after] !== ",") return null;
    let targetStart = after + 1;
    while (targetStart < trimmed.length && /\s/.test(trimmed[targetStart])) targetStart += 1;
    const target = trimmed.slice(targetStart).trim();
    if (!target || target.includes(",") || isRuleFlagToken(target)) {
      return null;
    }
    return { target, start: targetStart, end: trimmed.length };
  }

  // Regex rules and standard rules: scan trailing flags from the right
  let end = trimmed.length;
  while (end > firstComma + 1) {
    const prevComma = trimmed.lastIndexOf(",", end - 1);
    if (prevComma <= firstComma) break;
    const seg = trimmed.slice(prevComma + 1, end).trim();
    if (isRuleFlagToken(seg)) {
      end = prevComma;
      continue;
    }
    break;
  }
  const targetComma = trimmed.lastIndexOf(",", end - 1);
  if (targetComma <= firstComma) return null;
  if (!REGEX_RULE_TYPES.has(ruleType)) {
    const valSegment = trimmed.slice(firstComma + 1, targetComma).trim();
    if (!valSegment) return null;
  }
  let targetStart = targetComma + 1;
  while (targetStart < end && /\s/.test(trimmed[targetStart])) targetStart += 1;
  let targetEnd = end;
  while (targetEnd > targetStart && /\s/.test(trimmed[targetEnd - 1])) targetEnd -= 1;
  const target = trimmed.slice(targetStart, targetEnd);
  return target ? { target, start: targetStart, end: targetEnd } : null;
}

export function validateInlineOverrideYamlLocal(raw: string): string | null {
  const trimmedAll = raw.trim();
  if (!trimmedAll) return null;
  const lines = raw.split(/\r?\n/);
  let hasRootMapping = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    if (/^\t/.test(line)) {
      return `第 ${lineNo} 行存在 Tab 缩进，请改为空格缩进`;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed === "---" || trimmed === "...") {
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      if (trimmed.startsWith("- ") || trimmed === "-") {
        if (!hasRootMapping) {
          return `第 ${lineNo} 行顶层不能直接以列表开头，请写为 YAML 键段（如 rule-providers: / rules: / dns:）`;
        }
        continue;
      }
      if (
        /^(?:[A-Za-z0-9_.-]+|"[^"\r\n]+"|'[^'\r\n]+')\s*:/.test(trimmed) ||
        trimmed.startsWith("{")
      ) {
        hasRootMapping = true;
        continue;
      }
      if (!hasRootMapping) {
        return `第 ${lineNo} 行顶层语法有误，请确认键名后带有冒号（例如 rule-providers:）`;
      }
    }
  }
  if (!hasRootMapping) {
    return "未检测到有效的 YAML 配置段（如 rule-providers:、rules:、dns:）";
  }
  return null;
}
