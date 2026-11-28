import type {
  ActiveConnectionDto,
  CompiledYamlPreview,
  MultiGroup,
  PreAccelRelay,
} from "../../api/tauri";
import {
  LOGICAL_PAREN_RULE_TYPES,
  REGEX_RULE_TYPES,
  isRuleFlagToken,
  parseLogicalRuleParts,
} from "../../utils/mihomoRuleParser";
import { oneOfPref } from "../../utils/uiPrefs";

export type ActiveTab = "rules" | "connections";
export type ConnSortKey = "down" | "up" | "rate" | "age" | "process";
export const ACTIVE_TAB_VALIDATOR = oneOfPref(["rules", "connections"] as const);
export const CONN_SORT_VALIDATOR = oneOfPref(["down", "up", "rate", "age", "process"] as const);
export type RuleLayer = "prepend" | "group" | "append";
export type RuleMatchType =
  | "DOMAIN-SUFFIX"
  | "DOMAIN"
  | "DOMAIN-KEYWORD"
  | "IP-CIDR"
  | "PROCESS-NAME"
  | "PROCESS-PATH"
  | "DST-PORT"
  | "AND"
  | "OR"
  | "NOT"
  | "GEOSITE"
  | "GEOIP";

export interface ManagedRuleItem {
  id: string;
  layer: RuleLayer;
  ruleType: RuleMatchType | string;
  value: string;
  target: string;
  noResolve?: boolean;
  groupId?: string;
  rawLine?: string;
  isRawFallback?: boolean;
}

export interface AiPresetBundle {
  id: string;
  name: string;
  desc: string;
  domains: string[];
  targetGroup: string;
  enabled: boolean;
}

export interface LiveConnection {
  id: string;
  process: string;
  host: string;
  dstIp: string;
  port: number;
  network: "tcp" | "udp";
  rule: string;
  chains: string[];
  groupId: string;
  groupName: string;
  nodeName: string;
  viaPreAccel: boolean;
  isInnerTunnel: boolean;
  isLoopback: boolean;
  uploadBytes: number;
  downloadBytes: number;
  upBps: number;
  downBps: number;
  startedAtMs: number;
}

export interface ConnTrafficSnap {
  uploadBytes: number;
  downloadBytes: number;
  atMs: number;
}

export interface ConnectionBreakdown {
  appCount: number;
  innerTunnelCount: number;
  loopbackCount: number;
}

export interface ParsedValidationIssue {
  code: string;
  severity: "error" | "warning";
  message: string;
}

export interface ParsedCompiledMeta {
  totalRules: number | null;
  totalProxies: number | null;
  proxyGroups: number | null;
  validationOk: boolean;
  errors: ParsedValidationIssue[];
  warnings: ParsedValidationIssue[];
}

export const CONNECTIONS_PAGE_SIZE = 30;

export const RULE_TYPE_LABELS: Record<RuleMatchType, string> = {
  "DOMAIN-SUFFIX": "域名后缀",
  DOMAIN: "完整域名",
  "DOMAIN-KEYWORD": "域名关键词",
  "IP-CIDR": "IP 网段",
  "PROCESS-NAME": "软件进程",
  "PROCESS-PATH": "进程路径",
  "DST-PORT": "目标端口",
  AND: "复合与 (AND)",
  OR: "复合或 (OR)",
  NOT: "复合非 (NOT)",
  GEOSITE: "网站集合",
  GEOIP: "地区 IP",
};

export const RULE_VALUE_PLACEHOLDERS: Record<RuleMatchType, string> = {
  "DOMAIN-SUFFIX": "例如 github.com 或 codeium.com（也可直接粘贴整行规则）",
  DOMAIN: "例如 server.codeium.com",
  "DOMAIN-KEYWORD": "例如 google 或 openai",
  "IP-CIDR": "例如 192.168.0.0/16 或 10.0.0.0/8",
  "PROCESS-NAME": "例如 QQ.exe、WeChat.exe 或 chrome.exe",
  "PROCESS-PATH": "例如 C:\\Program Files\\Tencent\\QQNT\\QQ.exe",
  "DST-PORT": "例如 15000、443 或 80/443",
  AND: "双层括号，例如 ((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
  OR: "双层括号，例如 ((PROCESS-NAME,QQ.exe),(PROCESS-NAME,Weixin.exe))",
  NOT: "双层括号，例如 ((DOMAIN-SUFFIX,cn))",
  GEOSITE: "例如 cn、google 或 openai",
  GEOIP: "例如 CN 或 JP",
};

export const IM_DIRECT_PROCESS_RULES: ReadonlyArray<{ process: string; line: string }> = [
  { process: "QQ.exe", line: "PROCESS-NAME,QQ.exe,DIRECT" },
  { process: "WeChat.exe", line: "PROCESS-NAME,WeChat.exe,DIRECT" },
  { process: "Weixin.exe", line: "PROCESS-NAME,Weixin.exe,DIRECT" },
];

export const EXTRA_RULE_TYPE_LABELS: Record<string, string> = {
  "RULE-SET": "规则集合",
  AND: "复合与",
  OR: "复合或",
  NOT: "复合非",
  "SUB-RULE": "子规则",
  "DOMAIN-REGEX": "域名正则",
  "DOMAIN-WILDCARD": "域名通配",
  "IP-CIDR6": "IPv6 网段",
  "IP-ASN": "ASN 自治域",
  "DST-PORT": "目标端口",
  "SRC-IP-CIDR": "来源网段",
  "PROCESS-PATH": "进程路径",
  "PROCESS-PATH-REGEX": "路径正则",
  "PROCESS-NAME-REGEX": "进程正则",
  MATCH: "最终兜底",
  FINAL: "最终兜底",
  RAW: "原始规则",
};

export const DEMO_BULK_RULES_TEXT = [
  "# 支持直接粘贴 Mihomo rules 原始段（自动忽略注释与短横线）",
  "- DOMAIN-SUFFIX,example.com,DIRECT",
  "- RULE-SET,apple,DIRECT",
  "- AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443)),DIRECT",
].join("\n");

export const DEMO_INLINE_OVERRIDE_YAML = [
  "rule-providers:",
  "  apple_cn:",
  "    type: http",
  "    behavior: domain",
  '    url: "https://example.invalid/rules/apple-cn.yaml"',
  "    path: ./ruleset/apple-cn.yaml",
  "    interval: 86400",
].join("\n");

export const AI_PRESETS_TEMPLATE: ReadonlyArray<Omit<AiPresetBundle, "targetGroup" | "enabled">> =
  [
    {
      id: "ai-openai",
      name: "OpenAI / ChatGPT",
      desc: "ChatGPT 网页端、接口及静态资源",
      domains: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    },
    {
      id: "ai-anthropic",
      name: "Anthropic / Claude",
      desc: "Claude 对话网页、静态资源与接口",
      domains: ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
    },
    {
      id: "ai-gemini",
      name: "Google Gemini / AI Studio",
      desc: "Gemini、AI Studio、DeepMind 与 Google AI 相关接口",
      domains: [
        "gemini.google.com",
        "aistudio.google.com",
        "generativelanguage.googleapis.com",
        "googleapis.com",
        "cloudcode-pa.googleapis.com",
        "ai.google.dev",
        "deepmind.com",
      ],
    },
    {
      id: "ai-windsurf",
      name: "Windsurf & Codeium",
      desc: "Windsurf、Codeium 与 Devin 编程工具相关域名",
      domains: [
        "codeium.com",
        "codeiumdata.com",
        "windsurf.com",
        "devin.ai",
        "cognition.ai",
        "exafunction.com",
      ],
    },
  ];

export function serializeRuleItem(r: ManagedRuleItem): string {
  if (r.rawLine && r.rawLine.trim()) {
    return r.rawLine.trim();
  }
  const typeUpper = r.ruleType.trim().toUpperCase();
  const value = r.value.trim();
  const target = r.target.trim();
  if (typeUpper === "MATCH" || typeUpper === "FINAL") {
    return `${typeUpper},${target}`;
  }
  return `${typeUpper},${value},${target}${r.noResolve ? ",no-resolve" : ""}`;
}

export function parseRuleString(
  raw: string,
  layer: "prepend" | "append",
  id: string
): ManagedRuleItem | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const firstComma = trimmed.indexOf(",");
  if (firstComma < 0) return null;
  const ruleType = trimmed.slice(0, firstComma).trim().toUpperCase();
  if (!ruleType) return null;

  if (ruleType === "MATCH" || ruleType === "FINAL") {
    const target = trimmed.slice(firstComma + 1).trim();
    if (!target || target.includes(",")) return null;
    return {
      id,
      layer,
      ruleType,
      value: "*",
      target,
      rawLine: trimmed,
    };
  }

  if (LOGICAL_PAREN_RULE_TYPES.has(ruleType)) {
    const logical = parseLogicalRuleParts(trimmed);
    if (!logical || !logical.expr || !logical.target) return null;
    return {
      id,
      layer,
      ruleType: logical.ruleType,
      value: logical.expr,
      target: logical.target,
      noResolve: false,
      rawLine: trimmed,
    };
  }

  const parts = trimmed.split(",").map((s) => s.trim());
  if (parts.length < 3) return null;

  // Locate target by skipping known trailing flags (no-resolve, src) while preserving commas in regex values
  let targetIdx = parts.length - 1;
  while (targetIdx > 2 && isRuleFlagToken(parts[targetIdx])) {
    targetIdx -= 1;
  }
  const value = parts.slice(1, targetIdx).join(",").trim();
  const target = parts[targetIdx]?.trim() ?? "";
  if (!value || !target) return null;

  const extraParts = parts.slice(targetIdx + 1);
  const noResolve = extraParts.some((p) => p.toLowerCase() === "no-resolve");
  return {
    id,
    layer,
    ruleType,
    value,
    target,
    noResolve,
    rawLine: trimmed,
  };
}

export function createRawFallbackRuleItem(
  raw: string,
  layer: "prepend" | "append",
  id: string
): ManagedRuleItem | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const firstComma = trimmed.indexOf(",");
  const rawType = firstComma > 0 ? trimmed.slice(0, firstComma).trim().toUpperCase() : "RAW";
  return {
    id,
    layer,
    ruleType: rawType || "RAW",
    value: trimmed,
    target: "",
    rawLine: trimmed,
    isRawFallback: true,
  };
}

export function hydrateRulesFromConfig(
  prependLines: string[],
  appendLines: string[],
  fallbackTarget: string
): { presets: AiPresetBundle[]; userRules: ManagedRuleItem[] } {
  const consumedPrepend = new Set<number>();

  const presets: AiPresetBundle[] = AI_PRESETS_TEMPLATE.map((tpl) => {
    const domainSet = new Set(tpl.domains.map((d) => d.toLowerCase()));
    const matchedDomains = new Set<string>();
    const matchedTargets = new Set<string>();
    const matchedIndices: number[] = [];

    prependLines.forEach((raw, idx) => {
      if (consumedPrepend.has(idx)) return;
      const parts = raw.split(",").map((p) => p.trim());
      if (parts.length !== 3) return;
      if (parts[0].toUpperCase() !== "DOMAIN-SUFFIX") return;
      const domain = parts[1].toLowerCase();
      const target = parts[2];
      if (!domainSet.has(domain) || !target) return;
      matchedDomains.add(domain);
      matchedTargets.add(target);
      matchedIndices.push(idx);
    });

    // Only fold into an AI preset switch when ALL preset domains exist and share the exact same target
    if (matchedDomains.size === domainSet.size && matchedTargets.size === 1) {
      const [soleTarget] = Array.from(matchedTargets);
      for (const idx of matchedIndices) consumedPrepend.add(idx);
      return {
        ...tpl,
        targetGroup: soleTarget,
        enabled: true,
      };
    }

    return {
      ...tpl,
      targetGroup: fallbackTarget,
      enabled: false,
    };
  });

  const userRules: ManagedRuleItem[] = [];
  prependLines.forEach((raw, idx) => {
    if (consumedPrepend.has(idx)) return;
    const parsed =
      parseRuleString(raw, "prepend", `rule-pre-${idx}-${raw}`) ??
      createRawFallbackRuleItem(raw, "prepend", `rule-pre-raw-${idx}-${raw}`);
    if (parsed) userRules.push(parsed);
  });
  appendLines.forEach((raw, idx) => {
    const parsed =
      parseRuleString(raw, "append", `rule-app-${idx}-${raw}`) ??
      createRawFallbackRuleItem(raw, "append", `rule-app-raw-${idx}-${raw}`);
    if (parsed) userRules.push(parsed);
  });

  return { presets, userRules };
}

export function buildRulesOverridePayload(
  presets: AiPresetBundle[],
  userRules: ManagedRuleItem[]
): { global_prepend_rules: string[]; global_append_rules: string[] } {
  const global_prepend_rules: string[] = [];
  const seenPrepend = new Set<string>();
  const pushPrepend = (line: string) => {
    const trimmed = line.trim();
    if (trimmed && !seenPrepend.has(trimmed)) {
      seenPrepend.add(trimmed);
      global_prepend_rules.push(trimmed);
    }
  };

  for (const r of userRules) {
    if (r.layer === "prepend") {
      pushPrepend(serializeRuleItem(r));
    }
  }
  for (const preset of presets) {
    if (!preset.enabled) continue;
    const target = preset.targetGroup.trim() || "DIRECT";
    for (const domain of preset.domains) {
      pushPrepend(`DOMAIN-SUFFIX,${domain},${target}`);
    }
  }

  const global_append_rules: string[] = [];
  const seenAppend = new Set<string>();
  for (const r of userRules) {
    if (r.layer === "append") {
      const line = serializeRuleItem(r).trim();
      if (line && !seenAppend.has(line)) {
        seenAppend.add(line);
        global_append_rules.push(line);
      }
    }
  }

  return { global_prepend_rules, global_append_rules };
}

export function buildGroupBoundRules(groups: MultiGroup[]): ManagedRuleItem[] {
  const builtinTargets = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]);
  const groupNames = new Set(groups.map((g) => g.name.trim()).filter(Boolean));
  const isKnownExplicitTarget = (candidate: string) =>
    builtinTargets.has(candidate.toUpperCase()) || groupNames.has(candidate);

  const list: ManagedRuleItem[] = [];
  for (const grp of groups) {
    grp.match_rules.forEach((raw, idx) => {
      const trimmed = raw.trim();
      if (!trimmed) return;
      const firstComma = trimmed.indexOf(",");
      let rType = "DOMAIN-SUFFIX";
      let val = trimmed;
      let target = grp.name;
      let noResolve = false;

      if (firstComma > 0) {
        rType = trimmed.slice(0, firstComma).trim().toUpperCase();
        if (LOGICAL_PAREN_RULE_TYPES.has(rType)) {
          const logical = parseLogicalRuleParts(trimmed);
          if (logical) {
            val = logical.expr;
            if (rType !== "SUB-RULE" && logical.target) {
              target = logical.target;
            } else if (rType === "SUB-RULE" && logical.target) {
              val = `${logical.expr},${logical.target}`;
            }
          } else {
            val = trimmed.slice(firstComma + 1).trim() || trimmed;
          }
        } else if (REGEX_RULE_TYPES.has(rType)) {
          let rest = trimmed.slice(firstComma + 1).trim();
          while (true) {
            const lastComma = rest.lastIndexOf(",");
            if (lastComma <= 0) break;
            const tailToken = rest.slice(lastComma + 1).trim();
            if (isRuleFlagToken(tailToken)) {
              if (tailToken.toLowerCase() === "no-resolve") noResolve = true;
              rest = rest.slice(0, lastComma).trim();
              continue;
            }
            if (isKnownExplicitTarget(tailToken)) {
              target = tailToken;
              rest = rest.slice(0, lastComma).trim();
            }
            break;
          }
          val = rest || trimmed;
        } else {
          const parts = trimmed.split(",").map((s) => s.trim());
          let endIdx = parts.length;
          while (endIdx > 2 && isRuleFlagToken(parts[endIdx - 1])) {
            if (parts[endIdx - 1].toLowerCase() === "no-resolve") noResolve = true;
            endIdx -= 1;
          }
          if (endIdx >= 3) {
            target = parts[endIdx - 1] || grp.name;
            val = parts.slice(1, endIdx - 1).join(",").trim() || trimmed;
          } else if (endIdx === 2) {
            val = parts[1] || trimmed;
          }
        }
      }

      list.push({
        id: `grp-${grp.id}-${idx}`,
        layer: "group",
        ruleType: rType,
        value: val,
        target,
        noResolve,
        rawLine: trimmed,
        groupId: grp.id,
      });
    });
  }
  return list;
}

export function formatRuleTargetLabel(target: string): string {
  if (target === "DIRECT") return "直接连接";
  if (target === "REJECT") return "拦截阻止";
  return target;
}

export function formatConnectionRuleLabel(
  rawRule: string,
  isInnerTunnel = false,
  preaccelEnabled = false
): string {
  if (isInnerTunnel) {
    return preaccelEnabled ? "国内提速拨号" : "内核内部连接";
  }
  const trimmed = rawRule.trim();
  if (trimmed === "国内提速拨号" || trimmed === "内核内部连接") return trimmed;
  if (!trimmed) return "默认走代理";
  const commaIdx = trimmed.indexOf(",");
  const rawType = (commaIdx >= 0 ? trimmed.slice(0, commaIdx) : trimmed).trim();
  const payload = commaIdx >= 0 ? trimmed.slice(commaIdx + 1).trim() : "";
  const normalized = rawType.toUpperCase().replace(/[-_\s]/g, "");

  if (normalized === "MATCH" || normalized === "FINAL") {
    if (payload.toUpperCase() === "DIRECT") return "默认直接连接";
    if (payload.toUpperCase() === "REJECT") return "默认拦截阻止";
    return "默认走代理";
  }
  if (normalized === "DOMAINSUFFIX") {
    return payload ? `按域名匹配：${payload}` : "按域名匹配";
  }
  if (normalized === "DOMAIN") {
    return payload ? `完整域名：${payload}` : "完整域名";
  }
  if (normalized === "DOMAINKEYWORD") {
    return payload ? `域名关键词：${payload}` : "域名关键词";
  }
  if (normalized === "IPCIDR" || normalized === "IPCIDR6") {
    return payload ? `IP 网段：${payload}` : "IP 网段";
  }
  if (normalized === "PROCESSNAME") {
    return payload ? `按软件匹配：${payload}` : "按软件匹配";
  }
  if (normalized === "PROCESSPATH") {
    return payload ? `按路径匹配：${payload}` : "按路径匹配";
  }
  if (normalized === "PROCESSNAMEREGEX") {
    return payload ? `进程正则：${payload}` : "进程正则";
  }
  if (normalized === "PROCESSPATHREGEX") {
    return payload ? `路径正则：${payload}` : "路径正则";
  }
  if (normalized === "DOMAINREGEX") {
    return payload ? `域名正则：${payload}` : "域名正则";
  }
  if (normalized === "DOMAINWILDCARD") {
    return payload ? `域名通配：${payload}` : "域名通配";
  }
  if (normalized === "AND") {
    return payload ? `复合与：${payload}` : "复合与";
  }
  if (normalized === "OR") {
    return payload ? `复合或：${payload}` : "复合或";
  }
  if (normalized === "NOT") {
    return payload ? `复合非：${payload}` : "复合非";
  }
  if (normalized === "SUBRULE") {
    return payload ? `子规则：${payload}` : "子规则";
  }
  if (normalized === "GEOSITE") {
    const label = payload.toLowerCase() === "cn" ? "国内常用网站" : payload;
    return label ? `网站集合：${label}` : "网站集合";
  }
  if (normalized === "GEOIP") {
    const label = payload.toUpperCase() === "CN" ? "中国大陆" : payload;
    return label ? `地区 IP：${label}` : "地区 IP";
  }
  if (normalized === "RULESET") {
    return payload ? `规则集合：${payload}` : "规则集合";
  }
  if (normalized === "DSTPORT") {
    return payload ? `目标端口：${payload}` : "目标端口";
  }
  if (normalized === "SRCIPCIDR") {
    return payload ? `来源网段：${payload}` : "来源网段";
  }
  return payload ? `${rawType}：${payload}` : rawType;
}

export function matchesPreAccelChain(chains: string[], relays: PreAccelRelay[]): boolean {
  const relayNames = new Set(
    relays.map((r) => r.name.trim().toLowerCase()).filter((name) => name.length > 0)
  );
  return chains.some((c) => {
    const trimmed = c.trim();
    if (!trimmed) return false;
    const lower = trimmed.toLowerCase();
    return (
      lower.includes("preaccel") ||
      trimmed.includes("预加速") ||
      trimmed.includes("国内预加速入口") ||
      relayNames.has(lower)
    );
  });
}

export function mapDtoConnection(
  dto: ActiveConnectionDto,
  groups: MultiGroup[],
  relays: PreAccelRelay[],
  preaccelEnabled = false
): LiveConnection {
  const chains = Array.isArray(dto.chains) ? dto.chains : [];
  const matchedGroup = groups.find((g) => chains.includes(g.name) || chains.includes(g.id));
  const groupName = matchedGroup?.name ?? chains[chains.length - 1] ?? "DIRECT";
  const groupId = matchedGroup?.id ?? groupName;
  const nodeName = chains[0] ?? groupName;
  const viaPreAccel = matchesPreAccelChain(chains, relays);
  const parsedStart = Date.parse(dto.start);
  const connTypeLower = (dto.conn_type || "").trim().toLowerCase();
  const isInnerTunnel = connTypeLower === "inner";
  const isPreAccelInner = isInnerTunnel && (preaccelEnabled || viaPreAccel);
  const rawHost = (dto.host || "").trim();
  const rawHostLower = rawHost.toLowerCase();
  const rawDstIp = (dto.destination_ip || "").trim();
  const isLoopback =
    rawHostLower === "127.0.0.1" ||
    rawHostLower === "localhost" ||
    rawHostLower === "::1" ||
    rawDstIp.startsWith("127.") ||
    rawDstIp === "::1";

  return {
    id: dto.id,
    process: isInnerTunnel
      ? isPreAccelInner
        ? "底层提速隧道 (Inner)"
        : "内核内部连接 (Inner)"
      : dto.process || dto.conn_type || "unknown",
    host: rawHost || rawDstIp || "--",
    dstIp: rawDstIp || "--",
    port: Number(dto.destination_port) || 0,
    network: dto.network.toLowerCase() === "udp" ? "udp" : "tcp",
    rule: isInnerTunnel
      ? isPreAccelInner
        ? "国内提速拨号"
        : "内核内部连接"
      : dto.rule_payload
        ? `${dto.rule},${dto.rule_payload}`
        : dto.rule || "MATCH",
    chains,
    groupId,
    groupName,
    nodeName,
    viaPreAccel,
    isInnerTunnel,
    isLoopback,
    uploadBytes: dto.upload ?? 0,
    downloadBytes: dto.download ?? 0,
    upBps: 0,
    downBps: 0,
    startedAtMs: Number.isFinite(parsedStart) ? parsedStart : Date.now(),
  };
}

export function computeConnectionBreakdown(connections: LiveConnection[]): ConnectionBreakdown {
  let innerTunnelCount = 0;
  let loopbackCount = 0;
  for (const c of connections) {
    if (c.isInnerTunnel) {
      innerTunnelCount += 1;
    } else if (c.isLoopback) {
      loopbackCount += 1;
    }
  }
  return {
    appCount: connections.length - innerTunnelCount,
    innerTunnelCount,
    loopbackCount,
  };
}

export function parseCompiledPreviewMeta(preview: CompiledYamlPreview): ParsedCompiledMeta {
  const stats = preview.stats ?? {};
  const toOptNum = (v: unknown): number | null =>
    typeof v === "number" && Number.isFinite(v) ? v : null;

  const totalRules = toOptNum(stats.total_rules);
  const totalProxies = toOptNum(stats.total_proxies);
  const proxyGroups = toOptNum(stats.proxy_groups);

  const validation = preview.validation ?? {};
  const rawIssues = Array.isArray(validation.issues) ? validation.issues : [];
  const errors: ParsedValidationIssue[] = [];
  const warnings: ParsedValidationIssue[] = [];

  for (const item of rawIssues) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const severity = rec.severity === "error" ? "error" : "warning";
    const parsed: ParsedValidationIssue = {
      code: typeof rec.code === "string" ? rec.code : "",
      severity,
      message: typeof rec.message === "string" ? rec.message : JSON.stringify(item),
    };
    if (severity === "error") {
      errors.push(parsed);
    } else {
      warnings.push(parsed);
    }
  }

  const validationOk =
    typeof validation.ok === "boolean" ? validation.ok : errors.length === 0;

  return {
    totalRules,
    totalProxies,
    proxyGroups,
    validationOk,
    errors,
    warnings,
  };
}

export function formatDuration(startedAtMs: number, nowMs: number): string {
  const sec = Math.max(0, Math.floor((nowMs - startedAtMs) / 1000));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}
