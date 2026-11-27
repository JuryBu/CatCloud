/**
 * Browser-preview-only mock helpers for Gateway YAML export, bulk rule parsing,
 * and inline override YAML validation.
 *
 * Dynamically imported by `tauri.ts` ONLY when `!isTauriEnv()`, keeping desktop
 * production main-bundle size lean.
 */

import type {
  AppConfig,
  BulkRulesParseResult,
  FullAppConfig,
  GatewayExportOptions,
  GatewayExportOutput,
  MultiGroup,
  PreAccelRelay,
  ProxyNode,
} from "./tauri";

const KNOWN_MIHOMO_RULE_TYPES = new Set([
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
  "SRC-GEOIP",
  "SRC-IP-CIDR",
  "SRC-IP-SUFFIX",
  "SRC-IP-ASN",
  "DST-PORT",
  "SRC-PORT",
  "IN-PORT",
  "IN-TYPE",
  "IN-USER",
  "IN-NAME",
  "PROCESS-PATH",
  "PROCESS-PATH-REGEX",
  "PROCESS-NAME",
  "PROCESS-NAME-REGEX",
  "UID",
  "NETWORK",
  "DSCP",
  "RULE-SET",
  "AND",
  "OR",
  "NOT",
  "SUB-RULE",
  "MATCH",
  "FINAL",
]);

const LOGICAL_PAREN_RULE_TYPES = new Set(["AND", "OR", "NOT", "SUB-RULE"]);

function splitTopLevelRuleParts(line: string): string[] | null {
  const firstComma = line.indexOf(",");
  if (firstComma < 0) return null;
  const ruleType = line.slice(0, firstComma).trim().toUpperCase();
  if (!ruleType) return null;

  if (LOGICAL_PAREN_RULE_TYPES.has(ruleType)) {
    const parts: string[] = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === "(") {
        depth += 1;
      } else if (ch === ")") {
        depth -= 1;
        if (depth < 0) return null;
      } else if (ch === "," && depth === 0) {
        parts.push(line.slice(start, i).trim());
        start = i + 1;
      }
    }
    if (depth !== 0) return null;
    parts.push(line.slice(start).trim());
    return parts;
  }

  return line.split(",").map((s) => s.trim());
}

function stripInlineRuleComment(line: string): string {
  const firstComma = line.indexOf(",");
  const ruleType = firstComma > 0 ? line.slice(0, firstComma).trim().toUpperCase() : "";
  const trackParens = LOGICAL_PAREN_RULE_TYPES.has(ruleType);
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (!inSingle && !inDouble) {
      if (trackParens && ch === "(") depth += 1;
      else if (trackParens && ch === ")" && depth > 0) depth -= 1;
      else if (ch === "#" && depth === 0 && (i === 0 || /\s/.test(line[i - 1]))) {
        return line.slice(0, i).trim();
      }
    }
  }
  return line.trim();
}

export function parseBulkRulesTextFallback(rawText: string): BulkRulesParseResult {
  const valid_rules: string[] = [];
  const skipped_lines: string[] = [];
  const seen = new Set<string>();

  for (const rawLine of rawText.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed === "---" || trimmed === "...") {
      continue;
    }
    if (/^rules\s*:$/i.test(trimmed)) {
      continue;
    }
    let candidate = trimmed.replace(/^-\s+/, "").trim();
    candidate = stripInlineRuleComment(candidate);
    if (
      (candidate.startsWith("'") && candidate.endsWith("'") && candidate.length >= 2) ||
      (candidate.startsWith('"') && candidate.endsWith('"') && candidate.length >= 2)
    ) {
      candidate = candidate.slice(1, -1).trim();
    }
    if (!candidate) continue;

    const parts = splitTopLevelRuleParts(candidate);
    if (!parts || parts.length < 2) {
      skipped_lines.push(trimmed);
      continue;
    }
    const ruleType = parts[0].toUpperCase();
    if (!KNOWN_MIHOMO_RULE_TYPES.has(ruleType)) {
      skipped_lines.push(trimmed);
      continue;
    }
    if (ruleType === "MATCH" || ruleType === "FINAL") {
      const target = parts[1];
      if (!target) {
        skipped_lines.push(trimmed);
        continue;
      }
      const normalized = `${ruleType},${target}`;
      if (!seen.has(normalized)) {
        seen.add(normalized);
        valid_rules.push(normalized);
      }
      continue;
    }
    if (parts.length < 3 || !parts[1] || !parts[2]) {
      skipped_lines.push(trimmed);
      continue;
    }
    const normalized = [ruleType, ...parts.slice(1)].join(",");
    if (!seen.has(normalized)) {
      seen.add(normalized);
      valid_rules.push(normalized);
    }
  }

  return { valid_rules, skipped_lines };
}

export function validateInlineOverrideYamlMock(raw: string): string | null {
  const lines = raw.split(/\r?\n/);
  let hasRootKey = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    if (/^\t/.test(line)) {
      return `第 ${lineNo} 行使用了 Tab 缩进，YAML 仅支持空格缩进`;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed === "---" || trimmed === "...") {
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      if (trimmed.startsWith("- ") || trimmed === "-") {
        if (!hasRootKey) {
          return `第 ${lineNo} 行顶层必须是 YAML 键值映射（例如 rule-providers: / rules: / dns:），不能直接以列表开头`;
        }
        continue;
      }
      if (
        /^(?:[A-Za-z0-9_.-]+|"[^"\r\n]+"|'[^'\r\n]+')\s*:/.test(trimmed) ||
        trimmed.startsWith("{")
      ) {
        hasRootKey = true;
        continue;
      }
      if (!hasRootKey) {
        return `第 ${lineNo} 行格式无效：顶层键必须以「键名:」开头`;
      }
    }
  }
  if (!hasRootKey) {
    return "未检测到有效的 YAML 顶层配置段（例如 rule-providers:、rules:、dns:）";
  }
  return null;
}

export interface MockGatewayExportContext {
  relays: PreAccelRelay[];
  nodes: ProxyNode[];
  groups: MultiGroup[];
  config: AppConfig;
  fullConfig: FullAppConfig;
}

function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export function buildMockGatewayExportOutput(
  options: GatewayExportOptions,
  ctx: MockGatewayExportContext
): GatewayExportOutput {
  if (options.profile === "transparent_gateway") {
    if (
      !isValidPort(options.tproxy_port) ||
      !isValidPort(options.redir_port) ||
      !isValidPort(options.dns_listen_port)
    ) {
      throw new Error("监听端口必须为 1–65535 之间的有效整数");
    }
    if (
      options.tproxy_port === options.redir_port ||
      options.tproxy_port === options.dns_listen_port ||
      options.redir_port === options.dns_listen_port
    ) {
      throw new Error("TProxy、Redir 与 DNS 监听端口不能冲突");
    }
  }

  const enabledRelays = ctx.relays
    .filter((r) => r.enabled)
    .sort((a, b) => a.priority - b.priority);
  const enabledNodes = ctx.nodes.filter((n) => n.enabled);
  const redact = options.redact_secrets;
  const warnings: string[] = [];

  if (enabledRelays.length === 0) {
    warnings.push("当前没有启用的国内中转线路，导出的中转组将仅保留 DIRECT 回落。");
  }
  if (redact) {
    warnings.push(
      "当前为脱敏预览模式，中转与节点的服务器地址和密码已隐藏；部署到软路由前请切换为「含真实连接凭据」。"
    );
  }

  const maskServer = (server: string) => {
    if (!redact) return server;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(server)) {
      const segs = server.split(".");
      return `${segs[0]}.${segs[1]}.${segs[2]}.***`;
    }
    return "***REDACTED***";
  };

  const relayYamlLines = enabledRelays.flatMap((r) => [
    `  - name: "${r.name}"`,
    `    type: ${r.protocol}`,
    `    server: ${maskServer(r.server)}`,
    `    port: ${r.port}`,
    `    password: "${redact ? "***REDACTED***" : "<DEMO_RELAY_SECRET>"}"`,
    `    tfo: false`,
    ...(r.protocol === "anytls"
      ? [
          `    min-idle-session: 0`,
          `    idle-session-check-interval: 30`,
          `    idle-session-timeout: 30`,
        ]
      : []),
    `    skip-cert-verify: ${r.skip_cert_verify ? "true" : "false"}`,
    `    udp: true`,
  ]);

  const relayNames = enabledRelays.map((r) => r.name);
  const relayAntiLoopRules = enabledRelays.map(
    (r) => `  - IP-CIDR,${maskServer(r.server)}/32,DIRECT,no-resolve`
  );

  const UDP_ONLY_PROTOCOLS = new Set(["hysteria2", "hy2", "hysteria", "tuic", "wireguard"]);
  const buildNodeProxyLines = (list: ProxyNode[]) =>
    list.flatMap((n) => {
      const proto = n.protocol.trim().toLowerCase();
      const isTcpProxy = !UDP_ONLY_PROTOCOLS.has(proto);
      return [
        `  - name: "${n.name}"`,
        `    type: ${n.protocol}`,
        `    server: ${maskServer(n.server)}`,
        `    port: ${n.port}`,
        ...(n.protocol === "vless"
          ? [`    uuid: "${redact ? "***REDACTED***" : "00000000-0000-4000-8000-000000000000"}"`]
          : [`    password: "${redact ? "***REDACTED***" : "<DEMO_NODE_SECRET>"}"`]),
        ...(isTcpProxy ? [`    tfo: false`] : []),
        ...(proto === "anytls"
          ? [
              `    min-idle-session: 0`,
              `    idle-session-check-interval: 30`,
              `    idle-session-timeout: 30`,
            ]
          : []),
        `    udp: true`,
        ...(!n.is_443_native && isTcpProxy && enabledRelays.length > 0
          ? [`    dialer-proxy: "⚡ 国内预加速入口"`]
          : []),
      ];
    });

  if (options.profile === "relay_fragment") {
    const lines = [
      "# ============================================================================",
      "# CatCloud 软路由 / 透明网关导出：仅国内中转与防环片段",
      "# 零改动你现有透明网关规则，粘贴并给需要提速的节点加 dialer-proxy 即可",
      "# ============================================================================",
      "",
      "proxies:",
      ...(relayYamlLines.length > 0 ? relayYamlLines : ["  # 暂无已启用的国内中转线路"]),
      "",
      "proxy-groups:",
      `  - name: "⚡ 国内预加速入口"`,
      `    type: ${relayNames.length >= 2 ? "load-balance" : "fallback"}`,
      ...(relayNames.length >= 2 ? [`    strategy: consistent-hashing`] : []),
      `    url: "${ctx.config.preaccel.probe_url}"`,
      `    interval: 30`,
      `    expected-status: "204"`,
      `    proxies:`,
      ...(relayNames.length > 0
        ? relayNames.map((name) => `      - "${name}"`)
        : [`      - DIRECT`]),
      "",
      "rules:",
      "  # 防环规则（请放在现有透明网关 rules 最顶部）",
      ...relayAntiLoopRules,
      "",
      "# 使用方式：给你现有配置里需要国内 443 提速的海外节点追加一行：",
      '#   dialer-proxy: "⚡ 国内预加速入口"',
    ];
    return {
      profile: options.profile,
      yaml: lines.join("\n"),
      redacted: redact,
      relay_count: enabledRelays.length,
      node_count: 0,
      rule_count: relayAntiLoopRules.length,
      warnings,
      integration_hint:
        '把 proxies、proxy-groups 合并进你现有的 Mihomo / OpenClash 配置，并将 rules 中的中转防环规则放到最前面，再给需要提速的海外节点加上 dialer-proxy: "⚡ 国内预加速入口" 即可，完全无需改动你现有的分流规则。',
    };
  }

  if (options.profile === "preferred_nodes") {
    const preferred = enabledNodes.slice(0, 6);
    const lines = [
      "# ============================================================================",
      "# CatCloud 软路由 / 透明网关导出：优选节点 + 国内中转片段",
      "# 已自动为非 443 海外节点挂载 dialer-proxy，保留你的透明网关规则不变",
      "# ============================================================================",
      "",
      "proxies:",
      ...relayYamlLines,
      ...buildNodeProxyLines(preferred),
      "",
      "proxy-groups:",
      `  - name: "⚡ 国内预加速入口"`,
      `    type: ${relayNames.length >= 2 ? "load-balance" : "fallback"}`,
      ...(relayNames.length >= 2 ? [`    strategy: consistent-hashing`] : []),
      `    url: "${ctx.config.preaccel.probe_url}"`,
      `    interval: 30`,
      `    expected-status: "204"`,
      `    proxies:`,
      ...(relayNames.length > 0
        ? relayNames.map((name) => `      - "${name}"`)
        : [`      - DIRECT`]),
      `  - name: "🌟 优选节点"`,
      `    type: select`,
      `    proxies:`,
      ...preferred.map((n) => `      - "${n.name}"`),
      "",
      "rules:",
      "  # 中转服务器直连防环规则（请置于 rules 顶部）",
      ...relayAntiLoopRules,
    ];
    return {
      profile: options.profile,
      yaml: lines.join("\n"),
      redacted: redact,
      relay_count: enabledRelays.length,
      node_count: preferred.length,
      rule_count: relayAntiLoopRules.length,
      warnings,
      integration_hint:
        "包含实测优选节点与国内中转链路（已自动为非 443 节点挂好 dialer-proxy），直接合并到你软路由配置中并把分流目标指向「🌟 优选节点」即可。",
    };
  }

  // transparent_gateway
  const customOnly = Boolean(ctx.fullConfig.rules_override?.custom_rules_only);
  const prependRules = ctx.fullConfig.rules_override?.global_prepend_rules ?? [];
  const appendRules = ctx.fullConfig.rules_override?.global_append_rules ?? [];
  const primaryGroupName = ctx.groups[0]?.name || "猫云主代理组";
  const fallbackDomesticDirectRules = [
    "  - DOMAIN-SUFFIX,cn,DIRECT",
    "  - DOMAIN-SUFFIX,qq.com,DIRECT",
    "  - DOMAIN-SUFFIX,qpic.cn,DIRECT",
    "  - DOMAIN-SUFFIX,qlogo.cn,DIRECT",
    "  - DOMAIN-SUFFIX,gtimg.cn,DIRECT",
    "  - DOMAIN-SUFFIX,gtimg.com,DIRECT",
    "  - DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
    "  - DOMAIN-SUFFIX,wechat.com,DIRECT",
    "  - DOMAIN-SUFFIX,qcloud.com,DIRECT",
    "  - DOMAIN-SUFFIX,myqcloud.com,DIRECT",
    "  - DOMAIN-SUFFIX,tencent.com,DIRECT",
    "  - DOMAIN-SUFFIX,aliyun.com,DIRECT",
    "  - DOMAIN-SUFFIX,baidu.com,DIRECT",
    "  - DOMAIN-SUFFIX,bilibili.com,DIRECT",
    "  - DOMAIN-SUFFIX,taobao.com,DIRECT",
    "  - DOMAIN-SUFFIX,jd.com,DIRECT",
    "  - DOMAIN-SUFFIX,163.com,DIRECT",
  ];
  const baseRules = [
    ...relayAntiLoopRules,
    "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    ...prependRules.map((r) => `  - ${r}`),
    ...(customOnly ? [] : fallbackDomesticDirectRules),
    ...appendRules.map((r) => `  - ${r}`),
    `  - MATCH,${primaryGroupName}`,
  ];
  const inlineOverride = (ctx.fullConfig.rules_override?.inline_override_yaml ?? "").trim();

  const lines = [
    "# ============================================================================",
    "# CatCloud 完整透明网关配置（适配 OpenWrt / Linux 旁路由 TProxy）",
    "# 已自动关闭桌面 TUN，启用局域网监听、TProxy/Redir 透明转发与 DNS 服务",
    "# ============================================================================",
    `tproxy-port: ${options.tproxy_port}`,
    `redir-port: ${options.redir_port}`,
    `mixed-port: ${ctx.config.mixed_port}`,
    `allow-lan: true`,
    `bind-address: "*"`,
    `mode: ${ctx.config.proxy_mode}`,
    `log-level: info`,
    `unified-delay: true`,
    `keep-alive-idle: 45`,
    `keep-alive-interval: 15`,
    "",
    "tun:",
    "  enable: false",
    "",
    "dns:",
    "  enable: true",
    `  listen: 0.0.0.0:${options.dns_listen_port}`,
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "",
    "proxies:",
    ...relayYamlLines,
    ...buildNodeProxyLines(enabledNodes),
    "",
    "proxy-groups:",
    ...(enabledRelays.length > 0
      ? [
          `  - name: "⚡ 国内预加速入口"`,
          `    type: ${relayNames.length >= 2 ? "load-balance" : "fallback"}`,
          ...(relayNames.length >= 2 ? [`    strategy: consistent-hashing`] : []),
          `    url: "${ctx.config.preaccel.probe_url}"`,
          `    interval: 30`,
          `    expected-status: "204"`,
          `    proxies:`,
          ...relayNames.map((name) => `      - "${name}"`),
        ]
      : []),
    `  - name: "${primaryGroupName}"`,
    `    type: select`,
    `    proxies:`,
    ...(enabledNodes.length > 0
      ? enabledNodes.map((n) => `      - "${n.name}"`)
      : [`      - DIRECT`]),
    "",
    "rules:",
    ...baseRules,
    ...(inlineOverride
      ? ["", "# --- 内联 YAML 覆写片段（浏览器预览展示） ---", inlineOverride]
      : []),
  ];

  return {
    profile: options.profile,
    yaml: lines.join("\n"),
    redacted: redact,
    relay_count: enabledRelays.length,
    node_count: enabledNodes.length,
    rule_count: baseRules.length,
    warnings,
    integration_hint: `适用于 OpenWrt（OpenClash / Nikki / HomeProxy）或 Linux 旁路由 Mihomo：已自动设置 tun.enable: false、allow-lan: true，并开启 TProxy (${options.tproxy_port}) / Redir (${options.redir_port}) / DNS (${options.dns_listen_port}) 监听。`,
  };
}
