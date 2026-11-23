import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Code2,
  Copy,
  Eye,
  Filter,
  Layers,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type ActiveConnectionDto,
  type CompiledYamlPreview,
  type MultiGroup,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { AppSelect, type AppSelectOption } from "../components/AppSelect";
import { formatBytes, formatRate } from "../components/TrafficSparkline";
import { appActions, useAppSelector } from "../store/appStore";

type ActiveTab = "rules" | "connections";
type RuleLayer = "prepend" | "group" | "append";
type RuleMatchType =
  | "DOMAIN-SUFFIX"
  | "DOMAIN"
  | "DOMAIN-KEYWORD"
  | "IP-CIDR"
  | "PROCESS-NAME"
  | "GEOSITE"
  | "GEOIP";

interface ManagedRuleItem {
  id: string;
  layer: RuleLayer;
  ruleType: RuleMatchType | string;
  value: string;
  target: string;
  noResolve?: boolean;
  groupId?: string;
}

interface AiPresetBundle {
  id: string;
  name: string;
  desc: string;
  domains: string[];
  targetGroup: string;
  enabled: boolean;
}

interface LiveConnection {
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

interface ConnTrafficSnap {
  uploadBytes: number;
  downloadBytes: number;
  atMs: number;
}

interface ParsedValidationIssue {
  code: string;
  severity: "error" | "warning";
  message: string;
}

interface ParsedCompiledMeta {
  totalRules: number | null;
  totalProxies: number | null;
  proxyGroups: number | null;
  validationOk: boolean;
  errors: ParsedValidationIssue[];
  warnings: ParsedValidationIssue[];
}

const CONNECTIONS_PAGE_SIZE = 30;

const RULE_TYPE_LABELS: Record<RuleMatchType, string> = {
  "DOMAIN-SUFFIX": "域名后缀",
  DOMAIN: "完整域名",
  "DOMAIN-KEYWORD": "域名关键词",
  "IP-CIDR": "IP 网段",
  "PROCESS-NAME": "软件进程",
  GEOSITE: "网站集合",
  GEOIP: "地区 IP",
};

const AI_PRESETS_TEMPLATE: ReadonlyArray<Omit<AiPresetBundle, "targetGroup" | "enabled">> = [
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
      "windsurf.com",
      "devin.ai",
      "cognition.ai",
      "exafunction.com",
    ],
  },
];

function serializeRuleItem(r: ManagedRuleItem): string {
  const typeUpper = r.ruleType.trim().toUpperCase();
  const value = r.value.trim();
  const target = r.target.trim();
  if (typeUpper === "MATCH") {
    return `MATCH,${target}`;
  }
  return `${typeUpper},${value},${target}${r.noResolve ? ",no-resolve" : ""}`;
}

function parseRuleString(
  raw: string,
  layer: "prepend" | "append",
  id: string
): ManagedRuleItem | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const parts = trimmed.split(",").map((p) => p.trim());
  if (parts.length < 2) return null;
  const ruleType = parts[0].toUpperCase();
  if (ruleType === "MATCH") {
    return {
      id,
      layer,
      ruleType,
      value: "*",
      target: parts[1] || "DIRECT",
    };
  }
  if (parts.length < 3) return null;
  const value = parts[1];
  const target = parts[2];
  if (!value || !target) return null;
  const noResolve = parts.slice(3).some((p) => p.toLowerCase() === "no-resolve");
  return {
    id,
    layer,
    ruleType,
    value,
    target,
    noResolve,
  };
}

function hydrateRulesFromConfig(
  prependLines: string[],
  appendLines: string[],
  fallbackTarget: string
): { presets: AiPresetBundle[]; userRules: ManagedRuleItem[] } {
  const consumedPrepend = new Set<number>();

  const presets: AiPresetBundle[] = AI_PRESETS_TEMPLATE.map((tpl) => {
    const domainSet = new Set(tpl.domains.map((d) => d.toLowerCase()));
    let matchedTarget: string | null = null;
    const matchedIndices: number[] = [];

    prependLines.forEach((raw, idx) => {
      const parts = raw.split(",").map((p) => p.trim());
      if (parts.length < 3) return;
      if (parts[0].toUpperCase() !== "DOMAIN-SUFFIX") return;
      if (!domainSet.has(parts[1].toLowerCase())) return;
      if (matchedTarget === null) {
        matchedTarget = parts[2];
      }
      if (parts[2] === matchedTarget) {
        matchedIndices.push(idx);
      }
    });

    if (matchedTarget !== null && matchedIndices.length > 0) {
      for (const idx of matchedIndices) consumedPrepend.add(idx);
      return {
        ...tpl,
        targetGroup: matchedTarget,
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
    const parsed = parseRuleString(raw, "prepend", `rule-pre-${idx}-${raw}`);
    if (parsed) userRules.push(parsed);
  });
  appendLines.forEach((raw, idx) => {
    const parsed = parseRuleString(raw, "append", `rule-app-${idx}-${raw}`);
    if (parsed) userRules.push(parsed);
  });

  return { presets, userRules };
}

function buildRulesOverridePayload(
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

function formatRuleTargetLabel(target: string): string {
  if (target === "DIRECT") return "直接连接";
  if (target === "REJECT") return "拦截阻止";
  return target;
}

function formatConnectionRuleLabel(
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

function matchesPreAccelChain(chains: string[], relays: PreAccelRelay[]): boolean {
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

function buildPreviewConnections(preaccelEnabled = true): LiveConnection[] {
  const now = Date.now();
  return [
    {
      id: "conn-101",
      process: "Antigravity.exe",
      host: "generativelanguage.googleapis.com",
      dstIp: "203.0.113.14",
      port: 443,
      network: "tcp",
      rule: "DOMAIN-SUFFIX,googleapis.com",
      chains: ["JP-Tokyo-01 · 1x", "AI 专线粘性组"],
      groupId: "grp-ai",
      groupName: "AI 专线粘性组",
      nodeName: "JP-Tokyo-01 · 1x",
      viaPreAccel: false,
      isInnerTunnel: false,
      isLoopback: false,
      uploadBytes: 18_420_000,
      downloadBytes: 94_180_000,
      upBps: 5_800,
      downBps: 46_400,
      startedAtMs: now - 420_000,
    },
    {
      id: "conn-102",
      process: "Code.exe",
      host: "server.codeium.com",
      dstIp: "203.0.113.28",
      port: 443,
      network: "tcp",
      rule: "DOMAIN-SUFFIX,codeium.com",
      chains: ["JP-Tokyo-01 · 1x", "AI 专线粘性组"],
      groupId: "grp-ai",
      groupName: "AI 专线粘性组",
      nodeName: "JP-Tokyo-01 · 1x",
      viaPreAccel: false,
      isInnerTunnel: false,
      isLoopback: false,
      uploadBytes: 6_240_000,
      downloadBytes: 24_860_000,
      upBps: 11_600,
      downBps: 69_600,
      startedAtMs: now - 310_000,
    },
    {
      id: "conn-104",
      process: "chrome.exe",
      host: "www.youtube.com",
      dstIp: "203.0.113.52",
      port: 443,
      network: "udp",
      rule: "DOMAIN-SUFFIX,youtube.com",
      chains: ["SG-Edge-02 · 1x", "⚡ 国内预加速入口", "流媒体与下载受控均衡"],
      groupId: "grp-media",
      groupName: "流媒体与下载受控均衡",
      nodeName: "SG-Edge-02 · 1x",
      viaPreAccel: true,
      isInnerTunnel: false,
      isLoopback: false,
      uploadBytes: 2_890_000,
      downloadBytes: 286_400_000,
      upBps: 17_400,
      downBps: 92_800,
      startedAtMs: now - 690_000,
    },
    {
      id: "conn-105-loopback",
      process: "CatCloud.exe",
      host: "127.0.0.1",
      dstIp: "127.0.0.1",
      port: 19090,
      network: "tcp",
      rule: "IP-CIDR,127.0.0.0/8",
      chains: ["DIRECT"],
      groupId: "DIRECT",
      groupName: "DIRECT",
      nodeName: "DIRECT",
      viaPreAccel: false,
      isInnerTunnel: false,
      isLoopback: true,
      uploadBytes: 420_000,
      downloadBytes: 1_280_000,
      upBps: 640,
      downBps: 1_920,
      startedAtMs: now - 820_000,
    },
    {
      id: "conn-106-inner",
      process: preaccelEnabled ? "底层提速隧道 (Inner)" : "内核内部连接 (Inner)",
      host: preaccelEnabled ? "198.51.100.10" : "223.5.5.5",
      dstIp: preaccelEnabled ? "198.51.100.10" : "223.5.5.5",
      port: 443,
      network: "tcp",
      rule: preaccelEnabled ? "国内提速拨号" : "内核内部连接",
      chains: preaccelEnabled ? ["CN-East-443 Primary", "⚡ 国内预加速入口"] : ["DIRECT"],
      groupId: preaccelEnabled ? "⚡ 国内预加速入口" : "DIRECT",
      groupName: preaccelEnabled ? "⚡ 国内预加速入口" : "DIRECT",
      nodeName: preaccelEnabled ? "CN-East-443 Primary" : "DIRECT",
      viaPreAccel: preaccelEnabled,
      isInnerTunnel: true,
      isLoopback: false,
      uploadBytes: 2_890_000,
      downloadBytes: 286_400_000,
      upBps: 17_400,
      downBps: 92_800,
      startedAtMs: now - 690_000,
    },
  ];
}

function mapDtoConnection(
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

function parseCompiledPreviewMeta(preview: CompiledYamlPreview): ParsedCompiledMeta {
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

function formatDuration(startedAtMs: number, nowMs: number): string {
  const sec = Math.max(0, Math.floor((nowMs - startedAtMs) / 1000));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function RulesConnsPage() {
  const groups = useAppSelector((s) => s.groups);
  const preAccelRelays = useAppSelector((s) => s.preAccelRelays);
  const runtime = useAppSelector((s) => s.runtime);
  const preAccelEnabled = useAppSelector(
    (s) => s.runtime.preaccel_active || s.config.preaccel.enabled
  );
  const inTauri = isTauriEnv();

  const defaultGroupTarget = groups[0]?.name || "DIRECT";

  const [activeTab, setActiveTab] = useState<ActiveTab>("rules");

  // --- Tab A: Rules State (hydrated from catcloudApi.getFullConfig) ---
  const [aiPresets, setAiPresets] = useState<AiPresetBundle[]>(() =>
    AI_PRESETS_TEMPLATE.map((tpl) => ({
      ...tpl,
      targetGroup: defaultGroupTarget,
      enabled: false,
    }))
  );
  const [userRules, setUserRules] = useState<ManagedRuleItem[]>([]);
  const [loadingRules, setLoadingRules] = useState<boolean>(true);
  const [savingRules, setSavingRules] = useState<boolean>(false);
  const [ruleSearch, setRuleSearch] = useState<string>("");
  const [ruleLayerFilter, setRuleLayerFilter] = useState<"all" | RuleLayer>("all");
  const [showYamlPreview, setShowYamlPreview] = useState<boolean>(false);
  const [compiledPreview, setCompiledPreview] = useState<CompiledYamlPreview | null>(null);
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  // New rule composer state
  const [newLayer, setNewLayer] = useState<"prepend" | "append">("prepend");
  const [newType, setNewType] = useState<RuleMatchType>("DOMAIN-SUFFIX");
  const [newValue, setNewValue] = useState<string>("");
  const [newTarget, setNewTarget] = useState<string>(defaultGroupTarget);
  const [newNoResolve, setNewNoResolve] = useState<boolean>(false);

  // --- Tab B: Connections State ---
  const [connections, setConnections] = useState<LiveConnection[]>(() =>
    inTauri ? [] : buildPreviewConnections(preAccelEnabled)
  );
  const [connSearch, setConnSearch] = useState<string>("");
  const [connGroupFilter, setConnGroupFilter] = useState<string>("all");
  const [connSort, setConnSort] = useState<"down" | "up" | "rate" | "age" | "process">("down");
  const [showInnerTunnels, setShowInnerTunnels] = useState<boolean>(false);
  const [hideLoopback, setHideLoopback] = useState<boolean>(false);
  const [connPage, setConnPage] = useState<number>(1);
  const [pageJumpInput, setPageJumpInput] = useState<string>("");
  const [connPaused, setConnPaused] = useState<boolean>(false);
  const [confirmCloseAll, setConfirmCloseAll] = useState<boolean>(false);
  const [nowTick, setNowTick] = useState<number>(() => Date.now());
  const [refreshingConns, setRefreshingConns] = useState<boolean>(false);

  const copiedYamlTimerRef = useRef<number | null>(null);
  const confirmCloseAllTimerRef = useRef<number | null>(null);
  const groupsRef = useRef<MultiGroup[]>(groups);
  groupsRef.current = groups;
  const relaysRef = useRef<PreAccelRelay[]>(preAccelRelays);
  relaysRef.current = preAccelRelays;
  const runtimeRunningRef = useRef<boolean>(runtime.running);
  runtimeRunningRef.current = runtime.running;
  const preAccelEnabledRef = useRef<boolean>(preAccelEnabled);
  preAccelEnabledRef.current = preAccelEnabled;
  const aiPresetsRef = useRef<AiPresetBundle[]>(aiPresets);
  aiPresetsRef.current = aiPresets;
  const userRulesRef = useRef<ManagedRuleItem[]>(userRules);
  userRulesRef.current = userRules;
  const showYamlPreviewRef = useRef<boolean>(showYamlPreview);
  showYamlPreviewRef.current = showYamlPreview;
  const userPickedNewTargetRef = useRef<boolean>(false);
  const inFlightRef = useRef<boolean>(false);
  const prevSnapRef = useRef<Map<string, ConnTrafficSnap>>(new Map());
  const previewReqSeqRef = useRef<number>(0);

  useEffect(() => {
    return () => {
      if (copiedYamlTimerRef.current !== null) {
        window.clearTimeout(copiedYamlTimerRef.current);
      }
      if (confirmCloseAllTimerRef.current !== null) {
        window.clearTimeout(confirmCloseAllTimerRef.current);
      }
    };
  }, []);

  const loadCompiledPreview = useCallback(async () => {
    const seq = ++previewReqSeqRef.current;
    setLoadingPreview(true);
    setPreviewError(null);
    try {
      const res = await catcloudApi.compilePreviewYaml();
      if (seq !== previewReqSeqRef.current) return;
      setCompiledPreview(res);
    } catch (err) {
      if (seq !== previewReqSeqRef.current) return;
      const msg = formatErrorMessage(err);
      setPreviewError(msg);
      appActions.showToast(`编译配置预览失败：${msg}`, "warn");
    } finally {
      if (seq === previewReqSeqRef.current) {
        setLoadingPreview(false);
      }
    }
  }, []);

  // Load persisted rules_override from backend config on mount
  useEffect(() => {
    let cancelled = false;
    setLoadingRules(true);
    void catcloudApi
      .getFullConfig()
      .then((fullCfg) => {
        if (cancelled) return;
        const fallbackTarget = groupsRef.current[0]?.name || "DIRECT";
        const savedOverride = fullCfg.rules_override;
        const hasSavedOverride =
          savedOverride !== undefined &&
          (Array.isArray(savedOverride.global_prepend_rules) ||
            Array.isArray(savedOverride.global_append_rules));

        if (!inTauri && !hasSavedOverride) {
          // Browser preview demo defaults before first save
          const demoPrepend = AI_PRESETS_TEMPLATE.flatMap((tpl) =>
            tpl.domains.map((d) => `DOMAIN-SUFFIX,${d},${fallbackTarget}`)
          );
          const demoAppend = ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"];
          const hydrated = hydrateRulesFromConfig(demoPrepend, demoAppend, fallbackTarget);
          setAiPresets(hydrated.presets);
          setUserRules(hydrated.userRules);
          return;
        }

        const prependList = Array.isArray(savedOverride?.global_prepend_rules)
          ? savedOverride.global_prepend_rules
          : [];
        const appendList = Array.isArray(savedOverride?.global_append_rules)
          ? savedOverride.global_append_rules
          : [];
        const hydrated = hydrateRulesFromConfig(prependList, appendList, fallbackTarget);
        setAiPresets(hydrated.presets);
        setUserRules(hydrated.userRules);
      })
      .catch((err) => {
        if (!cancelled) {
          appActions.showToast(`读取已保存的分流规则失败：${formatErrorMessage(err)}`, "warn");
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingRules(false);
      });
    return () => {
      cancelled = true;
    };
  }, [inTauri]);

  const targetChoices = useMemo(() => {
    const names = groups
      .map((g) => g.name.trim())
      .filter((name) => name.length > 0);
    return Array.from(new Set([...names, "DIRECT", "REJECT"]));
  }, [groups]);

  const hadRealGroupsRef = useRef<boolean>(groups.length > 0);

  // Keep default target synced to real groups once loaded
  useEffect(() => {
    const firstGroup = groups[0]?.name?.trim();
    if (!firstGroup) return;
    const justLoadedGroups = !hadRealGroupsRef.current;
    hadRealGroupsRef.current = true;

    if ((justLoadedGroups && !userPickedNewTargetRef.current) || !targetChoices.includes(newTarget)) {
      setNewTarget(firstGroup);
    }
    setAiPresets((prev) =>
      prev.map((p) => {
        if (p.enabled) return p;
        if (!p.targetGroup || !targetChoices.includes(p.targetGroup) || (justLoadedGroups && p.targetGroup === "DIRECT")) {
          return { ...p, targetGroup: firstGroup };
        }
        return p;
      })
    );
  }, [groups, newTarget, targetChoices]);

  const persistRulesOverride = useCallback(
    async (
      nextPresets: AiPresetBundle[],
      nextUserRules: ManagedRuleItem[],
      successToast: string
    ): Promise<boolean> => {
      const prevPresets = aiPresetsRef.current;
      const prevUserRules = userRulesRef.current;
      setAiPresets(nextPresets);
      setUserRules(nextUserRules);
      setSavingRules(true);
      try {
        const payload = buildRulesOverridePayload(nextPresets, nextUserRules);
        await catcloudApi.saveExtendedSettings({ rules_override: payload });
        appActions.showToast(successToast, "ok");
        if (showYamlPreviewRef.current) {
          void loadCompiledPreview();
        }
        return true;
      } catch (err) {
        setAiPresets(prevPresets);
        setUserRules(prevUserRules);
        appActions.showToast(`保存分流规则失败：${formatErrorMessage(err)}`, "warn");
        return false;
      } finally {
        setSavingRules(false);
      }
    },
    [loadCompiledPreview]
  );

  const fetchLiveConnections = useCallback(
    async (manual = false, notifyOnError = false): Promise<boolean> => {
      if (inFlightRef.current) return false;
      if (!inTauri) {
        setConnections(buildPreviewConnections(preAccelEnabledRef.current));
        setNowTick(Date.now());
        return true;
      }
      if (!runtimeRunningRef.current) {
        prevSnapRef.current = new Map();
        setConnections([]);
        if (notifyOnError) {
          appActions.showToast("代理核心尚未启动，开启代理后这里会实时显示连接", "info");
        }
        return false;
      }

      inFlightRef.current = true;
      if (manual) {
        setRefreshingConns(true);
      }
      try {
        const snap = await catcloudApi.getActiveConnections();
        const nowMs = Date.now();
        const prevMap = prevSnapRef.current;
        const nextMap = new Map<string, ConnTrafficSnap>();

        const mapped = snap.connections.map((dto) => {
          const item = mapDtoConnection(
            dto,
            groupsRef.current,
            relaysRef.current,
            preAccelEnabledRef.current
          );
          const prev = prevMap.get(item.id);
          if (prev && nowMs > prev.atMs) {
            const dtSec = Math.max(0.2, (nowMs - prev.atMs) / 1000);
            item.upBps = Math.max(0, (item.uploadBytes - prev.uploadBytes) / dtSec);
            item.downBps = Math.max(0, (item.downloadBytes - prev.downloadBytes) / dtSec);
          }
          nextMap.set(item.id, {
            uploadBytes: item.uploadBytes,
            downloadBytes: item.downloadBytes,
            atMs: nowMs,
          });
          return item;
        });

        prevSnapRef.current = nextMap;
        setConnections(mapped);
        setNowTick(nowMs);
        return true;
      } catch (err) {
        if (notifyOnError) {
          appActions.showToast(`获取当前连接失败：${formatErrorMessage(err)}`, "warn");
        }
        return false;
      } finally {
        inFlightRef.current = false;
        if (manual) {
          setRefreshingConns(false);
        }
      }
    },
    [inTauri]
  );

  // Fetch active connection count once on mount (even on Rules tab) when core is running,
  // and clear stale connections when core stops.
  useEffect(() => {
    if (!inTauri) return;
    if (!runtime.running) {
      prevSnapRef.current = new Map();
      setConnections([]);
      return;
    }
    void fetchLiveConnections(false, false);
  }, [fetchLiveConnections, inTauri, runtime.running]);

  // Re-evaluate custom relay names whenever preAccelRelays updates
  useEffect(() => {
    if (preAccelRelays.length === 0) return;
    setConnections((prev) => {
      let changed = false;
      const next = prev.map((c) => {
        const via = matchesPreAccelChain(c.chains, preAccelRelays);
        if (via !== c.viaPreAccel) {
          changed = true;
          return { ...c, viaPreAccel: via };
        }
        return c;
      });
      return changed ? next : prev;
    });
  }, [preAccelRelays]);

  // Silently poll real connections in Tauri runtime when Connections tab is active; tick preview demo in browser
  useEffect(() => {
    if (connPaused) return;
    if (inTauri && !runtime.running) return;
    if (inTauri && activeTab === "connections") {
      void fetchLiveConnections(false, false);
    }
    const timer = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      const nowMs = Date.now();
      setNowTick(nowMs);
      if (inTauri) {
        if (activeTab === "connections" && runtimeRunningRef.current) {
          void fetchLiveConnections(false, false);
        }
      } else {
        setConnections((prev) => {
          const prevMap = prevSnapRef.current;
          const nextMap = new Map<string, ConnTrafficSnap>();
          const updated = prev.map((c, idx) => {
            const deltaUp = (idx + 1) * 14_500;
            const deltaDown = (idx + 2) * 58_000;
            const nextUp = c.uploadBytes + deltaUp;
            const nextDown = c.downloadBytes + deltaDown;
            const last = prevMap.get(c.id);
            const dtSec = last && nowMs > last.atMs ? Math.max(0.2, (nowMs - last.atMs) / 1000) : 2.5;
            const upBps = last ? Math.max(0, (nextUp - last.uploadBytes) / dtSec) : deltaUp / 2.5;
            const downBps = last ? Math.max(0, (nextDown - last.downloadBytes) / dtSec) : deltaDown / 2.5;
            nextMap.set(c.id, { uploadBytes: nextUp, downloadBytes: nextDown, atMs: nowMs });
            return {
              ...c,
              uploadBytes: nextUp,
              downloadBytes: nextDown,
              upBps,
              downBps,
            };
          });
          prevSnapRef.current = nextMap;
          return updated;
        });
      }
    }, 2500);
    return () => window.clearInterval(timer);
  }, [activeTab, connPaused, fetchLiveConnections, inTauri, runtime.running]);

  // Combine group match_rules from store with editable local rules
  const groupBoundRules = useMemo<ManagedRuleItem[]>(() => {
    const list: ManagedRuleItem[] = [];
    for (const grp of groups) {
      grp.match_rules.forEach((raw, idx) => {
        const parts = raw.split(",");
        const rType = (parts[0] ?? "DOMAIN-SUFFIX").trim().toUpperCase();
        const val = (parts[1] ?? raw).trim();
        list.push({
          id: `grp-${grp.id}-${idx}`,
          layer: "group",
          ruleType: rType,
          value: val,
          target: grp.name,
          groupId: grp.id,
        });
      });
    }
    return list;
  }, [groups]);

  const allDisplayRules = useMemo(() => {
    const combined = [...userRules, ...groupBoundRules];
    const kw = ruleSearch.trim().toLowerCase();
    return combined.filter((item) => {
      if (ruleLayerFilter !== "all" && item.layer !== ruleLayerFilter) return false;
      if (!kw) return true;
      return (
        item.value.toLowerCase().includes(kw) ||
        item.ruleType.toLowerCase().includes(kw) ||
        item.target.toLowerCase().includes(kw)
      );
    });
  }, [groupBoundRules, ruleLayerFilter, ruleSearch, userRules]);

  const compiledMeta = useMemo<ParsedCompiledMeta | null>(
    () => (compiledPreview ? parseCompiledPreviewMeta(compiledPreview) : null),
    [compiledPreview]
  );

  const handleToggleYamlPreview = () => {
    const next = !showYamlPreview;
    setShowYamlPreview(next);
    if (next) {
      void loadCompiledPreview();
    }
  };

  const handleAddRule = async () => {
    if (savingRules) return;
    const val = newValue.trim();
    if (!val) {
      appActions.showToast("请填写要匹配的网址、IP 或软件名", "warn");
      return;
    }
    const effectiveTarget = newTarget.trim() || targetChoices[0] || "DIRECT";
    const created: ManagedRuleItem = {
      id: `rule-custom-${Date.now()}`,
      layer: newLayer,
      ruleType: newType,
      value: val,
      target: effectiveTarget,
      noResolve: (newType === "IP-CIDR" || newType === "GEOIP") && newNoResolve,
    };
    const nextRules = [created, ...userRules];
    const ok = await persistRulesOverride(
      aiPresets,
      nextRules,
      `已保存并生效：${created.value} → ${formatRuleTargetLabel(created.target)}`
    );
    if (ok) {
      setNewValue("");
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (savingRules) return;
    const found = userRules.find((r) => r.id === id);
    if (!found) {
      appActions.showToast("分组自带规则请前往「智能多选组」页面修改", "info");
      return;
    }
    const nextRules = userRules.filter((r) => r.id !== id);
    await persistRulesOverride(aiPresets, nextRules, "已删除规则并保存生效");
  };

  const handleToggleAiPreset = async (id: string) => {
    if (savingRules) return;
    const targetPreset = aiPresets.find((p) => p.id === id);
    if (!targetPreset) return;
    const nextEnabled = !targetPreset.enabled;
    const nextTarget =
      targetPreset.targetGroup.trim() || groups[0]?.name || "DIRECT";
    const nextPresets = aiPresets.map((p) =>
      p.id === id ? { ...p, enabled: nextEnabled, targetGroup: nextTarget } : p
    );
    await persistRulesOverride(
      nextPresets,
      userRules,
      nextEnabled
        ? `已开启「${targetPreset.name}」分流并保存生效`
        : `已关闭「${targetPreset.name}」分流并保存生效`
    );
  };

  const handleChangeAiPresetTarget = async (id: string, targetGroup: string) => {
    if (savingRules) return;
    const targetPreset = aiPresets.find((p) => p.id === id);
    if (!targetPreset) return;
    const nextPresets = aiPresets.map((p) =>
      p.id === id ? { ...p, targetGroup } : p
    );
    if (!targetPreset.enabled) {
      setAiPresets(nextPresets);
      return;
    }
    await persistRulesOverride(
      nextPresets,
      userRules,
      `已将「${targetPreset.name}」指向「${formatRuleTargetLabel(targetGroup)}」并保存生效`
    );
  };

  const handleCopyYaml = async () => {
    if (!compiledPreview?.yaml) {
      appActions.showToast("暂无可复制的编译配置", "warn");
      return;
    }
    try {
      await navigator.clipboard.writeText(compiledPreview.yaml);
      setCopiedYaml(true);
      appActions.showToast("已复制后端编译生成的脱敏配置", "ok");
      if (copiedYamlTimerRef.current !== null) {
        window.clearTimeout(copiedYamlTimerRef.current);
      }
      copiedYamlTimerRef.current = window.setTimeout(() => {
        copiedYamlTimerRef.current = null;
        setCopiedYaml(false);
      }, 1800);
    } catch {
      appActions.showToast("剪贴板不可用，请手动选中复制", "warn");
    }
  };

  // --- Connections classification, filtering, pagination & teardown ---
  const connectionBreakdown = useMemo(() => {
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
  }, [connections]);

  const filteredConnections = useMemo(() => {
    const kw = connSearch.trim().toLowerCase();
    const list = connections.filter((c) => {
      if (!showInnerTunnels && c.isInnerTunnel) return false;
      if (hideLoopback && !c.isInnerTunnel && c.isLoopback) return false;
      if (connGroupFilter !== "all") {
        if (connGroupFilter === "DIRECT") {
          const isDirect =
            c.groupId.toUpperCase() === "DIRECT" ||
            c.groupName.toUpperCase() === "DIRECT" ||
            c.nodeName.toUpperCase() === "DIRECT";
          if (!isDirect) return false;
        } else if (c.groupId !== connGroupFilter && c.groupName !== connGroupFilter) {
          return false;
        }
      }
      if (!kw) return true;
      const isPreAccelInner = c.isInnerTunnel && (preAccelEnabled || c.viaPreAccel);
      const friendlyRule = formatConnectionRuleLabel(
        c.rule,
        c.isInnerTunnel,
        isPreAccelInner
      ).toLowerCase();
      const displayProcess = c.isInnerTunnel
        ? isPreAccelInner
          ? "底层提速隧道 (Inner)"
          : "内核内部连接 (Inner)"
        : c.process;
      const extraTag = c.isInnerTunnel
        ? isPreAccelInner
          ? "底层提速隧道 inner 国内提速拨号"
          : "内核内部连接 inner dns 加密dns 规则探测"
        : c.isLoopback
          ? "本机内部通信 loopback 回环"
          : "";
      return (
        displayProcess.toLowerCase().includes(kw) ||
        c.host.toLowerCase().includes(kw) ||
        c.dstIp.includes(kw) ||
        c.rule.toLowerCase().includes(kw) ||
        friendlyRule.includes(kw) ||
        c.nodeName.toLowerCase().includes(kw) ||
        c.groupName.toLowerCase().includes(kw) ||
        extraTag.includes(kw)
      );
    });

    list.sort((a, b) => {
      if (connSort === "rate") return b.upBps + b.downBps - (a.upBps + a.downBps);
      if (connSort === "down") return b.downloadBytes - a.downloadBytes;
      if (connSort === "up") return b.uploadBytes - a.uploadBytes;
      if (connSort === "age") return a.startedAtMs - b.startedAtMs;
      return a.process.localeCompare(b.process);
    });
    return list;
  }, [
    connGroupFilter,
    connSearch,
    connSort,
    connections,
    hideLoopback,
    preAccelEnabled,
    showInnerTunnels,
  ]);

  const totalConnPages = Math.max(
    1,
    Math.ceil(filteredConnections.length / CONNECTIONS_PAGE_SIZE)
  );
  const safeConnPage = Math.min(connPage, totalConnPages);

  useEffect(() => {
    setConnPage(1);
  }, [connGroupFilter, connSearch, connSort, hideLoopback, showInnerTunnels]);

  useEffect(() => {
    if (connPage > totalConnPages) {
      setConnPage(totalConnPages);
    }
  }, [connPage, totalConnPages]);

  const pagedConnections = useMemo(() => {
    const start = (safeConnPage - 1) * CONNECTIONS_PAGE_SIZE;
    return filteredConnections.slice(start, start + CONNECTIONS_PAGE_SIZE);
  }, [filteredConnections, safeConnPage]);

  const handleJumpConnPage = () => {
    const parsed = Number.parseInt(pageJumpInput.trim(), 10);
    if (!Number.isFinite(parsed)) {
      appActions.showToast("请输入有效的页码数字", "warn");
      return;
    }
    const target = Math.max(1, Math.min(totalConnPages, parsed));
    setConnPage(target);
    setPageJumpInput("");
  };

  // Strictly exclude `isInnerTunnel` connections from aggregate bytes & rates to avoid double-counting
  const filteredAppConnCount = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + 1), 0),
    [filteredConnections]
  );
  const totalConnUpload = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.uploadBytes), 0),
    [filteredConnections]
  );
  const totalConnDownload = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.downloadBytes), 0),
    [filteredConnections]
  );
  const totalConnUpBps = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.upBps), 0),
    [filteredConnections]
  );
  const totalConnDownBps = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.downBps), 0),
    [filteredConnections]
  );

  const ruleLayerOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "prepend", label: "优先匹配（最先判断）" },
      { value: "append", label: "兜底匹配（最后判断）" },
    ],
    []
  );

  const ruleTypeOptions = useMemo<AppSelectOption[]>(
    () =>
      (Object.keys(RULE_TYPE_LABELS) as RuleMatchType[]).map((key) => ({
        value: key,
        label: RULE_TYPE_LABELS[key],
      })),
    []
  );

  const ruleTargetOptions = useMemo<AppSelectOption[]>(
    () =>
      targetChoices.map((t) => ({
        value: t,
        label: formatRuleTargetLabel(t),
      })),
    [targetChoices]
  );

  const connGroupFilterOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "all", label: "全部分组" },
      { value: "DIRECT", label: "直接连接" },
      ...groups.map((g) => ({ value: g.id, label: g.name })),
    ],
    [groups]
  );

  const connSortOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "down", label: "按下载量排序" },
      { value: "up", label: "按上传量排序" },
      { value: "rate", label: "按实时速率排序" },
      { value: "age", label: "按连接时长排序" },
      { value: "process", label: "按软件名排序" },
    ],
    []
  );

  const handleCloseSingleConn = async (conn: LiveConnection) => {
    try {
      await catcloudApi.closeConnection(conn.id);
      prevSnapRef.current.delete(conn.id);
      setConnections((prev) => prev.filter((c) => c.id !== conn.id));
      appActions.showToast(`已断开连接：${conn.process} -> ${conn.host}`, "ok");
    } catch (err) {
      appActions.showToast(`断开连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleCloseByGroup = async () => {
    const targetGroupId =
      connGroupFilter !== "all" ? connGroupFilter : groups[0]?.id ?? "";
    const targetGroupName =
      groups.find((g) => g.id === targetGroupId)?.name ??
      connections.find((c) => c.groupId === targetGroupId)?.groupName ??
      targetGroupId;

    if (!targetGroupName) {
      appActions.showToast("请先选择要清理连接的分组", "warn");
      return;
    }

    try {
      const closed = await catcloudApi.closeGroupConnections(targetGroupName);
      setConnections((prev) =>
        prev.filter((c) => c.groupId !== targetGroupId && c.groupName !== targetGroupName)
      );
      appActions.showToast(
        `已断开「${targetGroupName}」的 ${closed} 条旧连接`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`按分组断开连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleCloseAllConns = async () => {
    if (!confirmCloseAll) {
      setConfirmCloseAll(true);
      if (confirmCloseAllTimerRef.current !== null) {
        window.clearTimeout(confirmCloseAllTimerRef.current);
      }
      confirmCloseAllTimerRef.current = window.setTimeout(() => {
        confirmCloseAllTimerRef.current = null;
        setConfirmCloseAll(false);
      }, 3500);
      return;
    }
    if (confirmCloseAllTimerRef.current !== null) {
      window.clearTimeout(confirmCloseAllTimerRef.current);
      confirmCloseAllTimerRef.current = null;
    }
    try {
      const closed = await catcloudApi.closeAllConnections();
      const shownCount = inTauri ? closed : connections.length;
      prevSnapRef.current = new Map();
      setConnections([]);
      setConfirmCloseAll(false);
      appActions.showToast(`已断开全部 ${shownCount} 条连接`, "ok");
    } catch (err) {
      setConfirmCloseAll(false);
      appActions.showToast(`断开全部连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleRefreshConns = async () => {
    const ok = await fetchLiveConnections(true, true);
    if (ok) {
      appActions.showToast("已刷新当前连接列表", "info");
    }
  };

  const enabledAiDomainCount = aiPresets
    .filter((p) => p.enabled)
    .reduce((acc, p) => acc + p.domains.length, 0);
  const innerCountShortLabel = preAccelEnabled ? "提速隧道" : "内核内部连接";

  return (
    <div className="space-y-4">
      {/* 顶部标题与标签切换 */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--accent)]">
            <Network className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold text-[var(--text)]">分流规则与当前连接</h1>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              决定哪些网站走哪组节点或直接连接，也可以随时查看并断开正在进行的网络连接。
            </p>
          </div>
        </div>

        <div className="flex items-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-1 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab("rules")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition-colors ${
              activeTab === "rules"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            分流规则
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {userRules.length + groupBoundRules.length + enabledAiDomainCount}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("connections")}
            title={
              connectionBreakdown.innerTunnelCount > 0 || connectionBreakdown.loopbackCount > 0
                ? `真实应用连接 ${connectionBreakdown.appCount} 条（另含 ${connectionBreakdown.innerTunnelCount} 条${innerCountShortLabel} · ${connectionBreakdown.loopbackCount} 条本机回环）`
                : `真实应用连接 ${connectionBreakdown.appCount} 条`
            }
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition-colors ${
              activeTab === "connections"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            当前连接
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {connectionBreakdown.appCount}
            </span>
          </button>
        </div>
      </section>

      {activeTab === "rules" ? (
        <div className="space-y-4">
          {/* 常用网站分流 */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Sparkles className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  常用网站分流
                </h2>
                <span className="text-[11px] text-[var(--muted)]">
                  打开开关即可自动保存，让常用 AI 与开发网站走指定分组
                </span>
              </div>
              <div className="flex items-center gap-2">
                {savingRules && (
                  <span className="text-[11px] text-[var(--accent)]">保存中...</span>
                )}
                <button
                  type="button"
                  onClick={handleToggleYamlPreview}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
                >
                  <Code2 className="h-3.5 w-3.5 text-[var(--accent)]" />
                  {showYamlPreview ? "收起实际规则" : "预览实际规则"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {aiPresets.map((preset) => {
                const presetOptions = targetChoices.includes(preset.targetGroup)
                  ? targetChoices
                  : [preset.targetGroup, ...targetChoices].filter(Boolean);
                return (
                  <div
                    key={preset.id}
                    className={`rounded-xl border p-3.5 transition-colors ${
                      preset.enabled
                        ? "border-[var(--line-strong)] bg-[var(--bg-elevated)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)]/50 opacity-75"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-xs font-semibold text-[var(--text)]">
                          {preset.name}
                        </div>
                        <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                          {preset.desc}
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={savingRules || loadingRules}
                        onClick={() => void handleToggleAiPreset(preset.id)}
                        className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-50 ${
                          preset.enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                        }`}
                        aria-label={`切换 ${preset.name}`}
                      >
                        <span
                          className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                            preset.enabled ? "translate-x-4" : "translate-x-0"
                          }`}
                        />
                      </button>
                    </div>

                    <div className="mt-2.5 flex flex-wrap gap-1">
                      {preset.domains.map((d) => (
                        <span
                          key={d}
                          className="cc-mono rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                        >
                          {d}
                        </span>
                      ))}
                    </div>

                    <div className="mt-2.5 flex items-center justify-between gap-2 border-t border-[var(--line)] pt-2 text-[11px]">
                      <span className="text-[var(--muted)]">走哪个分组</span>
                      <AppSelect
                        size="xs"
                        aria-label={`${preset.name} 目标分组`}
                        value={preset.targetGroup}
                        disabled={savingRules || loadingRules}
                        onChange={(val) => void handleChangeAiPresetTarget(preset.id, val)}
                        options={presetOptions.map((t) => ({
                          value: t,
                          label: formatRuleTargetLabel(t),
                        }))}
                        className="min-w-[132px] max-w-[200px]"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* 后端真实编译配置预览（已脱敏） */}
          {showYamlPreview && (
            <section className="cc-card cc-glass overflow-hidden rounded-2xl">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-2.5">
                <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-[var(--text)]">
                  <Eye className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span>后端编译配置预览（已脱敏）</span>
                  {compiledMeta && (
                    <>
                      <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--text-secondary)]">
                        规则 {compiledMeta.totalRules ?? "--"} 条
                        {compiledMeta.proxyGroups !== null ? ` · 分组 ${compiledMeta.proxyGroups}` : ""}
                        {compiledMeta.totalProxies !== null ? ` · 节点 ${compiledMeta.totalProxies}` : ""}
                      </span>
                      {compiledMeta.validationOk ? (
                        compiledMeta.warnings.length > 0 ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                            <AlertTriangle className="h-3 w-3" />
                            校验通过（{compiledMeta.warnings.length} 条提醒）
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--green)]">
                            <CheckCircle2 className="h-3 w-3" />
                            编译校验通过
                          </span>
                        )
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--red)]">
                          <AlertTriangle className="h-3 w-3" />
                          校验未通过（{compiledMeta.errors.length} 项错误）
                        </span>
                      )}
                    </>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    disabled={loadingPreview}
                    onClick={() => void loadCompiledPreview()}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                  >
                    <RefreshCw className={`h-3 w-3 ${loadingPreview ? "animate-spin" : ""}`} />
                    重新编译
                  </button>
                  <button
                    type="button"
                    disabled={loadingPreview || !compiledPreview?.yaml}
                    onClick={() => void handleCopyYaml()}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                  >
                    {copiedYaml ? (
                      <Check className="h-3 w-3 text-[var(--green)]" />
                    ) : (
                      <Copy className="h-3 w-3 text-[var(--accent)]" />
                    )}
                    {copiedYaml ? "已复制" : "复制配置"}
                  </button>
                </div>
              </div>

              {compiledMeta && (compiledMeta.errors.length > 0 || compiledMeta.warnings.length > 0) && (
                <div className="space-y-1 border-b border-[var(--line)] bg-[var(--bg-elevated)]/50 px-4 py-2 text-[11px]">
                  {compiledMeta.errors.map((issue, idx) => (
                    <div key={`err-${idx}`} className="flex items-start gap-1.5 text-[var(--red)]">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>
                        {issue.code ? `[${issue.code}] ` : ""}
                        {issue.message}
                      </span>
                    </div>
                  ))}
                  {compiledMeta.warnings.map((issue, idx) => (
                    <div key={`warn-${idx}`} className="flex items-start gap-1.5 text-[var(--amber)]">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>
                        {issue.code ? `[${issue.code}] ` : ""}
                        {issue.message}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {loadingPreview && !compiledPreview ? (
                <div className="py-8 text-center text-xs text-[var(--muted)]">
                  正在调用后端编译并校验配置...
                </div>
              ) : previewError && !compiledPreview ? (
                <div className="px-4 py-6 text-center text-xs text-[var(--red)]">
                  编译预览失败：{previewError}
                </div>
              ) : (
                <pre className="cc-selectable cc-mono max-h-[300px] overflow-auto p-4 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  {compiledPreview?.yaml ?? ""}
                </pre>
              )}
            </section>
          )}

          {/* 自定义分流规则表单 */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-xs font-semibold text-[var(--text)]">自定义分流规则</h2>
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] text-[var(--green)]">
                <Shield className="h-3 w-3" />
                系统已自动保护本机直连与防绕路死循环，添加规则后立即保存生效
              </span>
            </div>
            <div className="grid grid-cols-1 items-center gap-2 sm:grid-cols-2 lg:grid-cols-12">
              <AppSelect
                size="md"
                aria-label="规则优先级层级"
                value={newLayer}
                onChange={(v) => setNewLayer(v as "prepend" | "append")}
                options={ruleLayerOptions}
                className="w-full lg:col-span-2"
                buttonClassName="w-full rounded-xl"
              />

              <AppSelect
                size="md"
                aria-label="规则匹配类型"
                value={newType}
                onChange={(v) => setNewType(v as RuleMatchType)}
                options={ruleTypeOptions}
                className="w-full lg:col-span-2"
                buttonClassName="w-full rounded-xl"
              />

              <input
                type="text"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void handleAddRule();
                }}
                placeholder="填写网址或内容，例如 github.com、cn 或 chrome.exe"
                className="cc-mono h-9 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none lg:col-span-4"
              />

              <AppSelect
                size="md"
                aria-label="规则目标分组"
                value={newTarget}
                onChange={(v) => {
                  userPickedNewTargetRef.current = true;
                  setNewTarget(v);
                }}
                options={ruleTargetOptions}
                className="w-full lg:col-span-2"
                buttonClassName="w-full rounded-xl"
              />

              <button
                type="button"
                disabled={savingRules || loadingRules}
                onClick={() => void handleAddRule()}
                className="inline-flex h-9 items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50 lg:col-span-2"
              >
                <Plus className="h-3.5 w-3.5" />
                添加并保存
              </button>
            </div>

            {(newType === "IP-CIDR" || newType === "GEOIP") && (
              <label className="mt-2 inline-flex items-center gap-2 text-[11px] text-[var(--muted)]">
                <input
                  type="checkbox"
                  checked={newNoResolve}
                  onChange={(e) => setNewNoResolve(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                跳过域名解析（直连规则推荐勾选，避免多余 DNS 查询）
              </label>
            )}
          </section>

          {/* 已保存规则列表 */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-3">
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {(
                  [
                    { id: "all", label: "全部规则" },
                    { id: "prepend", label: "优先匹配" },
                    { id: "group", label: "分组自带" },
                    { id: "append", label: "兜底匹配" },
                  ] as const
                ).map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setRuleLayerFilter(tab.id)}
                    className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                      ruleLayerFilter === tab.id
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="relative min-w-[220px] flex-1 max-w-sm">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                <input
                  type="text"
                  value={ruleSearch}
                  onChange={(e) => setRuleSearch(e.target.value)}
                  placeholder="搜索网址、类型或目标分组..."
                  className="w-full rounded-xl border border-[var(--line)] bg-[var(--card)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
                />
                {ruleSearch && (
                  <button
                    type="button"
                    onClick={() => setRuleSearch("")}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>

            <div className="divide-y divide-[var(--line)]">
              {loadingRules ? (
                <div className="py-10 text-center text-xs text-[var(--muted)]">
                  正在读取已保存的分流规则...
                </div>
              ) : allDisplayRules.length === 0 ? (
                <div className="py-10 text-center text-xs text-[var(--muted)]">
                  暂无自定义分流规则，可在上方直接添加或开启「常用网站分流」
                </div>
              ) : (
                allDisplayRules.map((item) => {
                  const typeLabel =
                    RULE_TYPE_LABELS[item.ruleType as RuleMatchType] ?? item.ruleType;
                  return (
                    <div
                      key={item.id}
                      className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-xs hover:bg-[var(--card-hover)]"
                    >
                      <div className="flex min-w-0 flex-wrap items-center gap-2">
                        <span
                          className="rounded-md px-2 py-0.5 text-[10px] font-medium"
                          style={{
                            backgroundColor:
                              item.layer === "prepend"
                                ? "var(--accent-soft)"
                                : item.layer === "group"
                                  ? "var(--sky-soft)"
                                  : "var(--bg-elevated)",
                            color:
                              item.layer === "prepend"
                                ? "var(--accent)"
                                : item.layer === "group"
                                  ? "var(--sky)"
                                  : "var(--muted)",
                          }}
                        >
                          {item.layer === "prepend"
                            ? "优先匹配"
                            : item.layer === "group"
                              ? "分组自带"
                              : "兜底匹配"}
                        </span>

                        <span
                          title={item.ruleType}
                          className="rounded border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                        >
                          {typeLabel}
                        </span>

                        <span className="cc-mono cc-selectable font-medium text-[var(--text)]">
                          {item.value}
                        </span>

                        {item.noResolve && (
                          <span className="text-[10px] text-[var(--muted)]">
                            跳过域名解析
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2.5">
                        <span className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
                          → {formatRuleTargetLabel(item.target)}
                        </span>
                        <button
                          type="button"
                          onClick={() => void handleDeleteRule(item.id)}
                          disabled={savingRules || Boolean(item.groupId)}
                          className="rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--red-soft)] hover:text-[var(--red)] disabled:cursor-not-allowed disabled:opacity-35"
                          title={
                            item.groupId
                              ? "分组自带规则请前往「智能多选组」页调整"
                              : "删除此规则"
                          }
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>
        </div>
      ) : (
        /* ======================== TAB B: 当前连接 ======================== */
        <div className="space-y-4">
          {/* 连接概览与批量操作 */}
          <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
            <div className="flex flex-wrap items-center gap-4 text-xs">
              <div>
                <span className="text-[var(--muted)]">真实应用连接</span>
                <div className="cc-mono mt-0.5 text-base font-semibold text-[var(--text)]">
                  {filteredAppConnCount}
                  <span className="ml-1 text-[11px] font-normal text-[var(--muted)]">
                    / {connectionBreakdown.appCount}
                  </span>
                </div>
                {(connectionBreakdown.innerTunnelCount > 0 ||
                  connectionBreakdown.loopbackCount > 0) && (
                  <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                    {connectionBreakdown.innerTunnelCount > 0 &&
                    connectionBreakdown.loopbackCount > 0
                      ? `另含 ${connectionBreakdown.innerTunnelCount} 条${innerCountShortLabel} · ${connectionBreakdown.loopbackCount} 条本机回环`
                      : connectionBreakdown.innerTunnelCount > 0
                        ? `另含 ${connectionBreakdown.innerTunnelCount} 条${innerCountShortLabel}`
                        : `含 ${connectionBreakdown.loopbackCount} 条本机回环`}
                  </div>
                )}
              </div>
              <div className="h-7 w-px bg-[var(--line)]" />
              <div
                title={
                  preAccelEnabled
                    ? "已自动排除底层提速隧道，避免应用层与隧道层重复累计"
                    : "已自动排除内核内部连接（如加密 DNS、规则探测），仅统计真实应用流量"
                }
              >
                <span className="text-[var(--muted)]">实时上传 / 累计</span>
                <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--coral)]">
                  ↑ {formatRate(totalConnUpBps)}
                  <span className="ml-1.5 text-[11px] font-normal text-[var(--muted)]">
                    ({formatBytes(totalConnUpload)})
                  </span>
                </div>
              </div>
              <div
                title={
                  preAccelEnabled
                    ? "已自动排除底层提速隧道，避免应用层与隧道层重复累计"
                    : "已自动排除内核内部连接（如加密 DNS、规则探测），仅统计真实应用流量"
                }
              >
                <span className="text-[var(--muted)]">实时下载 / 累计</span>
                <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--sky)]">
                  ↓ {formatRate(totalConnDownBps)}
                  <span className="ml-1.5 text-[11px] font-normal text-[var(--muted)]">
                    ({formatBytes(totalConnDownload)})
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setConnPaused((p) => !p)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--line-strong)]"
              >
                {connPaused ? (
                  <Play className="h-3.5 w-3.5 text-[var(--accent)]" />
                ) : (
                  <Pause className="h-3.5 w-3.5 text-[var(--muted)]" />
                )}
                {connPaused ? "继续刷新" : "暂停刷新"}
              </button>

              <button
                type="button"
                onClick={() => void handleCloseByGroup()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--amber)] hover:opacity-90"
                title="断开所选分组下的旧连接，切换节点后可让新线路立刻生效"
              >
                <Zap className="h-3.5 w-3.5" />
                按分组断开旧连接
              </button>

              <button
                type="button"
                onClick={() => void handleCloseAllConns()}
                className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold transition-colors ${
                  confirmCloseAll
                    ? "border-[var(--red)] bg-[var(--red)] text-[var(--accent-ink)]"
                    : "border-[var(--red)]/50 bg-[var(--red-soft)] text-[var(--red)] hover:border-[var(--red)]"
                }`}
              >
                <Trash2 className="h-3.5 w-3.5" />
                {confirmCloseAll ? "再点一次确认全部断开" : "断开全部连接"}
              </button>
            </div>
          </section>

          {/* 筛选与排序栏 */}
          <section className="cc-card cc-glass flex flex-wrap items-center gap-2.5 rounded-2xl p-3.5">
            <div className="relative min-w-[240px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={connSearch}
                onChange={(e) => setConnSearch(e.target.value)}
                placeholder="按软件名、目标网址/IP、规则或节点搜索..."
                className="h-8 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] pl-8 pr-7 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
              {connSearch && (
                <button
                  type="button"
                  onClick={() => setConnSearch("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <label
                className={`inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-xl border px-2.5 text-[11px] font-medium transition-colors ${
                  showInnerTunnels
                    ? "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
                title={
                  preAccelEnabled
                    ? "默认隐藏 Mihomo 底层国内提速拨号隧道（Inner），勾选后可展开排查中转连接"
                    : "默认隐藏 Mihomo 内核内部连接（如加密 DNS、规则探测），勾选后可展开排查"
                }
              >
                <input
                  type="checkbox"
                  checked={showInnerTunnels}
                  onChange={(e) => setShowInnerTunnels(e.target.checked)}
                  className="h-3.5 w-3.5 accent-[var(--accent)]"
                />
                <span>
                  {preAccelEnabled ? "显示底层提速隧道 (Inner)" : "显示内核内部连接 (Inner)"}
                </span>
                {connectionBreakdown.innerTunnelCount > 0 && (
                  <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px]">
                    {connectionBreakdown.innerTunnelCount}
                  </span>
                )}
              </label>

              <label
                className={`inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-xl border px-2.5 text-[11px] font-medium transition-colors ${
                  hideLoopback
                    ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
                title="隐藏发往 127.0.0.1 / localhost / ::1 的本机内部通信"
              >
                <input
                  type="checkbox"
                  checked={hideLoopback}
                  onChange={(e) => setHideLoopback(e.target.checked)}
                  className="h-3.5 w-3.5 accent-[var(--accent)]"
                />
                <span>隐藏本机回环 (127.0.0.1)</span>
                {connectionBreakdown.loopbackCount > 0 && (
                  <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px]">
                    {connectionBreakdown.loopbackCount}
                  </span>
                )}
              </label>

              <div className="flex items-center gap-1.5">
                <Filter className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                <AppSelect
                  size="sm"
                  aria-label="按分组筛选连接"
                  value={connGroupFilter}
                  onChange={setConnGroupFilter}
                  options={connGroupFilterOptions}
                  className="min-w-[128px]"
                  buttonClassName="rounded-xl"
                />

                <AppSelect
                  size="sm"
                  aria-label="连接排序方式"
                  value={connSort}
                  onChange={(v) =>
                    setConnSort(v as "down" | "up" | "rate" | "age" | "process")
                  }
                  options={connSortOptions}
                  className="min-w-[132px]"
                  buttonClassName="rounded-xl"
                />

                <button
                  type="button"
                  disabled={refreshingConns}
                  onClick={() => void handleRefreshConns()}
                  className="inline-flex h-8 w-8 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                  title="刷新当前连接"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${refreshingConns ? "animate-spin" : ""}`} />
                </button>
              </div>
            </div>
          </section>

          {/* 当前连接表格 */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[11px] text-[var(--muted)]">
                    <th className="whitespace-nowrap px-3 py-2.5 font-medium">软件 / 协议</th>
                    <th className="whitespace-nowrap px-2.5 py-2.5 font-medium">访问地址与端口</th>
                    <th className="whitespace-nowrap px-2.5 py-2.5 font-medium">命中规则</th>
                    <th className="min-w-[136px] whitespace-nowrap px-2.5 py-2.5 font-medium">分组与当前节点</th>
                    <th className="whitespace-nowrap px-2.5 py-2.5 text-right font-medium">实时速率 / 累计流量</th>
                    <th className="whitespace-nowrap px-2.5 py-2.5 text-right font-medium">时长</th>
                    <th className="whitespace-nowrap px-3 py-2.5 text-right font-medium">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--line)]">
                  {filteredConnections.length === 0 ? (
                    <tr>
                      <td
                        colSpan={7}
                        className="py-10 text-center text-xs text-[var(--muted)]"
                      >
                        {!runtime.running
                          ? "代理核心尚未启动，开启代理后这里会实时显示每个软件的连接去向"
                          : connections.length === 0
                            ? "当前没有进行中的连接"
                            : "没有符合当前筛选条件的连接"}
                      </td>
                    </tr>
                  ) : (
                    pagedConnections.map((conn) => {
                      const isPreAccelInner =
                        conn.isInnerTunnel && (preAccelEnabled || conn.viaPreAccel);
                      const displayProcess = conn.isInnerTunnel
                        ? isPreAccelInner
                          ? "底层提速隧道 (Inner)"
                          : "内核内部连接 (Inner)"
                        : conn.process;
                      return (
                      <tr
                        key={conn.id}
                        className={`hover:bg-[var(--card-hover)] ${
                          conn.isInnerTunnel ? "bg-[var(--amber-soft)]/15" : ""
                        }`}
                      >
                        <td className="max-w-[140px] px-3 py-2.5">
                          <div className="flex flex-wrap items-center gap-1">
                            <span
                              title={displayProcess}
                              className={`cc-mono max-w-[126px] truncate font-semibold ${
                                conn.isInnerTunnel
                                  ? "text-[var(--amber)]"
                                  : "text-[var(--text)]"
                              }`}
                            >
                              {displayProcess}
                            </span>
                            {conn.isInnerTunnel && (
                              <span className="rounded bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                                {isPreAccelInner ? "底层隧道" : "内核内部"}
                              </span>
                            )}
                            {!conn.isInnerTunnel && conn.isLoopback && (
                              <span className="rounded bg-[var(--sky-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--sky)]">
                                本机内部通信
                              </span>
                            )}
                          </div>
                          <span className="cc-mono mt-0.5 inline-block rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--muted)]">
                            {conn.network}
                          </span>
                        </td>

                        <td className="max-w-[185px] px-2.5 py-2.5">
                          <div
                            title={`${conn.host}:${conn.port}`}
                            className="cc-mono cc-selectable truncate font-medium text-[var(--text)]"
                          >
                            {conn.host}:{conn.port}
                          </div>
                          <div className="cc-mono truncate text-[10px] text-[var(--muted)]">
                            {conn.dstIp}
                            {!conn.isInnerTunnel && conn.isLoopback ? " · 本机内部通信" : ""}
                          </div>
                        </td>

                        <td className="px-2.5 py-2.5">
                          <span
                            title={
                              conn.isInnerTunnel
                                ? isPreAccelInner
                                  ? "国内提速拨号（Inner 底层隧道）"
                                  : "内核内部连接（如加密 DNS、规则探测）"
                                : conn.rule
                            }
                            className={`inline-block max-w-[132px] truncate rounded-lg border px-2 py-0.5 text-[11px] ${
                              conn.isInnerTunnel
                                ? "border-[var(--amber)]/40 bg-[var(--amber-soft)]/70 font-medium text-[var(--amber)]"
                                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                            }`}
                          >
                            {formatConnectionRuleLabel(
                              conn.rule,
                              conn.isInnerTunnel,
                              isPreAccelInner
                            )}
                          </span>
                        </td>

                        <td className="min-w-[136px] max-w-[165px] px-2.5 py-2.5">
                          <div className="flex flex-wrap items-center gap-1">
                            <span
                              title={formatRuleTargetLabel(conn.groupName)}
                              className="max-w-[125px] truncate text-[11px] font-medium text-[var(--accent)]"
                            >
                              {formatRuleTargetLabel(conn.groupName)}
                            </span>
                            {conn.viaPreAccel && (
                              <span className="shrink-0 whitespace-nowrap rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] text-[var(--green)]">
                                走国内提速
                              </span>
                            )}
                          </div>
                          <div
                            title={formatRuleTargetLabel(conn.nodeName)}
                            className="cc-mono mt-0.5 max-w-[155px] truncate text-[11px] text-[var(--text-secondary)]"
                          >
                            {formatRuleTargetLabel(conn.nodeName)}
                          </div>
                        </td>

                        <td className="cc-mono px-2.5 py-2.5 text-right whitespace-nowrap">
                          <div className="text-[11px] font-medium">
                            <span className="text-[var(--coral)]">↑ {formatRate(conn.upBps)}</span>
                            <span className="mx-1 text-[var(--muted)]">·</span>
                            <span className="text-[var(--sky)]">↓ {formatRate(conn.downBps)}</span>
                          </div>
                          <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                            累计 ↑ {formatBytes(conn.uploadBytes)} · ↓ {formatBytes(conn.downloadBytes)}
                          </div>
                        </td>

                        <td className="cc-mono whitespace-nowrap px-2.5 py-2.5 text-right text-[11px] text-[var(--muted)]">
                          {formatDuration(conn.startedAtMs, nowTick)}
                        </td>

                        <td className="whitespace-nowrap px-3 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => void handleCloseSingleConn(conn)}
                            className="inline-flex shrink-0 whitespace-nowrap items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] font-medium text-[var(--muted)] hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)]"
                          >
                            <X className="h-3 w-3 shrink-0" />
                            断开
                          </button>
                        </td>
                      </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {filteredConnections.length > CONNECTIONS_PAGE_SIZE && (
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-2.5 text-xs">
                <div className="text-[11px] text-[var(--muted)]">
                  显示第 {(safeConnPage - 1) * CONNECTIONS_PAGE_SIZE + 1}–
                  {Math.min(safeConnPage * CONNECTIONS_PAGE_SIZE, filteredConnections.length)} 条，共{" "}
                  {filteredConnections.length} 条（每页 {CONNECTIONS_PAGE_SIZE} 条）
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={safeConnPage <= 1}
                    onClick={() => setConnPage((p) => Math.max(1, p - 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    上一页
                  </button>

                  <span className="cc-mono text-[11px] text-[var(--text-secondary)]">
                    第 {safeConnPage} / {totalConnPages} 页
                  </span>

                  <button
                    type="button"
                    disabled={safeConnPage >= totalConnPages}
                    onClick={() => setConnPage((p) => Math.min(totalConnPages, p + 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    下一页
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>

                  <div className="ml-1 flex items-center gap-1">
                    <input
                      type="number"
                      min={1}
                      max={totalConnPages}
                      value={pageJumpInput}
                      onChange={(e) => setPageJumpInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleJumpConnPage();
                      }}
                      placeholder="页码"
                      className="cc-mono w-14 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-center text-[11px] text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={handleJumpConnPage}
                      className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                    >
                      跳转
                    </button>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
