import {
  Activity,
  Check,
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
  type MultiGroup,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { formatBytes } from "../components/TrafficSparkline";
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
  ruleType: RuleMatchType;
  value: string;
  target: string;
  noResolve?: boolean;
  builtin?: boolean;
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
  groupId: string;
  groupName: string;
  nodeName: string;
  viaPreAccel: boolean;
  uploadBytes: number;
  downloadBytes: number;
  startedAtMs: number;
}

const AI_PRESETS_INITIAL: AiPresetBundle[] = [
  {
    id: "ai-openai",
    name: "OpenAI / ChatGPT",
    desc: "ChatGPT 网页端、API 及静态资源域",
    domains: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    targetGroup: "AI 专线粘性组",
    enabled: true,
  },
  {
    id: "ai-anthropic",
    name: "Anthropic / Claude",
    desc: "Claude 对话与 API 端点",
    domains: ["anthropic.com", "claude.ai"],
    targetGroup: "AI 专线粘性组",
    enabled: true,
  },
  {
    id: "ai-gemini",
    name: "Google Gemini / AI Studio",
    desc: "Gemini、AI Studio 与 Generative Language 接口",
    domains: [
      "gemini.google.com",
      "aistudio.google.com",
      "generativelanguage.googleapis.com",
    ],
    targetGroup: "AI 专线粘性组",
    enabled: true,
  },
  {
    id: "ai-windsurf",
    name: "Windsurf & Codeium（5 域名完整预设）",
    desc: "覆盖 Windsurf、Codeium、Devin 与 Cognition 全系编码服务",
    domains: [
      "codeium.com",
      "windsurf.com",
      "devin.ai",
      "cognition.ai",
      "exafunction.com",
    ],
    targetGroup: "AI 专线粘性组",
    enabled: true,
  },
];

const INITIAL_USER_RULES: ManagedRuleItem[] = [
  {
    id: "rule-pre-1",
    layer: "prepend",
    ruleType: "IP-CIDR",
    value: "198.51.100.10/32",
    target: "DIRECT",
    noResolve: true,
    builtin: true,
  },
  {
    id: "rule-pre-2",
    layer: "prepend",
    ruleType: "DOMAIN",
    value: "connectivitycheck.platform.hicloud.com",
    target: "DIRECT",
    builtin: true,
  },
  {
    id: "rule-pre-3",
    layer: "prepend",
    ruleType: "PROCESS-NAME",
    value: "catcloud.exe",
    target: "DIRECT",
    builtin: true,
  },
  {
    id: "rule-app-1",
    layer: "append",
    ruleType: "GEOSITE",
    value: "cn",
    target: "DIRECT",
  },
  {
    id: "rule-app-2",
    layer: "append",
    ruleType: "GEOIP",
    value: "CN",
    target: "DIRECT",
    noResolve: true,
  },
];

function buildPreviewConnections(): LiveConnection[] {
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
      groupId: "grp-ai",
      groupName: "AI 专线粘性组",
      nodeName: "JP-Tokyo-01 · 1x",
      viaPreAccel: false,
      uploadBytes: 18_420_000,
      downloadBytes: 94_180_000,
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
      groupId: "grp-ai",
      groupName: "AI 专线粘性组",
      nodeName: "JP-Tokyo-01 · 1x",
      viaPreAccel: false,
      uploadBytes: 6_240_000,
      downloadBytes: 24_860_000,
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
      groupId: "grp-media",
      groupName: "流媒体与下载受控均衡",
      nodeName: "SG-Edge-02 · 1x",
      viaPreAccel: true,
      uploadBytes: 2_890_000,
      downloadBytes: 286_400_000,
      startedAtMs: now - 690_000,
    },
  ];
}

function mapDtoConnection(dto: ActiveConnectionDto, groups: MultiGroup[]): LiveConnection {
  const chains = Array.isArray(dto.chains) ? dto.chains : [];
  const matchedGroup = groups.find((g) => chains.includes(g.name) || chains.includes(g.id));
  const groupName = matchedGroup?.name ?? chains[chains.length - 1] ?? "DIRECT";
  const groupId = matchedGroup?.id ?? groupName;
  const nodeName = chains[0] ?? groupName;
  const viaPreAccel = chains.some((c) => c.toLowerCase().includes("preaccel") || c.includes("预加速"));
  const parsedStart = Date.parse(dto.start);

  return {
    id: dto.id,
    process: dto.process || dto.conn_type || "unknown",
    host: dto.host || dto.destination_ip || "--",
    dstIp: dto.destination_ip || "--",
    port: Number(dto.destination_port) || 0,
    network: dto.network.toLowerCase() === "udp" ? "udp" : "tcp",
    rule: dto.rule_payload ? `${dto.rule},${dto.rule_payload}` : dto.rule || "MATCH",
    groupId,
    groupName,
    nodeName,
    viaPreAccel,
    uploadBytes: dto.upload ?? 0,
    downloadBytes: dto.download ?? 0,
    startedAtMs: Number.isFinite(parsedStart) ? parsedStart : Date.now(),
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
  const runtime = useAppSelector((s) => s.runtime);
  const inTauri = isTauriEnv();

  const [activeTab, setActiveTab] = useState<ActiveTab>("rules");

  // --- Tab A: Rules State ---
  const [aiPresets, setAiPresets] = useState<AiPresetBundle[]>(AI_PRESETS_INITIAL);
  const [userRules, setUserRules] = useState<ManagedRuleItem[]>(INITIAL_USER_RULES);
  const [ruleSearch, setRuleSearch] = useState<string>("");
  const [ruleLayerFilter, setRuleLayerFilter] = useState<"all" | RuleLayer>("all");
  const [showYamlPreview, setShowYamlPreview] = useState<boolean>(false);
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  // New rule composer state
  const [newLayer, setNewLayer] = useState<RuleLayer>("prepend");
  const [newType, setNewType] = useState<RuleMatchType>("DOMAIN-SUFFIX");
  const [newValue, setNewValue] = useState<string>("");
  const [newTarget, setNewTarget] = useState<string>("AI 专线粘性组");
  const [newNoResolve, setNewNoResolve] = useState<boolean>(false);

  // --- Tab B: Connections State ---
  const [connections, setConnections] = useState<LiveConnection[]>(() =>
    inTauri ? [] : buildPreviewConnections()
  );
  const [connSearch, setConnSearch] = useState<string>("");
  const [connGroupFilter, setConnGroupFilter] = useState<string>("all");
  const [connSort, setConnSort] = useState<"down" | "up" | "age" | "process">("down");
  const [connPaused, setConnPaused] = useState<boolean>(false);
  const [confirmCloseAll, setConfirmCloseAll] = useState<boolean>(false);
  const [nowTick, setNowTick] = useState<number>(() => Date.now());
  const [refreshingConns, setRefreshingConns] = useState<boolean>(false);

  const copiedYamlTimerRef = useRef<number | null>(null);
  const confirmCloseAllTimerRef = useRef<number | null>(null);
  const groupsRef = useRef<MultiGroup[]>(groups);
  groupsRef.current = groups;

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

  const fetchLiveConnections = useCallback(
    async (notifyOnError = false) => {
      if (!inTauri) {
        setConnections(buildPreviewConnections());
        return;
      }
      setRefreshingConns(true);
      try {
        const snap = await catcloudApi.getActiveConnections();
        setConnections(snap.connections.map((c) => mapDtoConnection(c, groupsRef.current)));
        setNowTick(Date.now());
      } catch (err) {
        if (notifyOnError) {
          appActions.showToast(`拉取活跃连接失败：${formatErrorMessage(err)}`, "warn");
        }
      } finally {
        setRefreshingConns(false);
      }
    },
    [inTauri]
  );

  // Poll real connections in Tauri runtime when Connections tab is active; tick preview demo in browser
  useEffect(() => {
    if (connPaused) return;
    if (inTauri && activeTab === "connections") {
      void fetchLiveConnections(false);
    }
    const timer = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      setNowTick(Date.now());
      if (inTauri) {
        if (activeTab === "connections") {
          void fetchLiveConnections(false);
        }
      } else {
        setConnections((prev) =>
          prev.map((c, idx) => ({
            ...c,
            uploadBytes: c.uploadBytes + (idx + 1) * 14_500,
            downloadBytes: c.downloadBytes + (idx + 2) * 58_000,
          }))
        );
      }
    }, 2500);
    return () => window.clearInterval(timer);
  }, [activeTab, connPaused, fetchLiveConnections, inTauri]);

  const targetChoices = useMemo(() => {
    const names = groups.map((g) => g.name);
    return Array.from(new Set([...names, "AI 专线粘性组", "DIRECT", "REJECT"]));
  }, [groups]);

  // Combine group match_rules from store with editable local rules
  const groupBoundRules = useMemo<ManagedRuleItem[]>(() => {
    const list: ManagedRuleItem[] = [];
    for (const grp of groups) {
      grp.match_rules.forEach((raw, idx) => {
        const parts = raw.split(",");
        const rType = (parts[0] ?? "DOMAIN-SUFFIX").trim().toUpperCase() as RuleMatchType;
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

  const compiledOverrideYaml = useMemo(() => {
    const lines: string[] = [
      "# CatCloud Declarative Rules Override Preview (Sanitized)",
      "# Precedence: Prepend (Anti-Loop & User) -> Built-in AI Presets -> Multi-Group Rules -> Append -> MATCH",
      "",
      "prepend-rules:",
    ];
    for (const r of userRules.filter((x) => x.layer === "prepend")) {
      lines.push(
        `  - ${r.ruleType},${r.value},${r.target}${r.noResolve ? ",no-resolve" : ""}`
      );
    }
    lines.push("");
    lines.push("ai-preset-rules:");
    for (const preset of aiPresets.filter((p) => p.enabled)) {
      lines.push(`  # ${preset.name}`);
      for (const domain of preset.domains) {
        lines.push(`  - DOMAIN-SUFFIX,${domain},${preset.targetGroup}`);
      }
    }
    lines.push("");
    lines.push("group-bound-rules:");
    for (const r of [...groupBoundRules, ...userRules.filter((x) => x.layer === "group")]) {
      lines.push(
        `  - ${r.ruleType},${r.value},${r.target}${r.noResolve ? ",no-resolve" : ""}`
      );
    }
    lines.push("");
    lines.push("append-rules:");
    for (const r of userRules.filter((x) => x.layer === "append")) {
      lines.push(
        `  - ${r.ruleType},${r.value},${r.target}${r.noResolve ? ",no-resolve" : ""}`
      );
    }
    lines.push(`  - MATCH,${runtime.active_group_name || "AI 专线粘性组"}`);
    return lines.join("\n");
  }, [aiPresets, groupBoundRules, runtime.active_group_name, userRules]);

  const handleAddRule = () => {
    const val = newValue.trim();
    if (!val) {
      appActions.showToast("请填写规则匹配内容（如域名、CIDR 或进程名）", "warn");
      return;
    }
    const created: ManagedRuleItem = {
      id: `rule-custom-${Date.now()}`,
      layer: newLayer,
      ruleType: newType,
      value: val,
      target: newTarget,
      noResolve: (newType === "IP-CIDR" || newType === "GEOIP") && newNoResolve,
    };
    setUserRules((prev) => [created, ...prev]);
    setNewValue("");
    appActions.showToast(`已新增规则：${created.ruleType},${created.value},${created.target}`, "ok");
  };

  const handleDeleteRule = (id: string) => {
    const found = userRules.find((r) => r.id === id);
    if (!found) {
      appActions.showToast("多选组绑定规则请前往「智能多选组」页调整", "info");
      return;
    }
    if (found.builtin) {
      appActions.showToast("预加速防环保护规则不可删除，防止回环断网", "warn");
      return;
    }
    setUserRules((prev) => prev.filter((r) => r.id !== id));
    appActions.showToast("已删除该分流规则", "info");
  };

  const handleToggleAiPreset = (id: string) => {
    setAiPresets((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const handleChangeAiPresetTarget = (id: string, targetGroup: string) => {
    setAiPresets((prev) =>
      prev.map((p) => (p.id === id ? { ...p, targetGroup } : p))
    );
  };

  const handleCopyYaml = async () => {
    try {
      await navigator.clipboard.writeText(compiledOverrideYaml);
      setCopiedYaml(true);
      appActions.showToast("已复制声明式规则覆写 YAML 预览", "ok");
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

  // --- Connections filtering & teardown ---
  const filteredConnections = useMemo(() => {
    const kw = connSearch.trim().toLowerCase();
    const list = connections.filter((c) => {
      if (connGroupFilter !== "all" && c.groupId !== connGroupFilter) return false;
      if (!kw) return true;
      return (
        c.process.toLowerCase().includes(kw) ||
        c.host.toLowerCase().includes(kw) ||
        c.dstIp.includes(kw) ||
        c.rule.toLowerCase().includes(kw) ||
        c.nodeName.toLowerCase().includes(kw) ||
        c.groupName.toLowerCase().includes(kw)
      );
    });

    list.sort((a, b) => {
      if (connSort === "down") return b.downloadBytes - a.downloadBytes;
      if (connSort === "up") return b.uploadBytes - a.uploadBytes;
      if (connSort === "age") return a.startedAtMs - b.startedAtMs;
      return a.process.localeCompare(b.process);
    });
    return list;
  }, [connGroupFilter, connSearch, connSort, connections]);

  const totalConnUpload = useMemo(
    () => filteredConnections.reduce((acc, c) => acc + c.uploadBytes, 0),
    [filteredConnections]
  );
  const totalConnDownload = useMemo(
    () => filteredConnections.reduce((acc, c) => acc + c.downloadBytes, 0),
    [filteredConnections]
  );

  const handleCloseSingleConn = async (conn: LiveConnection) => {
    try {
      await catcloudApi.closeConnection(conn.id);
      setConnections((prev) => prev.filter((c) => c.id !== conn.id));
      appActions.showToast(`已精准踢断连接：${conn.process} -> ${conn.host}`, "ok");
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
      appActions.showToast("请先选择要清理连接的策略组", "warn");
      return;
    }

    try {
      const closed = await catcloudApi.closeGroupConnections(targetGroupName);
      setConnections((prev) =>
        prev.filter((c) => c.groupId !== targetGroupId && c.groupName !== targetGroupName)
      );
      appActions.showToast(
        `已按组踢断「${targetGroupName}」的 ${closed} 条旧连接`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`按组断开连接失败：${formatErrorMessage(err)}`, "warn");
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
      setConnections([]);
      setConfirmCloseAll(false);
      appActions.showToast(`已断开全部 ${shownCount} 条活跃连接`, "ok");
    } catch (err) {
      setConfirmCloseAll(false);
      appActions.showToast(`断开全部连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleRefreshConns = async () => {
    await fetchLiveConnections(true);
    appActions.showToast("已刷新实时活跃连接快照", "info");
  };

  const enabledAiDomainCount = aiPresets
    .filter((p) => p.enabled)
    .reduce((acc, p) => acc + p.domains.length, 0);

  return (
    <div className="space-y-4">
      {/* Top Tab Bar & Quick Overview */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--accent)]">
            <Network className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold text-[var(--text)]">分流规则与实时活跃连接</h1>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              声明式分流覆写管线（含内置 AI 预设）与按进程 / 规则 / 多选组精准踢断僵尸连接。
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
            分流规则管理
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {userRules.length + groupBoundRules.length + enabledAiDomainCount}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("connections")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition-colors ${
              activeTab === "connections"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            实时活跃连接
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {connections.length}
            </span>
          </button>
        </div>
      </section>

      {activeTab === "rules" ? (
        <div className="space-y-4">
          {/* Built-in AI Routing Presets */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  内置 AI 分流预设（OpenAI / Anthropic / Gemini / Windsurf & Codeium）
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setShowYamlPreview((v) => !v)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
              >
                <Code2 className="h-3.5 w-3.5 text-[var(--accent)]" />
                {showYamlPreview ? "收起覆写 YAML 预览" : "声明式覆写 YAML 预览"}
              </button>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {aiPresets.map((preset) => (
                <div
                  key={preset.id}
                  className={`rounded-xl border p-3.5 transition-colors ${
                    preset.enabled
                      ? "border-[var(--line-strong)] bg-[var(--bg-elevated)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)]/50 opacity-70"
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
                      onClick={() => handleToggleAiPreset(preset.id)}
                      className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
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
                    <span className="text-[var(--muted)]">命中策略组</span>
                    <select
                      value={preset.targetGroup}
                      onChange={(e) => handleChangeAiPresetTarget(preset.id, e.target.value)}
                      className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                    >
                      {targetChoices.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Declarative Override YAML Preview */}
          {showYamlPreview && (
            <section className="cc-card cc-glass overflow-hidden rounded-2xl">
              <div className="flex items-center justify-between border-b border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-2.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text)]">
                  <Eye className="h-3.5 w-3.5 text-[var(--accent)]" />
                  声明式规则覆写编译预览（YAML）
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopyYaml()}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                >
                  {copiedYaml ? (
                    <Check className="h-3 w-3 text-[var(--green)]" />
                  ) : (
                    <Copy className="h-3 w-3 text-[var(--accent)]" />
                  )}
                  复制 YAML
                </button>
              </div>
              <pre className="cc-selectable cc-mono max-h-[260px] overflow-auto p-4 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                {compiledOverrideYaml}
              </pre>
            </section>
          )}

          {/* Add New Rule Form */}
          <section className="cc-card cc-glass rounded-2xl p-4">
            <h2 className="mb-3 text-xs font-semibold text-[var(--text)]">新增自定义分流规则</h2>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-12">
              <select
                value={newLayer}
                onChange={(e) => setNewLayer(e.target.value as RuleLayer)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none lg:col-span-2"
              >
                <option value="prepend">全局前置规则</option>
                <option value="group">自定义组绑定</option>
                <option value="append">全局附加规则</option>
              </select>

              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value as RuleMatchType)}
                className="cc-mono rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none lg:col-span-2"
              >
                <option value="DOMAIN-SUFFIX">DOMAIN-SUFFIX</option>
                <option value="DOMAIN">DOMAIN</option>
                <option value="DOMAIN-KEYWORD">DOMAIN-KEYWORD</option>
                <option value="IP-CIDR">IP-CIDR</option>
                <option value="PROCESS-NAME">PROCESS-NAME</option>
                <option value="GEOSITE">GEOSITE</option>
                <option value="GEOIP">GEOIP</option>
              </select>

              <input
                type="text"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddRule();
                }}
                placeholder="匹配值，例如 example.com 或 203.0.113.0/24"
                className="cc-mono rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none lg:col-span-4"
              />

              <select
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none lg:col-span-2"
              >
                {targetChoices.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>

              <button
                type="button"
                onClick={handleAddRule}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 lg:col-span-2"
              >
                <Plus className="h-3.5 w-3.5" />
                加入规则
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
                附加 <span className="cc-mono text-[var(--text)]">no-resolve</span>（不触发远程 DNS 解析，直连防环推荐）
              </label>
            )}
          </section>

          {/* Rule List with Search & Layer Filter */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-3">
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {(
                  [
                    { id: "all", label: "全部层级" },
                    { id: "prepend", label: "全局前置" },
                    { id: "group", label: "多选组绑定" },
                    { id: "append", label: "全局附加" },
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
                  placeholder="快速搜索规则域名、类型或目标组..."
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
              {allDisplayRules.length === 0 ? (
                <div className="py-10 text-center text-xs text-[var(--muted)]">
                  暂无匹配的分流规则
                </div>
              ) : (
                allDisplayRules.map((item) => (
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
                          ? "全局前置"
                          : item.layer === "group"
                            ? "组绑定"
                            : "全局附加"}
                      </span>

                      <span className="cc-mono rounded border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
                        {item.ruleType}
                      </span>

                      <span className="cc-mono cc-selectable font-medium text-[var(--text)]">
                        {item.value}
                      </span>

                      {item.noResolve && (
                        <span className="cc-mono text-[10px] text-[var(--muted)]">
                          no-resolve
                        </span>
                      )}

                      {item.builtin && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] text-[var(--green)]">
                          <Shield className="h-2.5 w-2.5" />
                          防环锁定
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2.5">
                      <span className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
                        → {item.target}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleDeleteRule(item.id)}
                        disabled={Boolean(item.builtin)}
                        className="rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--red-soft)] hover:text-[var(--red)] disabled:cursor-not-allowed disabled:opacity-35"
                        title={
                          item.builtin
                            ? "内置防环保护规则不可删除"
                            : item.groupId
                              ? "多选组绑定规则"
                              : "删除此规则"
                        }
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      ) : (
        /* ======================== TAB B: LIVE CONNECTIONS ======================== */
        <div className="space-y-4">
          {/* Connections KPI & Batch Teardown Controls */}
          <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
            <div className="flex flex-wrap items-center gap-4 text-xs">
              <div>
                <span className="text-[var(--muted)]">筛选活跃连接</span>
                <div className="cc-mono mt-0.5 text-base font-semibold text-[var(--text)]">
                  {filteredConnections.length}
                  <span className="ml-1 text-[11px] font-normal text-[var(--muted)]">
                    / {connections.length}
                  </span>
                </div>
              </div>
              <div className="h-7 w-px bg-[var(--line)]" />
              <div>
                <span className="text-[var(--muted)]">连接累计上传</span>
                <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--coral)]">
                  ↑ {formatBytes(totalConnUpload)}
                </div>
              </div>
              <div>
                <span className="text-[var(--muted)]">连接累计下载</span>
                <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--sky)]">
                  ↓ {formatBytes(totalConnDownload)}
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
                {connPaused ? "恢复刷新" : "暂停刷新"}
              </button>

              <button
                type="button"
                onClick={() => void handleCloseByGroup()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--amber)] hover:opacity-90"
                title="断开所选多选组下的全部旧连接，解决切节点后 HTTP/2 长连接粘滞"
              >
                <Zap className="h-3.5 w-3.5" />
                按组批量踢断旧连接
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
                {confirmCloseAll ? "再次点击确认断开全部" : "断开全部连接"}
              </button>
            </div>
          </section>

          {/* Connections Filter & Sort Bar */}
          <section className="cc-card cc-glass flex flex-wrap items-center gap-2.5 rounded-2xl p-3.5">
            <div className="relative min-w-[240px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={connSearch}
                onChange={(e) => setConnSearch(e.target.value)}
                placeholder="按进程名、目标域名/IP、命中规则或当前节点过滤..."
                className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
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

            <div className="flex items-center gap-1.5 text-xs">
              <Filter className="h-3.5 w-3.5 text-[var(--muted)]" />
              <select
                value={connGroupFilter}
                onChange={(e) => setConnGroupFilter(e.target.value)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
              >
                <option value="all">全部多选组</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>

              <select
                value={connSort}
                onChange={(e) =>
                  setConnSort(e.target.value as "down" | "up" | "age" | "process")
                }
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
              >
                <option value="down">按下载流量排序</option>
                <option value="up">按上传流量排序</option>
                <option value="age">按持续时长排序</option>
                <option value="process">按进程名排序</option>
              </select>

              <button
                type="button"
                disabled={refreshingConns}
                onClick={() => void handleRefreshConns()}
                className="inline-flex h-8 w-8 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                title="重新拉取连接快照"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${refreshingConns ? "animate-spin" : ""}`} />
              </button>
            </div>
          </section>

          {/* Connections Data Table */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[11px] text-[var(--muted)]">
                    <th className="px-4 py-2.5 font-medium">进程 / 协议</th>
                    <th className="px-3 py-2.5 font-medium">目标主机与端口</th>
                    <th className="px-3 py-2.5 font-medium">命中规则</th>
                    <th className="px-3 py-2.5 font-medium">策略组与当前节点</th>
                    <th className="px-3 py-2.5 text-right font-medium">上传 / 下载</th>
                    <th className="px-3 py-2.5 text-right font-medium">时长</th>
                    <th className="px-4 py-2.5 text-right font-medium">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--line)]">
                  {filteredConnections.length === 0 ? (
                    <tr>
                      <td
                        colSpan={7}
                        className="py-10 text-center text-xs text-[var(--muted)]"
                      >
                        当前无匹配的活跃连接
                      </td>
                    </tr>
                  ) : (
                    filteredConnections.map((conn) => (
                      <tr key={conn.id} className="hover:bg-[var(--card-hover)]">
                        <td className="px-4 py-2.5">
                          <div className="cc-mono font-semibold text-[var(--text)]">
                            {conn.process}
                          </div>
                          <span className="cc-mono mt-0.5 inline-block rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--muted)]">
                            {conn.network}
                          </span>
                        </td>

                        <td className="px-3 py-2.5">
                          <div className="cc-mono cc-selectable font-medium text-[var(--text)]">
                            {conn.host}:{conn.port}
                          </div>
                          <div className="cc-mono text-[10px] text-[var(--muted)]">
                            {conn.dstIp}
                          </div>
                        </td>

                        <td className="px-3 py-2.5">
                          <span className="cc-mono inline-block max-w-[210px] truncate rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10.5px] text-[var(--text-secondary)]">
                            {conn.rule}
                          </span>
                        </td>

                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[11px] font-medium text-[var(--accent)]">
                              {conn.groupName}
                            </span>
                            {conn.viaPreAccel && (
                              <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] text-[var(--green)]">
                                预加速
                              </span>
                            )}
                          </div>
                          <div className="cc-mono mt-0.5 text-[11px] text-[var(--text-secondary)]">
                            {conn.nodeName}
                          </div>
                        </td>

                        <td className="cc-mono px-3 py-2.5 text-right">
                          <div className="text-[11px] text-[var(--coral)]">
                            ↑ {formatBytes(conn.uploadBytes)}
                          </div>
                          <div className="text-[11px] text-[var(--sky)]">
                            ↓ {formatBytes(conn.downloadBytes)}
                          </div>
                        </td>

                        <td className="cc-mono px-3 py-2.5 text-right text-[11px] text-[var(--muted)]">
                          {formatDuration(conn.startedAtMs, nowTick)}
                        </td>

                        <td className="px-4 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => void handleCloseSingleConn(conn)}
                            className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] font-medium text-[var(--muted)] hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)]"
                          >
                            <X className="h-3 w-3" />
                            踢断
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
