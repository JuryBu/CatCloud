import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CheckCircle2,
  Clock,
  Filter,
  Gauge,
  Pause,
  Play,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  type ProbeDefinition,
  type ProbeKind,
  type ProbeSnapshot,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { MascotSprite } from "../components/MascotSprite";
import { appActions, useAppSelector } from "../store/appStore";

interface ProbeItem {
  id: string;
  name: string;
  kind: ProbeKind;
  target: string;
  method: string;
  expectedStatus?: number | null;
  bodyRegex?: string;
  payloadKb?: number;
  timeoutMs: number;
  builtin: boolean;
  enabled: boolean;
}

const PROBE_KIND_LABELS: Record<ProbeKind, string> = {
  latency: "测活延迟 URL",
  upload: "上行测速 URL",
  download: "下行测速 URL",
  keepalive: "60s 保活",
  google_cn: "Google 真值",
  unlock_regex: "正则解锁",
  external_cmd: "外部脚本探针",
};

const INITIAL_PROBES: ProbeItem[] = [
  {
    id: "builtin_latency",
    name: "标准连通延迟 204",
    kind: "latency",
    target: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 5000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_google_cn",
    name: "Google 侧真值防送中",
    kind: "google_cn",
    target: "https://www.google.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 6000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_upload",
    name: "上行吞吐 (512KB 快熔断)",
    kind: "upload",
    target: "https://speed.cloudflare.com/__up",
    method: "POST",
    expectedStatus: 200,
    payloadKb: 512,
    timeoutMs: 12000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_download",
    name: "下行吞吐测速",
    kind: "download",
    target: "https://speed.cloudflare.com/__down?bytes=2097152",
    method: "GET",
    expectedStatus: 200,
    payloadKb: 2048,
    timeoutMs: 12000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_keepalive_60s",
    name: "60s 静默长连接黑洞检测",
    kind: "keepalive",
    target: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 65000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_unlock_windsurf",
    name: "Windsurf / Codeium 解锁",
    kind: "unlock_regex",
    target: "https://windsurf.com",
    method: "GET",
    expectedStatus: 200,
    bodyRegex: "windsurf|codeium",
    timeoutMs: 8000,
    builtin: true,
    enabled: true,
  },
];

const UNLOCK_PRESETS: ReadonlyArray<{
  label: string;
  id: string;
  name: string;
  target: string;
  bodyRegex: string;
}> = [
  {
    label: "ChatGPT 预设",
    id: "unlock_chatgpt_api",
    name: "ChatGPT API 可达性",
    target: "https://api.openai.com/v1/models",
    bodyRegex: "invalid_api_key|unauthorized|data",
  },
  {
    label: "Claude 预设",
    id: "unlock_claude_web",
    name: "Claude 地区解锁校验",
    target: "https://claude.ai/login",
    bodyRegex: "claude",
  },
  {
    label: "Windsurf 预设",
    id: "unlock_windsurf_ide",
    name: "Windsurf IDE 通道校验",
    target: "https://windsurf.com",
    bodyRegex: "windsurf|codeium",
  },
];

function fromProbeDefinition(def: ProbeDefinition): ProbeItem {
  return {
    id: def.id,
    name: def.name,
    kind: def.kind,
    target: def.target_url,
    method: def.method,
    expectedStatus: def.expected_status ?? null,
    bodyRegex: def.body_regex ?? undefined,
    payloadKb:
      typeof def.payload_bytes === "number" && def.payload_bytes > 0
        ? Math.max(1, Math.round(def.payload_bytes / 1024))
        : undefined,
    timeoutMs: def.timeout_ms,
    builtin: def.builtin,
    enabled: true,
  };
}

function toProbeDefinition(item: ProbeItem): ProbeDefinition {
  return {
    id: item.id,
    name: item.name,
    kind: item.kind,
    target_url: item.target,
    method: item.method,
    expected_status:
      item.expectedStatus ??
      (item.kind === "latency" || item.kind === "google_cn" || item.kind === "keepalive"
        ? 204
        : 200),
    body_regex: item.bodyRegex?.trim() ? item.bodyRegex.trim() : null,
    payload_bytes:
      typeof item.payloadKb === "number" && item.payloadKb > 0
        ? Math.round(item.payloadKb * 1024)
        : null,
    timeout_ms: item.timeoutMs,
    builtin: item.builtin,
  };
}

type FunnelStageKey = "l0" | "l1" | "l2";
type FunnelStageState = "idle" | "running" | "done" | "skipped";

interface FunnelProgress {
  l0: { status: FunnelStageState; pct: number; passed: number; total: number };
  l1: { status: FunnelStageState; pct: number; passed: number; total: number };
  l2: { status: FunnelStageState; pct: number; passed: number; total: number };
}

type SortKey =
  | "name"
  | "source"
  | "region"
  | "multiplier"
  | "latency"
  | "up"
  | "down"
  | "google"
  | "keepalive"
  | "unlocks";

type SortDir = "asc" | "desc";

function formatFormulaHint(probe: ProbeItem): string {
  switch (probe.kind) {
    case "upload":
      return `probe_up("${probe.id}")`;
    case "download":
      return `probe_down("${probe.id}")`;
    case "latency":
      return `probe_ping("${probe.id}")`;
    default:
      return `probe_ok("${probe.id}")`;
  }
}

export function SpeedTestPage() {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const storeProbes = useAppSelector((s) => s.probes);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  const [snapshots, setSnapshots] = useState<Record<string, ProbeSnapshot>>(storeProbes);
  const [probeList, setProbeList] = useState<ProbeItem[]>(() => (inTauri ? [] : INITIAL_PROBES));

  // Add Probe Form State
  const [showAddProbe, setShowAddProbe] = useState(false);
  const [newProbeId, setNewProbeId] = useState("");
  const [newProbeName, setNewProbeName] = useState("");
  const [newProbeKind, setNewProbeKind] = useState<ProbeKind>("upload");
  const [newProbeTarget, setNewProbeTarget] = useState("");
  const [newProbeRegex, setNewProbeRegex] = useState("");
  const [newProbePayloadKb, setNewProbePayloadKb] = useState(512);
  const [newProbeTimeoutMs, setNewProbeTimeoutMs] = useState(10000);

  // Funnel Execution State
  const [running, setRunning] = useState(false);
  const [runMode, setRunMode] = useState<"full" | "lite">("full");
  const [funnel, setFunnel] = useState<FunnelProgress>({
    l0: { status: "idle", pct: 0, passed: 0, total: nodes.length },
    l1: { status: "idle", pct: 0, passed: 0, total: nodes.length },
    l2: { status: "idle", pct: 0, passed: 0, total: nodes.length },
  });

  // Matrix Filters & Sorting
  const [searchQuery, setSearchQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [onlyGoogleClean, setOnlyGoogleClean] = useState(false);
  const [onlyKeepAliveOk, setOnlyKeepAliveOk] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("up");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const syncedRef = useRef(false);
  const timersRef = useRef<number[]>([]);
  const cancelledRunRef = useRef(false);

  const clearAllTimers = () => {
    for (const id of timersRef.current) {
      window.clearTimeout(id);
    }
    timersRef.current = [];
  };

  useEffect(() => {
    return () => {
      cancelledRunRef.current = true;
      clearAllTimers();
    };
  }, []);

  useEffect(() => {
    let active = true;
    void catcloudApi
      .listProbeDefinitions()
      .then((defs) => {
        if (!active) return;
        if (defs.length > 0 || inTauri) {
          setProbeList(defs.map(fromProbeDefinition));
        }
      })
      .catch((err) => {
        if (active && inTauri) {
          appActions.showToast(`加载探针定义失败：${formatErrorMessage(err)}`, "warn");
        }
      });
    return () => {
      active = false;
    };
  }, [inTauri]);

  useEffect(() => {
    if (initialized && !syncedRef.current) {
      syncedRef.current = true;
      setSnapshots(storeProbes);
      const count = nodes.length;
      const hasAny = Object.keys(storeProbes).length > 0;
      if (hasAny && count > 0) {
        const l0Passed = nodes.filter((n) => storeProbes[n.id]?.ok).length;
        const l1Passed = nodes.filter((n) => storeProbes[n.id]?.google_clean === true).length;
        const l2Passed = nodes.filter((n) => storeProbes[n.id]?.up_mbps != null).length;
        setFunnel({
          l0: { status: "done", pct: 100, passed: l0Passed, total: count },
          l1: { status: "done", pct: 100, passed: l1Passed, total: count },
          l2: { status: "done", pct: 100, passed: l2Passed, total: count },
        });
      }
    }
  }, [storeProbes, nodes, initialized]);

  const subNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const sub of subscriptions) {
      map.set(sub.id, sub.name);
    }
    return map;
  }, [subscriptions]);

  const scheduleStep = (fn: () => void, delayMs: number) => {
    const id = window.setTimeout(() => {
      timersRef.current = timersRef.current.filter((item) => item !== id);
      fn();
    }, delayMs);
    timersRef.current.push(id);
  };

  const handleStopTest = () => {
    cancelledRunRef.current = true;
    clearAllTimers();
    setRunning(false);
    appActions.setMascotState("idle");
    appActions.showToast("已中止当前测速状态监听", "info");
  };

  const handleStartTest = async (mode: "full" | "lite") => {
    if (running) return;
    if (nodes.length === 0) {
      appActions.showToast("当前节点库为空，请先导入订阅节点", "warn");
      return;
    }

    const enabledProbes = probeList.filter((p) => p.enabled);
    const selectedProbes =
      mode === "lite"
        ? enabledProbes.filter(
            (p) => p.kind === "latency" || p.kind === "google_cn" || p.kind === "unlock_regex"
          )
        : enabledProbes;

    if (selectedProbes.length === 0) {
      appActions.showToast("请至少启用一个匹配的探针后再开始测速", "warn");
      return;
    }

    clearAllTimers();
    cancelledRunRef.current = false;
    setRunMode(mode);
    setRunning(true);
    appActions.setMascotState("searching");
    const total = nodes.length;

    setFunnel({
      l0: { status: "running", pct: 35, passed: 0, total },
      l1: { status: "running", pct: 20, passed: 0, total },
      l2: { status: mode === "lite" ? "skipped" : "running", pct: mode === "lite" ? 0 : 15, passed: 0, total },
    });

    if (inTauri) {
      try {
        const nodeIds = nodes.map((n) => n.id);
        const probeIds = selectedProbes.map((p) => p.id);
        const result = await catcloudApi.runIsolatedProbes(nodeIds, probeIds);
        if (cancelledRunRef.current) return;

        const mergedSnapshots: Record<string, ProbeSnapshot> = {
          ...snapshots,
          ...result.snapshots,
        };
        setSnapshots(mergedSnapshots);
        appActions.syncProbes(mergedSnapshots);

        const l0Passed = nodes.filter((n) => mergedSnapshots[n.id]?.ok).length;
        const l1Passed = nodes.filter((n) => mergedSnapshots[n.id]?.google_clean === true).length;
        const l2Passed = nodes.filter(
          (n) =>
            mergedSnapshots[n.id]?.up_mbps != null ||
            mergedSnapshots[n.id]?.down_mbps != null ||
            mergedSnapshots[n.id]?.keepalive_60s_ok === true
        ).length;

        setFunnel({
          l0: { status: "done", pct: 100, passed: l0Passed, total },
          l1: { status: "done", pct: 100, passed: l1Passed, total },
          l2:
            mode === "lite"
              ? { status: "skipped", pct: 0, passed: 0, total }
              : { status: "done", pct: 100, passed: l2Passed, total },
        });

        if (!result.core_available) {
          appActions.showToast(
            result.errors[0] ?? "测速核心未就绪，请先确认 Mihomo 二进制存在并配置正确",
            "warn"
          );
        } else if (result.errors.length > 0) {
          appActions.showToast(
            `测速完成 ${result.probed_count}/${total} 节点（${result.errors.length} 项警告：${result.errors[0]}）`,
            "warn"
          );
        } else {
          appActions.showToast(
            mode === "full"
              ? `三级零干扰漏斗测速完成（${result.probed_count} 节点，临时核心已释放）`
              : `L0+L1 极速省流测活完成（${result.probed_count} 节点）`,
            "ok"
          );
        }
      } catch (err) {
        if (!cancelledRunRef.current) {
          setFunnel({
            l0: { status: "idle", pct: 0, passed: 0, total },
            l1: { status: "idle", pct: 0, passed: 0, total },
            l2: { status: "idle", pct: 0, passed: 0, total },
          });
          appActions.showToast(`隔离测速执行失败：${formatErrorMessage(err)}`, "warn");
        }
      } finally {
        if (!cancelledRunRef.current) {
          setRunning(false);
          appActions.setMascotState("idle");
        }
      }
      return;
    }

    // Browser preview demonstration only (marked explicitly as preview simulation)
    scheduleStep(() => {
      setFunnel((prev) => ({
        ...prev,
        l0: { status: "done", pct: 100, passed: total, total },
        l1: { status: "running", pct: 60, passed: 0, total },
      }));
    }, 360);

    scheduleStep(() => {
      void catcloudApi
        .runIsolatedProbes(
          nodes.map((n) => n.id),
          selectedProbes.map((p) => p.id)
        )
        .then((res) => {
          if (cancelledRunRef.current) return;
          const merged = { ...snapshots, ...res.snapshots };
          setSnapshots(merged);
          appActions.syncProbes(merged);
          setFunnel({
            l0: { status: "done", pct: 100, passed: total, total },
            l1: { status: "done", pct: 100, passed: total, total },
            l2:
              mode === "lite"
                ? { status: "skipped", pct: 0, passed: 0, total }
                : { status: "done", pct: 100, passed: total, total },
          });
          setRunning(false);
          appActions.setMascotState("idle");
          appActions.showToast(`预览模拟：已完成 ${total} 节点测速演示`, "info");
        });
    }, 780);
  };

  const handleAddProbe = async (ev: FormEvent) => {
    ev.preventDefault();
    const trimmedName = newProbeName.trim();
    const trimmedTarget = newProbeTarget.trim();
    if (!trimmedName || !trimmedTarget) {
      appActions.showToast("请填写探针名称与目标 URL 或命令", "warn");
      return;
    }

    if (newProbeKind !== "external_cmd") {
      try {
        const parsed = new URL(trimmedTarget);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          appActions.showToast("探针 URL 仅支持 HTTP / HTTPS 协议", "warn");
          return;
        }
      } catch {
        appActions.showToast("请输入有效的探针目标 URL", "warn");
        return;
      }
    }

    const safeId = (
      newProbeId.trim() || `custom_${newProbeKind}_${Date.now().toString(36)}`
    ).replace(/[^a-zA-Z0-9_-]/g, "_");

    if (probeList.some((p) => p.id === safeId)) {
      appActions.showToast(`探针 ID「${safeId}」已存在，请更换`, "warn");
      return;
    }

    const created: ProbeItem = {
      id: safeId,
      name: trimmedName,
      kind: newProbeKind,
      target: trimmedTarget,
      method: newProbeKind === "upload" ? "POST" : newProbeKind === "external_cmd" ? "EXEC" : "GET",
      bodyRegex: newProbeKind === "unlock_regex" && newProbeRegex.trim() ? newProbeRegex.trim() : undefined,
      payloadKb:
        newProbeKind === "upload" || newProbeKind === "download"
          ? Math.max(64, newProbePayloadKb)
          : undefined,
      timeoutMs: Math.max(1000, newProbeTimeoutMs),
      builtin: false,
      enabled: true,
    };

    try {
      const saved = await catcloudApi.upsertProbeDefinition(toProbeDefinition(created));
      setProbeList((prev) => [...prev, fromProbeDefinition(saved)]);
      setNewProbeId("");
      setNewProbeName("");
      setNewProbeTarget("");
      setNewProbeRegex("");
      setShowAddProbe(false);
      appActions.showToast(`已注册自定义探针：${saved.name} (${saved.id})`, "ok");
    } catch (err) {
      appActions.showToast(`保存探针失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleProbe = (id: string) => {
    setProbeList((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const handleDeleteProbe = async (id: string) => {
    try {
      await catcloudApi.deleteProbeDefinition(id);
      setProbeList((prev) => prev.filter((p) => p.id !== id));
      appActions.showToast("已移除自定义探针", "info");
    } catch (err) {
      appActions.showToast(`删除探针失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "latency" || key === "multiplier" || key === "name" ? "asc" : "desc");
    }
  };

  const matrixRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = nodes
      .map((node) => {
        const snap = snapshots[node.id];
        const sourceName = subNameById.get(node.sub_id) ?? node.sub_id;
        const unlocks = {
          gemini: snap?.unlocked_sites.gemini ?? snap?.unlocked_sites.google_ai ?? false,
          chatgpt: snap?.unlocked_sites.chatgpt ?? false,
          claude: snap?.unlocked_sites.claude ?? false,
          windsurf: snap?.unlocked_sites.windsurf ?? snap?.per_probe_ok?.builtin_unlock_windsurf ?? false,
        };
        const unlockScore = Object.values(unlocks).filter(Boolean).length;
        const cfYtMismatch =
          Boolean(snap?.google_risk_mismatch) ||
          Boolean(
            snap?.cf_loc &&
              snap?.yt_gl &&
              snap.yt_gl.toUpperCase() !== node.region_code.toUpperCase()
          );
        return { node, snap, sourceName, unlocks, unlockScore, cfYtMismatch };
      })
      .filter((row) => {
        if (q) {
          const hay = `${row.node.name} ${row.sourceName} ${row.node.region_code} ${row.node.protocol}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        if (sourceFilter !== "all" && row.node.sub_id !== sourceFilter) return false;
        if (onlyGoogleClean && row.snap?.google_clean !== true) return false;
        if (onlyKeepAliveOk && row.snap?.keepalive_60s_ok !== true) return false;
        return true;
      });

    list.sort((a, b) => {
      let diff = 0;
      switch (sortKey) {
        case "name":
          diff = a.node.name.localeCompare(b.node.name);
          break;
        case "source":
          diff = a.sourceName.localeCompare(b.sourceName);
          break;
        case "region":
          diff = a.node.region_code.localeCompare(b.node.region_code);
          break;
        case "multiplier":
          diff = a.node.multiplier - b.node.multiplier;
          break;
        case "latency":
          diff = (a.snap?.latency_ms ?? 99999) - (b.snap?.latency_ms ?? 99999);
          break;
        case "up":
          diff = (a.snap?.up_mbps ?? -1) - (b.snap?.up_mbps ?? -1);
          break;
        case "down":
          diff = (a.snap?.down_mbps ?? -1) - (b.snap?.down_mbps ?? -1);
          break;
        case "google":
          diff = (a.snap?.google_clean ? 1 : 0) - (b.snap?.google_clean ? 1 : 0);
          break;
        case "keepalive":
          diff = (a.snap?.keepalive_60s_ok ? 1 : 0) - (b.snap?.keepalive_60s_ok ? 1 : 0);
          break;
        case "unlocks":
          diff = a.unlockScore - b.unlockScore;
          break;
      }
      return sortDir === "asc" ? diff : -diff;
    });

    return list;
  }, [nodes, snapshots, subNameById, searchQuery, sourceFilter, onlyGoogleClean, onlyKeepAliveOk, sortKey, sortDir]);

  const funnelStages: ReadonlyArray<{
    key: FunnelStageKey;
    step: string;
    title: string;
    detail: string;
    budget: string;
  }> = [
    {
      key: "l0",
      step: "L0",
      title: "连通延迟与抖动",
      detail: "并发 204 握手 · 快速淘汰超时与高丢包节点",
      budget: "~4 KB/节点",
    },
    {
      key: "l1",
      step: "L1",
      title: "Google 真值防送中 & AI 解锁",
      detail: "Google 侧硬门禁校验 + ChatGPT / Claude / Windsurf 解锁",
      budget: "~32 KB/节点",
    },
    {
      key: "l2",
      step: "L2",
      title: "自定义上下行 + 512KB 快熔断 & 60s 保活",
      detail: "低速 512KB 立即止损省流 · 检测 60s 静默长连接黑洞",
      budget: "仅测 L1 达标项",
    },
  ];

  const renderSortIcon = (key: SortKey) => {
    if (sortKey !== key) {
      return <ArrowUpDown className="h-3 w-3 opacity-45" />;
    }
    return sortDir === "asc" ? (
      <ArrowUp className="h-3 w-3 text-[var(--accent)]" />
    ) : (
      <ArrowDown className="h-3 w-3 text-[var(--accent)]" />
    );
  };

  return (
    <div className="space-y-4">
      {/* Top Zero-Interference Isolated SpeedTest Console */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-3.5">
            <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)]">
              <MascotSprite state="searching" scale={2} title="零干扰隔离测速 · 放大镜猫咪" />
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                  零干扰隔离测速控制台
                </h1>
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--green)]">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  独立临时核心 127.0.0.1 · 现役业务 0 断流
                </span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-[var(--muted)]">
                测速期间按需拉起隔离临时 Mihomo（强制{" "}
                <span className="cc-mono text-[var(--text-secondary)]">redir-host</span> +{" "}
                <span className="cc-mono text-[var(--text-secondary)]">GOMEMLIMIT=32MiB</span> +{" "}
                <span className="cc-mono text-[var(--text-secondary)]">socks5h://</span>），规避现役 TUN Fake-IP 污染，测完由 JobGuard 自动彻底回收。
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button
                type="button"
                onClick={handleStopTest}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--red)]/50 bg-[var(--red-soft)] px-4 py-2 text-xs font-semibold text-[var(--red)] transition-opacity hover:opacity-90"
              >
                <Pause className="h-3.5 w-3.5" />
                <span>终止测速</span>
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => void handleStartTest("full")}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  <Play className="h-3.5 w-3.5" />
                  <span>一键零干扰测速 (L0→L2)</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleStartTest("lite")}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                >
                  <Gauge className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span>仅测 L0+L1 省流</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* 3-Stage Data-Saving Funnel Progress Bar */}
        <div className="mt-4 grid grid-cols-1 gap-2.5 md:grid-cols-3">
          {funnelStages.map((stage) => {
            const st = funnel[stage.key];
            const barColor =
              st.status === "done"
                ? "var(--green)"
                : st.status === "running"
                  ? "var(--accent)"
                  : "var(--line-strong)";
            const badgeText =
              st.status === "done"
                ? `通过 ${st.passed}/${st.total}`
                : st.status === "running"
                  ? "探测中..."
                  : st.status === "skipped"
                    ? "本次跳过"
                    : "待命";
            return (
              <div
                key={stage.key}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 cc-mono text-[10px] font-semibold text-[var(--accent)]">
                      {stage.step}
                    </span>
                    <span className="text-xs font-semibold text-[var(--text)]">{stage.title}</span>
                  </div>
                  <span
                    className="cc-mono text-[10px] font-medium"
                    style={{
                      color:
                        st.status === "done"
                          ? "var(--green)"
                          : st.status === "running"
                            ? "var(--accent)"
                            : "var(--muted)",
                    }}
                  >
                    {badgeText}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-[var(--muted)]">{stage.detail}</p>
                <div className="mt-2.5 flex items-center gap-2">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--card)]">
                    <div
                      className="h-full rounded-full transition-all duration-300"
                      style={{ width: `${st.pct}%`, backgroundColor: barColor }}
                    />
                  </div>
                  <span className="shrink-0 cc-mono text-[10px] text-[var(--muted)]">
                    {stage.budget}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
        {running && (
          <div className="mt-2.5 flex items-center gap-2 text-[11px] text-[var(--accent)]">
            <Clock className="h-3.5 w-3.5" />
            <span>
              正在独立临时核心中运行「{runMode === "full" ? "L0→L1→L2 完整漏斗" : "L0→L1 省流模式"}」
              ，当前现役代理连接零中断…
            </span>
          </div>
        )}
      </section>

      {/* Extensible Probe Registry Panel */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              可扩展探针管理面板（Probe Registry）
            </h2>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              管理内置与自定义探针，支持在「智能多选组」公式中通过探针 ID 精确引用实测指标
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowAddProbe((v) => !v)}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
          >
            {showAddProbe ? <X className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
            <span>{showAddProbe ? "收起表单" : "新增探针"}</span>
          </button>
        </div>

        {/* Add Custom Probe Form */}
        {showAddProbe && (
          <form
            onSubmit={(ev) => void handleAddProbe(ev)}
            className="mb-3.5 space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5 text-xs"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-semibold text-[var(--text)]">注册自定义探针</span>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-[var(--muted)]">正则解锁快捷模板：</span>
                {UNLOCK_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => {
                      setNewProbeKind("unlock_regex");
                      setNewProbeId(preset.id);
                      setNewProbeName(preset.name);
                      setNewProbeTarget(preset.target);
                      setNewProbeRegex(preset.bodyRegex);
                    }}
                    className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
              <label>
                <span className="text-[11px] text-[var(--muted)]">探针类型</span>
                <select
                  value={newProbeKind}
                  onChange={(e) => setNewProbeKind(e.target.value as ProbeKind)}
                  className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                >
                  <option value="latency">自定义测活 URL (latency)</option>
                  <option value="upload">上行测速 URL (upload)</option>
                  <option value="download">下行测速 URL (download)</option>
                  <option value="unlock_regex">正则解锁 (unlock_regex)</option>
                  <option value="keepalive">60s 保活 (keepalive)</option>
                  <option value="google_cn">Google 真值 (google_cn)</option>
                  <option value="external_cmd">外部脚本探针 (external_cmd)</option>
                </select>
              </label>

              <label>
                <span className="text-[11px] text-[var(--muted)]">显示名称</span>
                <input
                  type="text"
                  value={newProbeName}
                  onChange={(e) => setNewProbeName(e.target.value)}
                  placeholder="如 AI API 上行专项"
                  className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>

              <label>
                <span className="text-[11px] text-[var(--muted)]">公式寻址 ID（可选）</span>
                <input
                  type="text"
                  value={newProbeId}
                  onChange={(e) => setNewProbeId(e.target.value)}
                  placeholder="如 antigravity_up"
                  className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>

              <label>
                <span className="text-[11px] text-[var(--muted)]">超时 (ms)</span>
                <input
                  type="number"
                  min={1000}
                  max={65000}
                  value={newProbeTimeoutMs}
                  onChange={(e) => setNewProbeTimeoutMs(Number(e.target.value) || 8000)}
                  className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>
            </div>

            <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-12">
              <label className="lg:col-span-6">
                <span className="text-[11px] text-[var(--muted)]">
                  {newProbeKind === "external_cmd" ? "外部脚本命令（接收 JSON stdin）" : "目标探测 URL"}
                </span>
                <input
                  type="text"
                  value={newProbeTarget}
                  onChange={(e) => setNewProbeTarget(e.target.value)}
                  placeholder={
                    newProbeKind === "external_cmd"
                      ? "python scripts/custom_probe.py --timeout 8"
                      : "https://example.com/generate_204"
                  }
                  className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>

              {newProbeKind === "unlock_regex" ? (
                <label className="lg:col-span-4">
                  <span className="text-[11px] text-[var(--muted)]">响应正文匹配正则</span>
                  <input
                    type="text"
                    value={newProbeRegex}
                    onChange={(e) => setNewProbeRegex(e.target.value)}
                    placeholder="loc=(?!CN|HK)"
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>
              ) : newProbeKind === "upload" || newProbeKind === "download" ? (
                <label className="lg:col-span-4">
                  <span className="text-[11px] text-[var(--muted)]">
                    测试负载大小 (KB · 建议 512KB 快熔断)
                  </span>
                  <input
                    type="number"
                    min={64}
                    max={16384}
                    value={newProbePayloadKb}
                    onChange={(e) => setNewProbePayloadKb(Number(e.target.value) || 512)}
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>
              ) : (
                <div className="flex items-end text-[11px] text-[var(--muted)] lg:col-span-4">
                  支持经由隔离 socks5h 隧道独立执行
                </div>
              )}

              <div className="flex items-end lg:col-span-2">
                <button
                  type="submit"
                  className="w-full rounded-lg bg-[var(--accent)] py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  保存探针
                </button>
              </div>
            </div>
          </form>
        )}

        <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
          {probeList.map((probe) => (
            <div
              key={probe.id}
              className={`rounded-xl border p-3 transition-colors ${
                probe.enabled
                  ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                  : "border-[var(--line)]/60 bg-[var(--bg-elevated)]/50 opacity-70"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    {probe.kind === "external_cmd" && (
                      <Terminal className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    )}
                    <span className="truncate text-xs font-semibold text-[var(--text)]">
                      {probe.name}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                      {PROBE_KIND_LABELS[probe.kind]}
                    </span>
                    <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                      {probe.builtin ? "内置" : "自定义"}
                    </span>
                  </div>
                </div>

                <div className="flex shrink-0 items-center gap-1">
                  <button
                    type="button"
                    onClick={() => handleToggleProbe(probe.id)}
                    className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                      probe.enabled
                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                        : "bg-[var(--card)] text-[var(--muted)]"
                    }`}
                  >
                    {probe.enabled ? "启用" : "停用"}
                  </button>
                  {!probe.builtin && (
                    <button
                      type="button"
                      onClick={() => void handleDeleteProbe(probe.id)}
                      className="rounded-md p-1 text-[var(--muted)] hover:bg-[var(--card)] hover:text-[var(--red)]"
                      aria-label={`删除探针 ${probe.name}`}
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>

              <div className="mt-2 truncate cc-mono text-[10px] text-[var(--muted)]" title={probe.target}>
                {probe.target}
              </div>
              <div className="mt-1.5 flex items-center justify-between gap-2 border-t border-[var(--line)]/60 pt-1.5 cc-mono text-[10px]">
                <span className="truncate text-[var(--text-secondary)]">
                  {formatFormulaHint(probe)}
                </span>
                <span className="shrink-0 text-[var(--muted)]">{probe.timeoutMs}ms</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Multi-Dimensional Results Matrix Table */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="mb-3 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">多维测速结果矩阵</h2>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              点击任意列头升降序排序；Google 洁净度仅以 Google 侧真值作硬门禁，CF/YT 地区差异仅标风险提示
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="筛选节点 / 地区 / 协议"
                className="w-44 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-2.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1">
              <Filter className="h-3.5 w-3.5 text-[var(--muted)]" />
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="bg-transparent text-xs text-[var(--text)] outline-none"
              >
                <option value="all">全部来源订阅</option>
                {subscriptions.map((sub) => (
                  <option key={sub.id} value={sub.id}>
                    {sub.name}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              onClick={() => setOnlyGoogleClean((v) => !v)}
              className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                onlyGoogleClean
                  ? "border-[var(--green)]/50 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              仅 Google 洁净
            </button>

            <button
              type="button"
              onClick={() => setOnlyKeepAliveOk((v) => !v)}
              className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                onlyKeepAliveOk
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              仅 60s 保活通过
            </button>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl border border-[var(--line)]">
          <table className="w-full min-w-[960px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)] text-[11px] text-[var(--muted)]">
                {(
                  [
                    { key: "name", label: "节点名" },
                    { key: "source", label: "来源" },
                    { key: "region", label: "地区" },
                    { key: "multiplier", label: "倍率" },
                    { key: "latency", label: "延迟 / 抖动" },
                    { key: "up", label: "上行 Mbps" },
                    { key: "down", label: "下行 Mbps" },
                    { key: "google", label: "Google 洁净度" },
                    { key: "keepalive", label: "60s 保活" },
                    { key: "unlocks", label: "站点解锁" },
                  ] as ReadonlyArray<{ key: SortKey; label: string }>
                ).map((col) => (
                  <th key={col.key} className="px-3 py-2.5 font-medium">
                    <button
                      type="button"
                      onClick={() => handleSort(col.key)}
                      className="inline-flex items-center gap-1 text-left transition-colors hover:text-[var(--text)]"
                    >
                      <span>{col.label}</span>
                      {renderSortIcon(col.key)}
                    </button>
                  </th>
                ))}
              </tr>
            </thead>

            <tbody className="divide-y divide-[var(--line)]/70">
              {matrixRows.map(({ node, snap, sourceName, unlocks, cfYtMismatch }) => (
                <tr
                  key={node.id}
                  className="bg-[var(--card)]/40 transition-colors hover:bg-[var(--card-hover)]"
                >
                  {/* Node Name */}
                  <td className="px-3 py-2.5">
                    <div className="font-semibold text-[var(--text)]">{node.name}</div>
                    <div className="mt-0.5 flex items-center gap-1.5 cc-mono text-[10px] text-[var(--muted)]">
                      <span className="uppercase">{node.protocol}</span>
                      <span>:{node.port}</span>
                      {node.is_443_native && (
                        <span className="rounded bg-[var(--accent-soft)] px-1 text-[var(--accent)]">
                          原生 443
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Source Subscription */}
                  <td className="px-3 py-2.5 text-[var(--text-secondary)]">{sourceName}</td>

                  {/* Region */}
                  <td className="px-3 py-2.5 cc-mono">
                    <div className="font-semibold text-[var(--text)]">{node.region_code}</div>
                    {(snap?.cf_loc || snap?.yt_gl) && (
                      <div className="text-[10px] text-[var(--muted)]">
                        CF:{snap?.cf_loc ?? "-"} / YT:{snap?.yt_gl ?? "-"}
                      </div>
                    )}
                  </td>

                  {/* Multiplier */}
                  <td className="px-3 py-2.5 cc-mono cc-tabular">
                    <span
                      className={`rounded-md px-1.5 py-0.5 text-[11px] font-medium ${
                        node.multiplier <= 1.0
                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                          : "bg-[var(--amber-soft)] text-[var(--amber)]"
                      }`}
                    >
                      {node.multiplier.toFixed(1)}x
                    </span>
                  </td>

                  {/* Latency / Jitter */}
                  <td className="px-3 py-2.5 cc-mono cc-tabular">
                    <div className="font-semibold text-[var(--text)]">
                      {snap?.latency_ms !== null && snap?.latency_ms !== undefined
                        ? `${Math.round(snap.latency_ms)} ms`
                        : "--"}
                    </div>
                    <div className="text-[10px] text-[var(--muted)]">
                      ±{snap?.jitter_ms !== null && snap?.jitter_ms !== undefined ? snap.jitter_ms.toFixed(1) : "--"} ms
                    </div>
                  </td>

                  {/* Upload Mbps */}
                  <td className="px-3 py-2.5 cc-mono cc-tabular font-semibold text-[var(--coral)]">
                    {snap?.up_mbps !== null && snap?.up_mbps !== undefined
                      ? `${snap.up_mbps.toFixed(1)}`
                      : "--"}
                  </td>

                  {/* Download Mbps */}
                  <td className="px-3 py-2.5 cc-mono cc-tabular font-semibold text-[var(--sky)]">
                    {snap?.down_mbps !== null && snap?.down_mbps !== undefined
                      ? `${snap.down_mbps.toFixed(1)}`
                      : "--"}
                  </td>

                  {/* Google Cleanliness (Hard Gate vs CF/YT Advisory Tag) */}
                  <td className="px-3 py-2.5">
                    <div className="flex flex-col items-start gap-1">
                      {snap?.google_clean === true ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                          <CheckCircle2 className="h-3 w-3" />
                          Google 硬门禁洁净
                        </span>
                      ) : snap?.google_clean === false ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--red)]">
                          <XCircle className="h-3 w-3" />
                          送中拦截
                        </span>
                      ) : (
                        <span className="text-[11px] text-[var(--muted)]">待测</span>
                      )}

                      {cfYtMismatch && (
                        <span
                          className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                          title="CF 与 YouTube 归属不一致，仅作参考提示，不触发硬门禁误杀"
                        >
                          <AlertTriangle className="h-2.5 w-2.5" />
                          CF/YT 提示
                        </span>
                      )}
                    </div>
                  </td>

                  {/* 60s Keep-Alive */}
                  <td className="px-3 py-2.5">
                    {snap?.keepalive_60s_ok === true ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--green)]">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        通过
                      </span>
                    ) : snap?.keepalive_60s_ok === false ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--red)]">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        黑洞断开
                      </span>
                    ) : (
                      <span className="text-[11px] text-[var(--muted)]">未检</span>
                    )}
                  </td>

                  {/* Site Unlock Badges */}
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {(
                        [
                          { id: "gemini", label: "Gemini", ok: unlocks.gemini },
                          { id: "chatgpt", label: "ChatGPT", ok: unlocks.chatgpt },
                          { id: "claude", label: "Claude", ok: unlocks.claude },
                          { id: "windsurf", label: "Windsurf", ok: unlocks.windsurf },
                        ] as const
                      ).map((badge) => (
                        <span
                          key={badge.id}
                          className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                            badge.ok
                              ? "bg-[var(--green-soft)] text-[var(--green)]"
                              : "bg-[var(--bg-elevated)] text-[var(--muted)] line-through"
                          }`}
                        >
                          {badge.label}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}

              {matrixRows.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-4 py-8 text-center text-xs text-[var(--muted)]">
                    无符合筛选条件的节点测速记录。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
