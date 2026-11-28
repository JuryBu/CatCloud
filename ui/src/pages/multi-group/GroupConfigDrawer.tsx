import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Plus,
  RotateCcw,
  Save,
  Settings2,
  ShieldCheck,
  Sparkles,
  X,
  Zap,
} from "lucide-react";
import type { FormEvent, RefObject } from "react";
import { createPortal } from "react-dom";
import type {
  DynamicFilterSpec,
  FallbackPolicy,
  GroupEvaluationReport,
  MultiGroup,
  MultiGroupMode,
  TriggerRule,
} from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import type { useUiDict } from "../../i18n";
import {
  FORMULA_COST_EFFECTIVE,
  FORMULA_MAX_PERF,
  FORMULA_VARIABLES,
  GEMINI_GATE_EXPR,
  HARD_GATE_PRESETS,
  LEGACY_GEMINI_GATE_EXPR,
  PROBE_ADDRESS_SNIPPETS,
} from "../../utils/formulaEvaluator";
import { formatMatchRuleChip } from "../../utils/mihomoRuleParser";
import { formatGroupDisplayName } from "../../utils/releaseUrl";
import { GroupEvalSection } from "./GroupEvalModal";

export interface ModeMeta {
  id: MultiGroupMode;
  title: string;
  shortLabel: string;
  desc: string;
}

export const GROUP_MODES: readonly ModeMeta[] = [
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

export interface FallbackMeta {
  id: FallbackPolicy;
  title: string;
  desc: string;
  tone: "amber" | "accent" | "red";
}

export const FALLBACK_POLICIES: readonly FallbackMeta[] = [
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

export interface TriggerMeta {
  consecutiveFailures: number;
  bypassCooldownOnDisconnect: boolean;
}

export function formatDynamicFilter(filter: MultiGroup["dynamic_filter"]): string {
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

export function buildDynamicFilterUpdate(
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

export function getPrimaryTriggerExpr(group: MultiGroup): string {
  if (Array.isArray(group.trigger_rules) && group.trigger_rules.length > 0) {
    return group.trigger_rules[0].expr ?? "";
  }
  return group.trigger_expr ?? "";
}

export function getPrimaryTriggerMeta(group: MultiGroup): TriggerMeta {
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

export function parseUploadTriggerInfo(expr: string): {
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

export function normalizeGroupForBackend(group: MultiGroup, meta: TriggerMeta): MultiGroup {
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

export interface GroupConfigDrawerProps {
  selectedGroup: MultiGroup;
  selectedGroupDisplayName: string;
  otherGroups: MultiGroup[];
  isWideDesktop: boolean;
  advancedOpen: boolean;
  setAdvancedOpen: (value: boolean | ((prev: boolean) => boolean)) => void;
  setDrawerOpen: (value: boolean) => void;
  section5Ref: RefObject<HTMLDivElement | null>;
  dict: ReturnType<typeof useUiDict>;
  formattedDynamicFilter: string;
  customHardGates: string[];
  uploadTriggerInfo: {
    enabled: boolean;
    threshold: number;
    prefix: string;
    isSimple: boolean;
  };
  currentTriggerMeta: TriggerMeta;
  currentTriggerExpr: string;
  newRuleInput: string;
  setNewRuleInput: (value: string) => void;
  customGateInput: string;
  setCustomGateInput: (value: string) => void;
  formulaSyntaxCheck: {
    ok: boolean;
    error: string | null;
    source: "local" | "backend";
  };
  evaluating: boolean;
  anyEvaluating: boolean;
  evalReport: GroupEvaluationReport | null;
  evalUntestedCount: number;
  savingGroup: boolean;
  isSelectedDirty: boolean;
  updateSelectedGroup: (updater: (group: MultiGroup) => MultiGroup) => void;
  updateTriggerMeta: (patch: Partial<TriggerMeta>) => void;
  setPrimaryTriggerExpr: (nextExpr: string) => void;
  onToggleGate: (expr: string) => void;
  onAddCustomGate: (ev: FormEvent) => void;
  onToggleUploadTrigger: () => void;
  onUploadThresholdChange: (raw: string) => void;
  onAddMatchRule: (ev: FormEvent) => void;
  onInsertFormulaToken: (snippet: string) => void;
  onEvaluateBackend: () => void;
  onSaveSelectedGroup: () => void;
}

export function GroupConfigDrawer({
  selectedGroup,
  selectedGroupDisplayName,
  otherGroups,
  isWideDesktop,
  advancedOpen,
  setAdvancedOpen,
  setDrawerOpen,
  section5Ref,
  dict,
  formattedDynamicFilter,
  customHardGates,
  uploadTriggerInfo,
  currentTriggerMeta,
  currentTriggerExpr,
  newRuleInput,
  setNewRuleInput,
  customGateInput,
  setCustomGateInput,
  formulaSyntaxCheck,
  evaluating,
  anyEvaluating,
  evalReport,
  evalUntestedCount,
  savingGroup,
  isSelectedDirty,
  updateSelectedGroup,
  updateTriggerMeta,
  setPrimaryTriggerExpr,
  onToggleGate,
  onAddCustomGate,
  onToggleUploadTrigger,
  onUploadThresholdChange,
  onAddMatchRule,
  onInsertFormulaToken,
  onEvaluateBackend,
  onSaveSelectedGroup,
}: GroupConfigDrawerProps) {
  const strategyDrawerBody = (
    <>
      {/* Drawer Header */}
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--line)] px-4 py-3">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Settings2 className="h-4 w-4 shrink-0 text-[var(--accent)]" />
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-xs font-semibold text-[var(--text)]">策略与标准</h2>
            <p className="truncate text-[10px] text-[var(--muted)]" title={selectedGroupDisplayName}>
              针对「{selectedGroupDisplayName}」的选点规则
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setDrawerOpen(false)}
          className="shrink-0 rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
          title="收起策略面板"
          aria-label="收起策略面板"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto overscroll-contain p-4">
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
                    <span className="text-xs font-semibold text-[var(--text)]">{m.title}</span>
                    {active && <Check className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />}
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">{m.desc}</p>
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
                  onClick={() => onToggleGate(preset.expr)}
                  className={`inline-flex max-w-full min-w-0 items-center gap-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
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
                  <span className="min-w-0 truncate">{preset.label}</span>
                </button>
              );
            })}
          </div>

          {customHardGates.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {customHardGates.map((expr) => (
                <span
                  key={expr}
                  title={expr}
                  className="cc-mono inline-flex min-w-0 max-w-full items-center gap-1 rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                >
                  <span className="min-w-0 break-all">{expr}</span>
                  <button
                    type="button"
                    onClick={() => onToggleGate(expr)}
                    aria-label={`移除条件 ${expr}`}
                    className="shrink-0 text-[var(--muted)] hover:text-[var(--red)]"
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
          <div className="text-xs font-semibold text-[var(--text)]">3. 什么时候自动换节点</div>

          <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                上行速度太慢时自动切
              </span>
              <button
                type="button"
                onClick={onToggleUploadTrigger}
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
                    onChange={(e) => onUploadThresholdChange(e.target.value)}
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
                  g.switch_mode === "force_close_old" ? "graceful_new_only" : "force_close_old",
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
                          ? (g.fallback_pool_id ?? otherGroups[0]?.id ?? null)
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
                    <span className="text-xs font-semibold text-[var(--text)]">{pol.title}</span>
                    {selected && <Check className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />}
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
              <div className="block">
                <span className="block text-[11px] text-[var(--muted)]">选择备用组</span>
                <AppSelect
                  aria-label="选择备用组"
                  size="sm"
                  value={selectedGroup.fallback_pool_id ?? ""}
                  onChange={(v) =>
                    updateSelectedGroup((g) => ({
                      ...g,
                      fallback_pool_id: v || null,
                    }))
                  }
                  options={[
                    { value: "", label: "请选择一个备用多选组" },
                    ...otherGroups.map((og) => ({
                      value: og.id,
                      label: formatGroupDisplayName(og.name),
                    })),
                  ]}
                  className="mt-1 w-full"
                  buttonClassName="rounded-lg bg-[var(--card)]"
                />
              </div>
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
                      recover_probe_interval_sec: Math.max(30, Number(e.target.value) || 120),
                    }))
                  }
                  className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
              </label>
            </div>
          )}
        </div>

        {/* 5. 分流规则（网站 / 软件进程 / 复合规则） */}
        <div ref={section5Ref} className="space-y-2.5 border-t border-[var(--line)]/70 pt-4">
          <div className="text-xs font-semibold text-[var(--text)]">
            {dict.groups.section5Title}
          </div>

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
                独立接管专属分流（无需切为主组）
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
              关闭时，只有首页选中本组才会走这里，绝不抢其它组的流量；打开后，即使首页在用别的组，命中下方域名、软件进程或复合规则的流量也会单独走本组
            </p>
            {selectedGroup.independent_routing && selectedGroup.match_rules.length === 0 && (
              <p className="mt-1 text-[10px] font-medium text-[var(--amber)]">
                提示：请在下方添加至少一条域名、进程或复合规则，独立分流才会匹配生效
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
                    className="inline-flex min-w-0 max-w-full items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--text-secondary)]"
                  >
                    {chip.tag && (
                      <span className="shrink-0 whitespace-nowrap rounded bg-[var(--card)] px-1 text-[9px] text-[var(--muted)]">
                        {chip.tag}
                      </span>
                    )}
                    <span className="cc-mono min-w-0 break-all">{chip.display}</span>
                    <button
                      type="button"
                      onClick={() =>
                        updateSelectedGroup((g) => ({
                          ...g,
                          match_rules: g.match_rules.filter((r) => r !== rule),
                        }))
                      }
                      aria-label={`移除规则 ${chip.display}`}
                      className="shrink-0 text-[var(--muted)] hover:text-[var(--red)]"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                );
              })
            ) : (
              <span className="text-[11px] text-[var(--muted)]">
                暂未限定规则（可作主兜底组或备用组）
              </span>
            )}
          </div>

          <form onSubmit={onAddMatchRule} className="flex gap-1.5">
            <input
              type="text"
              value={newRuleInput}
              onChange={(e) => setNewRuleInput(e.target.value)}
              placeholder={dict.groups.section5Placeholder}
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
            直接填域名自动按后缀匹配；支持软件进程（如 PROCESS-NAME,QQ.exe）、复合规则（如
            AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))）及正则规则，多条请用分号或换行分隔。
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
                      onClick={() => onInsertFormulaToken(v.token)}
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
                      onClick={() => onInsertFormulaToken(p.token)}
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
                  <span className="text-[10px] text-[var(--muted)]">自定义切换触发表达式</span>
                  <input
                    type="text"
                    value={currentTriggerExpr}
                    onChange={(e) => setPrimaryTriggerExpr(e.target.value)}
                    placeholder="留空或输入自定义触发规则"
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <label className="block">
                  <span className="text-[10px] text-[var(--muted)]">防频繁切换缓冲幅度 (%)</span>
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
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <form onSubmit={onAddCustomGate} className="flex gap-1">
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
              <GroupEvalSection
                groupDisplayName={selectedGroupDisplayName}
                evaluating={evaluating}
                anyEvaluating={anyEvaluating}
                savingGroup={savingGroup}
                evalReport={evalReport}
                evalUntestedCount={evalUntestedCount}
                onEvaluateBackend={onEvaluateBackend}
              />
            </div>
          )}
        </div>
      </div>

      {/* Solid Bottom Apply Strategy Bar (zero bleed-through) */}
      <div className="sticky bottom-0 shrink-0 rounded-b-2xl border-t border-[var(--line)] bg-[var(--card)] px-4 py-3">
        <button
          type="button"
          disabled={savingGroup || !formulaSyntaxCheck.ok}
          onClick={onSaveSelectedGroup}
          className={`inline-flex w-full items-center justify-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-semibold transition-opacity disabled:opacity-50 ${
            isSelectedDirty
              ? "bg-[var(--accent)] text-[var(--accent-ink)] shadow-xs hover:opacity-90"
              : "border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
          }`}
        >
          <Save className="h-3.5 w-3.5 shrink-0" />
          <span>
            {savingGroup
              ? "正在应用..."
              : isSelectedDirty
                ? "应用策略（有未保存改动）"
                : "应用策略"}
          </span>
        </button>
      </div>
    </>
  );

  if (isWideDesktop) {
    return (
      <aside className="flex w-full shrink-0 flex-col xl:w-[332px]">
        <div className="cc-card cc-glass flex flex-1 flex-col overflow-hidden rounded-2xl">
          {strategyDrawerBody}
        </div>
      </aside>
    );
  }

  if (typeof document === "undefined") {
    return null;
  }

  return createPortal(
    <>
      <div
        className="fixed inset-x-0 top-9 bottom-0 z-[39] bg-black/35"
        onClick={() => setDrawerOpen(false)}
        aria-hidden="true"
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`策略与标准 - ${selectedGroupDisplayName}`}
        className="cc-surface fixed top-9 bottom-0 right-0 z-40 flex w-[min(360px,calc(100vw-48px))] flex-col overflow-hidden border-l border-[var(--line-strong)] shadow-2xl"
      >
        {strategyDrawerBody}
      </aside>
    </>,
    document.body
  );
}
