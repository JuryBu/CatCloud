import { Activity, Check, Loader2, Play, Star } from "lucide-react";
import { type KeyboardEvent, memo, useMemo } from "react";
import type { NodeHealthHint, ProbeSnapshot, ProxyNode } from "../../api/tauri";
import { formatI18nTemplate, type useUiDict } from "../../i18n";
import {
  type AiBadgeTone,
  formatGoogleRegionTooltip,
  getAiBadgeToneClass,
  getNodeAiBadgeDisplays,
} from "../../utils/aiUnlockDisplay";
import { assessNodeAgainstGates } from "../../utils/formulaEvaluator";
import {
  type ResolvedNodeLatency,
  getLatencyTooltipKey,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "../../utils/latencyDisplay";
import { getRegionLabel, resolveNodeRegionCode } from "../../utils/regions";

export function formatLatencyTone(ms: number): string {
  if (ms <= 140) return "var(--green)";
  if (ms <= 300) return "var(--amber)";
  return "var(--red)";
}

export function formatMultiplierLabel(multiplier: number): string {
  if (!Number.isFinite(multiplier)) return "1x";
  return Number.isInteger(multiplier) ? `${multiplier}x` : `${Number(multiplier.toFixed(2))}x`;
}

export function extractCardAiDots(snap: ProbeSnapshot | undefined): Array<{
  id: string;
  label: string;
  short: string;
  tone: AiBadgeTone;
  isLegacy: boolean;
}> {
  if (!snap) return [];
  return getNodeAiBadgeDisplays(snap)
    .filter(
      (b) =>
        b.unlocked ||
        b.windsurfState === "proxy_risk" ||
        b.windsurfState === "legacy_retest"
    )
    .map((b) => ({
      id: b.id,
      label: b.tooltip,
      short: b.dotLabel,
      tone: b.tone,
      isLegacy: b.windsurfState === "legacy_retest",
    }));
}

export function formatGroupLatencyTooltip(
  resolved: ResolvedNodeLatency,
  dict: ReturnType<typeof useUiDict>,
  hint?: NodeHealthHint | null
): string {
  const tipKey = getLatencyTooltipKey(resolved);
  const base =
    tipKey === "probeHot"
      ? dict.latency.probeHotTooltip
      : tipKey === "healthCold"
        ? dict.latency.healthColdTooltip
        : tipKey === "failed"
          ? dict.latency.failedTooltip
          : dict.latency.untestedTooltip;
  const tags: string[] = [];
  if (resolved.isProbation) tags.push(dict.latency.probationBadge);
  if (resolved.isDegraded) tags.push(dict.latency.degradedBadge);
  if (hint?.status === "cooldown") {
    tags.push(
      hint.cooldown_remaining_sec > 0
        ? formatI18nTemplate(dict.latency.cooldownSec, {
            sec: Math.ceil(hint.cooldown_remaining_sec),
          })
        : dict.latency.cooldownActive
    );
  }
  if (hint?.reason?.trim()) {
    tags.push(`${dict.latency.reasonPrefix}${hint.reason.trim()}`);
  }
  return tags.length > 0 ? `${base} · ${tags.join(" · ")}` : base;
}

export function handleCardKeyDown(ev: KeyboardEvent<HTMLDivElement>, onTrigger: () => void) {
  if (ev.key === "Enter" || ev.key === " ") {
    ev.preventDefault();
    onTrigger();
  }
}

export interface GroupNodeCardProps {
  node: ProxyNode;
  snap: ProbeSnapshot | undefined;
  healthHint: NodeHealthHint | undefined;
  subName: string;
  hardGates: string[];
  isActive: boolean;
  isLiveActive: boolean;
  isMember: boolean;
  isProbing: boolean;
  isSelecting: boolean;
  isProbeEngineBusy: boolean;
  benchmarkRunning: boolean;
  dict: ReturnType<typeof useUiDict>;
  onToggleMembership: (node: ProxyNode) => void;
  onProbeSingleNode: (node: ProxyNode) => void;
  onUseNode: (node: ProxyNode) => void;
}

export const GroupNodeCard = memo(function GroupNodeCard({
  node,
  snap,
  healthHint,
  subName,
  hardGates,
  isActive,
  isLiveActive,
  isMember,
  isProbing,
  isSelecting,
  isProbeEngineBusy,
  benchmarkRunning,
  dict,
  onToggleMembership,
  onProbeSingleNode,
  onUseNode,
}: GroupNodeCardProps) {
  const resolvedLat = resolveNodeDisplayLatency(snap, healthHint);
  const latTooltip = formatGroupLatencyTooltip(resolvedLat, dict, healthHint);
  const gateEval = useMemo(
    () => assessNodeAgainstGates(node, snap, hardGates),
    [node, snap, hardGates]
  );
  const aiDots = useMemo(() => extractCardAiDots(snap), [snap]);
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
      role="button"
      tabIndex={0}
      onClick={() => onToggleMembership(node)}
      onKeyDown={(ev) => handleCardKeyDown(ev, () => onToggleMembership(node))}
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
          <span className="inline-flex shrink-0 items-center whitespace-nowrap rounded-full border border-transparent px-1.5 py-0.5 text-[10px] font-medium text-[var(--muted)] transition-colors group-hover:border-[var(--accent)]/45 group-hover:bg-[var(--accent-soft)] group-hover:text-[var(--accent)]">
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
          <span
            title={formatGoogleRegionTooltip(snap, regionCode)}
            className="rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]"
          >
            谷歌正常
          </span>
        )}
        {snap?.google_clean === false && (
          <span
            title={formatGoogleRegionTooltip(snap, regionCode)}
            className="rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]"
          >
            送中
          </span>
        )}
        {snap?.google_risk_mismatch && (
          <span
            className="rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
            title={formatGoogleRegionTooltip(snap, regionCode)}
          >
            地区有偏差
          </span>
        )}

        {aiDots.length > 0 && (
          <span className="inline-flex items-center gap-1">
            {aiDots.map((dot) => {
              const dotColor =
                dot.tone === "green"
                  ? "bg-[var(--green)]"
                  : dot.tone === "amber"
                    ? "bg-[var(--amber)]"
                    : dot.tone === "red"
                      ? "bg-[var(--red)]"
                      : "bg-[var(--muted)]";
              const pillCls = dot.isLegacy
                ? getAiBadgeToneClass("muted", "legacy")
                : dot.tone === "green"
                  ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                  : getAiBadgeToneClass(dot.tone, "soft");
              return (
                <span
                  key={dot.id}
                  title={dot.label}
                  aria-label={dot.label}
                  className={`inline-flex items-center gap-0.5 rounded px-1 py-0.5 text-[9px] font-medium ${pillCls}`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
                  {dot.short}
                </span>
              );
            })}
          </span>
        )}
      </div>

      {/* Bottom row: unified latency dot + ms + throughput + gate status + 2 quick actions ("测" & "用它") */}
      <div className="flex items-center justify-between gap-2 pt-0.5">
        <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px]">
          {resolvedLat.latencyMs !== null ? (
            <span
              title={latTooltip}
              className="cc-mono cc-tabular inline-flex items-center gap-1.5 font-semibold"
              style={{ color: formatLatencyTone(resolvedLat.latencyMs) }}
            >
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{ backgroundColor: formatLatencyTone(resolvedLat.latencyMs) }}
                aria-hidden="true"
              />
              <span>{Math.round(resolvedLat.latencyMs)} ms</span>
            </span>
          ) : resolvedLat.state === "failed" ? (
            <span
              title={latTooltip}
              className="inline-flex items-center gap-1 rounded-md bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]"
            >
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--red)]"
                aria-hidden="true"
              />
              <span>暂不可达</span>
            </span>
          ) : (
            <span
              title={latTooltip}
              className="inline-flex items-center gap-1 rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]"
            >
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--muted)]/55"
                aria-hidden="true"
              />
              <span>待测</span>
            </span>
          )}
          {hasValidUpMbps(snap) && (
            <span
              title="实测上传速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
              className="cc-mono cc-tabular text-[10px] text-[var(--coral)]"
            >
              ↑{snap!.up_mbps!.toFixed(1)} Mbps
            </span>
          )}
          {hasValidDownMbps(snap) && (
            <span
              title="实测下载速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
              className="cc-mono cc-tabular text-[10px] text-[var(--sky)]"
            >
              ↓
              {snap!.down_mbps! >= 100
                ? Math.round(snap!.down_mbps!)
                : snap!.down_mbps!.toFixed(1)}{" "}
              Mbps
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
        </div>

        <div className="flex shrink-0 items-center gap-1" onClick={(ev) => ev.stopPropagation()}>
          <button
            type="button"
            disabled={isProbing || isProbeEngineBusy}
            onClick={() => onProbeSingleNode(node)}
            title={
              isProbing
                ? "正在快速测速中…"
                : benchmarkRunning
                  ? "国内提速对比测速正在后台进行，完成后可测速"
                  : isProbeEngineBusy
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
            onClick={() => onUseNode(node)}
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
});
