import {
  AlertTriangle,
  ArrowRightLeft,
  Check,
  CheckCircle2,
  Loader2,
  Play,
  Rocket,
  XCircle,
} from "lucide-react";
import { type MouseEvent as ReactMouseEvent, memo } from "react";
import type { NodeHealthHint, ProbeSnapshot, ProxyNode } from "../../api/tauri";
import { GroupMembershipPopover } from "../../components/GroupMembershipPopover";
import { formatI18nTemplate, type useUiDict } from "../../i18n";
import {
  formatGoogleRegionTooltip,
  getAiBadgeToneClass,
  getNodeAiBadgeDisplays,
} from "../../utils/aiUnlockDisplay";
import {
  type ResolvedNodeLatency,
  getLatencyTooltipKey,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "../../utils/latencyDisplay";
import { formatGroupDisplayName, getLatencyColor } from "../../utils/releaseUrl";

export interface ProbeTimestampIdSets {
  latencyIds: ReadonlySet<string>;
  speedIds: ReadonlySet<string>;
}

function resolveProbeTimestamps(
  snap: ProbeSnapshot | undefined,
  idSets: ProbeTimestampIdSets
): {
  latencyAt: string | null;
  speedAt: string | null;
  fallbackAt: string | null;
} {
  if (!snap) return { latencyAt: null, speedAt: null, fallbackAt: null };
  const map = snap.per_probe_tested_at;
  const pickNewestIso = (candidates: Array<string | undefined | null>): string | null => {
    let bestIso: string | null = null;
    let bestTs = -Infinity;
    for (const raw of candidates) {
      if (!raw) continue;
      const ts = Date.parse(raw);
      if (Number.isFinite(ts) && ts > bestTs) {
        bestTs = ts;
        bestIso = raw;
      }
    }
    return bestIso;
  };
  if (map && Object.keys(map).length > 0) {
    const latencyCandidates: string[] = [];
    const speedCandidates: string[] = [];
    for (const [pid, ts] of Object.entries(map)) {
      if (!ts) continue;
      const isLat =
        idSets.latencyIds.has(pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_ping_ms ?? {}, pid);
      const isSpeed =
        idSets.speedIds.has(pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_up_mbps ?? {}, pid) ||
        Object.prototype.hasOwnProperty.call(snap.per_probe_down_mbps ?? {}, pid);
      if (isLat) latencyCandidates.push(ts);
      if (isSpeed) speedCandidates.push(ts);
    }
    const latencyAt = pickNewestIso(latencyCandidates);
    const speedAt = pickNewestIso(speedCandidates);
    return {
      latencyAt,
      speedAt,
      fallbackAt: !latencyAt && !speedAt ? (snap.tested_at ?? null) : null,
    };
  }
  return {
    latencyAt: null,
    speedAt: null,
    fallbackAt: snap.tested_at ?? null,
  };
}

function formatSpeedTestLatencyTooltip(
  resolved: ResolvedNodeLatency,
  dict: ReturnType<typeof useUiDict>,
  hint?: NodeHealthHint | null,
  cooldownRemainingSec = 0
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
  const parts: string[] = [base];
  if (resolved.isProbation) parts.push(dict.latency.probationBadge);
  if (resolved.isDegraded) parts.push(dict.latency.degradedBadge);
  if (hint?.status === "cooldown") {
    parts.push(
      cooldownRemainingSec > 0
        ? formatI18nTemplate(dict.latency.cooldownRetryHint, {
            sec: cooldownRemainingSec,
          })
        : dict.latency.cooldownHint
    );
  }
  if (hint?.reason?.trim()) {
    parts.push(`${dict.latency.reasonPrefix}${hint.reason.trim()}`);
  }
  if (hint?.stage?.trim()) {
    parts.push(`${dict.latency.stagePrefix}${hint.stage.trim()}`);
  }
  return parts.join(" · ");
}

function formatRelativeProbeTime(iso?: string | null): { short: string; full: string } | null {
  if (!iso) return null;
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return null;
  const date = new Date(ts);
  const full = date.toLocaleString();
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 45) return { short: "刚刚测过", full };
  if (diffSec < 3600) return { short: `${Math.floor(diffSec / 60)}分钟前`, full };
  if (diffSec < 86400) return { short: `${Math.floor(diffSec / 3600)}小时前`, full };
  const days = Math.floor(diffSec / 86400);
  return { short: `${days}天前`, full };
}

export interface SpeedTestRowProps {
  node: ProxyNode;
  snap: ProbeSnapshot | undefined;
  healthHint: NodeHealthHint | undefined;
  sourceName: string;
  regionCode: string;
  regionLabel: string;
  isSelected: boolean;
  isActiveNode: boolean;
  isSingleMode: boolean;
  isFlashing: boolean;
  isProbingThis: boolean;
  isSwitchingThis: boolean;
  isProbeActionDisabled: boolean;
  isBlockedByBenchmark: boolean;
  probeTimestampIdSets: ProbeTimestampIdSets;
  dict: ReturnType<typeof useUiDict>;
  onRowMouseDown: (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => void;
  onRowMouseEnter: (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => void;
  onRowClick: (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => void;
  onCheckboxClick: (e: ReactMouseEvent<HTMLInputElement>, nodeId: string) => void;
  onSwitchToNode: (node: ProxyNode) => void;
  onProbeNode: (nodeId: string, tier: "full" | "latency") => void;
}

function areHealthHintsEqual(
  a: NodeHealthHint | undefined,
  b: NodeHealthHint | undefined
): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    a.latency_ms === b.latency_ms &&
    a.status === b.status &&
    a.cooldown_remaining_sec === b.cooldown_remaining_sec &&
    a.reason === b.reason &&
    a.stage === b.stage &&
    a.probed_at_ms === b.probed_at_ms
  );
}

function areSpeedTestRowPropsEqual(
  prev: SpeedTestRowProps,
  next: SpeedTestRowProps
): boolean {
  return (
    prev.node === next.node &&
    prev.snap === next.snap &&
    areHealthHintsEqual(prev.healthHint, next.healthHint) &&
    prev.sourceName === next.sourceName &&
    prev.regionCode === next.regionCode &&
    prev.regionLabel === next.regionLabel &&
    prev.isSelected === next.isSelected &&
    prev.isActiveNode === next.isActiveNode &&
    prev.isSingleMode === next.isSingleMode &&
    prev.isFlashing === next.isFlashing &&
    prev.isProbingThis === next.isProbingThis &&
    prev.isSwitchingThis === next.isSwitchingThis &&
    prev.isProbeActionDisabled === next.isProbeActionDisabled &&
    prev.isBlockedByBenchmark === next.isBlockedByBenchmark &&
    prev.probeTimestampIdSets === next.probeTimestampIdSets &&
    prev.dict === next.dict &&
    prev.onRowMouseDown === next.onRowMouseDown &&
    prev.onRowMouseEnter === next.onRowMouseEnter &&
    prev.onRowClick === next.onRowClick &&
    prev.onCheckboxClick === next.onCheckboxClick &&
    prev.onSwitchToNode === next.onSwitchToNode &&
    prev.onProbeNode === next.onProbeNode
  );
}

function SpeedTestRowInner({
  node,
  snap,
  healthHint,
  sourceName,
  regionCode,
  regionLabel,
  isSelected,
  isActiveNode,
  isSingleMode,
  isFlashing,
  isProbingThis,
  isSwitchingThis,
  isProbeActionDisabled,
  isBlockedByBenchmark,
  probeTimestampIdSets,
  dict,
  onRowMouseDown,
  onRowMouseEnter,
  onRowClick,
  onCheckboxClick,
  onSwitchToNode,
  onProbeNode,
}: SpeedTestRowProps) {
  const resolvedLatency = resolveNodeDisplayLatency(snap, healthHint);
  const isCooldown =
    healthHint?.status === "cooldown" && resolvedLatency.state === "failed";
  const cooldownRemainingSec = isCooldown
    ? Math.max(0, Math.ceil(healthHint?.cooldown_remaining_sec ?? 0))
    : 0;
  const effectiveLatencyMs = resolvedLatency.latencyMs;
  const effectiveLatencyOk: boolean | undefined =
    resolvedLatency.state === "failed"
      ? false
      : resolvedLatency.ok
        ? true
        : undefined;
  const aiBadges = getNodeAiBadgeDisplays(snap);
  const hasUnlockData = Boolean(
    snap &&
      (Object.keys(snap.unlocked_sites ?? {}).length > 0 ||
        snap.per_probe_ok?.builtin_unlock_windsurf !== undefined ||
        snap.ip_risk_level != null ||
        snap.google_clean !== null)
  );
  const regionMismatch =
    Boolean(snap?.google_risk_mismatch) ||
    Boolean(
      snap?.cf_loc &&
        snap?.yt_gl &&
        snap.yt_gl.toUpperCase() !== regionCode
    );
  const isSingleActiveNode = isSingleMode && isActiveNode;
  const latTooltip = formatSpeedTestLatencyTooltip(
    resolvedLatency,
    dict,
    healthHint,
    cooldownRemainingSec
  );

  return (
    <tr
      onMouseDown={(e) => onRowMouseDown(e, node.id)}
      onMouseEnter={(e) => onRowMouseEnter(e, node.id)}
      onClick={(e) => onRowClick(e, node.id)}
      className={`cursor-pointer transition-colors duration-500 ${
        isFlashing
          ? "bg-[var(--green-soft)]"
          : isProbingThis
            ? "bg-[var(--amber-soft)]/45 hover:bg-[var(--amber-soft)]/60"
            : isSelected
              ? "bg-[var(--accent-soft)] hover:bg-[var(--accent-soft)]"
              : "bg-[var(--card)]/40 hover:bg-[var(--card-hover)]"
      }`}
    >
      {/* Checkbox with clear accent left indicator when selected */}
      <td
        className={`w-8 px-2 py-2 text-center ${
          isSelected
            ? "shadow-[inset_3px_0_0_var(--accent)]"
            : isFlashing
              ? "shadow-[inset_3px_0_0_var(--green)]"
              : isProbingThis
                ? "shadow-[inset_3px_0_0_var(--amber)]"
                : ""
        }`}
      >
        <input
          type="checkbox"
          checked={isSelected}
          onChange={() => {}}
          onClick={(e) => onCheckboxClick(e, node.id)}
          aria-label={`选择节点 ${node.name}`}
          className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
        />
      </td>

      {/* Node Name */}
      <td className="w-[196px] min-w-[178px] px-2 py-2">
        <div className="flex min-w-0 items-center gap-1">
          <span
            className="min-w-0 flex-1 truncate font-semibold text-[var(--text)]"
            title={node.name}
          >
            {node.name}
          </span>
          {isActiveNode && (
            <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
              {isSingleMode ? "单节点" : "当前"}
            </span>
          )}
          {isProbingThis && (
            <span
              className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[9.5px] font-semibold text-[var(--amber)]"
              title="正在后台测速此节点"
            >
              <Loader2 className="h-2.5 w-2.5 animate-spin" />
              测速中
            </span>
          )}
          {isFlashing && !isProbingThis && (
            <span className="cc-pulse-dot shrink-0 rounded-full bg-[var(--green)] px-1.5 py-0.5 text-[9px] font-semibold text-[var(--accent-ink)]">
              新
            </span>
          )}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-1 gap-y-0.5 text-[10.5px] text-[var(--muted)]">
          <span className="truncate">{regionLabel}</span>
          <span>·</span>
          <span className="cc-tabular shrink-0">
            {node.multiplier % 1 === 0
              ? `${node.multiplier}x`
              : `${node.multiplier.toFixed(1)}x`}
          </span>
          {(() => {
            const { latencyAt, speedAt, fallbackAt } =
              resolveProbeTimestamps(snap, probeTimestampIdSets);
            const latRel = formatRelativeProbeTime(latencyAt);
            const speedRel = formatRelativeProbeTime(speedAt);
            if (latRel || speedRel) {
              const tooltipLines: string[] = [];
              if (latRel) {
                tooltipLines.push(
                  `${dict.latency.testedAtLatency}: ${latRel.full}`
                );
              }
              if (speedRel) {
                tooltipLines.push(
                  `${dict.latency.testedAtSpeed}: ${speedRel.full}`
                );
              }
              const fullTitle = tooltipLines.join("\n");
              return (
                <>
                  {latRel && (
                    <>
                      <span>·</span>
                      <span
                        className="shrink-0 text-[10px] text-[var(--muted)]/90"
                        title={fullTitle}
                      >
                        {dict.latency.testedAtLatency} {latRel.short}
                      </span>
                    </>
                  )}
                  {speedRel && (
                    <>
                      <span>·</span>
                      <span
                        className="shrink-0 text-[10px] text-[var(--muted)]/90"
                        title={fullTitle}
                      >
                        {dict.latency.testedAtSpeed} {speedRel.short}
                      </span>
                    </>
                  )}
                </>
              );
            }
            const rel = formatRelativeProbeTime(fallbackAt);
            if (!rel) return null;
            return (
              <>
                <span>·</span>
                <span
                  className="shrink-0 text-[10px] text-[var(--muted)]/90"
                  title={`上次测速时间：${rel.full}`}
                >
                  {rel.short}
                </span>
              </>
            );
          })()}
        </div>
      </td>

      {/* Source */}
      <td className="w-[84px] px-1.5 py-2">
        <span
          className="block truncate text-[11px] font-medium text-[var(--text-secondary)]"
          title={`来源分组：${sourceName}（协议：${node.protocol.toUpperCase()}）`}
        >
          {sourceName}
        </span>
      </td>

      {/* Latency */}
      <td className="w-[78px] px-1.5 py-2 cc-mono cc-tabular text-[11px]">
        {isCooldown ? (
          <div>
            <span
              className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold text-[var(--amber)]"
              title={latTooltip}
            >
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                aria-hidden="true"
              />
              <span>
                {cooldownRemainingSec > 0
                  ? formatI18nTemplate(dict.latency.cooldownSec, {
                      sec: cooldownRemainingSec,
                    })
                  : dict.latency.cooldownActive}
              </span>
            </span>
            {snap?.keepalive_60s_ok !== null &&
              snap?.keepalive_60s_ok !== undefined && (
                <div
                  className={`mt-0.5 whitespace-nowrap text-[10px] font-medium ${
                    snap.keepalive_60s_ok
                      ? "text-[var(--green)]"
                      : "text-[var(--red)]"
                  }`}
                >
                  {snap.keepalive_60s_ok ? "长连接稳" : "长连接断"}
                </div>
              )}
          </div>
        ) : resolvedLatency.state !== "untested" || snap ? (
          <div>
            <span
              className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold"
              style={{
                color: getLatencyColor(effectiveLatencyMs, effectiveLatencyOk),
              }}
              title={latTooltip}
            >
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{
                  backgroundColor: getLatencyColor(
                    effectiveLatencyMs,
                    effectiveLatencyOk
                  ),
                }}
                aria-hidden="true"
              />
              <span>
                {effectiveLatencyMs !== null
                  ? `${Math.round(effectiveLatencyMs)} ms`
                  : resolvedLatency.state === "failed"
                    ? dict.latency.timeoutShort
                    : "--"}
              </span>
            </span>
            {snap?.keepalive_60s_ok !== null &&
              snap?.keepalive_60s_ok !== undefined && (
                <div
                  className={`mt-0.5 whitespace-nowrap text-[10px] font-medium ${
                    snap.keepalive_60s_ok
                      ? "text-[var(--green)]"
                      : "text-[var(--red)]"
                  }`}
                >
                  {snap.keepalive_60s_ok ? "长连接稳" : "长连接断"}
                </div>
              )}
          </div>
        ) : (
          <span
            className="inline-flex items-center gap-1.5 text-[var(--muted)]"
            title={latTooltip}
          >
            <span
              className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--muted)]/55"
              aria-hidden="true"
            />
            <span>--</span>
          </span>
        )}
      </td>

      {/* Upload Speed */}
      <td
        className="w-[72px] whitespace-nowrap px-1 py-2 cc-mono cc-tabular text-[11px]"
        title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
      >
        {hasValidUpMbps(snap) ? (
          <span className="font-semibold text-[var(--coral)]">
            {snap!.up_mbps!.toFixed(1)}
            <span className="ml-0.5 text-[9.5px] font-normal text-[var(--muted)]">
              Mbps
            </span>
          </span>
        ) : (
          <span className="text-[var(--muted)]">--</span>
        )}
      </td>

      {/* Download Speed */}
      <td
        className="w-[74px] whitespace-nowrap px-1 py-2 cc-mono cc-tabular text-[11px]"
        title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
      >
        {hasValidDownMbps(snap) ? (
          <span className="font-semibold text-[var(--sky)]">
            {snap!.down_mbps! >= 100
              ? Math.round(snap!.down_mbps!)
              : snap!.down_mbps!.toFixed(1)}
            <span className="ml-0.5 text-[9.5px] font-normal text-[var(--muted)]">
              Mbps
            </span>
          </span>
        ) : (
          <span className="text-[var(--muted)]">--</span>
        )}
      </td>

      {/* Google Region Status */}
      <td
        className="w-[68px] whitespace-nowrap px-1 py-2"
        title={formatGoogleRegionTooltip(snap, regionCode)}
      >
        <div className="flex flex-col items-start gap-1">
          {snap?.google_clean === true ? (
            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
              <CheckCircle2 className="h-3 w-3 shrink-0" />
              正常
            </span>
          ) : snap?.google_clean === false ? (
            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]">
              <XCircle className="h-3 w-3 shrink-0" />
              送中
            </span>
          ) : (
            <span className="text-[11px] text-[var(--muted)]">待测</span>
          )}

          {regionMismatch && (
            <span
              className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1 py-0.5 text-[9px] text-[var(--amber)]"
              title={formatGoogleRegionTooltip(snap, regionCode)}
            >
              <AlertTriangle className="h-2.5 w-2.5 shrink-0" />
              地区偏差
            </span>
          )}
        </div>
      </td>

      {/* AI Unlocks (2x2 compact micro-grid with Windsurf 4-state & per_probe_detail hover) */}
      <td className="w-[126px] px-1 py-2">
        {hasUnlockData ? (
          <div className="grid w-full grid-cols-2 gap-0.5">
            {aiBadges.map((badge) => {
              const isLegacy = badge.windsurfState === "legacy_retest";
              const isDimmed =
                !isLegacy &&
                badge.tone === "muted" &&
                !badge.unlocked;
              const toneCls = isLegacy
                ? getAiBadgeToneClass("muted", "legacy")
                : getAiBadgeToneClass(badge.tone, "soft");
              return (
                <span
                  key={badge.id}
                  title={badge.tooltip}
                  className={`truncate whitespace-nowrap rounded-md px-0.5 py-0.5 text-center text-[9.5px] font-medium leading-tight ${toneCls} ${
                    isDimmed ? "opacity-55" : ""
                  }`}
                >
                  {badge.label}
                </span>
              );
            })}
          </div>
        ) : (
          <span className="text-[11px] text-[var(--muted)]">--</span>
        )}
      </td>

      {/* Row Actions: Primary Single-Node Use + Compact Full Probe + Lightweight Latency / +Group */}
      <td className="w-[204px] whitespace-nowrap px-1.5 py-2 text-right">
        <div className="inline-flex flex-nowrap items-center justify-end gap-0.5">
          <button
            type="button"
            disabled={isSingleActiveNode || isSwitchingThis}
            onClick={(e) => {
              e.stopPropagation();
              onSwitchToNode(node);
            }}
            title={
              isSingleActiveNode
                ? "当前正以单节点模式使用此节点"
                : "直接单节点使用此节点（不会修改多选组成员）"
            }
            aria-label={
              isSingleActiveNode
                ? `单节点在用中：${node.name}`
                : `用它（单节点）：${node.name}`
            }
            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap border px-1.5 py-0.5 text-[10px] font-semibold transition-colors ${
              isSingleActiveNode
                ? "rounded-full border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                : "rounded-lg border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-65"
            }`}
          >
            {isSingleActiveNode ? (
              <Check className="h-2.5 w-2.5 shrink-0" />
            ) : (
              <ArrowRightLeft className="h-2.5 w-2.5 shrink-0" />
            )}
            <span>
              {isSingleActiveNode
                ? "在用中"
                : isSwitchingThis
                  ? "切换"
                  : "用它"}
            </span>
          </button>

          <button
            type="button"
            disabled={isProbeActionDisabled}
            onClick={(e) => {
              e.stopPropagation();
              onProbeNode(node.id, "full");
            }}
            title={
              isBlockedByBenchmark
                ? "国内提速对比测速正在后台进行，完成后可测速"
                : "单测此节点的延迟、谷歌送中/AI 解锁与真实上下行速度，保留其它旧结果"
            }
            aria-label={`测全套：${node.name}`}
            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--sky)]/45 bg-[var(--sky-soft)] px-1 py-0.5 text-[10px] font-medium text-[var(--sky)] transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-55"
          >
            {isProbingThis ? (
              <Loader2 className="h-2.5 w-2.5 shrink-0 animate-spin" />
            ) : (
              <Rocket className="h-2.5 w-2.5 shrink-0" />
            )}
            <span>{isProbingThis ? "测速中" : "测全套"}</span>
          </button>

          <button
            type="button"
            disabled={isProbeActionDisabled}
            onClick={(e) => {
              e.stopPropagation();
              onProbeNode(node.id, "latency");
            }}
            title={
              isBlockedByBenchmark
                ? "国内提速对比测速正在后台进行，完成后可测速"
                : "只快速复测此节点延迟，不洗掉之前测好的上下行和解锁结果"
            }
            aria-label={`测延迟：${node.name}`}
            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-1 py-0.5 text-[10px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:text-[var(--muted)] disabled:opacity-65"
          >
            <Play className="h-2.5 w-2.5 shrink-0" />
            <span>测延迟</span>
          </button>

          <GroupMembershipPopover
            node={node}
            variant="icon"
            formatGroupName={formatGroupDisplayName}
          />
        </div>
      </td>
    </tr>
  );
}

export const SpeedTestRow = memo(SpeedTestRowInner, areSpeedTestRowPropsEqual);
