import {
  ArrowDown,
  ArrowUp,
  Clock,
  Gauge,
  Globe,
  Loader2,
  RefreshCw,
  Server,
  Star,
  Trash2,
} from "lucide-react";
import { memo } from "react";
import type { PreAccelRelay } from "../../api/tauri";
import {
  computeExpiryInfo,
  formatLatencyDisplay,
  getRelayLatencyColor,
  hasValidSpeed,
} from "./relayImportParser";

export interface RelayCardItemProps {
  relay: PreAccelRelay;
  idx: number;
  totalCount: number;
  isTopEnabled: boolean;
  isActivePrimary: boolean;
  roleLabel: string;
  isProbing: boolean;
  isSpeedTesting: boolean;
  isProbeEngineBusy: boolean;
  isMultiCloudLbActive: boolean;
  canSetPrimary: boolean;
  validChainMs: number | null;
  chainLatencyLabel: string;
  pinPrimaryBtnLabel: string;
  onToggleRelay: (id: string) => void;
  onMoveRelay: (id: string, direction: -1 | 1) => void;
  onSelectRelay: (relay: PreAccelRelay) => void;
  onProbeRelay: (id: string) => void;
  onSpeedTestRelay: (id: string) => void;
  onRequestDeleteRelay: (relay: PreAccelRelay) => void;
}

export const RelayCardItem = memo(function RelayCardItem({
  relay,
  idx,
  totalCount,
  isTopEnabled,
  isActivePrimary,
  roleLabel,
  isProbing,
  isSpeedTesting,
  isProbeEngineBusy,
  isMultiCloudLbActive,
  canSetPrimary,
  validChainMs,
  chainLatencyLabel,
  pinPrimaryBtnLabel,
  onToggleRelay,
  onMoveRelay,
  onSelectRelay,
  onProbeRelay,
  onSpeedTestRelay,
  onRequestDeleteRelay,
}: RelayCardItemProps) {
  const hasUpSpeed = hasValidSpeed(relay.last_up_mbps);
  const hasDownSpeed = hasValidSpeed(relay.last_down_mbps);
  const hasLegacySpeed = !hasUpSpeed && !hasDownSpeed && hasValidSpeed(relay.last_mbps);
  const expiry = computeExpiryInfo(relay.expires_at);
  const hasUrgentExpiry = expiry.tone === "warn" || expiry.tone === "expired";
  const safeSni = (relay.sni ?? "").trim();
  const hasConfigTip = relay.port !== 443 || safeSni !== "";

  return (
    <div
      className={`min-w-0 overflow-hidden rounded-2xl border p-4 transition-colors ${
        isTopEnabled || isActivePrimary
          ? "border-[var(--accent)]/75 bg-[var(--accent-soft)]/35"
          : "border-[var(--line)] bg-[var(--bg-elevated)]"
      } ${!relay.enabled ? "opacity-70" : ""}`}
    >
      {/* 卡片第一行：名称 + 角色徽章 + 状态开关 */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Server
              className={`h-4 w-4 shrink-0 ${
                isTopEnabled || isActivePrimary ? "text-[var(--accent)]" : "text-[var(--muted)]"
              }`}
            />
            <span
              className="min-w-0 max-w-full truncate text-sm font-semibold text-[var(--text)]"
              title={relay.name}
            >
              {relay.name}
            </span>
            <span
              className={`shrink-0 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                isTopEnabled
                  ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                  : !relay.enabled
                    ? "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]"
                    : "border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
              }`}
            >
              {roleLabel}
            </span>
            {isActivePrimary && !isTopEnabled && (
              <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                当前使用
              </span>
            )}
            {hasUrgentExpiry && (
              <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--red)]">
                <Clock className="h-3 w-3 shrink-0" />
                {expiry.label}
              </span>
            )}
          </div>
        </div>

        {/* 状态开关 */}
        <button
          type="button"
          role="switch"
          aria-checked={relay.enabled}
          aria-label={relay.enabled ? `停用 ${relay.name}` : `开启 ${relay.name}`}
          title={relay.enabled ? "已开启，点击停用" : "已停用，点击开启"}
          onClick={() => onToggleRelay(relay.id)}
          className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
            relay.enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
          }`}
        >
          <span
            className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
              relay.enabled ? "translate-x-4" : "translate-x-0"
            }`}
          />
        </button>
      </div>

      {/* 卡片第二行：地区、备注/地址 + 实时延迟 */}
      <div className="mt-3 flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-[var(--text-secondary)]">
            <span className="inline-flex min-w-0 max-w-full items-center gap-1">
              <Globe className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 truncate">{relay.region || "国内"}</span>
            </span>
            {relay.provider && (
              <span className="min-w-0 max-w-full truncate text-[11px] text-[var(--muted)]">
                · {relay.provider}
              </span>
            )}
            {!hasUrgentExpiry && expiry.label && (
              <span className="min-w-0 max-w-full truncate text-[11px] text-[var(--muted)]">
                · {expiry.label}
              </span>
            )}
          </div>
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-[10.5px] text-[var(--muted)]/85">
            <span
              className="cc-mono min-w-0 max-w-full truncate"
              title={`${relay.server}:${relay.port} (${relay.protocol.toUpperCase()})`}
            >
              {relay.server}:{relay.port}
            </span>
            <span className="shrink-0 uppercase opacity-80">{relay.protocol}</span>
            {hasConfigTip && (
              <span className="shrink-0 whitespace-nowrap rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] text-[var(--amber)]">
                {safeSni !== "" ? "建议留空域名" : "建议使用 443 端口"}
              </span>
            )}
          </div>
        </div>

        {/* 实时直连延迟 + 真实上下行（经海外对比延迟收进悬停提示保持首屏清爽） */}
        <div className="shrink-0 text-right">
          <div
            className="whitespace-nowrap cc-mono cc-tabular text-base font-bold leading-tight"
            style={{ color: getRelayLatencyColor(relay.last_probe_ms) }}
            title={
              validChainMs !== null
                ? `本机直连国内中转的真实延迟（${chainLatencyLabel} ${validChainMs} ms）`
                : "本机直连国内中转的真实延迟（绝不被经海外节点的两跳测速延迟污染）"
            }
          >
            {relay.last_probe_ms !== null
              ? formatLatencyDisplay(relay.last_probe_ms, "--")
              : "待测速"}
          </div>
          {hasUpSpeed || hasDownSpeed ? (
            <div
              title="实测中转速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
              className="mt-0.5 flex items-center justify-end gap-1.5 whitespace-nowrap cc-mono cc-tabular text-[11px] font-semibold"
            >
              {hasUpSpeed && (
                <span className="text-[var(--coral)]">↑{relay.last_up_mbps!.toFixed(1)} Mbps</span>
              )}
              {hasDownSpeed && (
                <span className="text-[var(--sky)]">↓{relay.last_down_mbps!.toFixed(1)} Mbps</span>
              )}
            </div>
          ) : hasLegacySpeed ? (
            <div
              title="实测中转上传速率（单位 Mbps，8 Mbps ≈ 1 MB/s）"
              className="mt-0.5 whitespace-nowrap cc-mono cc-tabular text-[11px] font-semibold text-[var(--coral)]"
            >
              ↑{relay.last_mbps!.toFixed(1)} Mbps
            </div>
          ) : (
            <div className="mt-0.5 whitespace-nowrap text-[10px] text-[var(--muted)]">
              {relay.last_probe_ms !== null ? "直连延迟" : "直连实时延迟"}
            </div>
          )}
        </div>
      </div>

      {/* 卡片第三行：操作栏 */}
      <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)]/65 pt-2.5 text-[11px]">
        {totalCount > 1 ? (
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              disabled={idx === 0}
              onClick={() => onMoveRelay(relay.id, -1)}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)] disabled:opacity-75"
              title="上移一位"
            >
              <ArrowUp className="h-3 w-3 shrink-0" />
              <span>上移</span>
            </button>
            <button
              type="button"
              disabled={idx === totalCount - 1}
              onClick={() => onMoveRelay(relay.id, 1)}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)] disabled:opacity-75"
              title="下移一位"
            >
              <ArrowDown className="h-3 w-3 shrink-0" />
              <span>下移</span>
            </button>
          </div>
        ) : (
          <span />
        )}

        <div className="flex min-w-0 flex-wrap items-center justify-end gap-1.5 gap-x-2.5">
          {canSetPrimary && (
            <button
              type="button"
              onClick={() => onSelectRelay(relay)}
              title={
                isMultiCloudLbActive
                  ? "切换为单线主备模式并固定优先使用此线（随时可切回多云自动均衡）"
                  : "设为首选主力线路（其余启用线路继续自动故障兜底）"
              }
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap font-medium text-[var(--accent)] transition-opacity hover:opacity-80"
            >
              <Star className="h-3.5 w-3.5 shrink-0" />
              <span>{isMultiCloudLbActive ? pinPrimaryBtnLabel : "设为主力"}</span>
            </button>
          )}

          <button
            type="button"
            disabled={isProbing}
            onClick={() => onProbeRelay(relay.id)}
            title="快速检测该中转线路的连通延迟"
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${isProbing ? "animate-spin" : ""}`} />
            <span>{isProbing ? "测延迟中" : "测延迟"}</span>
          </button>

          <button
            type="button"
            disabled={isSpeedTesting || isProbeEngineBusy}
            onClick={() => onSpeedTestRelay(relay.id)}
            title="实测该中转线路的实际上传与下载速率（切页不中断）"
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSpeedTesting ? (
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-[var(--accent)]" />
            ) : (
              <Gauge className="h-3.5 w-3.5 shrink-0" />
            )}
            <span>{isSpeedTesting ? "测速中" : "测上下行"}</span>
          </button>

          <button
            type="button"
            onClick={() => onRequestDeleteRelay(relay)}
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-[var(--muted)] transition-colors hover:text-[var(--red)]"
          >
            <Trash2 className="h-3.5 w-3.5 shrink-0" />
            <span>删除</span>
          </button>
        </div>
      </div>
    </div>
  );
});
