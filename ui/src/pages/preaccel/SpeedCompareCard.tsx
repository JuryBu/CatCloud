import { AlertTriangle, Clock, Gauge, RefreshCw, Zap } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { PreAccelComparisonResult, ProxyNode } from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import {
  formatClockStamp,
  formatLatencyDisplay,
  hasValidLatency,
} from "./relayImportParser";

export interface SpeedCompareCardProps {
  comparison: PreAccelComparisonResult | null;
  comparisonError: string | null;
  comparisonFinishedAt: number | null;
  comparisonIsDemo: boolean;
  benchmarking: boolean;
  speedTestingAny: boolean;
  isOtherProbeRunning: boolean;
  isProbeEngineBusy: boolean;
  relayLatencyStats: {
    enabledTotal: number;
    probedCount: number;
    bestMs: number | null;
  };
  benchmarkableNodes: ProxyNode[];
  otherBenchmarkableNodes: ProxyNode[];
  homeCurrentNode: ProxyNode | null;
  isHomeCurrentNodeUdpOnly: boolean;
  resolvedCompareNodeId: string;
  onSelectCompareNodeId: (nextNodeId: string) => void;
  onRunBenchmark: () => Promise<void>;
}

export function SpeedCompareCard({
  comparison,
  comparisonError,
  comparisonFinishedAt,
  comparisonIsDemo,
  benchmarking,
  speedTestingAny,
  isOtherProbeRunning,
  isProbeEngineBusy,
  relayLatencyStats,
  benchmarkableNodes,
  otherBenchmarkableNodes,
  homeCurrentNode,
  isHomeCurrentNodeUdpOnly,
  resolvedCompareNodeId,
  onSelectCompareNodeId,
  onRunBenchmark,
}: SpeedCompareCardProps) {
  // Soft "刚刚更新" badge expires cleanly 2 minutes after benchmark completion
  const [recentClockNow, setRecentClockNow] = useState(() => Date.now());
  useEffect(() => {
    if (!comparisonFinishedAt) return;
    const now = Date.now();
    setRecentClockNow(now);
    const remaining = comparisonFinishedAt + 120_000 - now;
    if (remaining <= 0) return;
    const id = window.setTimeout(() => {
      setRecentClockNow(Date.now());
    }, remaining + 50);
    return () => window.clearTimeout(id);
  }, [comparisonFinishedAt]);

  const isComparisonFresh = Boolean(
    comparison &&
      comparisonFinishedAt !== null &&
      recentClockNow - comparisonFinishedAt < 120_000
  );

  const effectiveUpRatio = useMemo(() => {
    if (!comparison) return null;
    if (
      comparison.up_boost_ratio !== null &&
      Number.isFinite(comparison.up_boost_ratio) &&
      comparison.up_boost_ratio > 0
    ) {
      return comparison.up_boost_ratio;
    }
    const accUp = comparison.accelerated.up_mbps;
    const dirUp = comparison.direct.up_mbps;
    if (accUp !== null && dirUp !== null && dirUp > 0) {
      return accUp / dirUp;
    }
    return null;
  }, [comparison]);

  const effectiveDownRatio = useMemo(() => {
    if (!comparison) return null;
    if (
      comparison.down_boost_ratio !== null &&
      Number.isFinite(comparison.down_boost_ratio) &&
      comparison.down_boost_ratio > 0
    ) {
      return comparison.down_boost_ratio;
    }
    const accDown = comparison.accelerated.down_mbps;
    const dirDown = comparison.direct.down_mbps;
    if (accDown !== null && dirDown !== null && dirDown > 0) {
      return accDown / dirDown;
    }
    return null;
  }, [comparison]);

  const maxCompareUpMbps = useMemo(() => {
    if (!comparison) return 100;
    return Math.max(comparison.accelerated.up_mbps ?? 0, comparison.direct.up_mbps ?? 0, 10);
  }, [comparison]);

  const maxCompareDownMbps = useMemo(() => {
    if (!comparison) return 100;
    return Math.max(comparison.accelerated.down_mbps ?? 0, comparison.direct.down_mbps ?? 0, 10);
  }, [comparison]);

  return (
    <div
      className={`cc-card cc-glass min-w-0 rounded-2xl p-5 transition-colors min-[1160px]:col-span-7 ${
        isComparisonFresh && !benchmarking ? "ring-1 ring-[var(--green)]/35" : ""
      }`}
    >
      <div className="mb-4 flex flex-wrap items-start justify-between gap-2.5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Gauge className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            <h2 className="text-sm font-semibold text-[var(--text)]">提速效果实测对比</h2>
            {isComparisonFresh && !benchmarking && (
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                刚刚更新
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
            默认直接拿首页当前节点对比「走国内中转」和「普通直连」的真实上传、下载速度（也可下拉换测其它节点）
          </p>
        </div>
        <button
          type="button"
          disabled={benchmarking || isOtherProbeRunning || isProbeEngineBusy}
          onClick={() => void onRunBenchmark()}
          title={
            speedTestingAny
              ? "中转上下行测速正在后台进行，完成后可运行提速对比"
              : isOtherProbeRunning
                ? "节点测速正在后台进行，完成后可运行提速对比"
                : undefined
          }
          className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${benchmarking ? "animate-spin" : ""}`} />
          <span>
            {benchmarking
              ? "正在实测对比（约 5～10 秒）…"
              : speedTestingAny
                ? "中转测速进行中…"
                : isOtherProbeRunning
                  ? "节点测速进行中…"
                  : "一键对比提速效果"}
          </span>
        </button>
      </div>

      {isOtherProbeRunning && (
        <div className="mb-3 flex items-center gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-[11px] text-[var(--amber)]">
          <Clock className="h-3.5 w-3.5 shrink-0" />
          <span>「节点与测速」页正在后台运行节点测速，测速结束后即可一键对比提速效果</span>
        </div>
      )}

      {benchmarking && comparison && (
        <div className="mb-3 flex items-center gap-2 rounded-xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/45 px-3.5 py-2 text-[11px] text-[var(--accent)]">
          <RefreshCw className="h-3.5 w-3.5 shrink-0 animate-spin" />
          <span>正在后台执行新一轮实测对比（约 5～10 秒），完成后自动刷新下方数据…</span>
        </div>
      )}

      {/* 中转连通概况 + 对照海外节点选择器 */}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
        <span className="text-[var(--text-secondary)]">
          已启用中转{" "}
          <strong className="cc-mono text-[var(--text)]">{relayLatencyStats.enabledTotal}</strong>{" "}
          条 · 已测通{" "}
          <strong className="cc-mono text-[var(--green)]">{relayLatencyStats.probedCount}</strong>{" "}
          条
          {hasValidLatency(relayLatencyStats.bestMs) && (
            <span className="cc-mono text-[var(--muted)]">
              {" "}
              · 最快 {formatLatencyDisplay(relayLatencyStats.bestMs)}
            </span>
          )}
        </span>

        <div className="flex items-center gap-1.5">
          <span className="shrink-0 text-[11px] text-[var(--muted)]">对照节点</span>
          {benchmarkableNodes.length > 0 || homeCurrentNode ? (
            <AppSelect
              aria-label="对照节点"
              size="xs"
              value={resolvedCompareNodeId}
              disabled={benchmarking}
              onChange={onSelectCompareNodeId}
              options={[
                {
                  value: "",
                  label: homeCurrentNode
                    ? `跟随首页当前节点（${homeCurrentNode.name}）`
                    : "跟随首页当前节点",
                },
                ...otherBenchmarkableNodes.map((node) => ({
                  value: node.id,
                  label: node.name,
                })),
              ]}
              className="max-w-[240px]"
              buttonClassName="bg-[var(--card)]"
            />
          ) : (
            <span className="text-[11px] text-[var(--muted)]">暂未导入海外节点</span>
          )}
        </div>
      </div>

      {resolvedCompareNodeId === "" && isHomeCurrentNodeUdpOnly && (
        <div className="mb-3 flex items-start gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/55 px-3.5 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            首页当前节点为纯 UDP 协议，无法套 TCP 中转；点击对比时将自动改测其它可用节点，或请直接从右侧下拉指定
          </span>
        </div>
      )}

      {!comparison ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-[var(--line-strong)] bg-[var(--bg-elevated)]/65 px-5 py-9 text-center">
          {benchmarking ? (
            <>
              <RefreshCw className="h-6 w-6 animate-spin text-[var(--accent)]" />
              <p className="mt-3 text-xs font-semibold text-[var(--text)]">
                正在实测对比（约 5～10 秒）…
              </p>
              <p className="mt-1 max-w-md text-[11px] leading-relaxed text-[var(--muted)]">
                正在依次检测中转连通性，并对所选海外节点实测「走国内中转」与「普通直连」的上传、下载速度
              </p>
            </>
          ) : (
            <>
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-[var(--accent-soft)] text-[var(--accent)]">
                <Gauge className="h-5 w-5" />
              </span>
              <p className="mt-3 text-xs font-semibold text-[var(--text)]">
                点击右上角按钮，立刻实测走中转能快多少
              </p>
              <p className="mt-1 max-w-md text-[11px] leading-relaxed text-[var(--muted)]">
                系统会用同一海外节点现场对比「开启国内提速（走国内中转）」与「普通线路直连」的真实上下行速度，平时零后台流量。
              </p>
            </>
          )}

          {comparisonError && (
            <div className="mt-3.5 flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-left text-[11px] text-[var(--red)]">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>{comparisonError}</span>
            </div>
          )}
        </div>
      ) : (
        <>
          {/* 本次实测对照组合 + 提速倍数徽章 */}
          <div className="mb-3 rounded-xl border border-[var(--accent)]/35 bg-[var(--accent-soft)]/35 px-3.5 py-2 text-[11px]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[var(--text-secondary)]">
                <span className="shrink-0 text-[var(--muted)]">本次对照：</span>
                <span className="truncate font-semibold text-[var(--text)]">
                  {comparison.relay_name}
                </span>
                <span className="text-[var(--muted)]">+</span>
                <span className="truncate font-semibold text-[var(--text)]">
                  {comparison.node_name}
                </span>
                {comparisonIsDemo && (
                  <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                    演示数据
                  </span>
                )}
              </div>

              <div className="flex shrink-0 items-center gap-1.5">
                {effectiveUpRatio !== null && (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                      effectiveUpRatio >= 1.1
                        ? "bg-[var(--green)] text-[var(--accent-ink)]"
                        : "border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]"
                    }`}
                  >
                    <Zap className="h-3 w-3" />
                    <span>
                      {effectiveUpRatio >= 1.1
                        ? `上传提速 ${effectiveUpRatio.toFixed(1)} 倍`
                        : `上传约 ${effectiveUpRatio.toFixed(1)} 倍`}
                    </span>
                  </span>
                )}
                {effectiveDownRatio !== null && effectiveDownRatio >= 1.1 && (
                  <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                    下载 {effectiveDownRatio.toFixed(1)} 倍
                  </span>
                )}
              </div>
            </div>

            {comparison.fallback_reason?.trim() && (
              <div className="mt-2 flex items-start gap-1.5 border-t border-[var(--accent)]/20 pt-2 leading-relaxed text-[var(--amber)]">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{comparison.fallback_reason.trim()}</span>
              </div>
            )}
          </div>

          <div className="space-y-3">
            {/* 走国内中转 */}
            {(() => {
              const side = comparison.accelerated;
              const sideHasLatency = hasValidLatency(side.latency_ms);
              const sideError = side.error?.trim() || "";
              return (
                <div className="rounded-xl border border-[var(--green)]/35 bg-[var(--bg-elevated)] p-3.5">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-semibold text-[var(--text)]">
                      开启国内提速（走国内中转）
                    </span>
                    <span
                      className={`cc-mono text-[11px] ${
                        side.ok
                          ? "text-[var(--green)]"
                          : sideHasLatency
                            ? "text-[var(--amber)]"
                            : "text-[var(--red)]"
                      }`}
                    >
                      {sideHasLatency
                        ? `延迟 ${formatLatencyDisplay(side.latency_ms)}${
                            side.ok ? "" : " · 部分超时"
                          }`
                        : side.ok
                          ? "测速成功"
                          : "测速失败"}
                    </span>
                  </div>
                  <div className="mt-2.5 space-y-2">
                    <div>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="text-[var(--muted)]">上传速度</span>
                        <span
                          className={`cc-mono cc-tabular font-semibold ${
                            side.up_mbps !== null ? "text-[var(--green)]" : "text-[var(--muted)]"
                          }`}
                        >
                          {side.up_mbps !== null
                            ? `${side.up_mbps.toFixed(1)} Mbps`
                            : sideHasLatency
                              ? "测速超时"
                              : "未测出"}
                        </span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                        <div
                          className="h-full rounded-full bg-[var(--green)] transition-all duration-300"
                          style={{
                            width:
                              side.up_mbps !== null && side.up_mbps > 0
                                ? `${Math.max(
                                    3,
                                    Math.min(100, (side.up_mbps / maxCompareUpMbps) * 100)
                                  )}%`
                                : "0%",
                          }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="text-[var(--muted)]">下载速度</span>
                        <span
                          className={`cc-mono cc-tabular font-medium ${
                            side.down_mbps !== null ? "text-[var(--sky)]" : "text-[var(--muted)]"
                          }`}
                        >
                          {side.down_mbps !== null
                            ? `${side.down_mbps.toFixed(1)} Mbps`
                            : sideHasLatency
                              ? "测速超时"
                              : "未测出"}
                        </span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                        <div
                          className="h-full rounded-full bg-[var(--sky)] transition-all duration-300"
                          style={{
                            width:
                              side.down_mbps !== null && side.down_mbps > 0
                                ? `${Math.max(
                                    3,
                                    Math.min(100, (side.down_mbps / maxCompareDownMbps) * 100)
                                  )}%`
                                : "0%",
                          }}
                        />
                      </div>
                    </div>
                    {sideError && (
                      <p
                        className={`text-[11px] leading-relaxed ${
                          !side.ok && !sideHasLatency
                            ? "text-[var(--red)]"
                            : "text-[var(--amber)]"
                        }`}
                      >
                        {!side.ok && !sideHasLatency ? "失败原因：" : "异常说明："}
                        {sideError}
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}

            {/* 普通直连 */}
            {(() => {
              const side = comparison.direct;
              const sideHasLatency = hasValidLatency(side.latency_ms);
              const sideError = side.error?.trim() || "";
              return (
                <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-semibold text-[var(--text)]">普通线路直连</span>
                    <span
                      className={`cc-mono text-[11px] ${
                        side.ok
                          ? "text-[var(--amber)]"
                          : sideHasLatency
                            ? "text-[var(--amber)]"
                            : "text-[var(--red)]"
                      }`}
                    >
                      {sideHasLatency
                        ? `延迟 ${formatLatencyDisplay(side.latency_ms)}${
                            side.ok ? "" : " · 部分超时"
                          }`
                        : side.ok
                          ? "测速成功"
                          : "测速失败"}
                    </span>
                  </div>
                  <div className="mt-2.5 space-y-2">
                    <div>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="text-[var(--muted)]">上传速度</span>
                        <span
                          className={`cc-mono cc-tabular font-semibold ${
                            side.up_mbps !== null ? "text-[var(--amber)]" : "text-[var(--muted)]"
                          }`}
                        >
                          {side.up_mbps !== null
                            ? `${side.up_mbps.toFixed(1)} Mbps`
                            : sideHasLatency
                              ? "测速超时"
                              : "未测出"}
                        </span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--card)]">
                        <div
                          className="h-full rounded-full bg-[var(--amber)] transition-all duration-300"
                          style={{
                            width:
                              side.up_mbps !== null && side.up_mbps > 0
                                ? `${Math.max(
                                    3,
                                    Math.min(100, (side.up_mbps / maxCompareUpMbps) * 100)
                                  )}%`
                                : "0%",
                          }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="mb-1 flex justify-between text-[11px]">
                        <span className="text-[var(--muted)]">下载速度</span>
                        <span
                          className={`cc-mono cc-tabular font-medium ${
                            side.down_mbps !== null
                              ? "text-[var(--text-secondary)]"
                              : "text-[var(--muted)]"
                          }`}
                        >
                          {side.down_mbps !== null
                            ? `${side.down_mbps.toFixed(1)} Mbps`
                            : sideHasLatency
                              ? "测速超时"
                              : "未测出"}
                        </span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                        <div
                          className="h-full rounded-full bg-[var(--text-secondary)]/65 transition-all duration-300"
                          style={{
                            width:
                              side.down_mbps !== null && side.down_mbps > 0
                                ? `${Math.max(
                                    3,
                                    Math.min(100, (side.down_mbps / maxCompareDownMbps) * 100)
                                  )}%`
                                : "0%",
                          }}
                        />
                      </div>
                    </div>
                    {sideError && (
                      <p
                        className={`text-[11px] leading-relaxed ${
                          !side.ok && !sideHasLatency
                            ? "text-[var(--red)]"
                            : "text-[var(--amber)]"
                        }`}
                      >
                        {!side.ok && !sideHasLatency ? "失败原因：" : "异常说明："}
                        {sideError}
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>

          {comparisonError && (
            <div className="mt-3 flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>上次重新测速出错：{comparisonError}</span>
            </div>
          )}

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px]">
            <span className="text-[var(--text-secondary)]">
              {effectiveUpRatio !== null && effectiveUpRatio >= 1.1 ? (
                <>
                  实测走国内中转上传速度提升{" "}
                  <strong className="cc-mono text-[var(--accent)]">
                    {effectiveUpRatio.toFixed(1)} 倍
                  </strong>
                  {comparisonIsDemo ? "（演示数据）" : "，建议保持开启国内提速。"}
                </>
              ) : comparison.accelerated.ok && comparison.direct.ok ? (
                "当前所选节点直连表现良好，可换一个普通海外节点再次对比。"
              ) : (
                "部分测速未通过，可切换其他中转或海外节点重试。"
              )}
            </span>
            <span className="cc-mono text-[var(--muted)]">
              实测时间：{formatClockStamp(comparison.tested_at)}
            </span>
          </div>
        </>
      )}
    </div>
  );
}
