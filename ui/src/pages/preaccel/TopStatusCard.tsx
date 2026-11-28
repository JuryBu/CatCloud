import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  FileText,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import type { GlobalPreAccelStatus } from "../../api/tauri";
import { formatBytes } from "../../components/TrafficSparkline";
import { appActions } from "../../store/appStore";
import type { PreAccelSummary } from "../../utils/preaccelStatus";

export interface TopStatusCardProps {
  title: string;
  subtitle: string;
  toggleMainTitle: string;
  toggleMainToggling: string;
  toggleMainDesc: string;
  socksCopyPlainHint: string;
  refreshLabel: string;
  enabled: boolean;
  togglingEnabled: boolean;
  topStatusBadge: { label: string; cls: string };
  preaccelSummary: PreAccelSummary;
  globalPreAccel: GlobalPreAccelStatus;
  effectiveGlobalConns: number;
  localSocksAddress: string | null;
  copiedGlobalAddr: boolean;
  isWindows: boolean;
  isPreparingDriver: boolean;
  isProbingVerify: boolean;
  isVerifiedVerify: boolean;
  isDegradedVerify: boolean;
  needsWindowsElevation: boolean;
  elevatingGlobal: boolean;
  installBusy: boolean;
  showReprobeButton: boolean;
  refreshingGlobal: boolean;
  showSecurityGuidanceBox: boolean;
  detectedSecurityProducts: string[];
  hasDistinctVerifyDetail: boolean;
  verifyMessageText: string | null;
  securityGuidanceText: string | null;
  onToggleEnabled: () => Promise<void>;
  onRelaunchAdminGlobal: () => Promise<void>;
  onInstallWinDivert: () => Promise<void>;
  onCopyGlobalAddress: (addr: string) => Promise<void>;
  onVerifyGlobalPreAccel: () => Promise<void>;
  onRefreshGlobalStatus: () => Promise<void>;
}

export function TopStatusCard({
  title,
  subtitle,
  toggleMainTitle,
  toggleMainToggling,
  toggleMainDesc,
  socksCopyPlainHint,
  refreshLabel,
  enabled,
  togglingEnabled,
  topStatusBadge,
  preaccelSummary,
  globalPreAccel,
  effectiveGlobalConns,
  localSocksAddress,
  copiedGlobalAddr,
  isWindows,
  isPreparingDriver,
  isProbingVerify,
  isVerifiedVerify,
  isDegradedVerify,
  needsWindowsElevation,
  elevatingGlobal,
  installBusy,
  showReprobeButton,
  refreshingGlobal,
  showSecurityGuidanceBox,
  detectedSecurityProducts,
  hasDistinctVerifyDetail,
  verifyMessageText,
  securityGuidanceText,
  onToggleEnabled,
  onRelaunchAdminGlobal,
  onInstallWinDivert,
  onCopyGlobalAddress,
  onVerifyGlobalPreAccel,
  onRefreshGlobalStatus,
}: TopStatusCardProps) {
  return (
    <section className="cc-card cc-glass rounded-2xl p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
              <Zap className="h-4 w-4" />
            </span>
            <h1 className="whitespace-nowrap text-base font-semibold tracking-tight text-[var(--text)]">
              {title}
            </h1>
            <span
              title={preaccelSummary.detailText}
              className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-medium ${topStatusBadge.cls}`}
            >
              {(isPreparingDriver || isProbingVerify) && (
                <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
              )}
              <span>{topStatusBadge.label}</span>
            </span>
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-[var(--muted)]">{subtitle}</p>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => appActions.openAiAssistant("preaccel", "web")}
            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
          >
            <FileText className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            <span>AI 部署说明</span>
          </button>
        </div>
      </div>

      {/* 唯一一个「开启国内提速」总开关 */}
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        disabled={togglingEnabled}
        onClick={() => void onToggleEnabled()}
        className={`mt-4 flex w-full items-center justify-between gap-4 rounded-2xl border px-4 py-3.5 text-left transition-colors disabled:opacity-65 ${
          enabled
            ? "border-[var(--accent)]/60 bg-[var(--accent-soft)]/45 hover:border-[var(--accent)]"
            : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
        }`}
      >
        <div className="flex min-w-0 items-start gap-3">
          <span
            className={`mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl transition-colors ${
              enabled
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]"
            }`}
          >
            {togglingEnabled ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Zap className="h-4 w-4" />
            )}
          </span>
          <div className="min-w-0">
            <div className="text-sm font-semibold text-[var(--text)]">
              {togglingEnabled ? toggleMainToggling : toggleMainTitle}
            </div>
            <div className="mt-0.5 text-xs leading-relaxed text-[var(--text-secondary)]">
              {toggleMainDesc}
            </div>
          </div>
        </div>

        <span
          className={`inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0.5 transition-colors ${
            enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
          }`}
        >
          <span
            className={`h-5 w-5 rounded-full bg-[var(--card)] transition-transform ${
              enabled ? "translate-x-5" : "translate-x-0"
            }`}
          />
        </span>
      </button>

      {/* 诚实状态条：仅在开启或准备中展示 */}
      {(preaccelSummary.enabled || isPreparingDriver) && (
        <div className="mt-3 space-y-2.5">
          <div
            className={`flex flex-wrap items-center justify-between gap-2.5 rounded-xl border px-3.5 py-2.5 text-xs ${
              isPreparingDriver ||
              needsWindowsElevation ||
              preaccelSummary.installState === "failed" ||
              isDegradedVerify ||
              isProbingVerify ||
              preaccelSummary.tone === "amber"
                ? "border-[var(--amber)]/45 bg-[var(--amber-soft)]/50"
                : preaccelSummary.realWinDivertActive || preaccelSummary.proxyActive
                  ? "border-[var(--green)]/35 bg-[var(--green-soft)]/45"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]"
            }`}
          >
            <div className="flex min-w-0 flex-1 items-center gap-2">
              {isPreparingDriver || isProbingVerify ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-[var(--amber)]" />
              ) : needsWindowsElevation ||
                preaccelSummary.installState === "failed" ||
                isDegradedVerify ||
                preaccelSummary.tone === "amber" ? (
                <ShieldAlert className="h-4 w-4 shrink-0 text-[var(--amber)]" />
              ) : preaccelSummary.realWinDivertActive || preaccelSummary.proxyActive ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--green)]" />
              ) : (
                <Clock className="h-4 w-4 shrink-0 text-[var(--amber)]" />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span
                    title={preaccelSummary.detailText}
                    className="font-medium text-[var(--text)]"
                  >
                    {preaccelSummary.plainText}
                  </span>
                  {isProbingVerify ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      <span>正在自动探测…</span>
                    </span>
                  ) : isVerifiedVerify ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-semibold text-[var(--green)]">
                      <Check className="h-3 w-3" />
                      <span className="cc-mono cc-tabular">
                        链路已验证
                        {preaccelSummary.verifyLatencyMs
                          ? ` ${preaccelSummary.verifyLatencyMs} ms`
                          : ""}
                      </span>
                    </span>
                  ) : isDegradedVerify ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                      <ShieldAlert className="h-3 w-3" />
                      <span>已自动停止拦截防断网</span>
                    </span>
                  ) : preaccelSummary.verifyState === "failed" ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--red)]">
                      <AlertTriangle className="h-3 w-3" />
                      <span>链路探测未通过</span>
                    </span>
                  ) : null}
                </div>
                {!preaccelSummary.realWinDivertActive &&
                  !preaccelSummary.suspendedForTun &&
                  localSocksAddress && (
                    <div className="mt-1 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                      {socksCopyPlainHint}
                    </div>
                  )}
                {preaccelSummary.realWinDivertActive && (
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-[var(--text-secondary)]">
                    <span>
                      当前加速连接{" "}
                      <strong className="cc-mono cc-tabular text-[var(--text)]">
                        {effectiveGlobalConns}
                      </strong>
                    </span>
                    <span>
                      累计{" "}
                      <strong className="cc-mono cc-tabular text-[var(--text)]">
                        {globalPreAccel.total_connections}
                      </strong>{" "}
                      次
                    </span>
                    <span>
                      ↑{" "}
                      <strong className="cc-mono cc-tabular text-[var(--coral)]">
                        {formatBytes(globalPreAccel.up_bytes)}
                      </strong>
                    </span>
                    <span>
                      ↓{" "}
                      <strong className="cc-mono cc-tabular text-[var(--sky)]">
                        {formatBytes(globalPreAccel.down_bytes)}
                      </strong>
                    </span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              {needsWindowsElevation && (
                <button
                  type="button"
                  disabled={elevatingGlobal}
                  onClick={() => void onRelaunchAdminGlobal()}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                >
                  {elevatingGlobal ? (
                    <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                  )}
                  <span>{elevatingGlobal ? "正在重启…" : "以管理员重启生效"}</span>
                </button>
              )}

              {isWindows &&
                preaccelSummary.installState === "failed" &&
                !preaccelSummary.realWinDivertActive && (
                  <button
                    type="button"
                    disabled={installBusy}
                    onClick={() => void onInstallWinDivert()}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                  >
                    {installBusy ? (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                    ) : (
                      <Download className="h-3.5 w-3.5 shrink-0" />
                    )}
                    <span>{installBusy ? "正在重试…" : "重试准备组件"}</span>
                  </button>
                )}

              {!preaccelSummary.realWinDivertActive &&
                !preaccelSummary.suspendedForTun &&
                localSocksAddress && (
                  <button
                    type="button"
                    onClick={() => void onCopyGlobalAddress(localSocksAddress)}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    title={socksCopyPlainHint}
                  >
                    {copiedGlobalAddr ? (
                      <Check className="h-3 w-3 shrink-0 text-[var(--green)]" />
                    ) : (
                      <Copy className="h-3 w-3 shrink-0" />
                    )}
                    <span className="cc-mono">{localSocksAddress}</span>
                  </button>
                )}

              {showReprobeButton && (
                <button
                  type="button"
                  disabled={isProbingVerify}
                  onClick={() => void onVerifyGlobalPreAccel()}
                  className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--accent)]/45 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]/55 disabled:opacity-60"
                  title="重新实测底层透明拦截与国内中转链路连通性"
                >
                  <RefreshCw
                    className={`h-3 w-3 shrink-0 ${isProbingVerify ? "animate-spin" : ""}`}
                  />
                  <span>{isProbingVerify ? "探测中…" : "重新探测"}</span>
                </button>
              )}

              <button
                type="button"
                disabled={refreshingGlobal}
                onClick={() => void onRefreshGlobalStatus()}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
                title="刷新提速状态与实时统计"
              >
                <RefreshCw
                  className={`h-3 w-3 shrink-0 ${refreshingGlobal ? "animate-spin" : ""}`}
                />
                <span>{refreshLabel}</span>
              </button>
            </div>
          </div>

          {/* 琥珀色环境指引提示框：仅在存在额外放行指引或与上方不重复的诊断明细，且底层拦截未运行时展示 */}
          {showSecurityGuidanceBox && (
            <div className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/55 px-3.5 py-2.5 text-xs">
              <div className="flex min-w-0 flex-1 items-start gap-2">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[var(--amber)]" />
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="font-semibold text-[var(--text)]">环境放行指引</span>
                    {detectedSecurityProducts.map((prod) => (
                      <span
                        key={prod}
                        className="rounded-md border border-[var(--amber)]/40 bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                      >
                        {prod}
                      </span>
                    ))}
                  </div>
                  {hasDistinctVerifyDetail && verifyMessageText && (
                    <p className="text-[11px] leading-relaxed text-[var(--text)]">
                      {verifyMessageText}
                    </p>
                  )}
                  {securityGuidanceText && (
                    <p className="whitespace-pre-line text-[11px] leading-relaxed text-[var(--text-secondary)]">
                      {securityGuidanceText}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
