import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  ShieldAlert,
  Wifi,
} from "lucide-react";

export interface CampusPortalCardProps {
  checkingPortal: boolean;
  portalRequired: boolean;
  portalHttpCode: number | null;
  portalLastCheck: string;
  portalRedirect: string | null;
  portalBypassHosts: string[];
  campusError: string | null;
  campusPortalGuard: boolean;
  savingCampusGuard: boolean;
  probeValidationOk: boolean;
  onCheckCampusAuth: () => Promise<void>;
  onToggleCampusPortalGuard: () => Promise<void>;
  onOpenProbeModal: () => void;
}

export function CampusPortalCard({
  checkingPortal,
  portalRequired,
  portalHttpCode,
  portalLastCheck,
  portalRedirect,
  portalBypassHosts,
  campusError,
  campusPortalGuard,
  savingCampusGuard,
  probeValidationOk,
  onCheckCampusAuth,
  onToggleCampusPortalGuard,
  onOpenProbeModal,
}: CampusPortalCardProps) {
  return (
    <div className="cc-card cc-glass flex min-w-0 flex-col justify-between rounded-2xl p-5 min-[1160px]:col-span-5">
      <div>
        <div className="mb-4 flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4 shrink-0 text-[var(--accent)]" />
              <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                校园网认证检测
              </h2>
            </div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              自动识别校园网或公共 Wi-Fi 登录页
            </p>
          </div>
          <button
            type="button"
            disabled={checkingPortal}
            onClick={() => void onCheckCampusAuth()}
            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
          >
            <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${checkingPortal ? "animate-spin" : ""}`} />
            <span>{checkingPortal ? "检测中..." : "立即检测"}</span>
          </button>
        </div>

        <div
          className={`mb-3.5 rounded-xl border px-3.5 py-3 ${
            portalRequired
              ? "border-[var(--amber)]/50 bg-[var(--amber-soft)]"
              : portalHttpCode === null
                ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                : "border-[var(--green)]/40 bg-[var(--green-soft)]"
          }`}
        >
          <div className="flex items-start gap-2.5">
            {portalRequired ? (
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[var(--amber)]" />
            ) : portalHttpCode === null ? (
              <Clock className="mt-0.5 h-5 w-5 shrink-0 text-[var(--muted)]" />
            ) : (
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-[var(--green)]" />
            )}
            <div className="min-w-0 flex-1">
              <div className="text-xs font-semibold text-[var(--text)]">
                {portalRequired
                  ? "检测到需要登录校园网 / 公共 Wi-Fi"
                  : portalHttpCode === null
                    ? "尚未检测当前网络"
                    : "当前国内网络正常，无需网页认证"}
              </div>
              <div className="mt-1 text-[11px] text-[var(--muted)]">
                {portalHttpCode !== null
                  ? portalRequired
                    ? "检测到登录页跳转 · "
                    : portalHttpCode === 204 || (portalHttpCode >= 200 && portalHttpCode < 300)
                      ? "检测状态正常 · "
                      : "检测状态异常 · "
                  : ""}
                上次检测：<span className="cc-mono">{portalLastCheck}</span>
              </div>
              {portalRedirect && (
                <div className="mt-1 truncate cc-mono text-[11px] text-[var(--amber)]">
                  认证页：{portalRedirect}
                </div>
              )}
              {portalBypassHosts.length > 0 && (
                <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                  已临时放行：{portalBypassHosts.join("、")}
                </div>
              )}
              {campusError && (
                <div className="mt-1 flex items-center gap-1 text-[11px] text-[var(--red)]">
                  <AlertTriangle className="h-3 w-3 shrink-0" />
                  <span className="truncate">上次检测失败：{campusError}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-2.5 text-xs">
          <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-[var(--text)]">登录页自动放行</span>
              <div className="flex items-center gap-2">
                <span
                  className={`text-[11px] font-medium ${
                    campusPortalGuard ? "text-[var(--accent)]" : "text-[var(--muted)]"
                  }`}
                >
                  {campusPortalGuard ? "已开启" : "已关闭"}
                </span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={campusPortalGuard}
                  aria-label="切换校园网登录页自动放行"
                  disabled={savingCampusGuard}
                  onClick={() => void onToggleCampusPortalGuard()}
                  className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-60 ${
                    campusPortalGuard ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                  }`}
                >
                  <span
                    className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                      campusPortalGuard ? "translate-x-4" : "translate-x-0"
                    }`}
                  />
                </button>
              </div>
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
              遇到校园网认证跳转时自动临时直连，完成登录后自动恢复提速。
            </p>
          </div>

          <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-[var(--text)]">国内直连防绕路</span>
              {probeValidationOk ? (
                <span className="text-[11px] font-medium text-[var(--green)]">正常</span>
              ) : (
                <button
                  type="button"
                  onClick={onOpenProbeModal}
                  className="text-[11px] font-medium text-[var(--amber)] underline-offset-2 hover:underline"
                >
                  去修正检测地址
                </button>
              )}
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
              中转服务器与连通检测自动走国内直连，不会出现网络反复绕圈。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
