import {
  AlertTriangle,
  Check,
  Download,
  Loader2,
  Plus,
  RotateCcw,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import type { GlobalPreAccelScope, GlobalPreAccelStatus } from "../../api/tauri";
import { appActions } from "../../store/appStore";
import { copyText } from "../../utils/clipboard";
import { buildGlobalPreAccelShellSnippet, type PlatformOs } from "../../utils/platform";
import type { PreAccelSummary } from "../../utils/preaccelStatus";

export interface WinDivertDiagPanelProps {
  isWindows: boolean;
  platformOs: PlatformOs;
  preaccelSummary: PreAccelSummary;
  globalPreAccel: GlobalPreAccelStatus;
  effectiveGlobalPort: number | null;
  installBusy: boolean;
  elevatingGlobal: boolean;
  savingGlobalScope: boolean;
  globalScope: GlobalPreAccelScope;
  targetProcesses: string[];
  detectedSecurityProducts: string[];
  verifyCheckedClock: string | null;
  verifyMessageText: string | null;
  verifyStateFallbackLabel: string;
  isVerifiedVerify: boolean;
  isDegradedVerify: boolean;
  onInstallWinDivert: () => Promise<void>;
  onRelaunchAdminGlobal: () => Promise<void>;
  onSelectGlobalScope: (scope: GlobalPreAccelScope) => Promise<void>;
  onAddTargetProcesses: (rawInput: string) => Promise<boolean>;
  onRemoveTargetProcess: (procName: string) => Promise<void>;
  onResetTargetProcesses: () => Promise<void>;
}

export function WinDivertDiagPanel({
  isWindows,
  platformOs,
  preaccelSummary,
  globalPreAccel,
  effectiveGlobalPort,
  installBusy,
  elevatingGlobal,
  savingGlobalScope,
  globalScope,
  targetProcesses,
  detectedSecurityProducts,
  verifyCheckedClock,
  verifyMessageText,
  verifyStateFallbackLabel,
  isVerifiedVerify,
  isDegradedVerify,
  onInstallWinDivert,
  onRelaunchAdminGlobal,
  onSelectGlobalScope,
  onAddTargetProcesses,
  onRemoveTargetProcess,
  onResetTargetProcesses,
}: WinDivertDiagPanelProps) {
  const [newProcessInput, setNewProcessInput] = useState("");
  const [copiedShellKind, setCopiedShellKind] = useState<string | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  const handleCopyGlobalShellCmd = async (
    port: number,
    shell: "posix" | "fish" | "powershell",
    label: string
  ) => {
    const cmd = buildGlobalPreAccelShellSnippet(port, shell);
    const ok = await copyText(cmd);
    if (ok) {
      setCopiedShellKind(shell);
      appActions.showToast(`已复制 ${label} 终端加速命令`, "ok");
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedShellKind(null);
        copyTimerRef.current = null;
      }, 1800);
    } else {
      appActions.showToast("复制失败，请手动选中复制", "warn");
    }
  };

  const handleAddFormSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (savingGlobalScope) return;
    const raw = newProcessInput.trim();
    if (!raw) return;
    const cleared = await onAddTargetProcesses(raw);
    if (cleared) {
      setNewProcessInput("");
    }
  };

  return (
    <>
      {/* 4.2 驱动状态 / 重装诊断（Windows）或 本地独立通道终端命令（macOS / Linux） */}
      {isWindows ? (
        <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-4">
          <div className="flex flex-wrap items-start justify-between gap-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold text-[var(--text)]">
                  提速组件与权限诊断（WinDivert）
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                    preaccelSummary.verifyState === "probing"
                      ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                      : preaccelSummary.realWinDivertActive
                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                        : globalPreAccel.windivert_available
                          ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "bg-[var(--amber-soft)] text-[var(--amber)]"
                  }`}
                >
                  {preaccelSummary.verifyState === "probing"
                    ? "探测链路中…"
                    : preaccelSummary.realWinDivertActive
                      ? "运行中"
                      : globalPreAccel.windivert_available
                        ? "组件已就绪"
                        : "尚未下载"}
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                    globalPreAccel.is_elevated
                      ? "bg-[var(--green-soft)] text-[var(--green)]"
                      : "bg-[var(--amber-soft)] text-[var(--amber)]"
                  }`}
                >
                  {globalPreAccel.is_elevated ? "已获管理员权限" : "普通权限运行"}
                </span>
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                开启顶部总开关时会自动下载并校验官方开源 WinDivert v2.2.2（SHA-256 指纹校验，仅存于应用目录）；如被安全软件误拦可在此手动重试安装。
              </p>
              {globalPreAccel.windivert_path && (
                <div
                  className="mt-1 truncate cc-mono text-[10px] text-[var(--muted)]"
                  title={globalPreAccel.windivert_path}
                >
                  组件路径：{globalPreAccel.windivert_path}
                </div>
              )}
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              <button
                type="button"
                disabled={installBusy}
                onClick={() => void onInstallWinDivert()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
              >
                {installBusy ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Download className="h-3.5 w-3.5" />
                )}
                <span>
                  {installBusy
                    ? "正在下载并校验…"
                    : globalPreAccel.windivert_available
                      ? "重新下载并校验组件"
                      : "下载并校验官方组件"}
                </span>
              </button>

              {!globalPreAccel.is_elevated && (
                <button
                  type="button"
                  disabled={elevatingGlobal}
                  onClick={() => void onRelaunchAdminGlobal()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  {elevatingGlobal ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  <span>{elevatingGlobal ? "正在重启…" : "以管理员重启生效"}</span>
                </button>
              )}
            </div>
          </div>

          {/* 紧凑一行环境诊断信息：物理出口网卡 + 安全环境标签 + 上次探测时间与结论 */}
          <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)]/75 px-3 py-2 text-[11px]">
            <span className="inline-flex items-center gap-1 text-[var(--muted)]">
              <span>物理出口网卡：</span>
              <strong className="cc-mono font-medium text-[var(--text)]">
                {globalPreAccel.bound_physical_interface || "自动识别"}
              </strong>
            </span>

            <span className="inline-flex flex-wrap items-center gap-1 text-[var(--muted)]">
              <span>安全环境：</span>
              {detectedSecurityProducts.length > 0 ? (
                detectedSecurityProducts.map((prod) => (
                  <span
                    key={prod}
                    className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]"
                  >
                    {prod}
                  </span>
                ))
              ) : (
                <span className="text-[var(--text-secondary)]">常规环境</span>
              )}
            </span>

            <span
              className="inline-flex min-w-0 items-center gap-1 text-[var(--muted)]"
              title={verifyMessageText ?? verifyStateFallbackLabel}
            >
              <span className="shrink-0">上次探测：</span>
              {verifyCheckedClock && (
                <span className="cc-mono shrink-0 text-[var(--text-secondary)]">
                  {verifyCheckedClock}
                </span>
              )}
              <span
                className={`truncate font-medium ${
                  isVerifiedVerify
                    ? "text-[var(--green)]"
                    : isDegradedVerify || preaccelSummary.verifyState === "failed"
                      ? "text-[var(--amber)]"
                      : "text-[var(--text-secondary)]"
                }`}
              >
                {verifyCheckedClock ? "· " : ""}
                {verifyMessageText ?? verifyStateFallbackLabel}
              </span>
            </span>
          </div>

          {globalPreAccel.last_error && (
            <div className="flex items-start gap-2 rounded-lg border border-[var(--amber)]/45 bg-[var(--amber-soft)]/60 px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{globalPreAccel.last_error}</span>
            </div>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">
                {platformOs === "macos" ? "macOS" : "Linux"} 本地独立 443 SOCKS5 入口
              </div>
              <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                {effectiveGlobalPort
                  ? "把其它代理软件的前置代理或终端环境变量指向此地址，免开猫猫主代理也能直享国内 443 上传加速。"
                  : "开启顶部「开启国内提速」总开关后会自动分配本地独立 443 SOCKS5 通道端口。"}
              </p>
            </div>
            {effectiveGlobalPort && (
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() =>
                    void handleCopyGlobalShellCmd(
                      effectiveGlobalPort,
                      "posix",
                      platformOs === "macos" ? "Zsh / Bash" : "Bash / Zsh"
                    )
                  }
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                >
                  {copiedShellKind === "posix" ? (
                    <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                  ) : (
                    <Terminal className="h-3.5 w-3.5" />
                  )}
                  <span>
                    {copiedShellKind === "posix"
                      ? "已复制命令"
                      : platformOs === "macos"
                        ? "复制 Zsh / Bash 加速命令"
                        : "复制 Bash / Zsh 加速命令"}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() =>
                    void handleCopyGlobalShellCmd(effectiveGlobalPort, "fish", "Fish")
                  }
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                >
                  {copiedShellKind === "fish" ? (
                    <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                  ) : (
                    <Terminal className="h-3.5 w-3.5" />
                  )}
                  <span>{copiedShellKind === "fish" ? "已复制 Fish" : "复制 Fish 命令"}</span>
                </button>
              </div>
            )}
          </div>
          {effectiveGlobalPort && (
            <div className="mt-2 rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono cc-selectable text-[11px] text-[var(--text-secondary)]">
              {buildGlobalPreAccelShellSnippet(effectiveGlobalPort, "posix")}
            </div>
          )}
        </div>
      )}

      {/* 4.3 Windows 加速范围与自定义额外/排除进程名 */}
      {isWindows && (
        <div className="space-y-3">
          <div className="text-xs font-semibold text-[var(--text)]">加速范围</div>
          <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
            <button
              type="button"
              disabled={savingGlobalScope}
              onClick={() => void onSelectGlobalScope("proxy_apps_only")}
              className={`rounded-xl border p-3.5 text-left transition-colors disabled:opacity-70 ${
                globalScope === "proxy_apps_only"
                  ? "border-[var(--accent)] bg-[var(--accent-soft)]/50"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-[var(--text)]">
                  智能自动识别代理核心
                </span>
                <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                  默认推荐
                </span>
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                实时识别本机运行的其它代理核心与远程命令行工具，不绕走日常国内大文件与普通软件。
              </p>
            </button>

            <button
              type="button"
              disabled={savingGlobalScope}
              onClick={() => void onSelectGlobalScope("all_non_443_tcp")}
              className={`rounded-xl border p-3.5 text-left transition-colors disabled:opacity-70 ${
                globalScope === "all_non_443_tcp"
                  ? "border-[var(--accent)] bg-[var(--accent-soft)]/50"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-[var(--text)]">
                  全机非 443 兜底加速
                </span>
                {globalScope === "all_non_443_tcp" && (
                  <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                    当前生效
                  </span>
                )}
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                除私网、中转机与 443 端口外全部非 443 TCP 连接走 443 加速（可能带入其它国内非 443 传输）。
              </p>
            </button>
          </div>

          {globalScope === "proxy_apps_only" && (
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">
                    自定义额外 / 排除进程名（当前 {targetProcesses.length} 项）
                  </span>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    运行时会自动识别代理核心；如需额外补充指定程序或点 × 移除不想包含的进程，可在此调整。
                  </p>
                </div>
                <button
                  type="button"
                  disabled={savingGlobalScope}
                  onClick={() => void onResetTargetProcesses()}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-55"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>恢复默认</span>
                </button>
              </div>

              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {targetProcesses.map((proc) => (
                  <span
                    key={proc}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 cc-mono text-[11px] text-[var(--text-secondary)]"
                  >
                    <span>{proc}</span>
                    <button
                      type="button"
                      disabled={savingGlobalScope}
                      onClick={() => void onRemoveTargetProcess(proc)}
                      className="rounded p-0.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--red)] disabled:opacity-45"
                      aria-label={`移除 ${proc}`}
                      title={`移除 ${proc}`}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
                {targetProcesses.length === 0 && (
                  <span className="text-[11px] text-[var(--muted)]">
                    当前完全依赖自动识别，也可在下方手动补充进程名
                  </span>
                )}
              </div>

              <form
                onSubmit={(ev) => void handleAddFormSubmit(ev)}
                className="mt-2.5 flex flex-wrap items-center gap-2"
              >
                <input
                  type="text"
                  value={newProcessInput}
                  onChange={(e) => setNewProcessInput(e.target.value)}
                  placeholder="输入额外进程名（如 mihomo.exe, sing-box.exe, ssh.exe）"
                  className="cc-mono min-w-[220px] flex-1 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                />
                <button
                  type="submit"
                  disabled={savingGlobalScope || !newProcessInput.trim()}
                  className="inline-flex shrink-0 items-center gap-1 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>添加进程</span>
                </button>
              </form>
            </div>
          )}
        </div>
      )}
    </>
  );
}
