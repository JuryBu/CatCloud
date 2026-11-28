import { AlertTriangle, Eye, EyeOff, Keyboard, Shield } from "lucide-react";
import { useState } from "react";
import {
  type AppConfig,
  type RuntimeInfoDto,
  type TunStackMode,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import { appActions } from "../../store/appStore";
import type { PlatformOs } from "../../utils/platform";
import {
  BTN_CLS,
  Card,
  INPUT_CLS,
  NumericDraftInput,
  SegButtons,
  SwitchRow,
} from "./SettingsPrimitives";
import {
  type ExtendedSettings,
  HOTKEY_LABELS,
  LOG_LEVEL_OPTIONS,
  type LogLevel,
  TRAY_CLICK_OPTIONS,
} from "./settingsPatch";

export interface SystemTabProps {
  draft: AppConfig;
  ext: ExtendedSettings;
  runtime: RuntimeInfoDto;
  platformOs: PlatformOs;
  isWindows: boolean;
  startupPageOptions: { value: string; label: string }[];
  patchDraft: (patch: Partial<AppConfig>) => void;
  patchExt: <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => void;
  onDnsPortChange: (nextPort: number) => void;
}

export function SystemTab({
  draft,
  ext,
  runtime,
  platformOs,
  isWindows,
  startupPageOptions,
  patchDraft,
  patchExt,
  onDnsPortChange,
}: SystemTabProps) {
  const [showSecret, setShowSecret] = useState(false);

  const handleLaunchUwp = async () => {
    try {
      const res = await catcloudApi.launchUwpLoopback();
      appActions.showToast(
        res.message || "已检查本机应用网络放行状态",
        res.launched ? "ok" : "info"
      );
    } catch (err) {
      appActions.showToast(`查看本机应用网络放行状态失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-2">
        <Card title="系统代理与分流接管" sub="控制电脑上网流量如何经过猫猫云梯">
          <SwitchRow
            title="启用系统代理"
            desc={`将系统流量转发至本地代理端口 :${draft.mixed_port}`}
            checked={runtime.system_proxy_enabled}
            onChange={(v) => void appActions.toggleSystemProxy(v)}
          />
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_126px]">
            <SwitchRow
              title="系统代理守护"
              desc="定期自动恢复被其他软件改掉的系统代理"
              checked={draft.proxy_guard_enabled}
              onChange={(v) => patchDraft({ proxy_guard_enabled: v })}
            />
            <label className="rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2 text-[11px] text-[var(--muted)]">
              检查间隔（秒）
              <NumericDraftInput
                min={5}
                max={300}
                fallback={30}
                value={draft.proxy_guard_interval_sec}
                onCommit={(nextVal) => patchDraft({ proxy_guard_interval_sec: nextVal })}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
          </div>
          <SwitchRow
            title="国内网站与局域网自动直连"
            desc="微信、QQ、国内网站、高校内网和局域网直连不绕代理"
            checked={ext.domesticDirectEnabled}
            onChange={(v) => patchExt("domesticDirectEnabled", v)}
          />
          <SwitchRow
            title="自动拦截 QUIC (UDP 443)"
            desc="防止 Chrome / Google / AI 走 UDP 443 经中转黑洞卡顿"
            checked={ext.blockQuicUdp443}
            onChange={(v) => patchExt("blockQuicUdp443", v)}
          />
          <div className="flex items-center justify-between gap-3 rounded-xl border border-dashed border-[var(--line)] bg-[var(--bg-elevated)]/55 px-3 py-2 opacity-75">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs font-medium text-[var(--muted)]">
                <span>本地 PAC 分流</span>
                <span className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                  规划中
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                本地 PAC 服务正在规划中，推荐使用规则模式或虚拟网卡
              </p>
            </div>
          </div>
          <label className="block text-[11px] text-[var(--muted)]">
            不走代理的地址（逗号分隔）
            <textarea
              rows={2}
              value={ext.bypassDomains}
              onChange={(e) => patchExt("bypassDomains", e.target.value)}
              className={`${INPUT_CLS} mt-1 cc-mono`}
            />
          </label>
        </Card>

        <Card title="虚拟网卡接管与端口设置" sub="接管全电脑软件、自定义监听端口与口令">
          <SwitchRow
            title="虚拟网卡接管"
            desc={
              runtime.tun_needs_elevation
                ? "你已勾选虚拟网卡，但当前普通权限未生效"
                : runtime.tun_admin_ready
                  ? "已具备虚拟网卡网络权限，可接管终端和桌面软件等全部流量"
                  : platformOs === "linux"
                    ? "需要为代理核心授予网络权限，开启时将弹出系统授权提示（界面保持普通用户）"
                    : platformOs === "macos"
                      ? "需要 macOS 系统安全授权，开启时将弹出授权指引"
                      : "需要管理员权限，开启时将弹出系统授权提示（UAC）"
            }
            checked={runtime.tun_enabled}
            onChange={(v) => void appActions.toggleTun(v)}
            badge={
              <span
                className="rounded-md px-1.5 py-0.5 text-[10px]"
                style={{
                  backgroundColor: runtime.tun_needs_elevation
                    ? "var(--amber-soft)"
                    : runtime.tun_admin_ready
                      ? "var(--green-soft)"
                      : "var(--amber-soft)",
                  color: runtime.tun_needs_elevation
                    ? "var(--amber)"
                    : runtime.tun_admin_ready
                      ? "var(--green)"
                      : "var(--amber)",
                }}
              >
                {runtime.tun_needs_elevation
                  ? "未生效 · 需提权"
                  : runtime.tun_admin_ready
                    ? "权限就绪"
                    : platformOs === "linux"
                      ? "需授核心权限"
                      : "需授权"}
              </span>
            }
          />
          {runtime.tun_needs_elevation && (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/70 px-3 py-2 text-xs">
              <div className="flex min-w-0 items-center gap-2 text-[var(--amber)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span className="font-medium">
                  {platformOs === "linux"
                    ? "虚拟网卡未生效，需授予核心网络权限"
                    : "虚拟网卡未生效，需以管理员身份重启"}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => appActions.openTunAdminPrompt(null)}
                  className="inline-flex items-center gap-1 rounded-lg bg-[var(--amber)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  <Shield className="h-3 w-3 shrink-0" />
                  <span>{platformOs === "linux" ? "授权核心权限" : "以管理员重启生效"}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void appActions.toggleTun(false)}
                  className="rounded-lg border border-[var(--amber)]/45 bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--amber)] hover:text-[var(--text)]"
                >
                  关闭此配置
                </button>
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
            <div className="text-xs font-medium text-[var(--text)]">虚拟网卡接管引擎</div>
            <SegButtons<TunStackMode>
              value={draft.tun_stack_mode}
              onChange={(v) => patchDraft({ tun_stack_mode: v })}
              options={[
                ["mixed", "默认引擎（推荐）"],
                ["system", "系统内核引擎"],
                ["gvisor", "独立兼容引擎"],
              ]}
            />
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <label className="min-w-0 text-[11px] text-[var(--muted)]">
              混合端口
              <NumericDraftInput
                min={1}
                max={65535}
                fallback={17890}
                value={draft.mixed_port}
                onCommit={(nextVal) => patchDraft({ mixed_port: nextVal })}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
            <label className="min-w-0 text-[11px] text-[var(--muted)]">
              控制端口
              <NumericDraftInput
                min={1}
                max={65535}
                fallback={19090}
                value={draft.controller_port}
                onCommit={(nextVal) => patchDraft({ controller_port: nextVal })}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
            <label className="min-w-0 text-[11px] text-[var(--muted)]">
              DNS 端口
              <NumericDraftInput
                min={1}
                max={65535}
                fallback={11053}
                value={draft.dns_listen_port}
                onCommit={onDnsPortChange}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
          </div>
          <label className="block text-[11px] text-[var(--muted)]">
            外部控制口令（可选）
            <div className="mt-1 flex items-center gap-1.5">
              <input
                type={showSecret ? "text" : "password"}
                value={ext.controllerSecret}
                onChange={(e) => patchExt("controllerSecret", e.target.value)}
                placeholder="留空由内核自动生成，仅外部面板需要固定密码时填写"
                className={`${INPUT_CLS} cc-mono`}
              />
              <button
                type="button"
                onClick={() => setShowSecret((v) => !v)}
                className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                title={showSecret ? "隐藏口令" : "显示口令"}
                aria-label={showSecret ? "隐藏口令" : "显示口令"}
              >
                {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>
          </label>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <SwitchRow
              title="允许局域网连接"
              desc="供局域网设备共用代理"
              checked={ext.allowLan}
              onChange={(v) => patchExt("allowLan", v)}
            />
            <SwitchRow
              title="统一测速延迟"
              desc="延迟测速更贴近真实"
              checked={draft.unified_delay}
              onChange={(v) => patchDraft({ unified_delay: v })}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
              <span>日志详细度</span>
              <AppSelect
                aria-label="内核日志详细度"
                size="sm"
                value={ext.logLevel}
                onChange={(v) => patchExt("logLevel", v as LogLevel)}
                options={LOG_LEVEL_OPTIONS.map((lv) => ({
                  value: lv.value,
                  label: lv.label,
                }))}
                className="min-w-[116px]"
                buttonClassName="rounded-lg"
              />
            </div>
            {isWindows && (
              <button type="button" onClick={() => void handleLaunchUwp()} className={BTN_CLS}>
                <Shield className="h-3.5 w-3.5" />
                <span>查看本机应用网络放行状态</span>
              </button>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-2">
        <Card
          title="启动与托盘行为"
          sub="管理开机启动、默认首页与关闭窗口时的驻留方式"
          action={
            <button
              type="button"
              onClick={() =>
                void catcloudApi
                  .enterWindowlessMode()
                  .then(() => appActions.showToast("已切换为无窗省内存模式", "info"))
                  .catch((err) =>
                    appActions.showToast(`进入无窗模式失败：${formatErrorMessage(err)}`, "warn")
                  )
              }
              className="text-xs font-medium text-[var(--accent)] hover:underline"
            >
              立即无窗驻留
            </button>
          }
        >
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <SwitchRow
              title="开机自启"
              desc="开机自动启动猫猫云梯"
              checked={draft.autostart_enabled}
              onChange={(v) => patchDraft({ autostart_enabled: v })}
            />
            <SwitchRow
              title="静默启动"
              desc="启动后静默藏于托盘"
              checked={draft.silent_start}
              onChange={(v) => patchDraft({ silent_start: v })}
            />
            <div className="sm:col-span-2">
              <SwitchRow
                title="关闭进无窗"
                desc="关闭主窗口时不退出，仅留托盘图标以省内存"
                checked={ext.closeToWindowless}
                onChange={(v) => patchExt("closeToWindowless", v)}
              />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div className="text-[11px] text-[var(--muted)]">
              <span className="block">启动默认页面</span>
              <AppSelect
                aria-label="启动默认页面"
                size="sm"
                value={ext.startupPage}
                onChange={(v) => patchExt("startupPage", v)}
                options={startupPageOptions}
                className="mt-1 w-full"
              />
            </div>
            <div className="text-[11px] text-[var(--muted)]">
              <span className="block">单击托盘图标</span>
              <AppSelect
                aria-label="单击托盘图标"
                size="sm"
                value={ext.trayClickAction}
                onChange={(v) => patchExt("trayClickAction", v)}
                options={TRAY_CLICK_OPTIONS.map((opt) => ({
                  value: opt.value,
                  label: opt.label,
                }))}
                className="mt-1 w-full"
              />
            </div>
          </div>
        </Card>

        <Card title="全局快捷键" sub="随时一键切换代理、节点或窗口，留空表示禁用">
          <div className="space-y-2">
            {Object.entries(ext.hotkeys).map(([k, val]) => (
              <label
                key={k}
                className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-1.5 text-xs text-[var(--text-secondary)]"
              >
                <span
                  title={HOTKEY_LABELS[k] ?? k}
                  className="inline-flex min-w-0 flex-1 items-center gap-2 overflow-hidden"
                >
                  <Keyboard className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                  <span className="min-w-0 truncate font-medium text-[var(--text)]">
                    {HOTKEY_LABELS[k] ?? k}
                  </span>
                </span>
                <input
                  value={val}
                  placeholder="未绑定"
                  onChange={(e) => patchExt("hotkeys", { ...ext.hotkeys, [k]: e.target.value })}
                  className="w-[136px] shrink-0 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-right text-[11px] cc-mono text-[var(--text)] outline-none focus:border-[var(--accent)] sm:w-[152px]"
                />
              </label>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
