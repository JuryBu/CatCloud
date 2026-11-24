import {
  Check,
  ChevronDown,
  Globe,
  Image,
  Layers,
  LayoutDashboard,
  Loader2,
  Moon,
  Network,
  PictureInPicture2,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Sun,
  Wifi,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  BUILTIN_WALLPAPER_PRESETS,
  type NavRouteId,
  type ProxyMode,
  type ResolvedTheme,
  type ThemeMode,
  appActions,
  selectHasBackgroundActivity,
  useAppSelector,
} from "../store/appStore";
import { MascotSprite } from "./MascotSprite";
import { TrafficSparkline } from "./TrafficSparkline";
import { resolvePlatformOs } from "../utils/platform";
import { type PreAccelSummary, resolvePreAccelSummary } from "../utils/preaccelStatus";

export interface NavItemSpec {
  id: NavRouteId;
  label: string;
  shortDesc: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: readonly NavItemSpec[] = [
  { id: "overview", label: "总览", shortDesc: "代理开关与实时状态", icon: LayoutDashboard },
  { id: "groups", label: "智能多选组", shortDesc: "路线分组与自动优选", icon: Layers },
  { id: "nodes", label: "节点与测速", shortDesc: "节点管理、订阅导入与测速", icon: Globe },
  { id: "preaccel", label: "国内提速", shortDesc: "国内中转与稳连加速", icon: Zap },
  { id: "rules", label: "分流与连接", shortDesc: "网站分流与当前连接", icon: Network },
  { id: "logs", label: "运行日志", shortDesc: "查看内核运行记录", icon: ScrollText },
  { id: "settings", label: "设置", shortDesc: "外观、启动与偏好", icon: SlidersHorizontal },
] as const;

const THEME_BUTTON_LABELS: Record<ThemeMode, string> = {
  auto_time: "自动",
  light: "暖纸",
  warm_dark: "深苔",
  midnight_blue: "星蓝",
};

const RESOLVED_THEME_NAMES: Record<ResolvedTheme, string> = {
  light: "浅色暖纸",
  "warm-dark": "深苔暖金",
  "midnight-blue": "午夜星蓝",
};

const THEME_OPTIONS: ReadonlyArray<{
  id: ThemeMode;
  label: string;
  swatchStyle: string;
  dotColor: string;
}> = [
  {
    id: "light",
    label: "浅色暖纸",
    swatchStyle: "linear-gradient(135deg, #fbf9f4 0%, #efeae0 100%)",
    dotColor: "#c4843d",
  },
  {
    id: "warm_dark",
    label: "深苔暖金",
    swatchStyle: "linear-gradient(135deg, #191c1c 0%, #272c2c 100%)",
    dotColor: "#dfb782",
  },
  {
    id: "midnight_blue",
    label: "午夜星蓝",
    swatchStyle: "linear-gradient(135deg, #0f172a 0%, #1c294a 100%)",
    dotColor: "#60a5fa",
  },
  {
    id: "auto_time",
    label: "按时间自动",
    swatchStyle: "linear-gradient(135deg, #fbf9f4 0%, #c4843d 45%, #16213e 100%)",
    dotColor: "#dfb782",
  },
];

const PROXY_MODES: ReadonlyArray<{ id: ProxyMode; label: string; hint: string }> = [
  { id: "rule", label: "规则", hint: "按规则自动分流" },
  { id: "global", label: "全局", hint: "全部流量走代理" },
  { id: "direct", label: "直连", hint: "全部流量直接连接" },
];

function resolveStatusLabel(status: string, preaccel: PreAccelSummary): string {
  if (status === "error") return "核心异常";
  if (status === "warn") return "路线存在波动";
  if (preaccel.proxyActive) {
    if (preaccel.enabled) {
      return preaccel.realWinDivertActive
        ? "国内提速中（猫云 + 其它软件）"
        : "国内提速运行中";
    }
    return "代理运行中";
  }
  if (preaccel.realWinDivertActive) return "全局提速中";
  if (preaccel.enabled) {
    if (preaccel.installState === "downloading" || preaccel.installState === "verifying") {
      return "正在准备提速组件…";
    }
    if (preaccel.installState === "need_elevation") {
      return "国内提速需管理员权限";
    }
    return "本地通道待命";
  }
  return "待命状态";
}

export function Sidebar() {
  const activeNav = useAppSelector((s) => s.activeNav);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const wallpaperPath = useAppSelector((s) => s.config.personalization.wallpaper_path);
  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const isProbeRunning = useAppSelector((s) => s.probeProgress.running);
  const bgPreaccel = useAppSelector((s) => selectHasBackgroundActivity(s).preaccel);
  const bgNodes = useAppSelector((s) => selectHasBackgroundActivity(s).nodes);
  const bgGroups = useAppSelector((s) => selectHasBackgroundActivity(s).groups);
  const bgHome = useAppSelector((s) => selectHasBackgroundActivity(s).home);
  const bgSettings = useAppSelector((s) => selectHasBackgroundActivity(s).settings);
  const multiGroupHasDirty = useAppSelector((s) => s.sessionDrafts.multiGroup.hasDirtyDrafts);
  const settingsHasDirty = useAppSelector((s) => s.sessionDrafts.settings.hasDirtyDrafts);
  const tunAdminPromptOpen = useAppSelector((s) => s.tunAdminPromptOpen);
  const tunAdminPromptBusy = useAppSelector((s) => s.tunAdminPromptBusy);
  const tunAdminPromptReason = useAppSelector((s) => s.tunAdminPromptReason);

  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const themeMenuRef = useRef<HTMLDivElement | null>(null);
  const platformOs = resolvePlatformOs(runtime.os_label);
  const preaccelSummary = resolvePreAccelSummary(
    runtime,
    globalPreAccel,
    preAccelEnabledConfig
  );
  const preaccelNavBadge = (() => {
    if (!preaccelSummary.enabled && !preaccelSummary.realWinDivertActive) {
      return null;
    }
    if (preaccelSummary.proxyActive) {
      return {
        label: "提速中",
        cls: "bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    if (preaccelSummary.realWinDivertActive) {
      return {
        label: "全局提速",
        cls: "bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    if (
      preaccelSummary.installState === "downloading" ||
      preaccelSummary.installState === "verifying"
    ) {
      return {
        label: "准备中",
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (preaccelSummary.installState === "need_elevation") {
      return {
        label: "需提权",
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    return {
      label: "待命",
      cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
    };
  })();

  useEffect(() => {
    if (!tunAdminPromptOpen) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !tunAdminPromptBusy) {
        appActions.closeTunAdminPrompt();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [tunAdminPromptOpen, tunAdminPromptBusy]);

  useEffect(() => {
    if (!themeMenuOpen) return;
    const handlePointerDown = (ev: MouseEvent) => {
      if (themeMenuRef.current && !themeMenuRef.current.contains(ev.target as Node)) {
        setThemeMenuOpen(false);
      }
    };
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setThemeMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [themeMenuOpen]);

  const statusColor =
    runtime.status === "error"
      ? "var(--red)"
      : runtime.status === "warn"
        ? "var(--amber)"
        : preaccelSummary.proxyActive && preaccelSummary.enabled
          ? "var(--accent)"
          : preaccelSummary.realWinDivertActive
            ? "var(--accent)"
            : preaccelSummary.enabled
              ? "var(--amber)"
              : preaccelSummary.proxyActive
                ? "var(--green)"
                : "var(--muted)";

  const statusLabel = resolveStatusLabel(runtime.status, preaccelSummary);

  const tunElevationCopy =
    platformOs === "linux"
      ? {
          ariaLabel: "为代理核心授予网络权限开启虚拟网卡",
          title: "为代理核心授予网络权限并开启虚拟网卡",
          desc: "虚拟网卡可接管终端、浏览器与桌面软件的全部流量。点击确认后，将通过系统授权仅给代理核心授予网络权限（cap_net_admin），界面继续以普通用户运行，不会污染个人配置目录。",
          actionLabel: "一键授予核心网络权限",
          busyLabel: "正在请求系统授权…",
          buttonHint: "开启虚拟网卡需要给代理核心授予网络权限，点击可一键授权",
        }
      : platformOs === "macos"
        ? {
            ariaLabel: "安全授权开启虚拟网卡",
            title: "安全授权开启虚拟网卡（macOS）",
            desc: "虚拟网卡可接管终端与桌面软件的全部流量，在 macOS 下创建系统虚拟网卡（utun）需要管理员安全授权。确认后将弹出系统授权指引，完成验证后即可自动开启虚拟网卡。",
            actionLabel: "前往系统授权并开启",
            busyLabel: "正在请求系统授权…",
            buttonHint: "开启虚拟网卡需要 macOS 系统安全授权，点击查看并一键授权",
          }
        : {
            ariaLabel: "需要管理员权限开启虚拟网卡",
            title: "以管理员身份重启并开启虚拟网卡",
            desc: "虚拟网卡可接管终端、游戏与桌面软件的全部流量，需要 Windows 管理员权限。确认后将弹出系统授权框（UAC），自动以管理员身份重启猫猫云梯并开启虚拟网卡。",
            actionLabel: "以管理员身份重启并开启",
            busyLabel: "正在请求授权…",
            buttonHint: "开启虚拟网卡需要管理员权限，点击可一键以管理员身份重启并开启",
          };

  const handleSelectTheme = (mode: ThemeMode) => {
    void appActions.setThemeMode(mode);
  };

  const handlePickWallpaper = async () => {
    setThemeMenuOpen(false);
    await appActions.pickWallpaperImage();
  };

  const handleSelectPresetWallpaper = (presetId: string | null, label: string) => {
    void appActions.setWallpaperPath(
      presetId,
      presetId ? `已更换背景：${label}` : "已恢复纯色背景"
    );
  };

  const handleOpenAppearanceSettings = () => {
    setThemeMenuOpen(false);
    appActions.openSettingsTab("appearance");
  };

  return (
    <aside className="cc-surface cc-glass relative z-20 flex h-full w-[236px] shrink-0 flex-col border-r border-[var(--line)] px-3 pb-3 pt-2.5">
      {/* Brand header with animated cream-cat MascotSprite & theme/wallpaper popover */}
      <div className="mb-2.5 flex items-center justify-between gap-1.5 px-0.5">
        <div className="flex min-w-0 items-center gap-1.5">
          <div className="relative flex h-10 w-[62px] shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--card)] px-0.5">
            <MascotSprite state="idle" scale={2} title="猫猫云梯 · 奶油猫饼" />
            <span
              className="cc-pulse-dot absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)]"
              style={{ backgroundColor: statusColor }}
              title={statusLabel}
            />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[14px] font-semibold tracking-tight text-[var(--text)]">
              猫猫云梯
            </div>
            <div className="flex items-center gap-1 whitespace-nowrap text-[10px] text-[var(--muted)]">
              <span className="cc-mono">v{runtime.app_version}</span>
            </div>
          </div>
        </div>

        {/* Theme & Wallpaper Popover Trigger */}
        <div ref={themeMenuRef} className="relative shrink-0">
          <button
            type="button"
            onClick={() => setThemeMenuOpen((open) => !open)}
            aria-expanded={themeMenuOpen}
            aria-haspopup="dialog"
            className={`inline-flex h-7 items-center gap-1 whitespace-nowrap rounded-lg border px-1.5 text-[11px] transition-colors ${
              themeMenuOpen
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--text)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            }`}
            title="切换主题配色与背景壁纸"
          >
            {resolvedTheme === "light" ? (
              <Sun className="h-3.5 w-3.5 text-[var(--accent)]" />
            ) : resolvedTheme === "midnight-blue" ? (
              <Sparkles className="h-3.5 w-3.5 text-[var(--sky)]" />
            ) : (
              <Moon className="h-3.5 w-3.5 text-[var(--accent)]" />
            )}
            <span>{THEME_BUTTON_LABELS[themeMode]}</span>
            <ChevronDown
              className={`h-3 w-3 shrink-0 opacity-75 transition-transform ${
                themeMenuOpen ? "rotate-180" : ""
              }`}
              aria-hidden="true"
            />
          </button>

          {themeMenuOpen && (
            <div
              role="dialog"
              aria-label="主题与壁纸快捷设置"
              className="absolute right-0 top-[calc(100%+6px)] z-50 max-h-[calc(100vh-100px)] w-[212px] overflow-y-auto rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2.5 text-[var(--text)]"
              style={{ boxShadow: "var(--shadow-popover)" }}
            >
              <div className="mb-1.5 flex items-center justify-between px-1">
                <span className="text-[11px] font-semibold text-[var(--text)]">界面主题</span>
                {themeMode === "auto_time" && (
                  <span className="text-[10px] text-[var(--muted)]">
                    当前：{RESOLVED_THEME_NAMES[resolvedTheme]}
                  </span>
                )}
              </div>

              <div className="space-y-1">
                {THEME_OPTIONS.map((opt) => {
                  const selected = themeMode === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => handleSelectTheme(opt.id)}
                      className={`flex w-full items-center justify-between gap-2 rounded-xl border px-2.5 py-1.5 text-left text-xs transition-colors ${
                        selected
                          ? "border-[var(--accent)]/60 bg-[var(--accent-soft)] font-semibold text-[var(--text)]"
                          : "border-transparent bg-transparent text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <span
                          className="relative inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-md border border-[var(--line-strong)]"
                          style={{ background: opt.swatchStyle }}
                          aria-hidden="true"
                        >
                          <span
                            className="h-1.5 w-1.5 rounded-full"
                            style={{ backgroundColor: opt.dotColor }}
                          />
                        </span>
                        <span>{opt.label}</span>
                      </span>
                      {selected && <Check className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />}
                    </button>
                  );
                })}
              </div>

              <div className="my-2.5 border-t border-[var(--line)]" />

              {/* Built-in wallpaper quick chips */}
              <div className="mb-2 px-1">
                <div className="mb-1.5 flex items-center justify-between text-[10px] text-[var(--muted)]">
                  <span>内置壁纸</span>
                  {wallpaperPath && (
                    <button
                      type="button"
                      onClick={() => handleSelectPresetWallpaper(null, "纯色背景")}
                      className="text-[var(--accent)] hover:underline"
                    >
                      清除
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-4 gap-1.5">
                  {BUILTIN_WALLPAPER_PRESETS.map((preset) => {
                    const active = wallpaperPath === preset.id;
                    return (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => handleSelectPresetWallpaper(preset.id, preset.label)}
                        title={preset.label}
                        className={`h-6 rounded-lg border transition-transform hover:scale-105 ${
                          active
                            ? "border-[var(--accent)] ring-1 ring-[var(--accent)]"
                            : "border-[var(--line-strong)]"
                        }`}
                        style={{ background: preset.previewStyle }}
                        aria-label={`选择内置壁纸：${preset.label}`}
                      />
                    );
                  })}
                </div>
              </div>

              {/* Pick custom wallpaper button */}
              <button
                type="button"
                onClick={() => void handlePickWallpaper()}
                className="flex w-full items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <Image className="h-3.5 w-3.5 shrink-0" />
                <span>更换背景壁纸…</span>
              </button>

              <div className="mt-2 flex justify-end px-0.5">
                <button
                  type="button"
                  onClick={handleOpenAppearanceSettings}
                  className="text-[11px] text-[var(--muted)] transition-colors hover:text-[var(--accent)]"
                >
                  更多外观设置 →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Unified 7-item primary navigation */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto pr-0.5" aria-label="主导航">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive =
            activeNav === item.id || (item.id === "nodes" && activeNav === "speedtest");
          const hasBgTask =
            item.id === "overview"
              ? bgHome
              : item.id === "groups"
                ? bgGroups
                : item.id === "nodes"
                  ? bgNodes
                  : item.id === "preaccel"
                    ? bgPreaccel
                    : item.id === "settings"
                      ? bgSettings
                      : false;
          const hasDirtyDraft =
            item.id === "groups"
              ? multiGroupHasDirty
              : item.id === "settings"
                ? settingsHasDirty
                : false;
          const showBgDot =
            !isActive && hasBgTask && !(item.id === "nodes" && isProbeRunning);
          const showDirtyDot = !isActive && !showBgDot && hasDirtyDraft;
          const bgDotTitle =
            item.id === "overview"
              ? "后台正在检测网站连通或出口信息，切回即可查看"
              : item.id === "groups"
                ? hasDirtyDraft
                  ? "后台正在测速或评估多选组（另有未应用的策略改动），切回即可查看"
                  : "后台正在测速或评估多选组，切回即可查看"
                : item.id === "nodes"
                  ? "后台正在刷新订阅、测速或捕捉节点，切回即可查看"
                  : item.id === "preaccel"
                    ? "后台正在运行提速对比、线路测速或准备组件，切回即可查看"
                    : hasDirtyDraft
                      ? "后台正在更新地理库、检查更新或执行维护任务（另有未保存更改），切回即可查看"
                      : "后台正在更新地理库、检查更新或执行维护任务，切回即可查看";
          const dirtyDotTitle =
            item.id === "groups"
              ? "有未应用的策略改动，切回可继续编辑"
              : "有未保存的设置更改，切回可继续保存";
          const hasRightIndicator =
            (item.id === "nodes" && isProbeRunning) ||
            (item.id === "preaccel" && Boolean(preaccelNavBadge)) ||
            (item.id === "overview" && runtime.captive_portal_required) ||
            showBgDot ||
            showDirtyDot;

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => appActions.setNav(item.id)}
              aria-current={isActive ? "page" : undefined}
              className={`group relative flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left text-[13px] transition-colors ${
                isActive
                  ? "bg-[var(--accent-soft)] font-semibold text-[var(--text)]"
                  : "text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
              }`}
            >
              {isActive && (
                <span
                  className="absolute left-0 top-1/2 h-4 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--accent)]"
                  aria-hidden="true"
                />
              )}
              <Icon
                className={`h-4 w-4 shrink-0 transition-colors ${
                  isActive
                    ? "text-[var(--accent)]"
                    : "text-[var(--muted)] group-hover:text-[var(--text)]"
                }`}
              />
              <span className="truncate">{item.label}</span>

              {hasRightIndicator && (
                <span className="ml-auto flex shrink-0 items-center gap-1.5">
                  {item.id === "nodes" && isProbeRunning && (
                    <span className="shrink-0 rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                      测速中
                    </span>
                  )}
                  {item.id === "preaccel" && preaccelNavBadge && (
                    <span
                      title={preaccelSummary.detailText}
                      className={`shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-medium ${preaccelNavBadge.cls}`}
                    >
                      {preaccelNavBadge.label}
                    </span>
                  )}
                  {item.id === "overview" && runtime.captive_portal_required && (
                    <span
                      className="h-2 w-2 rounded-full bg-[var(--red)]"
                      title="校园网待认证"
                    />
                  )}
                  {showBgDot && (
                    <span
                      className="h-1.5 w-1.5 rounded-full bg-[var(--amber)] ring-2 ring-[var(--amber-soft)]"
                      title={bgDotTitle}
                      aria-label={bgDotTitle}
                    />
                  )}
                  {showDirtyDot && (
                    <span
                      className="h-1.5 w-1.5 rounded-full bg-[var(--muted)]/75"
                      title={dirtyDotTitle}
                      aria-label={dirtyDotTitle}
                    />
                  )}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom compact control console: hidden on overview page to avoid duplicating Hero controls & sparkline */}
      {activeNav === "overview" ? (
        <div className="mt-3 border-t border-[var(--line)] pt-2.5">
          <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)]/80 bg-[var(--card)]/75 px-2.5 py-2 text-[11px] text-[var(--text-secondary)]">
            <span className="inline-flex min-w-0 items-center gap-1.5">
              <span
                className="h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: statusColor }}
                aria-hidden="true"
              />
              <span className="truncate">当前正在总览页管理</span>
            </span>
            <button
              type="button"
              onClick={() => void appActions.toggleCapsule()}
              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--surface)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
              title="打开悬浮小窗"
              aria-label="打开悬浮小窗"
            >
              <PictureInPicture2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-3 space-y-2 border-t border-[var(--line)] pt-2">
          <TrafficSparkline variant="mini" />

          {/* System Proxy / Virtual Network Card Quick Capsules */}
          <div className="grid grid-cols-2 gap-1.5">
            <button
              type="button"
              onClick={() => void appActions.toggleSystemProxy()}
              className={`flex items-center justify-between rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                runtime.system_proxy_enabled
                  ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
              title="点击开关系统代理"
            >
              <span className="inline-flex items-center gap-1 truncate">
                <Wifi className="h-3 w-3 shrink-0" />
                系统代理
              </span>
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                  runtime.system_proxy_enabled ? "bg-[var(--green)]" : "bg-[var(--muted)]/50"
                }`}
              />
            </button>

            <button
              type="button"
              onClick={() => void appActions.toggleTun()}
              className={`flex items-center justify-between rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                runtime.tun_enabled
                  ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
              title={
                runtime.tun_admin_ready
                  ? "点击开关虚拟网卡（接管电脑全部软件）"
                  : tunElevationCopy.buttonHint
              }
            >
              <span className="inline-flex items-center gap-1 truncate">
                <ShieldCheck className="h-3 w-3 shrink-0" />
                虚拟网卡
              </span>
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                  runtime.tun_enabled ? "bg-[var(--accent)]" : "bg-[var(--muted)]/50"
                }`}
              />
            </button>
          </div>

          {/* Compact proxy mode selector + floating mini window button */}
          <div className="flex items-center gap-1.5">
            <div
              className="grid flex-1 grid-cols-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
              role="group"
              aria-label="快捷切换代理模式"
            >
              {PROXY_MODES.map((m) => {
                const selected = runtime.proxy_mode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => void appActions.setProxyMode(m.id)}
                    title={m.hint}
                    className={`rounded-lg py-1 font-medium transition-colors ${
                      selected
                        ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                        : "text-[var(--muted)] hover:text-[var(--text)]"
                    }`}
                  >
                    {m.label}
                  </button>
                );
              })}
            </div>

            <button
              type="button"
              onClick={() => void appActions.toggleCapsule()}
              className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
              title="打开悬浮小窗"
              aria-label="打开悬浮小窗"
            >
              <PictureInPicture2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {tunAdminPromptOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!tunAdminPromptBusy) appActions.closeTunAdminPrompt();
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label={tunElevationCopy.ariaLabel}
              onClick={(e) => e.stopPropagation()}
              className="cc-surface w-full max-w-md rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                    <ShieldCheck className="h-5 w-5" />
                  </span>
                  <div>
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      {tunElevationCopy.title}
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      {tunElevationCopy.desc}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={tunAdminPromptBusy}
                  onClick={() => appActions.closeTunAdminPrompt()}
                  className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                  aria-label="关闭弹窗"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {tunAdminPromptReason && (
                <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] leading-relaxed text-[var(--muted)]">
                  {tunAdminPromptReason}
                </div>
              )}

              <div className="mt-5 flex items-center justify-end gap-2">
                <button
                  type="button"
                  disabled={tunAdminPromptBusy}
                  onClick={() => appActions.closeTunAdminPrompt()}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  暂不开启
                </button>
                <button
                  type="button"
                  disabled={tunAdminPromptBusy}
                  onClick={() => void appActions.relaunchAsAdminForTun()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
                >
                  {tunAdminPromptBusy ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  <span>
                    {tunAdminPromptBusy
                      ? tunElevationCopy.busyLabel
                      : tunElevationCopy.actionLabel}
                  </span>
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </aside>
  );
}
