import {
  Check,
  ChevronDown,
  Gauge,
  Globe,
  Image,
  Layers,
  LayoutDashboard,
  Moon,
  Network,
  PictureInPicture2,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Sun,
  Wifi,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  BUILTIN_WALLPAPER_PRESETS,
  type NavRouteId,
  type ProxyMode,
  type ResolvedTheme,
  type ThemeMode,
  appActions,
  useAppSelector,
} from "../store/appStore";
import { MascotSprite } from "./MascotSprite";
import { TrafficSparkline } from "./TrafficSparkline";

export interface NavItemSpec {
  id: NavRouteId;
  label: string;
  shortDesc: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: readonly NavItemSpec[] = [
  { id: "overview", label: "总览", shortDesc: "代理开关与实时状态", icon: LayoutDashboard },
  { id: "groups", label: "智能多选组", shortDesc: "路线分组与自动优选", icon: Layers },
  { id: "speedtest", label: "节点测速", shortDesc: "批量检测延迟与速度", icon: Gauge },
  { id: "preaccel", label: "国内提速", shortDesc: "国内中转与稳连加速", icon: Zap },
  { id: "nodes", label: "节点与订阅", shortDesc: "导入与管理全部节点", icon: Globe },
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

function resolveStatusLabel(status: string, running: boolean): string {
  if (!running && status === "idle") return "待命状态";
  switch (status) {
    case "error":
      return "核心异常";
    case "warn":
      return "路线存在波动";
    case "preaccel":
      return "国内提速运行中";
    case "ok":
      return "运行正常";
    default:
      return "待命状态";
  }
}

export function Sidebar() {
  const activeNav = useAppSelector((s) => s.activeNav);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const wallpaperPath = useAppSelector((s) => s.config.personalization.wallpaper_path);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const runtime = useAppSelector((s) => s.runtime);

  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const themeMenuRef = useRef<HTMLDivElement | null>(null);

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
        : runtime.status === "preaccel"
          ? "var(--accent)"
          : runtime.running
            ? "var(--green)"
            : "var(--muted)";

  const statusLabel = resolveStatusLabel(runtime.status, runtime.running);

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
    <aside className="cc-surface cc-glass relative z-20 flex h-full w-[236px] shrink-0 flex-col border-r border-[var(--line)] px-3 py-3.5">
      {/* Brand header with animated cream-cat MascotSprite & theme/wallpaper popover */}
      <div className="mb-3 flex items-center justify-between gap-1.5 px-0.5">
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
              className="absolute right-0 top-[calc(100%+8px)] z-50 w-[212px] rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2.5 text-[var(--text)]"
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

      {/* Unified 8-item primary navigation */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto pr-0.5" aria-label="主导航">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
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

              {item.id === "preaccel" && runtime.preaccel_active && (
                <span className="ml-auto rounded-full bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                  提速中
                </span>
              )}
              {item.id === "overview" && runtime.captive_portal_required && (
                <span
                  className="ml-auto h-2 w-2 rounded-full bg-[var(--red)]"
                  title="校园网待认证"
                />
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
                  : "开启虚拟网卡需要管理员权限"
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
    </aside>
  );
}
