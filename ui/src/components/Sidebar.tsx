import {
  Check,
  ChevronDown,
  Cpu,
  Gauge,
  Globe,
  Image,
  Layers,
  LayoutDashboard,
  Loader2,
  Moon,
  Network,
  Pause,
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
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  BUILTIN_WALLPAPER_PRESETS,
  type NavRouteId,
  type ProxyMode,
  type ResolvedTheme,
  type ThemeMode,
  appActions,
  appStore,
  useAppSelector,
  useLatestTraffic,
  useTrafficVersion,
} from "../store/appStore";
import { MascotSprite } from "./MascotSprite";
import { formatRate } from "./TrafficSparkline";

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

function buildMiniSvgPath(
  values: Float64Array,
  count: number,
  maxValue: number,
  width: number,
  height: number,
  padX: number,
  padTop: number,
  padBottom: number
): { linePath: string; areaPath: string } {
  if (count === 0) return { linePath: "", areaPath: "" };
  const innerW = Math.max(1, width - padX * 2);
  const innerH = Math.max(1, height - padTop - padBottom);
  const baseY = height - padBottom;
  const safeMax = Math.max(maxValue, 1024);
  const xs = new Float64Array(count);
  const ys = new Float64Array(count);

  for (let i = 0; i < count; i++) {
    xs[i] = count === 1 ? padX + innerW : padX + (i / (count - 1)) * innerW;
    const ratio = Math.min(1, Math.max(0, values[i] / safeMax));
    ys[i] = baseY - ratio * innerH;
  }

  if (count === 1) {
    const linePath = `M${padX.toFixed(1)},${ys[0].toFixed(1)} L${xs[0].toFixed(1)},${ys[0].toFixed(1)}`;
    const areaPath = `${linePath} L${xs[0].toFixed(1)},${baseY.toFixed(1)} L${padX.toFixed(1)},${baseY.toFixed(1)} Z`;
    return { linePath, areaPath };
  }

  const parts: string[] = [`M${xs[0].toFixed(1)},${ys[0].toFixed(1)}`];
  if (count === 2) {
    parts.push(`L${xs[1].toFixed(1)},${ys[1].toFixed(1)}`);
  } else {
    for (let i = 1; i < count - 1; i++) {
      const mx = (xs[i] + xs[i + 1]) * 0.5;
      const my = (ys[i] + ys[i + 1]) * 0.5;
      parts.push(`Q${xs[i].toFixed(1)},${ys[i].toFixed(1)} ${mx.toFixed(1)},${my.toFixed(1)}`);
    }
    const last = count - 1;
    parts.push(`L${xs[last].toFixed(1)},${ys[last].toFixed(1)}`);
  }

  const linePath = parts.join(" ");
  const areaPath = `${linePath} L${xs[count - 1].toFixed(1)},${baseY.toFixed(1)} L${xs[0].toFixed(1)},${baseY.toFixed(1)} Z`;
  return { linePath, areaPath };
}

function SidebarMiniTrafficCard() {
  const uid = useId().replace(/:/g, "");
  const liveVersion = useTrafficVersion();
  const latest = useLatestTraffic();
  const sparklineEnabled = useAppSelector(
    (s) => s.config.personalization.animations_enabled && s.config.personalization.sparkline_enabled
  );

  const [isVisible, setIsVisible] = useState<boolean>(() =>
    typeof document === "undefined" ? true : document.visibilityState === "visible"
  );
  const lastRenderedVersionRef = useRef<number>(liveVersion);

  useEffect(() => {
    const onVisibility = () => {
      setIsVisible(document.visibilityState === "visible");
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  const redrawPaused = !isVisible || !sparklineEnabled;
  if (!redrawPaused) {
    lastRenderedVersionRef.current = liveVersion;
  }
  const effectiveVersion = lastRenderedVersionRef.current;

  const ring = appStore.getTrafficBuffer();
  const vbWidth = 196;
  const vbHeight = 42;
  const computed = useMemo(() => {
    const total = ring.length;
    const count = Math.min(total, 60);
    const startOffset = total - count;
    const upSlice = new Float64Array(count);
    const downSlice = new Float64Array(count);

    let peak = 64 * 1024;
    for (let i = 0; i < count; i++) {
      const idx = startOffset + i;
      const u = ring.upAt(idx);
      const d = ring.downAt(idx);
      upSlice[i] = u;
      downSlice[i] = d;
      if (u > peak) peak = u;
      if (d > peak) peak = d;
    }

    const scaleMax = peak * 1.15;
    return {
      downGeom: buildMiniSvgPath(downSlice, count, scaleMax, vbWidth, vbHeight, 2, 4, 3),
      upGeom: buildMiniSvgPath(upSlice, count, scaleMax, vbWidth, vbHeight, 2, 4, 3),
      version: effectiveVersion,
    };
  }, [effectiveVersion, ring]);

  const gradDownId = `cc-sb-down-${uid}`;
  const gradUpId = `cc-sb-up-${uid}`;

  return (
    <div
      className="cc-card cc-glass rounded-xl px-3 py-2.5"
      title={
        redrawPaused
          ? "流量动画已暂停（省电模式）"
          : `近 2 分钟实时流量 · 内核内存 ${latest.memory_mb.toFixed(1)} MB`
      }
    >
      <div className="mb-1.5 flex items-center justify-between text-[11px] text-[var(--muted)]">
        <span className="font-medium">实时流量</span>
        {!sparklineEnabled ? (
          <span className="inline-flex items-center gap-1 text-[10px] text-[var(--amber)]">
            <Pause className="h-2.5 w-2.5" />
            已暂停
          </span>
        ) : (
          <span className="cc-tabular text-[10px] text-[var(--muted)]">
            {latest.connections} 个连接
          </span>
        )}
      </div>

      <svg
        viewBox={`0 0 ${vbWidth} ${vbHeight}`}
        preserveAspectRatio="none"
        className="block h-[40px] w-full overflow-visible"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id={gradDownId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--sky)" stopOpacity="0.34" />
            <stop offset="100%" stopColor="var(--sky)" stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id={gradUpId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--coral)" stopOpacity="0.32" />
            <stop offset="100%" stopColor="var(--coral)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {computed.downGeom.areaPath && (
          <path d={computed.downGeom.areaPath} fill={`url(#${gradDownId})`} />
        )}
        {computed.upGeom.areaPath && (
          <path d={computed.upGeom.areaPath} fill={`url(#${gradUpId})`} />
        )}
        {computed.downGeom.linePath && (
          <path
            d={computed.downGeom.linePath}
            fill="none"
            stroke="var(--sky)"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        )}
        {computed.upGeom.linePath && (
          <path
            d={computed.upGeom.linePath}
            fill="none"
            stroke="var(--coral)"
            strokeWidth="1.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        )}
      </svg>

      <div className="mt-2 flex items-center justify-between gap-2 text-[11px]">
        <span className="inline-flex min-w-0 items-center gap-1 whitespace-nowrap">
          <span className="text-[var(--coral)]">↑</span>
          <span className="cc-mono truncate font-medium text-[var(--text)]">
            {formatRate(latest.up_bps)}
          </span>
        </span>
        <span className="inline-flex min-w-0 items-center gap-1 whitespace-nowrap">
          <span className="text-[var(--sky)]">↓</span>
          <span className="cc-mono truncate font-medium text-[var(--text)]">
            {formatRate(latest.down_bps)}
          </span>
        </span>
      </div>

      <div className="mt-1.5 flex items-center justify-between border-t border-[var(--line)] pt-1.5 text-[11px]">
        <span className="inline-flex items-center gap-1 text-[var(--muted)]">
          <Cpu className="h-3 w-3 text-[var(--green)]" />
          内核内存
        </span>
        <span className="cc-mono font-medium text-[var(--green)]">
          {latest.memory_mb.toFixed(1)} MB
        </span>
      </div>
    </div>
  );
}

export function Sidebar() {
  const activeNav = useAppSelector((s) => s.activeNav);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const wallpaperPath = useAppSelector((s) => s.config.personalization.wallpaper_path);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const runtime = useAppSelector((s) => s.runtime);
  const tunAdminPromptOpen = useAppSelector((s) => s.tunAdminPromptOpen);
  const tunAdminPromptBusy = useAppSelector((s) => s.tunAdminPromptBusy);
  const tunAdminPromptReason = useAppSelector((s) => s.tunAdminPromptReason);

  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const themeMenuRef = useRef<HTMLDivElement | null>(null);

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
          <SidebarMiniTrafficCard />

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
                  : "开启虚拟网卡需要管理员权限，点击可一键以管理员身份重启并开启"
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
              aria-label="需要管理员权限开启虚拟网卡"
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
                      以管理员身份重启并开启虚拟网卡
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      虚拟网卡可接管终端、游戏与桌面软件的全部流量，需要 Windows 管理员权限。确认后将弹出系统授权框（UAC），自动以管理员身份重启猫猫云梯并开启虚拟网卡。
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
                    {tunAdminPromptBusy ? "正在请求授权…" : "以管理员身份重启并开启"}
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
