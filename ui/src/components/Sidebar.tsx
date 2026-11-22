import {
  Gauge,
  Globe,
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
import {
  type NavRouteId,
  type ProxyMode,
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
  { id: "overview", label: "总览", shortDesc: "监控与核心状态", icon: LayoutDashboard },
  { id: "groups", label: "智能多选组", shortDesc: "公式优选与兜底", icon: Layers },
  { id: "speedtest", label: "隔离测速", shortDesc: "零干扰探针漏斗", icon: Gauge },
  { id: "preaccel", label: "国内预加速", shortDesc: "443 双活与防环", icon: Zap },
  { id: "nodes", label: "节点与订阅", shortDesc: "多维混池与对口", icon: Globe },
  { id: "rules", label: "规则与连接", shortDesc: "分流与精准踢断", icon: Network },
  { id: "logs", label: "实时日志", shortDesc: "内核流式检索", icon: ScrollText },
  { id: "settings", label: "设置与 CLI", shortDesc: "专业配置与个性化", icon: SlidersHorizontal },
] as const;

const THEME_LABELS = {
  auto_time: "自动",
  light: "暖纸",
  warm_dark: "深苔",
  midnight_blue: "星蓝",
} as const;

const PROXY_MODES: Array<{ id: ProxyMode; label: string }> = [
  { id: "rule", label: "规则" },
  { id: "global", label: "全局" },
  { id: "direct", label: "直连" },
];

export function Sidebar() {
  const activeNav = useAppSelector((s) => s.activeNav);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const runtime = useAppSelector((s) => s.runtime);

  const statusColor =
    runtime.status === "error"
      ? "var(--red)"
      : runtime.status === "warn"
        ? "var(--amber)"
        : runtime.status === "preaccel"
          ? "var(--accent)"
          : "var(--green)";

  return (
    <aside className="cc-surface cc-glass relative z-10 flex h-full w-[236px] shrink-0 flex-col border-r border-[var(--line)] px-3 py-3.5">
      {/* Brand header with animated cream-cat MascotSprite */}
      <div className="mb-3 flex items-center justify-between gap-2 px-1">
        <div className="flex min-w-0 items-center gap-2">
          <div className="relative flex h-10 w-11 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--card)]">
            <MascotSprite state="idle" scale={2} title="猫猫云梯 · 奶油猫饼" />
            <span
              className="cc-pulse-dot absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)]"
              style={{ backgroundColor: statusColor }}
              title={`运行态：${runtime.status}`}
            />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[14px] font-semibold tracking-tight text-[var(--text)]">
              猫猫云梯
            </div>
            <div className="flex items-center gap-1 whitespace-nowrap text-[10px] text-[var(--muted)]">
              <span className="cc-mono uppercase tracking-wide">CatCloud</span>
              <span className="cc-mono">v{runtime.app_version}</span>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={() => appActions.cycleThemeMode()}
          className="inline-flex h-7 shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
          title="切换主题模式（自动昼夜 / 暖纸浅色 / 深苔暖金 / 午夜星蓝）"
        >
          {resolvedTheme === "light" ? (
            <Sun className="h-3.5 w-3.5 text-[var(--accent)]" />
          ) : resolvedTheme === "midnight-blue" ? (
            <Sparkles className="h-3.5 w-3.5 text-[var(--sky)]" />
          ) : (
            <Moon className="h-3.5 w-3.5 text-[var(--accent)]" />
          )}
          <span>{THEME_LABELS[themeMode]}</span>
        </button>
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
                  双活
                </span>
              )}
              {item.id === "overview" && runtime.captive_portal_required && (
                <span className="ml-auto h-2 w-2 rounded-full bg-[var(--red)]" title="校园网待认证" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom compact live sparkline + system proxy / TUN status capsules */}
      <div className="mt-3 space-y-2 pt-2 border-t border-[var(--line)]">
        <TrafficSparkline variant="mini" />

        {/* Service / Proxy / TUN Status Capsules */}
        <div className="grid grid-cols-2 gap-1.5">
          <button
            type="button"
            onClick={() => void appActions.toggleSystemProxy()}
            className={`flex items-center justify-between rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              runtime.system_proxy_enabled
                ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
            title="点击切换系统代理"
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
            title={runtime.tun_admin_ready ? "点击切换 TUN 虚拟网卡" : "TUN 需管理员或服务权限"}
          >
            <span className="inline-flex items-center gap-1 truncate">
              <ShieldCheck className="h-3 w-3 shrink-0" />
              TUN
            </span>
            <span
              className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                runtime.tun_enabled ? "bg-[var(--accent)]" : "bg-[var(--muted)]/50"
              }`}
            />
          </button>
        </div>

        {/* Compact proxy mode selector + capsule toggle */}
        <div className="flex items-center gap-1.5">
          <div className="grid flex-1 grid-cols-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]">
            {PROXY_MODES.map((m) => {
              const selected = runtime.proxy_mode === m.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => void appActions.setProxyMode(m.id)}
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
            title="打开 / 预览悬浮胶囊微窗 (#capsule)"
          >
            <PictureInPicture2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </aside>
  );
}
