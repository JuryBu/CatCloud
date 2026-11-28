import {
  Bot,
  Check,
  ChevronDown,
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
import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import { formatI18nTemplate, normalizeUiLanguage, type UiLanguage, useUiDict } from "../i18n";
import {
  BUILTIN_WALLPAPER_PRESETS,
  type MascotState,
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
import {
  type GlobalPreAccelFields,
  type PreAccelSummary,
  type RuntimePreAccelFields,
  resolvePreAccelSummary,
} from "../utils/preaccelStatus";
import { isBoolPref, usePersistedState } from "../utils/uiPrefs";

const TunAdminPromptModal = lazy(() =>
  import("./TunAdminPromptModal").then((m) => ({ default: m.TunAdminPromptModal }))
);

export interface NavItemSpec {
  id: NavRouteId;
  section: "network" | "ai" | "assist";
  label: string;
  shortDesc: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: readonly NavItemSpec[] = [
  { id: "overview", section: "network", label: "总览", shortDesc: "代理开关与实时状态", icon: LayoutDashboard },
  { id: "nodes", section: "network", label: "节点与测速", shortDesc: "节点管理、订阅导入与测速", icon: Globe },
  { id: "groups", section: "network", label: "智能多选组", shortDesc: "路线分组与自动优选", icon: Layers },
  { id: "preaccel", section: "network", label: "国内提速", shortDesc: "国内中转与稳连加速", icon: Zap },
  { id: "ai", section: "ai", label: "AI 帮手", shortDesc: "全能代管 · 排障 · 提反馈", icon: Bot },
  { id: "settings", section: "assist", label: "设置", shortDesc: "外观、启动与偏好", icon: SlidersHorizontal },
  { id: "rules", section: "assist", label: "分流与连接", shortDesc: "网站分流与当前连接", icon: Network },
  { id: "logs", section: "assist", label: "运行日志", shortDesc: "查看内核运行记录", icon: ScrollText },
] as const;

const NETWORK_NAV_ITEMS = NAV_ITEMS.filter((item) => item.section === "network");
const AI_NAV_ITEM = NAV_ITEMS.find((item) => item.id === "ai")!;
const SETTINGS_NAV_ITEM = NAV_ITEMS.find((item) => item.id === "settings")!;
const MORE_TOOLS_NAV_ITEMS = NAV_ITEMS.filter(
  (item) => item.id === "rules" || item.id === "logs"
);

const THEME_BUTTON_LABELS_I18N: Record<UiLanguage, Record<ThemeMode, string>> = {
  "zh-CN": {
    auto_time: "自动",
    light: "暖纸",
    warm_dark: "深苔",
    midnight_blue: "星蓝",
  },
  en: {
    auto_time: "Auto",
    light: "Light",
    warm_dark: "Moss",
    midnight_blue: "Night",
  },
  ja: {
    auto_time: "自動",
    light: "ライト",
    warm_dark: "ダーク",
    midnight_blue: "ミッド",
  },
  ru: {
    auto_time: "Авто",
    light: "Свет.",
    warm_dark: "Тёмн.",
    midnight_blue: "Ночь",
  },
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

const SIDEBAR_STATUS_COPY: Record<
  UiLanguage,
  {
    error: string;
    warn: string;
    proxyActive: string;
    standby: string;
    noRelayBadge: string;
    preparingBadge: string;
    needAdminBadge: string;
  }
> = {
  "zh-CN": {
    error: "核心异常",
    warn: "路线存在波动",
    proxyActive: "代理运行中",
    standby: "待命状态",
    noRelayBadge: "待加线",
    preparingBadge: "准备中",
    needAdminBadge: "需提权",
  },
  en: {
    error: "Core Error",
    warn: "Route Fluctuating",
    proxyActive: "Proxy Active",
    standby: "Standby",
    noRelayBadge: "No Relay",
    preparingBadge: "Setup",
    needAdminBadge: "Admin",
  },
  ja: {
    error: "コア異常",
    warn: "回線が不安定",
    proxyActive: "プロキシ稼働中",
    standby: "待機中",
    noRelayBadge: "回線なし",
    preparingBadge: "準備中",
    needAdminBadge: "権限要",
  },
  ru: {
    error: "Ошибка ядра",
    warn: "Нестабильный маршрут",
    proxyActive: "Прокси активен",
    standby: "Ожидание",
    noRelayBadge: "Нет реле",
    preparingBadge: "Подгот.",
    needAdminBadge: "Админ",
  },
};

function resolveStatusLabel(
  status: string,
  preaccel: PreAccelSummary,
  hasEnabledRelay: boolean,
  uiLang: UiLanguage
): string {
  const copy = SIDEBAR_STATUS_COPY[uiLang];
  if (status === "error") return copy.error;
  if (status === "warn") return copy.warn;
  if (preaccel.proxyActive) {
    if (preaccel.enabled && hasEnabledRelay && preaccel.tone === "green") {
      return preaccel.subBadgeText
        ? `${preaccel.badgeText} · ${preaccel.subBadgeText}`
        : preaccel.badgeText;
    }
    return copy.proxyActive;
  }
  if (preaccel.enabled) {
    return preaccel.subBadgeText
      ? `${preaccel.badgeText} · ${preaccel.subBadgeText}`
      : preaccel.badgeText;
  }
  return copy.standby;
}

export function Sidebar() {
  const activeNav = useAppSelector((s) => s.activeNav);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const wallpaperPath = useAppSelector((s) => s.config.personalization.wallpaper_path);
  const animationsEnabled = useAppSelector((s) => s.config.personalization.animations_enabled);
  const mascotEnabled = useAppSelector((s) => s.config.personalization.mascot_enabled);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const isZh = uiLang === "zh-CN";
  const mascotState = useAppSelector((s) => s.mascotState);
  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const hasEnabledRelay = useAppSelector((s) =>
    s.preAccelRelays.some((r) => r.enabled)
  );
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  // Atomic primitive selectors prevent Sidebar from re-rendering on unrelated runtime ticks.
  const runtimeStatus = useAppSelector((s) => s.runtime.status);
  const runtimeOsLabel = useAppSelector((s) => s.runtime.os_label);
  const runtimeAppVersion = useAppSelector((s) => s.runtime.app_version);
  const runtimeRunning = useAppSelector((s) => s.runtime.running);
  const runtimeSystemProxyEnabled = useAppSelector((s) => s.runtime.system_proxy_enabled);
  const runtimeTunEnabled = useAppSelector((s) => s.runtime.tun_enabled);
  const runtimeTunNeedsElevation = useAppSelector((s) => s.runtime.tun_needs_elevation);
  const runtimeTunAdminReady = useAppSelector((s) => s.runtime.tun_admin_ready);
  const runtimeProxyMode = useAppSelector((s) => s.runtime.proxy_mode);
  const runtimeCaptivePortalRequired = useAppSelector((s) => s.runtime.captive_portal_required);
  const runtimeActiveGroupCircuitOpen = useAppSelector(
    (s) => s.runtime.active_group_circuit_open
  );
  const runtimeProbingActive = useAppSelector((s) => s.runtime.probing_active);
  const runtimeSwitchingActive = useAppSelector((s) => s.runtime.switching_active);
  const runtimeDnsTlsDiagStatus = useAppSelector(
    (s) => s.runtime.dns_tls_diagnostics?.status ?? null
  );
  const runtimePreaccelActive = useAppSelector((s) => s.runtime.preaccel_active);
  const runtimePreaccelEnabled = useAppSelector((s) => s.runtime.preaccel_enabled);
  const runtimePreaccelRelayName = useAppSelector((s) => s.runtime.preaccel_relay_name);
  const runtimeGlobalPreaccelActive = useAppSelector((s) => s.runtime.global_preaccel_active);
  const runtimeGlobalPreaccelMode = useAppSelector((s) => s.runtime.global_preaccel_mode);
  const runtimeGlobalPreaccelSocksPort = useAppSelector(
    (s) => s.runtime.global_preaccel_socks_port
  );
  const runtimePreaccelEffectiveCarrier = useAppSelector(
    (s) => s.runtime.preaccel_effective_carrier
  );
  const runtimeStandaloneSuspendedForTun = useAppSelector(
    (s) => s.runtime.standalone_tunnel_suspended_for_tun
  );
  const runtimeGlobalWinDivertActive = useAppSelector((s) => s.runtime.global_windivert_active);
  const runtimePreaccelInstallState = useAppSelector((s) => s.runtime.preaccel_install_state);
  const runtimeGlobalPreaccelVerifyState = useAppSelector(
    (s) => s.runtime.global_preaccel_verify_state
  );
  const runtimeGlobalPreaccelVerifyMs = useAppSelector(
    (s) => s.runtime.global_preaccel_verify_ms
  );

  const globalRunning = useAppSelector((s) => s.globalPreAccel.running);
  const globalMode = useAppSelector((s) => s.globalPreAccel.mode);
  const globalSocksPort = useAppSelector((s) => s.globalPreAccel.socks_port);
  const globalWindivertAvailable = useAppSelector((s) => s.globalPreAccel.windivert_available);
  const globalIsElevated = useAppSelector((s) => s.globalPreAccel.is_elevated);
  const globalLastError = useAppSelector((s) => s.globalPreAccel.last_error);
  const globalIsWindivertActive = useAppSelector((s) => s.globalPreAccel.is_windivert_active);
  const globalInstallState = useAppSelector((s) => s.globalPreAccel.install_state);
  const globalVerifyState = useAppSelector((s) => s.globalPreAccel.verify_state);
  const globalVerifyLatencyMs = useAppSelector((s) => s.globalPreAccel.verify_latency_ms);
  const globalVerifyMessage = useAppSelector((s) => s.globalPreAccel.verify_message);

  const isProbeRunning = useAppSelector((s) => s.probeProgress.running);
  const bgPreaccel = useAppSelector((s) => selectHasBackgroundActivity(s).preaccel);
  const bgNodes = useAppSelector((s) => selectHasBackgroundActivity(s).nodes);
  const bgGroups = useAppSelector((s) => selectHasBackgroundActivity(s).groups);
  const bgHome = useAppSelector((s) => selectHasBackgroundActivity(s).home);
  const bgSettings = useAppSelector((s) => selectHasBackgroundActivity(s).settings);
  const multiGroupHasDirty = useAppSelector((s) => s.sessionDrafts.multiGroup.hasDirtyDrafts);
  const settingsHasDirty = useAppSelector((s) => s.sessionDrafts.settings.hasDirtyDrafts);
  const tunAdminPromptOpen = useAppSelector((s) => s.tunAdminPromptOpen);
  const pendingUpdate = useAppSelector((s) => s.pendingUpdate);
  const updateMode = useAppSelector((s) => s.config.update.mode);

  const [moreToolsOpen, setMoreToolsOpen] = usePersistedState<boolean>(
    "sidebar.moreToolsOpen",
    false,
    isBoolPref
  );
  const isMoreToolsRoute = activeNav === "rules" || activeNav === "logs";
  const [moreToolsTempReveal, setMoreToolsTempReveal] = useState<boolean>(
    () => isMoreToolsRoute
  );

  useEffect(() => {
    setMoreToolsTempReveal(isMoreToolsRoute);
  }, [isMoreToolsRoute]);

  const isMoreToolsExpanded = moreToolsOpen || moreToolsTempReveal;
  const handleToggleMoreTools = () => {
    if (isMoreToolsExpanded) {
      setMoreToolsTempReveal(false);
      if (moreToolsOpen) {
        setMoreToolsOpen(false);
      }
    } else {
      setMoreToolsOpen(true);
    }
  };

  const hasDnsDiagAlert = Boolean(
    runtimeDnsTlsDiagStatus && runtimeDnsTlsDiagStatus !== "healthy"
  );
  const hasMoreToolsAlert = runtimeStatus === "error" || hasDnsDiagAlert;
  const isMoreToolsAlertSevere =
    runtimeStatus === "error" ||
    runtimeDnsTlsDiagStatus === "cert_verification_failed";

  const isNextLaunchSilentBadge = Boolean(
    pendingUpdate &&
      (pendingUpdate.silent_badge_only || updateMode === "next_launch")
  );
  const pendingUpdateBadgeTitle = pendingUpdate
    ? isNextLaunchSilentBadge
      ? dict.update.nextLaunchBadgeTip
      : formatI18nTemplate(dict.settings.updateReadyTitle, {
          version: pendingUpdate.target_version,
        })
    : "";
  const handleOpenPendingUpdate = () => {
    if (!pendingUpdate) return;
    appActions.openUpdateModal();
  };

  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const [localPetting, setLocalPetting] = useState(false);
  const themeMenuRef = useRef<HTMLDivElement | null>(null);
  const petTimerRef = useRef<number | null>(null);
  const platformOs = resolvePlatformOs(runtimeOsLabel);

  const runtimePreAccelFields = useMemo<RuntimePreAccelFields>(
    () => ({
      running: runtimeRunning,
      system_proxy_enabled: runtimeSystemProxyEnabled,
      tun_enabled: runtimeTunEnabled,
      preaccel_active: runtimePreaccelActive,
      preaccel_enabled: runtimePreaccelEnabled,
      preaccel_relay_name: runtimePreaccelRelayName,
      global_preaccel_active: runtimeGlobalPreaccelActive,
      global_preaccel_mode: runtimeGlobalPreaccelMode,
      global_preaccel_socks_port: runtimeGlobalPreaccelSocksPort,
      preaccel_effective_carrier: runtimePreaccelEffectiveCarrier,
      standalone_tunnel_suspended_for_tun: runtimeStandaloneSuspendedForTun,
      global_windivert_active: runtimeGlobalWinDivertActive,
      preaccel_install_state: runtimePreaccelInstallState,
      global_preaccel_verify_state: runtimeGlobalPreaccelVerifyState,
      global_preaccel_verify_ms: runtimeGlobalPreaccelVerifyMs,
    }),
    [
      runtimeRunning,
      runtimeSystemProxyEnabled,
      runtimeTunEnabled,
      runtimePreaccelActive,
      runtimePreaccelEnabled,
      runtimePreaccelRelayName,
      runtimeGlobalPreaccelActive,
      runtimeGlobalPreaccelMode,
      runtimeGlobalPreaccelSocksPort,
      runtimePreaccelEffectiveCarrier,
      runtimeStandaloneSuspendedForTun,
      runtimeGlobalWinDivertActive,
      runtimePreaccelInstallState,
      runtimeGlobalPreaccelVerifyState,
      runtimeGlobalPreaccelVerifyMs,
    ]
  );

  const globalPreAccelFields = useMemo<GlobalPreAccelFields>(
    () => ({
      running: globalRunning,
      mode: globalMode,
      socks_port: globalSocksPort,
      windivert_available: globalWindivertAvailable,
      is_elevated: globalIsElevated,
      last_error: globalLastError,
      is_windivert_active: globalIsWindivertActive,
      install_state: globalInstallState,
      verify_state: globalVerifyState,
      verify_latency_ms: globalVerifyLatencyMs,
      verify_message: globalVerifyMessage,
    }),
    [
      globalRunning,
      globalMode,
      globalSocksPort,
      globalWindivertAvailable,
      globalIsElevated,
      globalLastError,
      globalIsWindivertActive,
      globalInstallState,
      globalVerifyState,
      globalVerifyLatencyMs,
      globalVerifyMessage,
    ]
  );

  const preaccelSummary = resolvePreAccelSummary(
    runtimePreAccelFields,
    globalPreAccelFields,
    preAccelEnabledConfig,
    hasEnabledRelay,
    uiLang
  );
  const statusCopy = SIDEBAR_STATUS_COPY[uiLang];
  const preaccelWithRelay = preaccelSummary.enabled && hasEnabledRelay;

  useEffect(() => {
    return () => {
      if (petTimerRef.current !== null) {
        window.clearTimeout(petTimerRef.current);
        petTimerRef.current = null;
      }
    };
  }, []);

  const effectiveBrandMascotState: MascotState = !mascotEnabled
    ? "idle"
    : runtimeStatus === "error" ||
        runtimeCaptivePortalRequired ||
        runtimeActiveGroupCircuitOpen ||
        runtimeTunNeedsElevation
      ? "approval"
      : isProbeRunning || runtimeProbingActive
        ? "searching"
        : runtimeSwitchingActive
          ? "thinking"
          : localPetting
            ? preaccelWithRelay
              ? "complete"
              : "thinking"
            : mascotState;
  const brandMascotScale = effectiveBrandMascotState === "idle" ? 2 : 1;
  const brandMascotStatusText =
    effectiveBrandMascotState !== "idle"
      ? dict.mascot[effectiveBrandMascotState]
      : preaccelSummary.proxyActive
        ? preaccelWithRelay && preaccelSummary.tone === "green"
          ? dict.mascot.preaccel
          : dict.mascot.ok
        : preaccelWithRelay && preaccelSummary.realWinDivertActive
          ? dict.mascot.preaccel
          : dict.mascot.idle;
  const brandMascotTitle = `${dict.common.appName} · ${brandMascotStatusText}`;

  const preaccelNavBadge = (() => {
    if (!preaccelSummary.enabled && !preaccelSummary.realWinDivertActive) {
      return null;
    }
    if (!hasEnabledRelay) {
      return {
        label: statusCopy.noRelayBadge,
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (preaccelSummary.proxyActive) {
      if (preaccelSummary.tone === "amber") {
        return {
          label: statusCopy.noRelayBadge,
          cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
        };
      }
      return {
        label: dict.nav.preaccelActiveBadge,
        cls: "bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    if (preaccelSummary.realWinDivertActive) {
      if (preaccelSummary.verifyState === "probing") {
        return {
          label: dict.nav.preaccelProbingBadge,
          cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
        };
      }
      if (preaccelSummary.verifyState === "verified") {
        return {
          label: dict.nav.preaccelVerifiedBadge,
          cls: "bg-[var(--green-soft)] text-[var(--green)]",
        };
      }
      return {
        label: dict.nav.preaccelActiveBadge,
        cls: "bg-[var(--accent-soft)] text-[var(--accent)]",
      };
    }
    if (
      preaccelSummary.installState === "downloading" ||
      preaccelSummary.installState === "verifying"
    ) {
      return {
        label: statusCopy.preparingBadge,
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (preaccelSummary.installState === "need_elevation") {
      return {
        label: statusCopy.needAdminBadge,
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (preaccelSummary.verifyState === "probing") {
      return {
        label: dict.nav.preaccelProbingBadge,
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    if (preaccelSummary.verifyState === "degraded") {
      return {
        label: dict.nav.preaccelDegradedBadge,
        cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
      };
    }
    return {
      label: dict.titleBar.standby,
      cls: "bg-[var(--amber-soft)] text-[var(--amber)]",
    };
  })();

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
    runtimeStatus === "error"
      ? "var(--red)"
      : runtimeStatus === "warn"
        ? "var(--amber)"
        : preaccelSummary.proxyActive && preaccelWithRelay && preaccelSummary.tone === "green"
          ? "var(--accent)"
          : preaccelWithRelay && preaccelSummary.realWinDivertActive
            ? preaccelSummary.verifyState === "probing"
              ? "var(--amber)"
              : preaccelSummary.verifyState === "verified"
                ? "var(--green)"
                : "var(--accent)"
            : preaccelSummary.proxyActive
              ? "var(--green)"
              : preaccelWithRelay
                ? "var(--amber)"
                : "var(--muted)";

  const statusLabel = resolveStatusLabel(
    runtimeStatus,
    preaccelSummary,
    hasEnabledRelay,
    uiLang
  );

  const tunButtonHint =
    platformOs === "linux"
      ? "开启虚拟网卡需要给代理核心授予网络权限，点击可一键授权"
      : platformOs === "macos"
        ? "开启虚拟网卡需要 macOS 系统安全授权，点击查看并一键授权"
        : "开启虚拟网卡需要管理员权限，点击可一键以管理员身份重启并开启";

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

  const resolveNavLabel = (id: NavRouteId): string => {
    switch (id) {
      case "overview":
        return dict.nav.overview;
      case "groups":
        return dict.nav.groups;
      case "speedtest":
      case "nodes":
        return dict.nav.nodes;
      case "preaccel":
        return dict.nav.preaccel;
      case "rules":
        return dict.nav.rules;
      case "logs":
        return dict.nav.logs;
      case "ai":
        return dict.nav.ai;
      case "settings":
        return dict.nav.settings;
    }
  };

  const handleToggleBrandMascot = () => {
    if (!mascotEnabled) return;
    if (petTimerRef.current !== null) {
      window.clearTimeout(petTimerRef.current);
      petTimerRef.current = null;
    }
    if (localPetting) {
      setLocalPetting(false);
      return;
    }
    setLocalPetting(true);
    petTimerRef.current = window.setTimeout(() => {
      setLocalPetting(false);
      petTimerRef.current = null;
    }, 2500);
  };

  const renderNavButton = (item: NavItemSpec) => {
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
    const hasSettingsUpdateBadge = item.id === "settings" && Boolean(pendingUpdate);
    const showBgDot =
      !isActive &&
      !hasSettingsUpdateBadge &&
      hasBgTask &&
      !(item.id === "nodes" && isProbeRunning);
    const showDirtyDot = !isActive && !hasSettingsUpdateBadge && !showBgDot && hasDirtyDraft;
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
              ? "后台正在探测链路、运行提速对比、线路测速或准备组件，切回即可查看"
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
      (item.id === "overview" && runtimeCaptivePortalRequired) ||
      showBgDot ||
      showDirtyDot;

    if (hasSettingsUpdateBadge && pendingUpdate) {
      return (
        <div key={item.id} className="relative flex w-full items-center gap-1">
          <button
            type="button"
            onClick={() => appActions.setNav(item.id)}
            aria-current={isActive ? "page" : undefined}
            className={`group relative flex min-w-0 flex-1 items-center gap-2.5 rounded-xl px-2.5 py-[7px] text-left text-[13px] transition-colors ${
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
            <span className="truncate">{resolveNavLabel(item.id)}</span>
          </button>
          <button
            type="button"
            onClick={handleOpenPendingUpdate}
            title={pendingUpdateBadgeTitle}
            aria-label={pendingUpdateBadgeTitle}
            className="inline-flex max-w-[82px] shrink-0 cursor-pointer items-center gap-1 rounded-full bg-[var(--accent)] px-1.5 py-0.5 text-[10px] font-semibold leading-none text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
          >
            <span
              className="cc-pulse-dot h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent-ink)]"
              aria-hidden="true"
            />
            <span className="cc-mono truncate">v{pendingUpdate.target_version}</span>
          </button>
        </div>
      );
    }

    return (
      <button
        key={item.id}
        type="button"
        onClick={() => appActions.setNav(item.id)}
        aria-current={isActive ? "page" : undefined}
        className={`group relative flex w-full items-center gap-2.5 rounded-xl px-2.5 py-[7px] text-left text-[13px] transition-colors ${
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
              : item.id === "ai"
                ? "text-[var(--accent)]/80 group-hover:text-[var(--accent)]"
                : "text-[var(--muted)] group-hover:text-[var(--text)]"
          }`}
        />
        <span className="truncate">{resolveNavLabel(item.id)}</span>

        {hasRightIndicator && (
          <span className="ml-auto flex shrink-0 items-center gap-1.5">
            {item.id === "nodes" && isProbeRunning && (
              <span className="shrink-0 rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                {isZh ? "测速中" : dict.nav.preaccelProbingBadge}
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
            {item.id === "overview" && runtimeCaptivePortalRequired && (
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
  };

  const proxyModeOptions: ReadonlyArray<{ id: ProxyMode; label: string; hint: string }> = [
    { id: "rule", label: dict.home.ruleMode, hint: PROXY_MODES[0].hint },
    { id: "global", label: dict.home.globalMode, hint: PROXY_MODES[1].hint },
    { id: "direct", label: dict.home.directMode, hint: PROXY_MODES[2].hint },
  ];

  return (
    <aside className="cc-surface cc-glass relative z-20 flex h-full w-[212px] shrink-0 flex-col border-r border-[var(--line)] px-2.5 pb-2.5 pt-2 min-[1160px]:w-[236px] min-[1160px]:px-3">
      {/* Brand header with reactive cream-cat MascotSprite & theme/wallpaper popover */}
      <div className="mb-2 flex shrink-0 items-center justify-between gap-1 px-0.5 min-[1160px]:gap-1.5">
        <div className="flex min-w-0 items-center gap-1 min-[1160px]:gap-1.5">
          <button
            type="button"
            onClick={handleToggleBrandMascot}
            title={brandMascotTitle}
            aria-label={brandMascotTitle}
            className="relative flex h-10 w-[50px] shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--card)] px-0.5 transition-colors hover:border-[var(--line-strong)] min-[1160px]:w-[62px]"
          >
            <MascotSprite
              state={effectiveBrandMascotState}
              scale={brandMascotScale}
              animationsEnabled={animationsEnabled && mascotEnabled}
              className="scale-[0.82] min-[1160px]:scale-100"
              title={brandMascotTitle}
            />
            <span
              className="cc-pulse-dot absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)]"
              style={{ backgroundColor: statusColor }}
              title={statusLabel}
            />
          </button>
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold tracking-tight text-[var(--text)] min-[1160px]:text-[14px]">
              {dict.common.appName}
            </div>
            <div className="flex min-w-0 items-center gap-1 text-[10px] text-[var(--muted)]">
              <span className="cc-mono truncate">v{runtimeAppVersion}</span>
              {pendingUpdate && (
                <button
                  type="button"
                  onClick={handleOpenPendingUpdate}
                  title={pendingUpdateBadgeTitle}
                  aria-label={pendingUpdateBadgeTitle}
                  className="inline-flex h-4 shrink-0 cursor-pointer items-center gap-0.5 rounded-full bg-[var(--accent)] px-1 text-[9px] font-bold leading-none text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                >
                  <span
                    className="cc-pulse-dot h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent-ink)]"
                    aria-hidden="true"
                  />
                  <span>↑</span>
                </button>
              )}
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
            className={`inline-flex h-7 items-center gap-0.5 whitespace-nowrap rounded-lg border px-1 text-[10.5px] transition-colors min-[1160px]:gap-1 min-[1160px]:px-1.5 min-[1160px]:text-[11px] ${
              themeMenuOpen
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--text)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            }`}
            title="切换主题配色与背景壁纸"
          >
            {resolvedTheme === "light" ? (
              <Sun className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            ) : resolvedTheme === "midnight-blue" ? (
              <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--sky)]" />
            ) : (
              <Moon className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            )}
            <span>{THEME_BUTTON_LABELS_I18N[uiLang][themeMode]}</span>
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
              className="absolute right-0 top-[calc(100%+6px)] z-50 max-h-[calc(100vh-110px)] w-[196px] overflow-y-auto rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2.5 text-[var(--text)] min-[1160px]:w-[212px]"
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

      {/* 6 Permanent Primary Nav Items (Network 4 + AI Helper 1 + Settings 1) + Collapsible More Tools (Rules & Logs) */}
      <nav className="min-h-0 flex-1 overflow-y-auto pr-0.5" aria-label={dict.nav.sectionNetwork}>
        <div className="mb-1 px-2.5 text-[10px] font-medium tracking-wide text-[var(--muted)]/85">
          {dict.nav.sectionNetwork}
        </div>
        <div className="space-y-0.5">
          {NETWORK_NAV_ITEMS.map((item) => renderNavButton(item))}
        </div>

        {/* Highlighted Mid-Level Warm-Gold AI Helper Card (instant 1-second visibility) */}
        <div className="my-2">
          <button
            type="button"
            onClick={() => appActions.setNav(AI_NAV_ITEM.id)}
            aria-current={activeNav === "ai" ? "page" : undefined}
            className={`group relative flex w-full items-center gap-2.5 rounded-2xl border px-2.5 py-2 text-left transition-all ${
              activeNav === "ai"
                ? "border-[var(--accent)] bg-[var(--accent-soft)] shadow-xs"
                : "border-[var(--accent)]/45 hover:border-[var(--accent)]"
            }`}
            style={{
              background:
                activeNav === "ai"
                  ? "linear-gradient(135deg, var(--accent-soft) 0%, color-mix(in srgb, var(--accent-soft) 55%, var(--card)) 100%)"
                  : "linear-gradient(135deg, color-mix(in srgb, var(--accent-soft) 72%, var(--card)) 0%, var(--card) 100%)",
            }}
          >
            {activeNav === "ai" && (
              <span
                className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--accent)]"
                aria-hidden="true"
              />
            )}
            <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-xl bg-[var(--accent)] text-[var(--accent-ink)] shadow-xs">
              <Bot className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-1.5">
                <span className="truncate text-[13px] font-semibold text-[var(--text)]">
                  {dict.nav.ai}
                </span>
                <span className="shrink-0 rounded-full border border-[var(--accent)]/45 bg-[var(--surface)]/90 px-1.5 py-0.5 text-[9.5px] font-semibold leading-none text-[var(--accent)]">
                  {dict.nav.aiAutopilotBadge}
                </span>
              </div>
              <div className="mt-0.5 truncate text-[10.5px] text-[var(--text-secondary)]">
                {dict.nav.aiAutopilotSub}
              </div>
            </div>
          </button>
        </div>

        {/* 6th Permanent Primary Nav Item: Settings */}
        <div className="space-y-0.5">
          {renderNavButton(SETTINGS_NAV_ITEM)}
        </div>

        {/* Collapsible More Tools Group (Rules & Logs, collapsed by default) */}
        <div className="mt-2 border-t border-[var(--line)]/60 pt-1.5">
          <button
            type="button"
            onClick={handleToggleMoreTools}
            aria-expanded={isMoreToolsExpanded}
            title={hasMoreToolsAlert ? dict.nav.moreToolsAlertTip : dict.nav.moreTools}
            className={`group relative flex w-full items-center justify-between gap-2 rounded-xl px-2.5 py-1.5 text-left text-[11.5px] font-medium transition-colors ${
              isMoreToolsRoute && !isMoreToolsExpanded
                ? "bg-[var(--accent-soft)]/80 font-semibold text-[var(--text)]"
                : "text-[var(--muted)] hover:bg-[var(--card)] hover:text-[var(--text)]"
            }`}
          >
            {isMoreToolsRoute && !isMoreToolsExpanded && (
              <span
                className="absolute left-0 top-1/2 h-3.5 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--accent)]"
                aria-hidden="true"
              />
            )}
            <span className="flex min-w-0 items-center gap-1.5">
              <span className="truncate">{dict.nav.moreTools}</span>
              {isMoreToolsRoute && !isMoreToolsExpanded && (
                <span className="truncate rounded-md bg-[var(--surface)]/85 px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                  {resolveNavLabel(activeNav)}
                </span>
              )}
            </span>
            <span className="flex shrink-0 items-center gap-1.5">
              {hasMoreToolsAlert && (
                <span
                  className={`cc-pulse-dot h-2 w-2 shrink-0 rounded-full ${
                    isMoreToolsAlertSevere
                      ? "bg-[var(--red)] ring-2 ring-[var(--red-soft)]"
                      : "bg-[var(--amber)] ring-2 ring-[var(--amber-soft)]"
                  }`}
                  title={dict.nav.moreToolsAlertTip}
                  aria-label={dict.nav.moreToolsAlertTip}
                />
              )}
              <ChevronDown
                className={`h-3.5 w-3.5 shrink-0 opacity-75 transition-transform ${
                  isMoreToolsExpanded ? "rotate-180" : ""
                }`}
                aria-hidden="true"
              />
            </span>
          </button>

          {isMoreToolsExpanded && (
            <div className="mt-0.5 space-y-0.5 pl-1">
              {MORE_TOOLS_NAV_ITEMS.map((item) => renderNavButton(item))}
            </div>
          )}
        </div>
      </nav>

      {/* Bottom compact control console: hidden on overview page to avoid duplicating Hero controls & sparkline */}
      {activeNav === "overview" ? (
        <div className="mt-1.5 shrink-0 border-t border-[var(--line)] pt-1.5">
          <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)]/80 bg-[var(--card)]/75 px-2.5 py-1.5 text-[11px] text-[var(--text-secondary)]">
            <span className="inline-flex min-w-0 items-center gap-1.5">
              <span
                className="h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: statusColor }}
                aria-hidden="true"
              />
              <span className="truncate">
                {isZh ? "当前正在总览页管理" : dict.nav.overview}
              </span>
            </span>
            <button
              type="button"
              onClick={() => void appActions.toggleCapsule()}
              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--surface)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
              title={dict.home.openCapsule}
              aria-label={dict.home.openCapsule}
            >
              <PictureInPicture2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-1.5 shrink-0 space-y-1.5 border-t border-[var(--line)] pt-1.5">
          <TrafficSparkline variant="mini" />

          {/* System Proxy / Virtual Network Card Quick Capsules */}
          <div className="grid grid-cols-2 gap-1 min-[1160px]:gap-1.5">
            <button
              type="button"
              onClick={() => void appActions.toggleSystemProxy()}
              className={`flex min-w-0 items-center justify-between gap-0.5 rounded-xl border px-1.5 py-1.5 text-[10px] font-medium transition-colors min-[1160px]:gap-1 min-[1160px]:px-2 min-[1160px]:text-[10.5px] ${
                runtimeSystemProxyEnabled
                  ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
              title={dict.home.systemProxy}
            >
              <span className="inline-flex min-w-0 flex-1 items-center gap-0.5 min-[1160px]:gap-1">
                <Wifi className="h-3 w-3 shrink-0" />
                <span className="truncate">{dict.home.systemProxy}</span>
              </span>
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                  runtimeSystemProxyEnabled ? "bg-[var(--green)]" : "bg-[var(--muted)]/50"
                }`}
              />
            </button>

            <button
              type="button"
              onClick={() =>
                runtimeTunNeedsElevation
                  ? appActions.openTunAdminPrompt(null)
                  : void appActions.toggleTun()
              }
              className={`flex min-w-0 items-center justify-between gap-0.5 rounded-xl border px-1.5 py-1.5 text-[10px] font-medium transition-colors min-[1160px]:gap-1 min-[1160px]:px-2 min-[1160px]:text-[10.5px] ${
                runtimeTunEnabled
                  ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : runtimeTunNeedsElevation
                    ? "border-[var(--amber)]/65 bg-[var(--amber-soft)] text-[var(--amber)] hover:border-[var(--amber)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
              title={
                runtimeTunNeedsElevation
                  ? "配置已开启虚拟网卡但当前权限不足，点击一键以管理员重启生效"
                  : runtimeTunAdminReady
                    ? dict.home.tunMode
                    : tunButtonHint
              }
            >
              <span className="inline-flex min-w-0 flex-1 items-center gap-0.5 min-[1160px]:gap-1">
                <ShieldCheck className="h-3 w-3 shrink-0" />
                <span className="truncate">
                  {runtimeTunNeedsElevation ? dict.home.tunNeedsAdminShort : dict.home.tunMode}
                </span>
              </span>
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                  runtimeTunEnabled
                    ? "bg-[var(--accent)]"
                    : runtimeTunNeedsElevation
                      ? "bg-[var(--amber)]"
                      : "bg-[var(--muted)]/50"
                }`}
              />
            </button>
          </div>

          {/* Compact proxy mode selector + floating mini window button */}
          <div className="flex items-center gap-1.5">
            <div
              className="grid min-w-0 flex-1 grid-cols-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
              role="group"
              aria-label="快捷切换代理模式"
            >
              {proxyModeOptions.map((m) => {
                const selected = runtimeProxyMode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => void appActions.setProxyMode(m.id)}
                    title={m.hint}
                    className={`truncate rounded-lg px-1 py-1 font-medium transition-colors ${
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
              title={dict.home.openCapsule}
              aria-label={dict.home.openCapsule}
            >
              <PictureInPicture2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {tunAdminPromptOpen && (
        <Suspense fallback={null}>
          <TunAdminPromptModal />
        </Suspense>
      )}
    </aside>
  );
}
