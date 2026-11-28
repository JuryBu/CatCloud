import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { isTauriEnv } from "../api/tauri";
import { normalizeUiLanguage, type UiLanguage, useUiDict } from "../i18n";
import { selectHasBackgroundActivity, useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";
import {
  type GlobalPreAccelFields,
  type PreAccelSummary,
  type RuntimePreAccelFields,
  resolvePreAccelSummary,
} from "../utils/preaccelStatus";

const TITLEBAR_STATUS_COPY: Record<
  UiLanguage,
  { coreError: string; captiveWarn: string }
> = {
  "zh-CN": { coreError: "核心异常", captiveWarn: "待认证" },
  en: { coreError: "Core Error", captiveWarn: "Auth Needed" },
  ja: { coreError: "コア異常", captiveWarn: "認証待ち" },
  ru: { coreError: "Ошибка ядра", captiveWarn: "Вход в сеть" },
};

function resolveModeBadge(
  status: string,
  proxyMode: string,
  preaccel: PreAccelSummary,
  hasEnabledRelay: boolean,
  dict: ReturnType<typeof useUiDict>,
  uiLang: UiLanguage
): { label: string; dotColor: string; title: string } {
  const statusCopy = TITLEBAR_STATUS_COPY[uiLang];

  if (!preaccel.proxyActive) {
    if (status === "error") {
      return {
        label: statusCopy.coreError,
        dotColor: "var(--red)",
        title: statusCopy.coreError,
      };
    }
    if (preaccel.enabled && !hasEnabledRelay) {
      if (status === "warn") {
        return {
          label: statusCopy.captiveWarn,
          dotColor: "var(--amber)",
          title: statusCopy.captiveWarn,
        };
      }
      return {
        label: preaccel.badgeText,
        dotColor: "var(--amber)",
        title: preaccel.detailText,
      };
    }
    if (preaccel.realWinDivertActive && hasEnabledRelay) {
      if (preaccel.verifyState === "probing") {
        return {
          label: dict.nav.preaccelProbingBadge,
          dotColor: "var(--amber)",
          title: preaccel.detailText,
        };
      }
      if (preaccel.verifyState === "verified") {
        const label = preaccel.verifyLatencyMs
          ? `${dict.nav.preaccelVerifiedBadge} ${preaccel.verifyLatencyMs}ms`
          : dict.nav.preaccelVerifiedBadge;
        return {
          label,
          dotColor: status === "warn" ? "var(--amber)" : "var(--green)",
          title: preaccel.detailText,
        };
      }
      return {
        label: dict.nav.preaccelActiveBadge,
        dotColor: status === "warn" ? "var(--amber)" : "var(--accent)",
        title: preaccel.detailText,
      };
    }
    if (preaccel.enabled && hasEnabledRelay) {
      if (
        preaccel.installState === "downloading" ||
        preaccel.installState === "verifying" ||
        preaccel.installState === "need_elevation"
      ) {
        return {
          label: preaccel.badgeText,
          dotColor: "var(--amber)",
          title: preaccel.detailText,
        };
      }
      if (preaccel.verifyState === "probing") {
        return {
          label: dict.nav.preaccelProbingBadge,
          dotColor: "var(--amber)",
          title: preaccel.detailText,
        };
      }
      if (preaccel.verifyState === "degraded") {
        return {
          label: dict.nav.preaccelDegradedBadge,
          dotColor: "var(--amber)",
          title: preaccel.detailText,
        };
      }
      return {
        label: `${dict.titleBar.preaccelOn} · ${dict.titleBar.standby}`,
        dotColor: "var(--amber)",
        title: preaccel.detailText,
      };
    }
    if (status === "warn") {
      return {
        label: statusCopy.captiveWarn,
        dotColor: "var(--amber)",
        title: statusCopy.captiveWarn,
      };
    }
    return {
      label: dict.titleBar.standby,
      dotColor: "var(--muted)",
      title: dict.titleBar.standby,
    };
  }

  const proxyPreaccelActive =
    preaccel.enabled && hasEnabledRelay && preaccel.tone === "green";
  const isProbing = proxyPreaccelActive && preaccel.verifyState === "probing";
  const dotColor =
    status === "error"
      ? "var(--red)"
      : status === "warn" || isProbing
        ? "var(--amber)"
        : proxyPreaccelActive
          ? "var(--accent)"
          : "var(--green)";

  const modeLabel =
    proxyMode === "global"
      ? dict.titleBar.modeGlobal
      : proxyMode === "direct"
        ? dict.titleBar.modeDirect
        : dict.titleBar.modeRule;
  const label = proxyPreaccelActive
    ? isProbing
      ? `${modeLabel} · ${dict.nav.preaccelProbingBadge}`
      : preaccel.realWinDivertActive
        ? `${modeLabel} · ${dict.nav.preaccelActiveBadge}`
        : `${modeLabel} · ${dict.titleBar.preaccelOn}`
    : modeLabel;
  return {
    label,
    dotColor,
    title: proxyPreaccelActive ? `${modeLabel} · ${preaccel.detailText}` : label,
  };
}

export function TitleBar() {
  // Atomic primitive selectors avoid re-rendering TitleBar on unrelated runtime ticks (memory/uptime/bps).
  const runtimeStatus = useAppSelector((s) => s.runtime.status);
  const runtimeProxyMode = useAppSelector((s) => s.runtime.proxy_mode);
  const runtimeOsLabel = useAppSelector((s) => s.runtime.os_label);
  const runtimeRunning = useAppSelector((s) => s.runtime.running);
  const runtimeSystemProxyEnabled = useAppSelector((s) => s.runtime.system_proxy_enabled);
  const runtimeTunEnabled = useAppSelector((s) => s.runtime.tun_enabled);
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

  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const hasEnabledRelay = useAppSelector((s) =>
    s.preAccelRelays.some((r) => r.enabled)
  );
  const minimizeToTrayOnClose = useAppSelector(
    (s) => s.config?.behavior?.minimize_to_tray_on_close ?? true
  );
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const hasAnyBgTask = useAppSelector((s) => {
    const bg = selectHasBackgroundActivity(s);
    return bg.preaccel || bg.nodes || bg.groups || bg.home || bg.settings;
  });
  const dict = useUiDict(uiLang);
  const [maximized, setMaximized] = useState(false);
  const inTauri = isTauriEnv();
  const isMac = resolvePlatformOs(runtimeOsLabel) === "macos";

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

  useEffect(() => {
    if (!isTauriEnv()) return;
    let disposed = false;
    let unlistenResize: (() => void) | null = null;
    const win = getCurrentWindow();

    const syncMaximized = async () => {
      try {
        const next = await win.isMaximized();
        if (!disposed) {
          setMaximized(next);
        }
      } catch {
        /* ignore transient window query errors */
      }
    };

    void syncMaximized();
    void win
      .onResized(() => {
        void syncMaximized();
      })
      .then((unlisten) => {
        if (disposed) {
          unlisten();
        } else {
          unlistenResize = unlisten;
        }
      })
      .catch(() => {
        /* fallback to DOM resize listener */
      });

    const handleDomResize = () => {
      void syncMaximized();
    };
    window.addEventListener("resize", handleDomResize);

    return () => {
      disposed = true;
      unlistenResize?.();
      window.removeEventListener("resize", handleDomResize);
    };
  }, []);

  const handleMinimize = async () => {
    if (!isTauriEnv()) return;
    try {
      await getCurrentWindow().minimize();
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const handleToggleMaximize = async () => {
    if (!isTauriEnv()) {
      setMaximized((prev) => !prev);
      return;
    }
    try {
      const win = getCurrentWindow();
      await win.toggleMaximize();
      const next = await win.isMaximized();
      setMaximized(next);
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const handleClose = async () => {
    if (!isTauriEnv()) return;
    try {
      await getCurrentWindow().close();
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const preaccelSummary = resolvePreAccelSummary(
    runtimePreAccelFields,
    globalPreAccelFields,
    preAccelEnabledConfig,
    hasEnabledRelay,
    uiLang
  );

  const badge = resolveModeBadge(
    runtimeStatus,
    runtimeProxyMode,
    preaccelSummary,
    hasEnabledRelay,
    dict,
    uiLang
  );

  const closeButtonLabel = minimizeToTrayOnClose
    ? hasAnyBgTask
      ? dict.titleBar.closeToTrayBusy
      : dict.titleBar.closeToTray
    : dict.titleBar.closeApp;

  const brandFull = dict.common.appNameFull;
  const brandSepIdx = brandFull.indexOf("·");
  const brandPrimary =
    brandSepIdx >= 0 ? brandFull.slice(0, brandSepIdx).trim() : dict.common.appName;
  const brandSuffix = brandSepIdx >= 0 ? brandFull.slice(brandSepIdx).trim() : "";

  return (
    <header className="cc-surface relative z-30 flex h-9 shrink-0 select-none items-center justify-between border-b border-[var(--line)]/60">
      {/* Left brand + compact mode badge + center drag region (macOS reserves 76px for native traffic lights) */}
      <div
        data-tauri-drag-region
        onDoubleClick={inTauri ? undefined : () => void handleToggleMaximize()}
        className={`flex h-full min-w-0 flex-1 items-center gap-2 pr-2 ${
          isMac ? "pl-[76px]" : "pl-3"
        }`}
      >
        <img
          src="./icons/icon_a_cream_cat.png"
          alt={dict.common.appName}
          className="pointer-events-none h-[18px] w-[18px] shrink-0 rounded-[5px] object-cover ring-1 ring-[var(--line)]"
          draggable={false}
        />

        <span className="pointer-events-none truncate text-xs font-semibold tracking-tight text-[var(--text)]">
          {brandPrimary}
          {brandSuffix && (
            <span className="ml-1 font-normal text-[var(--muted)]">{brandSuffix}</span>
          )}
        </span>

        <span
          title={badge.title}
          className="pointer-events-none inline-flex max-w-[180px] shrink-0 items-center gap-1 rounded-full border border-[var(--line)]/80 bg-[var(--card)]/85 px-2 py-0.5 text-[10px] font-medium leading-none text-[var(--text-secondary)]"
        >
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{ backgroundColor: badge.dotColor }}
            aria-hidden="true"
          />
          <span className="min-w-0 truncate">{badge.label}</span>
        </span>
      </div>

      {/* Right native-style window controls (Windows / Linux only; macOS uses native left traffic lights) */}
      {!isMac && (
        <div className="flex h-full shrink-0 items-center">
          <button
            type="button"
            onClick={() => void handleMinimize()}
            className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--card-hover)] hover:text-[var(--text)]"
            aria-label={dict.titleBar.minimize}
            title={dict.titleBar.minimize}
          >
            <Minus className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={() => void handleToggleMaximize()}
            className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--card-hover)] hover:text-[var(--text)]"
            aria-label={maximized ? dict.titleBar.restore : dict.titleBar.maximize}
            title={maximized ? dict.titleBar.restore : dict.titleBar.maximize}
          >
            {maximized ? <Copy className="h-3 w-3" /> : <Square className="h-3 w-3" />}
          </button>

          <button
            type="button"
            onClick={() => void handleClose()}
            className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[#e5534b]/90 hover:text-white"
            aria-label={closeButtonLabel}
            title={closeButtonLabel}
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </header>
  );
}
