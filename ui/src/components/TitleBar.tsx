import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";
import { isTauriEnv } from "../api/tauri";
import { normalizeUiLanguage, type UiLanguage, useUiDict } from "../i18n";
import { selectHasBackgroundActivity, useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";
import { type PreAccelSummary, resolvePreAccelSummary } from "../utils/preaccelStatus";

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
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
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
  const bg = useAppSelector(selectHasBackgroundActivity);
  const dict = useUiDict(uiLang);
  const hasAnyBgTask = bg.preaccel || bg.nodes || bg.groups || bg.home || bg.settings;
  const [maximized, setMaximized] = useState(false);
  const inTauri = isTauriEnv();
  const isMac = resolvePlatformOs(runtime.os_label) === "macos";

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
    runtime,
    globalPreAccel,
    preAccelEnabledConfig,
    hasEnabledRelay,
    uiLang
  );

  const badge = resolveModeBadge(
    runtime.status,
    runtime.proxy_mode,
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
