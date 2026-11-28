import type {
  CoreRuntimeInfo,
  GlobalPreAccelStatus,
  PreAccelVerifyState,
} from "../api/tauri";
import {
  formatI18nTemplate,
  getUiDictSync,
  normalizeUiLanguage,
  type UiLanguage,
} from "../i18n";

export type { PreAccelVerifyState };

export type PreAccelInstallState =
  | "idle"
  | "downloading"
  | "verifying"
  | "ready"
  | "need_elevation"
  | "failed";

export type PreAccelSummaryTone = "green" | "accent" | "amber" | "red" | "muted";

export interface PreAccelSummary {
  enabled: boolean;
  proxyActive: boolean;
  realWinDivertActive: boolean;
  localSocksActive: boolean;
  suspendedForTun: boolean;
  effectiveCarrier: string;
  installState: PreAccelInstallState;
  verifyState: PreAccelVerifyState;
  verifyLatencyMs: number | null;
  badgeText: string;
  subBadgeText: string | null;
  plainText: string;
  detailText: string;
  tone: PreAccelSummaryTone;
}

export interface PreAccelCoreState {
  enabled: boolean;
  proxyActive: boolean;
  realWinDivertActive: boolean;
  localSocksActive: boolean;
  suspendedForTun: boolean;
  effectiveCarrier: string;
  installState: PreAccelInstallState;
  verifyState: PreAccelVerifyState;
  verifyLatencyMs: number | null;
  relayName: string | null;
  socksPort: number | null;
  verifyMessage: string | null;
  lastError: string | null;
}

export type RuntimePreAccelFields = Pick<
  CoreRuntimeInfo,
  | "running"
  | "system_proxy_enabled"
  | "tun_enabled"
  | "preaccel_active"
  | "preaccel_enabled"
  | "preaccel_relay_name"
  | "global_preaccel_active"
  | "global_preaccel_mode"
  | "global_preaccel_socks_port"
> & {
  preaccel_effective_carrier?: string;
  standalone_tunnel_suspended_for_tun?: boolean;
  global_windivert_active?: boolean;
  preaccel_install_state?: string;
  global_preaccel_verify_state?: PreAccelVerifyState | string;
  global_preaccel_verify_ms?: number | null;
};

export type GlobalPreAccelFields = Pick<
  GlobalPreAccelStatus,
  | "running"
  | "mode"
  | "socks_port"
  | "windivert_available"
  | "is_elevated"
  | "last_error"
> & {
  is_windivert_active?: boolean;
  install_state?: string;
  verify_state?: PreAccelVerifyState | string;
  verify_latency_ms?: number | null;
  verify_message?: string | null;
};

const VALID_INSTALL_STATES = new Set<PreAccelInstallState>([
  "idle",
  "downloading",
  "verifying",
  "ready",
  "need_elevation",
  "failed",
]);

const VALID_VERIFY_STATES = new Set<PreAccelVerifyState>([
  "idle",
  "probing",
  "verified",
  "degraded",
  "failed",
]);

function normalizeCopyLang(raw?: UiLanguage | string): UiLanguage {
  if (!raw) return "zh-CN";
  const lower = raw.trim().toLowerCase();
  if (lower === "zh-cn" || lower === "zh" || lower.startsWith("zh-")) return "zh-CN";
  if (lower === "ja" || lower.startsWith("ja-")) return "ja";
  if (lower === "ru" || lower.startsWith("ru-")) return "ru";
  return normalizeUiLanguage(raw) === "zh-CN" ? "en" : normalizeUiLanguage(raw);
}

export function normalizePreAccelInstallState(raw?: string | null): PreAccelInstallState {
  const normalized = (raw ?? "").trim().toLowerCase() as PreAccelInstallState;
  return VALID_INSTALL_STATES.has(normalized) ? normalized : "idle";
}

export function normalizePreAccelVerifyState(raw?: string | null): PreAccelVerifyState {
  const normalized = (raw ?? "").trim().toLowerCase() as PreAccelVerifyState;
  return VALID_VERIFY_STATES.has(normalized) ? normalized : "idle";
}

/**
 * Strictly returns true ONLY when real WinDivert kernel-level interception is running.
 * Local SOCKS5 fallback (`mode === "local_socks5"`) MUST NEVER be reported as real WinDivert active.
 */
export function isRealWinDivertActive(
  runtime: Pick<RuntimePreAccelFields, "global_windivert_active"> | null | undefined,
  globalPreAccel: Pick<GlobalPreAccelFields, "running" | "mode"> | null | undefined
): boolean {
  return (
    Boolean(globalPreAccel && globalPreAccel.running && globalPreAccel.mode === "windivert") ||
    Boolean(runtime?.global_windivert_active)
  );
}

/**
 * Pure language-independent PreAccel state resolver for store/status consumers.
 */
export function resolvePreAccelCoreState(
  runtime: RuntimePreAccelFields | null | undefined,
  globalPreAccel: GlobalPreAccelFields | null | undefined,
  configPreAccelEnabled?: boolean,
  hasEnabledRelay?: boolean
): PreAccelCoreState {
  const proxyActive = Boolean(
    runtime?.running && (runtime.system_proxy_enabled || runtime.tun_enabled)
  );
  const rawCarrier = (runtime?.preaccel_effective_carrier ?? "").trim().toLowerCase();
  const suspendedForTun = Boolean(
    runtime?.standalone_tunnel_suspended_for_tun ||
      globalPreAccel?.mode === "suspended_for_tun" ||
      runtime?.global_preaccel_mode === "suspended_for_tun" ||
      rawCarrier === "main_core_tun_suspended_standalone" ||
      (runtime?.running &&
        runtime.tun_enabled &&
        (runtime.preaccel_enabled ?? configPreAccelEnabled ?? false))
  );
  const realWinDivertActive = suspendedForTun
    ? false
    : isRealWinDivertActive(runtime, globalPreAccel);
  const localSocksActive = Boolean(
    !suspendedForTun && globalPreAccel?.running && globalPreAccel.mode === "local_socks5"
  );
  const enabled = Boolean(
    (runtime?.preaccel_enabled ?? configPreAccelEnabled ?? false) ||
      realWinDivertActive ||
      suspendedForTun
  );
  const effectiveCarrier = !enabled
    ? "off"
    : rawCarrier && rawCarrier !== "off"
      ? rawCarrier
      : suspendedForTun
        ? "main_core_tun_suspended_standalone"
        : proxyActive
          ? "main_core_proxy_only"
          : realWinDivertActive
            ? "standalone_windivert"
            : localSocksActive
              ? "standalone_socks5"
              : "off";

  const globalState = normalizePreAccelInstallState(globalPreAccel?.install_state);
  const runtimeState = normalizePreAccelInstallState(runtime?.preaccel_install_state);
  let installState: PreAccelInstallState =
    globalState !== "idle" ? globalState : runtimeState;

  if (
    (installState === "idle" || installState === "ready") &&
    enabled &&
    hasEnabledRelay !== false &&
    !realWinDivertActive &&
    !suspendedForTun &&
    globalPreAccel?.windivert_available &&
    globalPreAccel.is_elevated === false
  ) {
    installState = "need_elevation";
  }

  const globalVerifyState = normalizePreAccelVerifyState(globalPreAccel?.verify_state);
  const runtimeVerifyState = normalizePreAccelVerifyState(runtime?.global_preaccel_verify_state);
  const verifyState: PreAccelVerifyState =
    globalVerifyState !== "idle" ? globalVerifyState : runtimeVerifyState;

  const rawVerifyLatency =
    globalPreAccel?.verify_latency_ms ?? runtime?.global_preaccel_verify_ms ?? null;
  const verifyLatencyMs =
    typeof rawVerifyLatency === "number" &&
    Number.isFinite(rawVerifyLatency) &&
    rawVerifyLatency > 0
      ? Math.round(rawVerifyLatency)
      : null;

  return {
    enabled,
    proxyActive,
    realWinDivertActive,
    localSocksActive,
    suspendedForTun,
    effectiveCarrier,
    installState,
    verifyState,
    verifyLatencyMs,
    relayName: runtime?.preaccel_relay_name?.trim() || null,
    socksPort: globalPreAccel?.socks_port ?? runtime?.global_preaccel_socks_port ?? null,
    verifyMessage: globalPreAccel?.verify_message?.trim() || null,
    lastError: globalPreAccel?.last_error?.trim() || null,
  };
}

export function resolvePreAccelSummary(
  runtime: RuntimePreAccelFields | null | undefined,
  globalPreAccel: GlobalPreAccelFields | null | undefined,
  configPreAccelEnabled?: boolean,
  hasEnabledRelay?: boolean,
  uiLang?: UiLanguage | string
): PreAccelSummary {
  const copy = getUiDictSync(normalizeCopyLang(uiLang)).preaccelStatus;
  const state = resolvePreAccelCoreState(
    runtime,
    globalPreAccel,
    configPreAccelEnabled,
    hasEnabledRelay
  );
  const {
    enabled,
    proxyActive,
    realWinDivertActive,
    localSocksActive,
    suspendedForTun,
    effectiveCarrier,
    installState,
    verifyState,
    verifyLatencyMs,
    relayName,
    socksPort,
    verifyMessage,
    lastError,
  } = state;

  const msPart = verifyLatencyMs ? formatI18nTemplate(copy.msSuffix, { ms: verifyLatencyMs }) : "";
  const fmtRelay = (withRelay: string, noRelay: string): string =>
    relayName ? formatI18nTemplate(withRelay, { relay: relayName }) : noRelay;
  const fmtRelayMs = (withRelay: string, noRelay: string): string =>
    relayName
      ? formatI18nTemplate(withRelay, { relay: relayName, msPart })
      : formatI18nTemplate(noRelay, { msPart });
  const fmtPort = (withPort: string, noPort: string): string =>
    socksPort ? formatI18nTemplate(withPort, { port: socksPort }) : noPort;

  if (!enabled) {
    return {
      enabled: false,
      proxyActive,
      realWinDivertActive: false,
      localSocksActive: false,
      suspendedForTun: false,
      effectiveCarrier: "off",
      installState: "idle",
      verifyState: "idle",
      verifyLatencyMs: null,
      badgeText: copy.offBadge,
      subBadgeText: null,
      plainText: copy.offPlain,
      detailText: copy.offDetail,
      tone: "muted",
    };
  }

  // Bug 5 hard guard: when no enabled domestic relay exists, NEVER claim standby/active
  // regardless of whether main proxy or TUN is running.
  if (hasEnabledRelay === false) {
    return {
      enabled: true,
      proxyActive,
      realWinDivertActive: false,
      localSocksActive: false,
      suspendedForTun: false,
      effectiveCarrier: "off",
      installState,
      verifyState,
      verifyLatencyMs: null,
      badgeText: copy.addRelayBadge,
      subBadgeText: null,
      plainText: copy.addRelayPlain,
      detailText: copy.addRelayDetail,
      tone: "amber",
    };
  }

  if (suspendedForTun && (runtime?.preaccel_active || relayName || proxyActive)) {
    return {
      enabled: true,
      proxyActive: true,
      realWinDivertActive: false,
      localSocksActive: false,
      suspendedForTun: true,
      effectiveCarrier: "main_core_tun_suspended_standalone",
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.activeBadge,
      subBadgeText:
        verifyState === "verified" && verifyLatencyMs ? `${verifyLatencyMs} ms` : null,
      plainText: fmtRelayMs(copy.tunPlainWithRelay, copy.tunPlainNoRelay),
      detailText: fmtRelayMs(copy.tunDetailWithRelay, copy.tunDetailNoRelay),
      tone: "green",
    };
  }

  if (proxyActive) {
    if (!runtime?.preaccel_active && !realWinDivertActive && !relayName) {
      return {
        enabled: true,
        proxyActive: true,
        realWinDivertActive: false,
        localSocksActive,
        suspendedForTun: false,
        effectiveCarrier,
        installState,
        verifyState,
        verifyLatencyMs,
        badgeText: copy.addRelayBadge,
        subBadgeText: null,
        plainText: copy.addRelayPlain,
        detailText: copy.addRelayDetail,
        tone: "amber",
      };
    }

    let subBadgeText: string | null = null;
    let plainText: string;
    let detailText: string;

    if (realWinDivertActive) {
      if (verifyState === "probing") {
        subBadgeText = copy.probingShort;
        plainText = fmtRelay(copy.proxyDualProbingPlainWithRelay, copy.proxyDualProbingPlainNoRelay);
        detailText = fmtRelay(
          copy.proxyDualProbingDetailWithRelay,
          copy.proxyDualProbingDetailNoRelay
        );
      } else if (verifyState === "verified") {
        subBadgeText = verifyLatencyMs ? `${verifyLatencyMs} ms` : null;
        plainText = fmtRelayMs(
          copy.proxyDualVerifiedPlainWithRelay,
          copy.proxyDualVerifiedPlainNoRelay
        );
        detailText =
          verifyLatencyMs || !verifyMessage
            ? fmtRelayMs(
                copy.proxyDualVerifiedDetailWithRelay,
                copy.proxyDualVerifiedDetailNoRelay
              )
            : verifyMessage;
      } else {
        subBadgeText = null;
        plainText = fmtRelay(copy.proxyDualActivePlainWithRelay, copy.proxyDualActivePlainNoRelay);
        detailText = fmtRelay(
          copy.proxyDualActiveDetailWithRelay,
          copy.proxyDualActiveDetailNoRelay
        );
      }
    } else if (verifyState === "probing") {
      subBadgeText = copy.probingShort;
      plainText = fmtRelay(copy.proxyDualProbingPlainWithRelay, copy.proxyDualProbingPlainNoRelay);
      detailText = fmtRelay(
        copy.proxyProbingOtherDetailWithRelay,
        copy.proxyProbingOtherDetailNoRelay
      );
    } else if (verifyState === "degraded") {
      subBadgeText = copy.degradedShort;
      plainText = fmtRelay(copy.proxyDegradedPlainWithRelay, copy.proxyDegradedPlainNoRelay);
      detailText = verifyMessage || lastError || copy.proxyDegradedFallbackDetail;
    } else if (installState === "downloading" || installState === "verifying") {
      plainText = fmtRelay(copy.proxyInstallingPlainWithRelay, copy.proxyInstallingPlainNoRelay);
      detailText = fmtRelay(
        copy.proxyInstallingDetailWithRelay,
        copy.proxyInstallingDetailNoRelay
      );
    } else if (installState === "need_elevation") {
      plainText = fmtRelay(copy.proxyNeedAdminPlainWithRelay, copy.proxyNeedAdminPlainNoRelay);
      detailText = fmtRelay(copy.proxyNeedAdminDetailWithRelay, copy.proxyNeedAdminDetailNoRelay);
    } else {
      plainText = fmtRelay(copy.proxyOnlyPlainWithRelay, copy.proxyOnlyPlainNoRelay);
      detailText = fmtRelay(copy.proxyOnlyDetailWithRelay, copy.proxyOnlyDetailNoRelay);
    }

    return {
      enabled: true,
      proxyActive: true,
      realWinDivertActive,
      localSocksActive,
      suspendedForTun: false,
      effectiveCarrier,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.activeBadge,
      subBadgeText,
      plainText,
      detailText,
      tone: "green",
    };
  }

  if (realWinDivertActive || effectiveCarrier === "standalone_windivert") {
    if (verifyState === "probing") {
      return {
        enabled: true,
        proxyActive: false,
        realWinDivertActive: true,
        localSocksActive: false,
        suspendedForTun: false,
        effectiveCarrier: "standalone_windivert",
        installState: "ready",
        verifyState,
        verifyLatencyMs,
        badgeText: copy.probingBadge,
        subBadgeText: null,
        plainText: fmtRelay(copy.standaloneProbingPlainWithRelay, copy.standaloneProbingPlainNoRelay),
        detailText: fmtRelay(
          copy.standaloneProbingDetailWithRelay,
          copy.standaloneProbingDetailNoRelay
        ),
        tone: "amber",
      };
    }

    if (verifyState === "verified") {
      return {
        enabled: true,
        proxyActive: false,
        realWinDivertActive: true,
        localSocksActive: false,
        suspendedForTun: false,
        effectiveCarrier: "standalone_windivert",
        installState: "ready",
        verifyState,
        verifyLatencyMs,
        badgeText: copy.boostingOtherBadge,
        subBadgeText: verifyLatencyMs ? `${verifyLatencyMs} ms` : null,
        plainText: fmtRelayMs(
          copy.standaloneVerifiedPlainWithRelay,
          copy.standaloneVerifiedPlainNoRelay
        ),
        detailText:
          verifyLatencyMs || !verifyMessage
            ? fmtRelayMs(
                copy.standaloneVerifiedDetailWithRelay,
                copy.standaloneVerifiedDetailNoRelay
              )
            : verifyMessage,
        tone: "green",
      };
    }

    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: true,
      localSocksActive: false,
      suspendedForTun: false,
      effectiveCarrier: "standalone_windivert",
      installState: "ready",
      verifyState,
      verifyLatencyMs,
      badgeText: copy.boostingOtherBadge,
      subBadgeText: verifyLatencyMs ? `${verifyLatencyMs} ms` : null,
      plainText: fmtRelay(copy.standaloneActivePlainWithRelay, copy.standaloneActivePlainNoRelay),
      detailText: fmtRelay(copy.standaloneActiveDetailWithRelay, copy.standaloneActiveDetailNoRelay),
      tone: "accent",
    };
  }

  if (installState === "downloading" || installState === "verifying") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      suspendedForTun: false,
      effectiveCarrier,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.preparingBadge,
      subBadgeText: null,
      plainText:
        installState === "verifying" ? copy.verifyingDriverPlain : copy.downloadingDriverPlain,
      detailText:
        installState === "verifying" ? copy.verifyingDriverDetail : copy.downloadingDriverDetail,
      tone: "amber",
    };
  }

  if (installState === "need_elevation") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      suspendedForTun: false,
      effectiveCarrier,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.needAdminBadge,
      subBadgeText: null,
      plainText: copy.needAdminPlain,
      detailText: fmtPort(copy.needAdminDetailWithPort, copy.needAdminDetailNoPort),
      tone: "amber",
    };
  }

  if (verifyState === "probing") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      suspendedForTun: false,
      effectiveCarrier,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.probingBadge,
      subBadgeText: null,
      plainText: fmtRelay(copy.probingLinkPlainWithRelay, copy.probingLinkPlainNoRelay),
      detailText:
        verifyMessage || fmtRelay(copy.probingLinkDetailWithRelay, copy.probingLinkDetailNoRelay),
      tone: "amber",
    };
  }

  if (verifyState === "degraded") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      suspendedForTun: false,
      effectiveCarrier,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: copy.degradedBadge,
      subBadgeText: null,
      plainText: copy.degradedStandalonePlain,
      detailText:
        verifyMessage ||
        lastError ||
        fmtPort(copy.degradedStandaloneDetailWithPort, copy.degradedStandaloneDetailNoPort),
      tone: "amber",
    };
  }

  const plainText =
    installState === "failed"
      ? copy.installFailedPlain
      : verifyState === "failed"
        ? copy.verifyFailedPlain
        : localSocksActive || socksPort
          ? fmtRelay(copy.localReadyPlainWithRelay, copy.localReadyPlainNoRelay)
          : fmtRelay(copy.standbyPlainWithRelay, copy.standbyPlainNoRelay);

  const relayPart = relayName
    ? formatI18nTemplate(copy.localSocksRelayPart, { relay: relayName })
    : "";
  const localSocksDetail = socksPort
    ? formatI18nTemplate(copy.localSocksDetailWithPort, { port: socksPort, relayPart })
    : formatI18nTemplate(copy.localSocksDetailNoPort, { relayPart });

  const detailText =
    installState === "failed" && lastError
      ? socksPort
        ? formatI18nTemplate(copy.installFailedDetailWithPort, { err: lastError, port: socksPort })
        : formatI18nTemplate(copy.installFailedDetailNoPort, { err: lastError })
      : verifyState === "failed" && (verifyMessage || lastError)
        ? verifyMessage ||
          lastError ||
          fmtPort(copy.verifyFailedDetailWithPort, copy.verifyFailedDetailNoPort)
        : localSocksActive || socksPort
          ? localSocksDetail
          : fmtRelay(copy.standbyDetailWithRelay, copy.standbyDetailNoRelay);

  return {
    enabled: true,
    proxyActive: false,
    realWinDivertActive: false,
    localSocksActive,
    suspendedForTun: false,
    effectiveCarrier,
    installState,
    verifyState,
    verifyLatencyMs,
    badgeText: localSocksActive ? copy.localReadyBadge : copy.standbyBadge,
    subBadgeText: null,
    plainText,
    detailText,
    tone: "amber",
  };
}
