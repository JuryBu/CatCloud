import type {
  CoreRuntimeInfo,
  GlobalPreAccelStatus,
  PreAccelVerifyState,
} from "../api/tauri";

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
  installState: PreAccelInstallState;
  verifyState: PreAccelVerifyState;
  verifyLatencyMs: number | null;
  badgeText: string;
  subBadgeText: string | null;
  detailText: string;
  tone: PreAccelSummaryTone;
}

type RuntimePreAccelFields = Pick<
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
  global_windivert_active?: boolean;
  preaccel_install_state?: string;
  global_preaccel_verify_state?: PreAccelVerifyState | string;
  global_preaccel_verify_ms?: number | null;
};

type GlobalPreAccelFields = Pick<
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

export function resolvePreAccelSummary(
  runtime: RuntimePreAccelFields | null | undefined,
  globalPreAccel: GlobalPreAccelFields | null | undefined,
  configPreAccelEnabled?: boolean
): PreAccelSummary {
  const proxyActive = Boolean(
    runtime?.running && (runtime.system_proxy_enabled || runtime.tun_enabled)
  );
  const realWinDivertActive = isRealWinDivertActive(runtime, globalPreAccel);
  const localSocksActive = Boolean(
    globalPreAccel?.running && globalPreAccel.mode === "local_socks5"
  );
  const enabled = Boolean(
    (runtime?.preaccel_enabled ?? configPreAccelEnabled ?? false) || realWinDivertActive
  );

  const globalState = normalizePreAccelInstallState(globalPreAccel?.install_state);
  const runtimeState = normalizePreAccelInstallState(runtime?.preaccel_install_state);
  let installState: PreAccelInstallState =
    globalState !== "idle" ? globalState : runtimeState;

  if (
    installState === "idle" &&
    enabled &&
    !realWinDivertActive &&
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

  const relayName = runtime?.preaccel_relay_name?.trim() || null;
  const socksPort = globalPreAccel?.socks_port ?? runtime?.global_preaccel_socks_port ?? null;
  const verifyMessage = globalPreAccel?.verify_message?.trim() || null;
  const lastError = globalPreAccel?.last_error?.trim() || null;

  if (!enabled) {
    return {
      enabled: false,
      proxyActive,
      realWinDivertActive: false,
      localSocksActive: false,
      installState: "idle",
      verifyState: "idle",
      verifyLatencyMs: null,
      badgeText: "已关闭",
      subBadgeText: null,
      detailText: "关闭后猫猫云梯与电脑上其它代理软件均不走国内 443 提速",
      tone: "muted",
    };
  }

  if (proxyActive) {
    if (!runtime?.preaccel_active && !realWinDivertActive && !relayName) {
      return {
        enabled: true,
        proxyActive: true,
        realWinDivertActive: false,
        localSocksActive,
        installState,
        verifyState,
        verifyLatencyMs,
        badgeText: "待配置中转",
        subBadgeText: null,
        detailText: "已开启国内提速，但尚未启用可用的国内中转线路，请先添加并启用至少一条中转",
        tone: "amber",
      };
    }

    let subBadgeText: string | null = null;
    let detailText: string;

    if (realWinDivertActive) {
      if (verifyState === "probing") {
        subBadgeText = "探测其它软件链路…";
        detailText = relayName
          ? `猫云代理已通过「${relayName}」提速 · 正在探测其它软件拦截链路…`
          : "猫云代理已走国内 443 提速 · 正在探测其它软件拦截链路…";
      } else if (verifyState === "verified") {
        subBadgeText = verifyLatencyMs
          ? `猫云 + 其它软件 · ${verifyLatencyMs} ms`
          : "猫云 + 其它软件";
        detailText = verifyLatencyMs
          ? relayName
            ? `猫云 + 其它软件均已通过「${relayName}」实测畅通（${verifyLatencyMs} ms）`
            : `猫云 + 其它软件均已走国内 443 提速，实测畅通（${verifyLatencyMs} ms）`
          : verifyMessage ||
            (relayName
              ? `猫云 + 其它软件均已通过「${relayName}」实测畅通`
              : "猫云 + 其它软件均已走国内 443 提速并实测畅通");
      } else {
        subBadgeText = "猫云 + 其它软件";
        detailText = relayName
          ? `猫云 + 其它软件均已通过「${relayName}」走国内 443 提速`
          : "猫云 + 其它软件均已走国内 443 提速";
      }
    } else if (verifyState === "probing") {
      subBadgeText = "探测其它软件链路…";
      detailText = relayName
        ? `猫云代理已通过「${relayName}」提速 · 正在探测其它软件拦截链路…`
        : "猫云代理已走国内 443 提速 · 正在探测其它软件拦截链路…";
    } else if (verifyState === "degraded") {
      subBadgeText = "其它软件已保护回退";
      detailText =
        verifyMessage ||
        lastError ||
        "自动探测发现底层拦截未畅通，已自动停止拦截防止断网，本地 443 通道仍待命";
    } else if (installState === "downloading" || installState === "verifying") {
      detailText = "猫猫代理已走国内 443 提速 · 正在后台准备其它软件提速组件…";
    } else if (installState === "need_elevation") {
      detailText = "猫猫代理已走国内 443 提速 · 其它软件自动加速需管理员权限";
    } else {
      detailText = relayName
        ? `正通过「${relayName}」加速猫猫代理上传`
        : "正在通过国内 443 中转加速猫猫代理上传";
    }

    return {
      enabled: true,
      proxyActive: true,
      realWinDivertActive,
      localSocksActive,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: "国内提速中",
      subBadgeText,
      detailText,
      tone: "green",
    };
  }

  if (realWinDivertActive) {
    if (verifyState === "probing") {
      return {
        enabled: true,
        proxyActive: false,
        realWinDivertActive: true,
        localSocksActive: false,
        installState: "ready",
        verifyState,
        verifyLatencyMs,
        badgeText: "正在探测链路…",
        subBadgeText: "自动加速其它软件",
        detailText: relayName
          ? `已通过「${relayName}」启用其它软件提速，正在自动探测链路连通性…`
          : "已启用其它软件提速，正在自动探测链路连通性…",
        tone: "amber",
      };
    }

    if (verifyState === "verified") {
      return {
        enabled: true,
        proxyActive: false,
        realWinDivertActive: true,
        localSocksActive: false,
        installState: "ready",
        verifyState,
        verifyLatencyMs,
        badgeText: "已探测畅通",
        subBadgeText: verifyLatencyMs ? `实测 ${verifyLatencyMs} ms` : "自动加速其它软件",
        detailText: verifyLatencyMs
          ? relayName
            ? `已通过「${relayName}」实测畅通（${verifyLatencyMs} ms），正自动加速电脑上其它代理软件`
            : `实测链路畅通（${verifyLatencyMs} ms），正自动加速电脑上其它代理软件`
          : verifyMessage ||
            (relayName
              ? `已通过「${relayName}」实测畅通，正自动加速电脑上其它代理软件`
              : "实测链路畅通，正自动加速电脑上其它代理软件"),
        tone: "green",
      };
    }

    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: true,
      localSocksActive: false,
      installState: "ready",
      verifyState,
      verifyLatencyMs,
      badgeText: "全局提速中",
      subBadgeText: "自动加速其它软件",
      detailText: relayName
        ? `正通过「${relayName}」自动加速电脑上其它代理软件`
        : "正在自动加速电脑上其它代理软件",
      tone: "accent",
    };
  }

  if (installState === "downloading" || installState === "verifying") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: "正在准备提速组件…",
      subBadgeText: null,
      detailText:
        installState === "verifying"
          ? "正在校验官方提速组件完整性，完成后将自动生效…"
          : "正在后台自动下载官方提速组件，完成后自动热生效…",
      tone: "amber",
    };
  }

  if (installState === "need_elevation") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: "需管理员权限",
      subBadgeText: null,
      detailText: "提速组件已就绪，点击「以管理员重启生效」即可自动加速其它代理软件",
      tone: "amber",
    };
  }

  if (verifyState === "probing") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: "正在探测链路…",
      subBadgeText: null,
      detailText:
        verifyMessage ||
        (relayName
          ? `正在通过「${relayName}」自动探测链路连通性…`
          : "正在自动探测其它软件提速链路连通性…"),
      tone: "amber",
    };
  }

  if (verifyState === "degraded") {
    return {
      enabled: true,
      proxyActive: false,
      realWinDivertActive: false,
      localSocksActive,
      installState,
      verifyState,
      verifyLatencyMs,
      badgeText: "已自动保护回退",
      subBadgeText: null,
      detailText:
        verifyMessage ||
        lastError ||
        "自动探测发现底层拦截未畅通，已自动停止拦截防止断网，本地 443 通道仍待命",
      tone: "amber",
    };
  }

  const detailText =
    installState === "failed" && lastError
      ? `提速组件准备未完成（${lastError}），当前仅本地通道待命`
      : verifyState === "failed" && (verifyMessage || lastError)
        ? verifyMessage || lastError || "链路探测未通过，当前处于本地通道待命状态"
        : socksPort
          ? `本地 443 通道 127.0.0.1:${socksPort} 待命中，启动猫猫代理或就绪底层组件后自动生效`
          : "国内提速已开启，当前处于本地通道待命状态";

  return {
    enabled: true,
    proxyActive: false,
    realWinDivertActive: false,
    localSocksActive,
    installState,
    verifyState,
    verifyLatencyMs,
    badgeText: "本地通道待命",
    subBadgeText: null,
    detailText,
    tone: "amber",
  };
}
