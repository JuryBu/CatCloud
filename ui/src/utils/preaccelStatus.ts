import type {
  CoreRuntimeInfo,
  GlobalPreAccelStatus,
  PreAccelVerifyState,
} from "../api/tauri";
import type { UiLanguage } from "../i18n/types";

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
  preaccel_effective_carrier?: string;
  standalone_tunnel_suspended_for_tun?: boolean;
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

type ResolvedCopyLang = "zh-CN" | "en" | "ja" | "ru";

function normalizeCopyLang(raw?: UiLanguage | string): ResolvedCopyLang {
  if (!raw) return "zh-CN";
  const lower = raw.trim().toLowerCase();
  if (lower === "zh-cn" || lower === "zh" || lower.startsWith("zh-")) return "zh-CN";
  if (lower === "ja" || lower.startsWith("ja-")) return "ja";
  if (lower === "ru" || lower.startsWith("ru-")) return "ru";
  return "en";
}

interface PreAccelCopySet {
  offBadge: string;
  offDetail: string;
  addRelayBadge: string;
  addRelayDetail: string;
  activeBadge: string;
  boostingOtherBadge: string;
  probingShort: string;
  probingBadge: string;
  degradedShort: string;
  degradedBadge: string;
  preparingBadge: string;
  needAdminBadge: string;
  localReadyBadge: string;
  standbyBadge: string;
  tunDetail: (relay: string | null, ms: number | null) => string;
  proxyDualProbingDetail: (relay: string | null) => string;
  proxyDualVerifiedDetail: (relay: string | null, ms: number | null) => string;
  proxyDualActiveDetail: (relay: string | null) => string;
  proxyProbingOtherDetail: (relay: string | null) => string;
  proxyDegradedFallbackDetail: string;
  proxyInstallingDetail: (relay: string | null) => string;
  proxyNeedAdminDetail: (relay: string | null) => string;
  proxyOnlyDetail: (relay: string | null) => string;
  standaloneProbingDetail: (relay: string | null) => string;
  standaloneVerifiedDetail: (relay: string | null, ms: number | null) => string;
  standaloneActiveDetail: (relay: string | null) => string;
  verifyingDriverDetail: string;
  downloadingDriverDetail: string;
  needAdminDetail: (socksPort: number | null) => string;
  probingLinkDetail: (relay: string | null) => string;
  degradedStandaloneDetail: (socksPort: number | null) => string;
  installFailedDetail: (err: string, socksPort: number | null) => string;
  verifyFailedDetail: (socksPort: number | null) => string;
  localSocksDetail: (relay: string | null, socksPort: number | null) => string;
  standbyDetail: (relay: string | null) => string;
  offPlain: string;
  addRelayPlain: string;
  tunPlain: (relay: string | null, ms: number | null) => string;
  proxyDualProbingPlain: (relay: string | null) => string;
  proxyDualVerifiedPlain: (relay: string | null, ms: number | null) => string;
  proxyDualActivePlain: (relay: string | null) => string;
  proxyDegradedPlain: (relay: string | null) => string;
  proxyInstallingPlain: (relay: string | null) => string;
  proxyNeedAdminPlain: (relay: string | null) => string;
  proxyOnlyPlain: (relay: string | null) => string;
  standaloneProbingPlain: (relay: string | null) => string;
  standaloneVerifiedPlain: (relay: string | null, ms: number | null) => string;
  standaloneActivePlain: (relay: string | null) => string;
  verifyingDriverPlain: string;
  downloadingDriverPlain: string;
  needAdminPlain: string;
  probingLinkPlain: (relay: string | null) => string;
  degradedStandalonePlain: string;
  installFailedPlain: string;
  verifyFailedPlain: string;
  localReadyPlain: (relay: string | null) => string;
  standbyPlain: (relay: string | null) => string;
}

const PREACCEL_COPY: Record<ResolvedCopyLang, PreAccelCopySet> = {
  "zh-CN": {
    offBadge: "已关闭",
    offDetail: "关闭后猫猫云梯与电脑上其它代理软件均不走国内提速线路",
    addRelayBadge: "请先添加提速线路",
    addRelayDetail: "国内提速尚未生效：请先添加或导入至少一条并启用的国内提速线路",
    activeBadge: "国内提速已生效",
    boostingOtherBadge: "正为原梯子提速",
    probingShort: "探测中…",
    probingBadge: "正在探测链路…",
    degradedShort: "原梯子已保护回退",
    degradedBadge: "已自动保护回退",
    preparingBadge: "正在准备提速组件…",
    needAdminBadge: "需管理员开启",
    localReadyBadge: "本地提速已就绪",
    standbyBadge: "提速待命中",
    tunDetail: (relay, ms) =>
      relay
        ? `主内核虚拟网卡正通过「${relay}」提速${ms ? `（${ms} ms）` : ""}，独立 443 通道已自动暂停避免冲突`
        : `主内核虚拟网卡提速中${ms ? `（${ms} ms）` : ""}，独立 443 通道已自动暂停避免冲突`,
    proxyDualProbingDetail: (relay) =>
      relay
        ? `主内核代理已通过「${relay}」提速 · 正在探测其它软件独立底层链路…`
        : "主内核代理已开启国内提速 · 正在探测其它软件独立底层链路…",
    proxyDualVerifiedDetail: (relay, ms) =>
      relay
        ? `主内核代理 + 独立底层通道均已通过「${relay}」实测畅通${ms ? `（${ms} ms）` : ""}`
        : `主内核代理 + 独立底层通道均已实测畅通${ms ? `（${ms} ms）` : ""}`,
    proxyDualActiveDetail: (relay) =>
      relay
        ? `主内核代理 + 独立底层通道正通过「${relay}」加速上传与连通`
        : "主内核代理 + 独立底层通道正加速上传与连通",
    proxyProbingOtherDetail: (relay) =>
      relay
        ? `主内核代理已通过「${relay}」提速 · 正在探测其它软件加速链路…`
        : "主内核代理已开启国内提速 · 正在探测其它软件加速链路…",
    proxyDegradedFallbackDetail:
      "自动探测发现其它软件独立底层拦截未畅通，已自动保护回退防止断网，主内核代理仍正常提速",
    proxyInstallingDetail: (relay) =>
      relay
        ? `主内核代理已通过「${relay}」提速 · 正在后台准备其它软件提速组件…`
        : "主内核代理已开启国内提速 · 正在后台准备其它软件提速组件…",
    proxyNeedAdminDetail: (relay) =>
      relay
        ? `主内核代理已通过「${relay}」提速 · 自动加速其它代理软件需管理员权限`
        : "主内核代理已开启国内提速 · 自动加速其它代理软件需管理员权限",
    proxyOnlyDetail: (relay) =>
      relay
        ? `主内核代理正通过「${relay}」提速上传与连通`
        : "主内核代理正在通过国内中转线路提速",
    standaloneProbingDetail: (relay) =>
      relay
        ? `已通过「${relay}」启用独立底层提速，正在自动探测原梯子链路连通性…`
        : "已启用独立底层提速，正在自动探测原梯子链路连通性…",
    standaloneVerifiedDetail: (relay, ms) =>
      relay
        ? `独立底层通道已通过「${relay}」实测畅通${ms ? `（${ms} ms）` : ""}，正自动为你的原梯子提速`
        : `独立底层通道实测畅通${ms ? `（${ms} ms）` : ""}，正自动为你的原梯子提速`,
    standaloneActiveDetail: (relay) =>
      relay
        ? `独立底层通道正通过「${relay}」自动为你原来的梯子提速`
        : "独立底层通道正自动为你原来的梯子提速",
    verifyingDriverDetail: "正在校验官方提速组件完整性，完成后将自动生效…",
    downloadingDriverDetail: "正在后台自动下载官方提速组件，完成后自动热生效…",
    needAdminDetail: (socksPort) =>
      socksPort
        ? `提速组件已就绪，点击「以管理员开启」即可自动加速原梯子（当前也可填本地 127.0.0.1:${socksPort} 作为前置代理）`
        : "提速组件已就绪，点击「以管理员开启」即可自动为你的原梯子提速",
    probingLinkDetail: (relay) =>
      relay
        ? `正在通过「${relay}」自动探测原梯子提速链路连通性…`
        : "正在自动探测原梯子提速链路连通性…",
    degradedStandaloneDetail: (socksPort) =>
      socksPort
        ? `自动探测发现底层拦截未畅通，已自动停止拦截防止断网（本地入口 127.0.0.1:${socksPort} 仍待命）`
        : "自动探测发现底层拦截未畅通，已自动停止拦截防止断网",
    installFailedDetail: (err, socksPort) =>
      socksPort
        ? `提速组件准备未完成（${err}），当前本地入口 127.0.0.1:${socksPort} 仍可用`
        : `提速组件准备未完成（${err}），开启猫云代理后仍可正常走提速`,
    verifyFailedDetail: (socksPort) =>
      socksPort
        ? `链路探测未通过，本地入口 127.0.0.1:${socksPort} 待命中`
        : "链路探测未通过，当前处于待命状态",
    localSocksDetail: (relay, socksPort) => {
      const relayPart = relay ? `（线路：${relay}）` : "";
      return socksPort
        ? `本地 SOCKS5 提速入口 127.0.0.1:${socksPort} 已就绪${relayPart}，可填入原梯子前置代理，或以管理员开启自动提速`
        : `本地提速入口已就绪${relayPart}，启动代理或以管理员开启后自动生效`;
    },
    standbyDetail: (relay) =>
      relay
        ? `国内提速已开启（线路：${relay}），启动代理或以管理员开启后即可自动提速`
        : "国内提速已开启，启动代理或以管理员开启后即可自动提速",
    offPlain: "已关闭，当前不走国内提速线路",
    addRelayPlain: "请先添加并启用至少一条国内提速线路",
    tunPlain: (relay, ms) =>
      relay
        ? `正在通过「${relay}」为你加速上传与访问${ms ? `（${ms} ms）` : ""}`
        : `正在为你加速上传与访问${ms ? `（${ms} ms）` : ""}`,
    proxyDualProbingPlain: (relay) =>
      relay
        ? `正在通过「${relay}」为你加速，并检查其它梯子的提速状态…`
        : "正在为你加速，并检查其它梯子的提速状态…",
    proxyDualVerifiedPlain: (relay, ms) =>
      relay
        ? `正在通过「${relay}」为猫猫云梯与其它梯子同时加速${ms ? `（${ms} ms）` : ""}`
        : `正在为猫猫云梯与其它梯子同时加速${ms ? `（${ms} ms）` : ""}`,
    proxyDualActivePlain: (relay) =>
      relay
        ? `正在通过「${relay}」为猫猫云梯与其它梯子同时加速`
        : "正在为猫猫云梯与其它梯子同时加速",
    proxyDegradedPlain: (relay) =>
      relay
        ? `正在通过「${relay}」为猫猫云梯加速（其它梯子已自动保护回退）`
        : "正在为猫猫云梯加速（其它梯子已自动保护回退）",
    proxyInstallingPlain: (relay) =>
      relay
        ? `正在通过「${relay}」为你加速，后台正准备其它梯子的提速组件…`
        : "正在为你加速，后台正准备其它梯子的提速组件…",
    proxyNeedAdminPlain: (relay) =>
      relay
        ? `正在通过「${relay}」为猫猫云梯加速，点右侧按钮以管理员重启即可同步加速其它梯子`
        : "正在为猫猫云梯加速，点右侧按钮以管理员重启即可同步加速其它梯子",
    proxyOnlyPlain: (relay) =>
      relay
        ? `正在通过「${relay}」为你加速上传与访问`
        : "正在为你加速上传与访问",
    standaloneProbingPlain: (relay) =>
      relay
        ? `已开启，正通过「${relay}」检查电脑上其它梯子的加速状态…`
        : "已开启，正在检查电脑上其它梯子的加速状态…",
    standaloneVerifiedPlain: (relay, ms) =>
      relay
        ? `已开启，正通过「${relay}」自动为电脑上其它梯子加速${ms ? `（${ms} ms）` : ""}`
        : `已开启，正自动为电脑上其它梯子加速${ms ? `（${ms} ms）` : ""}`,
    standaloneActivePlain: (relay) =>
      relay
        ? `已开启，正通过「${relay}」自动为电脑上其它梯子加速`
        : "已开启，正自动为电脑上其它梯子加速",
    verifyingDriverPlain: "正在校验提速组件，完成后自动生效…",
    downloadingDriverPlain: "正在后台准备提速组件，完成后自动生效…",
    needAdminPlain: "提速组件已就绪，点击右侧按钮以管理员重启即可自动加速",
    probingLinkPlain: (relay) =>
      relay ? `正在通过「${relay}」检查提速连通状态…` : "正在检查提速连通状态…",
    degradedStandalonePlain: "自动检查未畅通，已暂停自动加速防止断网，点右侧可重试",
    installFailedPlain: "提速组件准备未完成，可点右侧重试，或直接开启猫猫代理使用提速",
    verifyFailedPlain: "提速连通检查未通过，当前处于待命状态，可点右侧重新探测",
    localReadyPlain: (relay) =>
      relay
        ? `本地提速已就绪（线路：${relay}），填入原梯子前置代理即可加速`
        : "本地提速已就绪，填入原梯子前置代理即可加速",
    standbyPlain: (relay) =>
      relay
        ? `国内提速已开启（线路：${relay}），开启代理或以管理员重启即可自动加速`
        : "国内提速已开启，开启代理或以管理员重启即可自动加速",
  },
  en: {
    offBadge: "Off",
    offDetail: "Domestic boost is off for both CatCloud proxy and other proxy apps.",
    addRelayBadge: "Add Boost Relay",
    addRelayDetail:
      "Domestic Boost is inactive: please add or import at least one enabled domestic boost relay first.",
    activeBadge: "Domestic Boost Active",
    boostingOtherBadge: "Boosting Other Apps",
    probingShort: "Probing…",
    probingBadge: "Probing Link…",
    degradedShort: "Other Apps Fallback",
    degradedBadge: "Protected Fallback",
    preparingBadge: "Preparing Boost…",
    needAdminBadge: "Admin Required",
    localReadyBadge: "Local Boost Ready",
    standbyBadge: "Boost Standby",
    tunDetail: (relay, ms) =>
      relay
        ? `Main core TUN is boosting via "${relay}"${ms ? ` (${ms} ms)` : ""}; standalone :443 tunnel auto-paused to avoid conflict.`
        : `Main core TUN boost active${ms ? ` (${ms} ms)` : ""}; standalone :443 tunnel auto-paused to avoid conflict.`,
    proxyDualProbingDetail: (relay) =>
      relay
        ? `Main core boosted via "${relay}" · Probing standalone tunnel for other proxy apps…`
        : "Main core boosted · Probing standalone tunnel for other proxy apps…",
    proxyDualVerifiedDetail: (relay, ms) =>
      relay
        ? `Main core + standalone tunnel verified via "${relay}"${ms ? ` (${ms} ms)` : ""}.`
        : `Main core + standalone tunnel verified${ms ? ` (${ms} ms)` : ""}.`,
    proxyDualActiveDetail: (relay) =>
      relay
        ? `Main core + standalone tunnel boosting via "${relay}".`
        : "Main core + standalone tunnel boosting active.",
    proxyProbingOtherDetail: (relay) =>
      relay
        ? `Main core boosted via "${relay}" · Probing acceleration path for other apps…`
        : "Main core boosted · Probing acceleration path for other apps…",
    proxyDegradedFallbackDetail:
      "Standalone interception failed verification and fell back safely to prevent disconnects; main core boost remains active.",
    proxyInstallingDetail: (relay) =>
      relay
        ? `Main core boosted via "${relay}" · Preparing boost component for other apps in background…`
        : "Main core boosted · Preparing boost component for other apps in background…",
    proxyNeedAdminDetail: (relay) =>
      relay
        ? `Main core boosted via "${relay}" · Admin privilege needed to auto-boost other proxy apps.`
        : "Main core boosted · Admin privilege needed to auto-boost other proxy apps.",
    proxyOnlyDetail: (relay) =>
      relay
        ? `Main core proxy is boosting upload and connectivity via "${relay}".`
        : "Main core proxy is boosting via domestic relay.",
    standaloneProbingDetail: (relay) =>
      relay
        ? `Standalone boost started via "${relay}"; verifying connectivity for your current proxy app…`
        : "Standalone boost started; verifying connectivity for your current proxy app…",
    standaloneVerifiedDetail: (relay, ms) =>
      relay
        ? `Standalone tunnel verified via "${relay}"${ms ? ` (${ms} ms)` : ""}, automatically boosting your other proxy apps.`
        : `Standalone tunnel verified${ms ? ` (${ms} ms)` : ""}, automatically boosting your other proxy apps.`,
    standaloneActiveDetail: (relay) =>
      relay
        ? `Standalone tunnel is boosting your other proxy apps via "${relay}".`
        : "Standalone tunnel is boosting your other proxy apps.",
    verifyingDriverDetail: "Verifying official boost component integrity; will activate automatically…",
    downloadingDriverDetail: "Downloading official boost component in background; will activate automatically…",
    needAdminDetail: (socksPort) =>
      socksPort
        ? `Boost component is ready. Click "Enable as Admin" to auto-boost other proxy apps (or use local 127.0.0.1:${socksPort} as upstream proxy).`
        : 'Boost component is ready. Click "Enable as Admin" to auto-boost your current proxy app.',
    probingLinkDetail: (relay) =>
      relay
        ? `Verifying standalone boost link via "${relay}"…`
        : "Verifying standalone boost link…",
    degradedStandaloneDetail: (socksPort) =>
      socksPort
        ? `Standalone interception fell back safely to avoid disconnects (local 127.0.0.1:${socksPort} remains ready).`
        : "Standalone interception fell back safely to avoid disconnects.",
    installFailedDetail: (err, socksPort) =>
      socksPort
        ? `Boost component setup incomplete (${err}); local entry 127.0.0.1:${socksPort} remains available.`
        : `Boost component setup incomplete (${err}); main core proxy boost still works when enabled.`,
    verifyFailedDetail: (socksPort) =>
      socksPort
        ? `Link verification failed; local entry 127.0.0.1:${socksPort} is standing by.`
        : "Link verification failed; boost is standing by.",
    localSocksDetail: (relay, socksPort) => {
      const relayPart = relay ? ` (relay: ${relay})` : "";
      return socksPort
        ? `Local SOCKS5 boost entry 127.0.0.1:${socksPort} is ready${relayPart}. Set it as your proxy app's upstream, or enable as Admin for auto-boost.`
        : `Local boost entry is ready${relayPart}. Start proxy or enable as Admin to activate automatically.`;
    },
    standbyDetail: (relay) =>
      relay
        ? `Domestic Boost enabled (relay: ${relay}); start proxy or enable as Admin to activate.`
        : "Domestic Boost enabled; start proxy or enable as Admin to activate.",
    offPlain: "Domestic Boost is off.",
    addRelayPlain: "Add and enable at least one domestic boost relay first.",
    tunPlain: (relay, ms) =>
      relay
        ? `Boosting your uploads and browsing via "${relay}"${ms ? ` (${ms} ms)` : ""}.`
        : `Boosting your uploads and browsing${ms ? ` (${ms} ms)` : ""}.`,
    proxyDualProbingPlain: (relay) =>
      relay
        ? `Boosting via "${relay}" while checking acceleration for other proxy apps…`
        : "Boosting while checking acceleration for other proxy apps…",
    proxyDualVerifiedPlain: (relay, ms) =>
      relay
        ? `Boosting CatCloud and your other proxy apps via "${relay}"${ms ? ` (${ms} ms)` : ""}.`
        : `Boosting CatCloud and your other proxy apps${ms ? ` (${ms} ms)` : ""}.`,
    proxyDualActivePlain: (relay) =>
      relay
        ? `Boosting CatCloud and your other proxy apps via "${relay}".`
        : "Boosting CatCloud and your other proxy apps.",
    proxyDegradedPlain: (relay) =>
      relay
        ? `Boosting CatCloud via "${relay}" (other proxy apps safely paused to avoid disconnects).`
        : "Boosting CatCloud (other proxy apps safely paused to avoid disconnects).",
    proxyInstallingPlain: (relay) =>
      relay
        ? `Boosting via "${relay}" while preparing acceleration for other proxy apps…`
        : "Boosting while preparing acceleration for other proxy apps…",
    proxyNeedAdminPlain: (relay) =>
      relay
        ? `Boosting CatCloud via "${relay}". Click the button on the right to restart as admin and auto-boost other proxy apps.`
        : "Boosting CatCloud. Click the button on the right to restart as admin and auto-boost other proxy apps.",
    proxyOnlyPlain: (relay) =>
      relay
        ? `Boosting your uploads and browsing via "${relay}".`
        : "Boosting your uploads and browsing.",
    standaloneProbingPlain: (relay) =>
      relay
        ? `Enabled via "${relay}" — checking acceleration for your other proxy apps…`
        : "Enabled — checking acceleration for your other proxy apps…",
    standaloneVerifiedPlain: (relay, ms) =>
      relay
        ? `Enabled — automatically boosting your other proxy apps via "${relay}"${ms ? ` (${ms} ms)` : ""}.`
        : `Enabled — automatically boosting your other proxy apps${ms ? ` (${ms} ms)` : ""}.`,
    standaloneActivePlain: (relay) =>
      relay
        ? `Enabled — automatically boosting your other proxy apps via "${relay}".`
        : "Enabled — automatically boosting your other proxy apps.",
    verifyingDriverPlain: "Verifying boost component — will activate automatically…",
    downloadingDriverPlain: "Preparing boost component in background — will activate automatically…",
    needAdminPlain: "Boost component is ready — click the button on the right to restart as admin for auto-boost.",
    probingLinkPlain: (relay) =>
      relay ? `Checking boost connectivity via "${relay}"…` : "Checking boost connectivity…",
    degradedStandalonePlain: "Auto-check did not pass; auto-boost paused safely to prevent disconnects.",
    installFailedPlain: "Boost component setup is incomplete — retry on the right or enable CatCloud proxy directly.",
    verifyFailedPlain: "Boost connectivity check failed — standing by; click right to probe again.",
    localReadyPlain: (relay) =>
      relay
        ? `Local boost ready (${relay}) — set it as your proxy app's upstream to accelerate.`
        : "Local boost ready — set it as your proxy app's upstream to accelerate.",
    standbyPlain: (relay) =>
      relay
        ? `Domestic Boost enabled (${relay}) — start proxy or restart as admin to accelerate.`
        : "Domestic Boost enabled — start proxy or restart as admin to accelerate.",
  },
  ja: {
    offBadge: "オフ",
    offDetail: "CatCloud および他のプロキシアプリで国内高速化はオフになっています。",
    addRelayBadge: "高速化回線を追加",
    addRelayDetail:
      "国内高速化は未稼働です。利用可能な国内高速化回線を 1 件以上追加または取込してください。",
    activeBadge: "国内高速化 稼働中",
    boostingOtherBadge: "他アプリを高速化中",
    probingShort: "検証中…",
    probingBadge: "回線を検証中…",
    degradedShort: "他アプリ保護切替",
    degradedBadge: "保護フォールバック",
    preparingBadge: "コンポーネント準備中…",
    needAdminBadge: "管理者権限が必要",
    localReadyBadge: "ローカル高速化準備完了",
    standbyBadge: "高速化待機中",
    tunDetail: (relay, ms) =>
      relay
        ? `メインコア仮想 NIC が「${relay}」経由で高速化中${ms ? `（${ms} ms）` : ""}（独立 443 経路は競合回避のため自動一時停止）`
        : `メインコア仮想 NIC 高速化中${ms ? `（${ms} ms）` : ""}（独立 443 経路は競合回避のため自動一時停止）`,
    proxyDualProbingDetail: (relay) =>
      relay
        ? `メインコアは「${relay}」で高速化中 · 他アプリ向け独立経路を検証中…`
        : "メインコア高速化中 · 他アプリ向け独立経路を検証中…",
    proxyDualVerifiedDetail: (relay, ms) =>
      relay
        ? `メインコア＋独立経路が「${relay}」経由で疎通確認済み${ms ? `（${ms} ms）` : ""}`
        : `メインコア＋独立経路が疎通確認済み${ms ? `（${ms} ms）` : ""}`,
    proxyDualActiveDetail: (relay) =>
      relay
        ? `メインコア＋独立経路が「${relay}」経由で高速化中`
        : "メインコア＋独立経路で高速化中",
    proxyProbingOtherDetail: (relay) =>
      relay
        ? `メインコアは「${relay}」で高速化中 · 他アプリ向け高速化経路を検証中…`
        : "メインコア高速化中 · 他アプリ向け高速化経路を検証中…",
    proxyDegradedFallbackDetail:
      "他アプリ向け独立制御の検証に失敗したため断線防止で自動停止しました。メインコア高速化は継続中です。",
    proxyInstallingDetail: (relay) =>
      relay
        ? `メインコアは「${relay}」で高速化中 · 他アプリ向けコンポーネントを準備中…`
        : "メインコア高速化中 · 他アプリ向けコンポーネントを準備中…",
    proxyNeedAdminDetail: (relay) =>
      relay
        ? `メインコアは「${relay}」で高速化中 · 他アプリの自動高速化には管理者権限が必要です`
        : "メインコア高速化中 · 他アプリの自動高速化には管理者権限が必要です",
    proxyOnlyDetail: (relay) =>
      relay
        ? `メインコアプロキシが「${relay}」経由で高速化中`
        : "メインコアプロキシが国内中継経由で高速化中",
    standaloneProbingDetail: (relay) =>
      relay
        ? `「${relay}」経由の独立高速化を開始し、疎通を検証中…`
        : "独立高速化を開始し、疎通を検証中…",
    standaloneVerifiedDetail: (relay, ms) =>
      relay
        ? `独立経路が「${relay}」経由で疎通確認済み${ms ? `（${ms} ms）` : ""}、既存プロキシアプリを自動高速化中`
        : `独立経路が疎通確認済み${ms ? `（${ms} ms）` : ""}、既存プロキシアプリを自動高速化中`,
    standaloneActiveDetail: (relay) =>
      relay
        ? `独立経路が「${relay}」経由で既存プロキシアプリを自動高速化中`
        : "独立経路が既存プロキシアプリを自動高速化中",
    verifyingDriverDetail: "公式高速化コンポーネントを検証中です。完了後に自動で有効になります…",
    downloadingDriverDetail: "公式高速化コンポーネントをバックグラウンドで取得中です…",
    needAdminDetail: (socksPort) =>
      socksPort
        ? `コンポーネント準備完了。「管理者で有効化」で他アプリを自動高速化できます（127.0.0.1:${socksPort} を前置プロキシとしても利用可）`
        : "コンポーネント準備完了。「管理者で有効化」で既存プロキシアプリを自動高速化できます",
    probingLinkDetail: (relay) =>
      relay ? `「${relay}」経由の疎通を自動検証中…` : "高速化経路の疎通を自動検証中…",
    degradedStandaloneDetail: (socksPort) =>
      socksPort
        ? `独立制御の疎通検証に失敗したため自動保護切替しました（ローカル入口 127.0.0.1:${socksPort} は待機中）`
        : "独立制御の疎通検証に失敗したため自動保護切替しました",
    installFailedDetail: (err, socksPort) =>
      socksPort
        ? `コンポーネント準備未完了（${err}）。ローカル入口 127.0.0.1:${socksPort} は利用可能です`
        : `コンポーネント準備未完了（${err}）。プロキシ有効時は引き続き高速化されます`,
    verifyFailedDetail: (socksPort) =>
      socksPort
        ? `疎通検証に失敗しました（ローカル入口 127.0.0.1:${socksPort} 待機中）`
        : "疎通検証に失敗しました（待機中）",
    localSocksDetail: (relay, socksPort) => {
      const relayPart = relay ? `（回線：${relay}）` : "";
      return socksPort
        ? `ローカル SOCKS5 入口 127.0.0.1:${socksPort} 準備完了${relayPart}。既存アプリの前置プロキシに設定するか管理者で有効化してください`
        : `ローカル高速化入口が準備完了${relayPart}。プロキシ開始または管理者有効化で稼働します`;
    },
    standbyDetail: (relay) =>
      relay
        ? `国内高速化オン（回線：${relay}）。プロキシ開始または管理者有効化で稼働します`
        : "国内高速化オン。プロキシ開始または管理者有効化で稼働します",
    offPlain: "国内高速化はオフです",
    addRelayPlain: "有効な国内高速化回線を 1 件以上追加してください",
    tunPlain: (relay, ms) =>
      relay
        ? `「${relay}」経由でアップロードとアクセスを高速化中${ms ? `（${ms} ms）` : ""}`
        : `アップロードとアクセスを高速化中${ms ? `（${ms} ms）` : ""}`,
    proxyDualProbingPlain: (relay) =>
      relay
        ? `「${relay}」で高速化中・他のプロキシアプリの状態を確認中…`
        : "高速化中・他のプロキシアプリの状態を確認中…",
    proxyDualVerifiedPlain: (relay, ms) =>
      relay
        ? `「${relay}」経由で CatCloud と他のプロキシアプリを同時高速化中${ms ? `（${ms} ms）` : ""}`
        : `CatCloud と他のプロキシアプリを同時高速化中${ms ? `（${ms} ms）` : ""}`,
    proxyDualActivePlain: (relay) =>
      relay
        ? `「${relay}」経由で CatCloud と他のプロキシアプリを高速化中`
        : "CatCloud と他のプロキシアプリを高速化中",
    proxyDegradedPlain: (relay) =>
      relay
        ? `「${relay}」で CatCloud を高速化中（他アプリは断線防止のため自動一時停止）`
        : "CatCloud を高速化中（他アプリは断線防止のため自動一時停止）",
    proxyInstallingPlain: (relay) =>
      relay
        ? `「${relay}」で高速化中・他アプリ向けコンポーネントを準備中…`
        : "高速化中・他アプリ向けコンポーネントを準備中…",
    proxyNeedAdminPlain: (relay) =>
      relay
        ? `「${relay}」で CatCloud を高速化中。右のボタンから管理者で再起動すると他アプリも自動高速化できます`
        : "CatCloud を高速化中。右のボタンから管理者で再起動すると他アプリも自動高速化できます",
    proxyOnlyPlain: (relay) =>
      relay
        ? `「${relay}」経由でアップロードとアクセスを高速化中`
        : "アップロードとアクセスを高速化中",
    standaloneProbingPlain: (relay) =>
      relay
        ? `オン（「${relay}」）・他のプロキシアプリ向けの高速化を確認中…`
        : "オン・他のプロキシアプリ向けの高速化を確認中…",
    standaloneVerifiedPlain: (relay, ms) =>
      relay
        ? `オン・「${relay}」経由で他のプロキシアプリを自動高速化中${ms ? `（${ms} ms）` : ""}`
        : `オン・他のプロキシアプリを自動高速化中${ms ? `（${ms} ms）` : ""}`,
    standaloneActivePlain: (relay) =>
      relay
        ? `オン・「${relay}」経由で他のプロキシアプリを自動高速化中`
        : "オン・他のプロキシアプリを自動高速化中",
    verifyingDriverPlain: "高速化コンポーネントを検証中…完了後に自動有効化されます",
    downloadingDriverPlain: "高速化コンポーネントを準備中…完了後に自動有効化されます",
    needAdminPlain: "高速化コンポーネント準備完了。右のボタンから管理者で再起動すると自動高速化されます",
    probingLinkPlain: (relay) =>
      relay ? `「${relay}」経由の高速化接続を確認中…` : "高速化接続を確認中…",
    degradedStandalonePlain: "自動チェックが通らなかったため、断線防止で自動高速化を一時停止しました",
    installFailedPlain: "コンポーネントの準備が未完了です。右から再試行するか CatCloud プロキシを有効にしてください",
    verifyFailedPlain: "高速化チェックに失敗しました（待機中）。右のボタンから再チェックできます",
    localReadyPlain: (relay) =>
      relay
        ? `ローカル高速化準備完了（${relay}）。既存アプリの前置プロキシに設定して加速できます`
        : "ローカル高速化準備完了。既存アプリの前置プロキシに設定して加速できます",
    standbyPlain: (relay) =>
      relay
        ? `国内高速化オン（${relay}）。プロキシ開始または管理者再起動で高速化されます`
        : "国内高速化オン。プロキシ開始または管理者再起動で高速化されます",
  },
  ru: {
    offBadge: "Выкл",
    offDetail: "Ускорение отключено для CatCloud и других прокси-клиентов.",
    addRelayBadge: "Добавьте реле",
    addRelayDetail:
      "Ускорение не активно: сначала добавьте или импортируйте хотя бы одно включённое реле ускорения.",
    activeBadge: "Ускорение активно",
    boostingOtherBadge: "Ускорение других ПО",
    probingShort: "Проверка…",
    probingBadge: "Проверка канала…",
    degradedShort: "Защитный откат",
    degradedBadge: "Защитный откат",
    preparingBadge: "Подготовка…",
    needAdminBadge: "Нужны права",
    localReadyBadge: "Локальный вход готов",
    standbyBadge: "Ожидание ускорения",
    tunDetail: (relay, ms) =>
      relay
        ? `TUN основного ядра ускоряется через «${relay}»${ms ? ` (${ms} мс)` : ""}; отдельный туннель :443 приостановлен во избежание конфликта.`
        : `TUN основного ядра ускоряется${ms ? ` (${ms} мс)` : ""}; отдельный туннель :443 приостановлен во избежание конфликта.`,
    proxyDualProbingDetail: (relay) =>
      relay
        ? `Основное ядро ускоряется через «${relay}» · Проверка отдельного канала для других программ…`
        : "Основное ядро ускоряется · Проверка отдельного канала для других программ…",
    proxyDualVerifiedDetail: (relay, ms) =>
      relay
        ? `Основное ядро и отдельный канал проверены через «${relay}»${ms ? ` (${ms} мс)` : ""}.`
        : `Основное ядро и отдельный канал проверены${ms ? ` (${ms} мс)` : ""}.`,
    proxyDualActiveDetail: (relay) =>
      relay
        ? `Основное ядро и отдельный канал ускоряются через «${relay}».`
        : "Основное ядро и отдельный канал ускоряются.",
    proxyProbingOtherDetail: (relay) =>
      relay
        ? `Основное ядро ускоряется через «${relay}» · Проверка ускорения других программ…`
        : "Основное ядро ускоряется · Проверка ускорения других программ…",
    proxyDegradedFallbackDetail:
      "Отдельный перехват не прошёл проверку и безопасно отключён во избежание обрывов; ускорение основного ядра продолжает работать.",
    proxyInstallingDetail: (relay) =>
      relay
        ? `Основное ядро ускоряется через «${relay}» · В фоне готовится компонент для других программ…`
        : "Основное ядро ускоряется · В фоне готовится компонент для других программ…",
    proxyNeedAdminDetail: (relay) =>
      relay
        ? `Основное ядро ускоряется через «${relay}» · Для автоускорения других клиентов нужны права администратора.`
        : "Основное ядро ускоряется · Для автоускорения других клиентов нужны права администратора.",
    proxyOnlyDetail: (relay) =>
      relay
        ? `Основное ядро ускоряет отдачу и соединение через «${relay}».`
        : "Основное ядро работает через реле ускорения.",
    standaloneProbingDetail: (relay) =>
      relay
        ? `Отдельный канал запущен через «${relay}», выполняется проверка связи…`
        : "Отдельный канал запущен, выполняется проверка связи…",
    standaloneVerifiedDetail: (relay, ms) =>
      relay
        ? `Отдельный канал проверен через «${relay}»${ms ? ` (${ms} мс)` : ""} и автоматически ускоряет ваш прокси-клиент.`
        : `Отдельный канал проверен${ms ? ` (${ms} мс)` : ""} и автоматически ускоряет ваш прокси-клиент.`,
    standaloneActiveDetail: (relay) =>
      relay
        ? `Отдельный канал автоматически ускоряет ваш прокси-клиент через «${relay}».`
        : "Отдельный канал автоматически ускоряет ваш прокси-клиент.",
    verifyingDriverDetail: "Проверка целостности компонента ускорения; включится автоматически…",
    downloadingDriverDetail: "Фоновая загрузка компонента ускорения; включится автоматически…",
    needAdminDetail: (socksPort) =>
      socksPort
        ? `Компонент готов. Нажмите «Включить от админа» для автоускорения других клиентов (или укажите 127.0.0.1:${socksPort} как входной прокси).`
        : "Компонент готов. Нажмите «Включить от админа» для автоускорения вашего прокси-клиента.",
    probingLinkDetail: (relay) =>
      relay
        ? `Проверка доступности канала ускорения через «${relay}»…`
        : "Проверка доступности канала ускорения…",
    degradedStandaloneDetail: (socksPort) =>
      socksPort
        ? `Проверка перехвата не прошла, включён безопасный откат (локальный вход 127.0.0.1:${socksPort} доступен).`
        : "Проверка перехвата не прошла, включён безопасный откат.",
    installFailedDetail: (err, socksPort) =>
      socksPort
        ? `Подготовка компонента не завершена (${err}); локальный вход 127.0.0.1:${socksPort} доступен.`
        : `Подготовка компонента не завершена (${err}); ускорение ядра доступно при включённом прокси.`,
    verifyFailedDetail: (socksPort) =>
      socksPort
        ? `Проверка канала не прошла; локальный вход 127.0.0.1:${socksPort} в режиме ожидания.`
        : "Проверка канала не прошла; ожидание запуска.",
    localSocksDetail: (relay, socksPort) => {
      const relayPart = relay ? ` (реле: ${relay})` : "";
      return socksPort
        ? `Локальный SOCKS5 вход 127.0.0.1:${socksPort} готов${relayPart}. Укажите его в вашем клиенте или включите от администратора.`
        : `Локальный вход ускорения готов${relayPart}. Включите прокси или запустите от администратора.`;
    },
    standbyDetail: (relay) =>
      relay
        ? `Ускорение включено (реле: ${relay}); запустите прокси или права администратора для активации.`
        : "Ускорение включено; запустите прокси или права администратора для активации.",
    offPlain: "Ускорение отключено.",
    addRelayPlain: "Сначала добавьте и включите хотя бы одно реле ускорения.",
    tunPlain: (relay, ms) =>
      relay
        ? `Ускоряет отправку и доступ через «${relay}»${ms ? ` (${ms} мс)` : ""}.`
        : `Ускоряет отправку и доступ${ms ? ` (${ms} мс)` : ""}.`,
    proxyDualProbingPlain: (relay) =>
      relay
        ? `Ускорение через «${relay}», проверка других прокси-клиентов…`
        : "Ускорение активно, проверка других прокси-клиентов…",
    proxyDualVerifiedPlain: (relay, ms) =>
      relay
        ? `Ускоряет CatCloud и другие прокси-клиенты через «${relay}»${ms ? ` (${ms} мс)` : ""}.`
        : `Ускоряет CatCloud и другие прокси-клиенты${ms ? ` (${ms} мс)` : ""}.`,
    proxyDualActivePlain: (relay) =>
      relay
        ? `Ускоряет CatCloud и другие прокси-клиенты через «${relay}».`
        : "Ускоряет CatCloud и другие прокси-клиенты.",
    proxyDegradedPlain: (relay) =>
      relay
        ? `CatCloud ускоряется через «${relay}» (для других программ включён безопасный откат).`
        : "CatCloud ускоряется (для других программ включён безопасный откат).",
    proxyInstallingPlain: (relay) =>
      relay
        ? `Ускорение через «${relay}», в фоне готовится компонент для других клиентов…`
        : "Ускорение активно, в фоне готовится компонент для других клиентов…",
    proxyNeedAdminPlain: (relay) =>
      relay
        ? `CatCloud ускоряется через «${relay}». Нажмите кнопку справа для перезапуска от администратора и автоускорения других клиентов.`
        : "CatCloud ускоряется. Нажмите кнопку справа для перезапуска от администратора и автоускорения других клиентов.",
    proxyOnlyPlain: (relay) =>
      relay
        ? `Ускоряет отправку и доступ через «${relay}».`
        : "Ускоряет отправку и доступ.",
    standaloneProbingPlain: (relay) =>
      relay
        ? `Включено через «${relay}» — проверка ускорения других прокси-клиентов…`
        : "Включено — проверка ускорения других прокси-клиентов…",
    standaloneVerifiedPlain: (relay, ms) =>
      relay
        ? `Включено — автоматически ускоряет другие прокси-клиенты через «${relay}»${ms ? ` (${ms} мс)` : ""}.`
        : `Включено — автоматически ускоряет другие прокси-клиенты${ms ? ` (${ms} мс)` : ""}.`,
    standaloneActivePlain: (relay) =>
      relay
        ? `Включено — автоматически ускоряет другие прокси-клиенты через «${relay}».`
        : "Включено — автоматически ускоряет другие прокси-клиенты.",
    verifyingDriverPlain: "Проверка компонента ускорения — включится автоматически…",
    downloadingDriverPlain: "Подготовка компонента ускорения — включится автоматически…",
    needAdminPlain: "Компонент готов — нажмите кнопку справа для перезапуска от администратора и автоускорения.",
    probingLinkPlain: (relay) =>
      relay ? `Проверка соединения ускорения через «${relay}»…` : "Проверка соединения ускорения…",
    degradedStandalonePlain: "Автопроверка не прошла — автоускорение безопасно приостановлено во избежание обрывов.",
    installFailedPlain: "Подготовка компонента не завершена — повторите справа или включите прокси CatCloud.",
    verifyFailedPlain: "Проверка ускорения не прошла — режим ожидания; повторите проверку справа.",
    localReadyPlain: (relay) =>
      relay
        ? `Локальное ускорение готово (${relay}) — укажите адрес в вашем прокси-клиенте.`
        : "Локальное ускорение готово — укажите адрес в вашем прокси-клиенте.",
    standbyPlain: (relay) =>
      relay
        ? `Ускорение включено (${relay}) — запустите прокси или перезапустите от администратора.`
        : "Ускорение включено — запустите прокси или перезапустите от администратора.",
  },
};

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
  configPreAccelEnabled?: boolean,
  hasEnabledRelay?: boolean,
  uiLang?: UiLanguage | string
): PreAccelSummary {
  const copy = PREACCEL_COPY[normalizeCopyLang(uiLang)];
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
      plainText: copy.tunPlain(relayName, verifyLatencyMs),
      detailText: copy.tunDetail(relayName, verifyLatencyMs),
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
        plainText = copy.proxyDualProbingPlain(relayName);
        detailText = copy.proxyDualProbingDetail(relayName);
      } else if (verifyState === "verified") {
        subBadgeText = verifyLatencyMs ? `${verifyLatencyMs} ms` : null;
        plainText = copy.proxyDualVerifiedPlain(relayName, verifyLatencyMs);
        detailText =
          verifyLatencyMs || !verifyMessage
            ? copy.proxyDualVerifiedDetail(relayName, verifyLatencyMs)
            : verifyMessage;
      } else {
        subBadgeText = null;
        plainText = copy.proxyDualActivePlain(relayName);
        detailText = copy.proxyDualActiveDetail(relayName);
      }
    } else if (verifyState === "probing") {
      subBadgeText = copy.probingShort;
      plainText = copy.proxyDualProbingPlain(relayName);
      detailText = copy.proxyProbingOtherDetail(relayName);
    } else if (verifyState === "degraded") {
      subBadgeText = copy.degradedShort;
      plainText = copy.proxyDegradedPlain(relayName);
      detailText = verifyMessage || lastError || copy.proxyDegradedFallbackDetail;
    } else if (installState === "downloading" || installState === "verifying") {
      plainText = copy.proxyInstallingPlain(relayName);
      detailText = copy.proxyInstallingDetail(relayName);
    } else if (installState === "need_elevation") {
      plainText = copy.proxyNeedAdminPlain(relayName);
      detailText = copy.proxyNeedAdminDetail(relayName);
    } else {
      plainText = copy.proxyOnlyPlain(relayName);
      detailText = copy.proxyOnlyDetail(relayName);
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
        plainText: copy.standaloneProbingPlain(relayName),
        detailText: copy.standaloneProbingDetail(relayName),
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
        plainText: copy.standaloneVerifiedPlain(relayName, verifyLatencyMs),
        detailText:
          verifyLatencyMs || !verifyMessage
            ? copy.standaloneVerifiedDetail(relayName, verifyLatencyMs)
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
      plainText: copy.standaloneActivePlain(relayName),
      detailText: copy.standaloneActiveDetail(relayName),
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
      detailText: copy.needAdminDetail(socksPort),
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
      plainText: copy.probingLinkPlain(relayName),
      detailText: verifyMessage || copy.probingLinkDetail(relayName),
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
      detailText: verifyMessage || lastError || copy.degradedStandaloneDetail(socksPort),
      tone: "amber",
    };
  }

  const plainText =
    installState === "failed"
      ? copy.installFailedPlain
      : verifyState === "failed"
        ? copy.verifyFailedPlain
        : localSocksActive || socksPort
          ? copy.localReadyPlain(relayName)
          : copy.standbyPlain(relayName);

  const detailText =
    installState === "failed" && lastError
      ? copy.installFailedDetail(lastError, socksPort)
      : verifyState === "failed" && (verifyMessage || lastError)
        ? verifyMessage || lastError || copy.verifyFailedDetail(socksPort)
        : localSocksActive || socksPort
          ? copy.localSocksDetail(relayName, socksPort)
          : copy.standbyDetail(relayName);

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
