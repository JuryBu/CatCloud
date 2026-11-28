import type { ExitIpInfo, ProbeSnapshot } from "../api/tauri";

export type AiSiteId = "gemini" | "chatgpt" | "claude" | "windsurf";
export type AiBadgeTone = "green" | "amber" | "red" | "muted";
export type WindsurfUnlockState =
  | "clean"
  | "datacenter"
  | "proxy_risk"
  | "blocked"
  | "legacy_retest"
  | "untested";

export interface WindsurfUnlockDisplay {
  state: WindsurfUnlockState;
  tone: AiBadgeTone;
  label: string;
  shortLabel: string;
  dotLabel: string;
  measured: boolean;
  unlocked: boolean;
  isClean: boolean;
  isRisk: boolean;
  isLegacyRetest: boolean;
  tooltip: string;
}

export interface AiSiteBadgeDisplay {
  id: AiSiteId;
  name: string;
  label: string;
  shortLabel: string;
  dotLabel: string;
  tone: AiBadgeTone;
  measured: boolean;
  unlocked: boolean;
  tooltip: string;
  windsurfState?: WindsurfUnlockState;
}

export interface IpPurityBadgeDisplay {
  level: "clean" | "datacenter" | "proxy_risk" | "unknown";
  tone: AiBadgeTone;
  label: string;
  shortLabel: string;
  tooltip: string;
  asn: string | null;
  flags: string | null;
}

function normalizeRiskLevel(raw: string | null | undefined): string | null {
  const trimmed = raw?.trim().toLowerCase();
  return trimmed ? trimmed : null;
}

function formatRiskFlagsHuman(flags: string | null | undefined): string {
  const raw = flags?.trim();
  if (!raw) return "";
  const map: Record<string, string> = {
    proxy: "代理IP",
    vpn: "VPN",
    tor: "Tor出口",
    datacenter: "机房/IDC",
    hosting: "托管机房",
    mobile: "移动网络",
  };
  return raw
    .split(",")
    .map((part) => {
      const p = part.trim();
      if (!p) return "";
      const lower = p.toLowerCase();
      if (lower.startsWith("risk=")) {
        return `风险分 ${p.slice(5)}`;
      }
      return map[lower] ?? p;
    })
    .filter(Boolean)
    .join(" / ");
}

export function isProxyRiskSnapshot(
  snap: Pick<ProbeSnapshot, "ip_risk_level"> | Pick<ExitIpInfo, "ip_risk_level"> | undefined | null
): boolean {
  return normalizeRiskLevel(snap?.ip_risk_level) === "proxy_risk";
}

export function resolveWindsurfUnlockDisplay(
  snap: ProbeSnapshot | undefined
): WindsurfUnlockDisplay {
  const detailRaw = snap?.per_probe_detail?.builtin_unlock_windsurf?.trim() ?? "";
  const hasSemanticMarker = detailRaw.toLowerCase().includes("semantic_windsurf");
  const riskLevel = normalizeRiskLevel(snap?.ip_risk_level);
  const asn = snap?.ip_asn?.trim() || null;
  const flagsText = formatRiskFlagsHuman(snap?.ip_risk_flags);
  const unlockedRaw =
    snap?.unlocked_sites?.windsurf ?? snap?.per_probe_ok?.builtin_unlock_windsurf;

  const extraMetaParts: string[] = [];
  if (asn) extraMetaParts.push(`自治域：${asn}`);
  if (flagsText) extraMetaParts.push(`风险标记：${flagsText}`);
  if (detailRaw) extraMetaParts.push(`探测详情：${detailRaw}`);
  const extraSuffix = extraMetaParts.length > 0 ? `\n${extraMetaParts.join("\n")}` : "";

  if (riskLevel === "proxy_risk") {
    return {
      state: "proxy_risk",
      tone: "red",
      label: "WSF·风控",
      shortLabel: "WSF·风控",
      dotLabel: "WSF!",
      measured: true,
      unlocked: false,
      isClean: false,
      isRisk: true,
      isLegacyRetest: false,
      tooltip: `Windsurf / Devin 高危代理风控：出口被识别为代理/高风险 IP，推理易触发 error 13 或封禁，已拦截不亮绿灯。${extraSuffix}`,
    };
  }

  if (unlockedRaw === undefined) {
    return {
      state: "untested",
      tone: "muted",
      label: "Windsurf",
      shortLabel: "WSF",
      dotLabel: "WSF",
      measured: false,
      unlocked: false,
      isClean: false,
      isRisk: false,
      isLegacyRetest: false,
      tooltip: "Windsurf / Devin：尚未测速，请运行「测延迟 + 送中/AI」核验推理网关与出口 IP 纯净度。",
    };
  }

  if (unlockedRaw === false) {
    return {
      state: "blocked",
      tone: "muted",
      label: "Windsurf",
      shortLabel: "WSF",
      dotLabel: "WSF",
      measured: true,
      unlocked: false,
      isClean: false,
      isRisk: false,
      isLegacyRetest: false,
      tooltip: `Windsurf / Devin 受限或推理网关不可达。${extraSuffix}`,
    };
  }

  // unlockedRaw === true
  const isLegacyHomepageRecord =
    !hasSemanticMarker &&
    !riskLevel &&
    snap?.ip_clean == null &&
    (detailRaw.length === 0 || detailRaw.startsWith("site=windsurf,"));
  if (isLegacyHomepageRecord) {
    return {
      state: "legacy_retest",
      tone: "muted",
      label: "WSF·需重测",
      shortLabel: "WSF·重测",
      dotLabel: "WSF?",
      measured: true,
      unlocked: false,
      isClean: false,
      isRisk: false,
      isLegacyRetest: true,
      tooltip: `Windsurf（旧版历史记录）：旧版仅检测了官网可达，请重新测速以核验 AI 推理纯净度与出口 IP 风险。${extraSuffix}`,
    };
  }

  if (riskLevel === "clean" || (riskLevel === null && snap?.ip_clean === true)) {
    return {
      state: "clean",
      tone: "green",
      label: "Windsurf",
      shortLabel: "WSF",
      dotLabel: "WSF",
      measured: true,
      unlocked: true,
      isClean: true,
      isRisk: false,
      isLegacyRetest: false,
      tooltip: `Windsurf / Devin 纯净解锁：推理网关可达且出口为纯净住宅/ISP 网络。${extraSuffix}`,
    };
  }

  if (riskLevel === "datacenter" || snap?.ip_clean === false) {
    return {
      state: "datacenter",
      tone: "amber",
      label: "WSF·机房",
      shortLabel: "WSF·机房",
      dotLabel: "WSF",
      measured: true,
      unlocked: true,
      isClean: false,
      isRisk: false,
      isLegacyRetest: false,
      tooltip: `Windsurf / Devin 可用（机房提醒）：推理网关可达，但出口属于机房/托管 IP，高峰或高频调用可能受风控，建议优先选纯净住宅节点。${extraSuffix}`,
    };
  }

  return {
    state: "datacenter",
    tone: "amber",
    label: "WSF·待核",
    shortLabel: "WSF·待核",
    dotLabel: "WSF",
    measured: true,
    unlocked: true,
    isClean: false,
    isRisk: false,
    isLegacyRetest: false,
    tooltip: `Windsurf / Devin 推理网关可达（IP 纯净度情报暂不可用，建议复测确认出口风险）。${extraSuffix}`,
  };
}

function buildStandardAiTooltip(
  name: string,
  val: boolean | undefined,
  detail: string | undefined,
  extraLines: string[] = []
): string {
  const status =
    val === true ? "实测可用" : val === false ? "实测受限 / 不可用" : "尚未测速";
  const lines = [`${name}：${status}`];
  const trimmedDetail = detail?.trim();
  if (trimmedDetail) {
    lines.push(`探测详情：${trimmedDetail}`);
  }
  for (const line of extraLines) {
    if (line.trim()) lines.push(line.trim());
  }
  return lines.join("\n");
}

export function getNodeAiBadgeDisplays(
  snap: ProbeSnapshot | undefined
): AiSiteBadgeDisplay[] {
  const sites = snap?.unlocked_sites ?? {};
  const details = snap?.per_probe_detail ?? {};

  const geminiVal =
    sites.gemini ??
    sites.gemini_aistudio ??
    sites.google_ai ??
    snap?.per_probe_ok?.builtin_unlock_gemini;
  const chatgptVal = sites.chatgpt ?? snap?.per_probe_ok?.builtin_unlock_chatgpt;
  const claudeVal = sites.claude ?? snap?.per_probe_ok?.builtin_unlock_claude;

  const geminiExtras: string[] = [];
  if (snap?.cf_loc || snap?.yt_gl) {
    geminiExtras.push(
      `地区参考：CF=${snap.cf_loc ?? "--"} · YT=${snap.yt_gl ?? "--"}`
    );
  }
  const wsf = resolveWindsurfUnlockDisplay(snap);

  return [
    {
      id: "gemini",
      name: "Gemini",
      label: "Gemini",
      shortLabel: "Gemini",
      dotLabel: "G",
      tone: geminiVal === true ? "green" : "muted",
      measured: geminiVal !== undefined,
      unlocked: geminiVal === true,
      tooltip: buildStandardAiTooltip(
        "Gemini / AI Studio",
        geminiVal,
        details.builtin_unlock_gemini ?? details.builtin_google_cn,
        geminiExtras
      ),
    },
    {
      id: "chatgpt",
      name: "ChatGPT",
      label: "ChatGPT",
      shortLabel: "GPT",
      dotLabel: "GPT",
      tone: chatgptVal === true ? "green" : "muted",
      measured: chatgptVal !== undefined,
      unlocked: chatgptVal === true,
      tooltip: buildStandardAiTooltip(
        "ChatGPT / OpenAI",
        chatgptVal,
        details.builtin_unlock_chatgpt
      ),
    },
    {
      id: "claude",
      name: "Claude",
      label: "Claude",
      shortLabel: "Claude",
      dotLabel: "C",
      tone: claudeVal === true ? "green" : "muted",
      measured: claudeVal !== undefined,
      unlocked: claudeVal === true,
      tooltip: buildStandardAiTooltip(
        "Claude / Anthropic",
        claudeVal,
        details.builtin_unlock_claude
      ),
    },
    {
      id: "windsurf",
      name: "Windsurf",
      label: wsf.label,
      shortLabel: wsf.shortLabel,
      dotLabel: wsf.dotLabel,
      tone: wsf.tone,
      measured: wsf.measured,
      unlocked: wsf.unlocked,
      tooltip: wsf.tooltip,
      windsurfState: wsf.state,
    },
  ];
}

export function hasVerifiedAiUnlock(snap: ProbeSnapshot | undefined): boolean {
  if (!snap) return false;
  return getNodeAiBadgeDisplays(snap).some((b) => b.unlocked);
}

export function countVerifiedAiUnlocks(snap: ProbeSnapshot | undefined): number {
  if (!snap) return 0;
  return getNodeAiBadgeDisplays(snap).filter((b) => b.unlocked).length;
}

export function formatGoogleRegionTooltip(
  snap: ProbeSnapshot | undefined,
  nodeRegionCode?: string
): string {
  if (!snap) return "谷歌地区：尚未测速";
  const status =
    snap.google_clean === true
      ? "谷歌地区正常（未送中）"
      : snap.google_clean === false
        ? "谷歌送中 / 地区受限"
        : "谷歌地区：尚未测速";
  const lines = [status];
  if (snap.cf_loc || snap.yt_gl) {
    lines.push(`实测地区：Cloudflare=${snap.cf_loc ?? "--"} · YouTube=${snap.yt_gl ?? "--"}`);
  }
  if (
    snap.google_risk_mismatch ||
    (snap.yt_gl && nodeRegionCode && nodeRegionCode !== "UNK" && snap.yt_gl.toUpperCase() !== nodeRegionCode.toUpperCase())
  ) {
    lines.push("提示：不同站点识别出的出口地区存在偏差，仅供参考");
  }
  const googleDetail = snap.per_probe_detail?.builtin_google_cn?.trim();
  if (googleDetail) {
    lines.push(`探测详情：${googleDetail}`);
  }
  if (snap.ip_asn?.trim()) {
    lines.push(`出口自治域：${snap.ip_asn.trim()}`);
  }
  return lines.join("\n");
}

export function formatIpPurityBadge(
  info:
    | Pick<ProbeSnapshot, "ip_clean" | "ip_risk_level" | "ip_asn" | "ip_risk_flags">
    | Pick<ExitIpInfo, "ip_clean" | "ip_risk_level" | "ip_asn" | "ip_risk_flags">
    | undefined
    | null
): IpPurityBadgeDisplay | null {
  if (!info) return null;
  const riskLevel = normalizeRiskLevel(info.ip_risk_level);
  const asn = info.ip_asn?.trim() || null;
  const flags = info.ip_risk_flags?.trim() || null;
  const flagsHuman = formatRiskFlagsHuman(flags);

  const metaParts: string[] = [];
  if (asn) metaParts.push(`自治域：${asn}`);
  if (flagsHuman) metaParts.push(`标签：${flagsHuman}`);
  const metaSuffix = metaParts.length > 0 ? `\n${metaParts.join(" · ")}` : "";

  if (riskLevel === "proxy_risk") {
    return {
      level: "proxy_risk",
      tone: "red",
      label: "高危代理风控",
      shortLabel: "代理风控",
      tooltip: `当前出口 IP 被风险库标记为代理/高风险，Windsurf / Devin 等 AI 编程服务易报错。${metaSuffix}`,
      asn,
      flags: flagsHuman || flags,
    };
  }
  if (riskLevel === "clean" || (riskLevel === null && info.ip_clean === true)) {
    return {
      level: "clean",
      tone: "green",
      label: "纯净住宅/ISP",
      shortLabel: "纯净IP",
      tooltip: `当前出口 IP 纯净度良好，未被标记为公共代理或数据中心机房。${metaSuffix}`,
      asn,
      flags: flagsHuman || flags,
    };
  }
  if (riskLevel === "datacenter" || (riskLevel === null && info.ip_clean === false)) {
    return {
      level: "datacenter",
      tone: "amber",
      label: "机房托管 IP",
      shortLabel: "机房IP",
      tooltip: `当前出口 IP 属于数据中心/机房段，常规可用但高频 AI 调用可能遇风控。${metaSuffix}`,
      asn,
      flags: flagsHuman || flags,
    };
  }
  if (riskLevel === "unknown") {
    return {
      level: "unknown",
      tone: "muted",
      label: "纯净度未知",
      shortLabel: "待核IP",
      tooltip: `IP 风险情报暂不可用，可稍后重测核验。${metaSuffix}`,
      asn,
      flags: flagsHuman || flags,
    };
  }
  return null;
}

export function getAiBadgeToneClass(
  tone: AiBadgeTone,
  variant: "solid" | "soft" | "legacy" = "soft"
): string {
  if (variant === "legacy") {
    return "border border-dashed border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--muted)]";
  }
  switch (tone) {
    case "green":
      return variant === "solid"
        ? "bg-[var(--green)] text-[var(--accent-ink)]"
        : "bg-[var(--green-soft)] text-[var(--green)]";
    case "amber":
      return variant === "solid"
        ? "bg-[var(--amber)] text-[var(--accent-ink)]"
        : "bg-[var(--amber-soft)] text-[var(--amber)]";
    case "red":
      return variant === "solid"
        ? "bg-[var(--red)] text-[var(--accent-ink)]"
        : "bg-[var(--red-soft)] text-[var(--red)]";
    default:
      return "bg-[var(--bg-elevated)] text-[var(--muted)]";
  }
}
