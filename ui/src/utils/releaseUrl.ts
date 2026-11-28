/**
 * Shared release URL, friendly group display name, and latency color helpers
 * reused across HomePage, SpeedTestPage, MultiGroupPage, SettingsPage, and UpdateReadyModal.
 */

export const DEFAULT_UPDATE_REPO = "JuryBu/CatCloud";

export function normalizeUpdateRepo(raw: string | null | undefined): string {
  const cleaned = (raw ?? "").trim().replace(/^\/+|\/+$/g, "");
  return cleaned || DEFAULT_UPDATE_REPO;
}

export function buildReleasesFallbackUrl(repo: string | null | undefined): string {
  return `https://github.com/${normalizeUpdateRepo(repo)}/releases`;
}

export const FRIENDLY_GROUP_NAME_MAP: Record<string, string> = {
  流媒体与下载受控均衡: "影音下载均衡组",
  高优家宽备援池: "备用精选组",
};

export function formatGroupDisplayName(name: string): string {
  return FRIENDLY_GROUP_NAME_MAP[name] ?? name;
}

export function getLatencyColor(
  latencyMs: number | null | undefined,
  ok?: boolean | null
): string {
  if (ok === false) return "var(--red)";
  if (latencyMs === null || latencyMs === undefined || !Number.isFinite(latencyMs)) {
    return "var(--muted)";
  }
  if (latencyMs <= 140) return "var(--green)";
  if (latencyMs <= 300) return "var(--amber)";
  return "var(--red)";
}
