export type PlatformOs = "windows" | "macos" | "linux";

export type ShellEnvKind = "powershell" | "cmd" | "bash" | "zsh" | "fish";

export const DEFAULT_GLOBAL_TARGET_PROCESSES: readonly string[] = [
  "mihomo.exe",
  "clash-meta.exe",
  "xray.exe",
  "v2ray.exe",
  "sing-box.exe",
  "hysteria.exe",
  "tuic.exe",
  "trojan.exe",
  "ssh.exe",
  "scp.exe",
  "sftp.exe",
  "rsync.exe",
] as const;

/**
 * Fallback platform detection via browser navigator hints (safe before Tauri IPC hydration).
 */
export function detectNavigatorOs(): PlatformOs {
  if (typeof navigator === "undefined") return "windows";
  const navWithUaData = navigator as Navigator & {
    userAgentData?: { platform?: string };
  };
  const raw =
    navWithUaData.userAgentData?.platform ||
    navigator.platform ||
    navigator.userAgent ||
    "";
  const lower = raw.toLowerCase();
  if (lower.includes("mac") || lower.includes("darwin")) return "macos";
  if (lower.includes("linux") || lower.includes("x11")) return "linux";
  if (lower.includes("win")) return "windows";
  return "windows";
}

/**
 * Resolve runtime platform OS, preferring backend `runtime.os_label` (e.g. `"macos aarch64"`,
 * `"linux x86_64"`, `"windows x86_64"`) with navigator fallback for zero-flicker initial paint.
 */
export function resolvePlatformOs(osLabel?: string | null): PlatformOs {
  const trimmed = osLabel?.trim().toLowerCase() ?? "";
  if (trimmed) {
    if (trimmed.includes("mac") || trimmed.includes("darwin")) return "macos";
    if (trimmed.includes("linux")) return "linux";
    if (trimmed.includes("win")) return "windows";
  }
  return detectNavigatorOs();
}

export function defaultShellForOs(os: PlatformOs): ShellEnvKind {
  if (os === "macos") return "zsh";
  if (os === "linux") return "bash";
  return "powershell";
}

export function buildShellEnvFallback(shell: ShellEnvKind, port: number): string {
  const httpUrl = `http://127.0.0.1:${port}`;
  const socksUrl = `socks5://127.0.0.1:${port}`;
  const noProxy = "localhost,127.0.0.1,::1";
  switch (shell) {
    case "powershell":
      return `$env:HTTP_PROXY="${httpUrl}"; $env:HTTPS_PROXY="${httpUrl}"; $env:ALL_PROXY="${socksUrl}"; $env:NO_PROXY="${noProxy}"; $env:no_proxy="${noProxy}"`;
    case "cmd":
      return `set HTTP_PROXY=${httpUrl} && set HTTPS_PROXY=${httpUrl} && set ALL_PROXY=${socksUrl} && set NO_PROXY=${noProxy} && set no_proxy=${noProxy}`;
    case "fish":
      return `set -gx http_proxy "${httpUrl}"; set -gx https_proxy "${httpUrl}"; set -gx all_proxy "${socksUrl}"; set -gx no_proxy "${noProxy}"; set -gx HTTP_PROXY "${httpUrl}"; set -gx HTTPS_PROXY "${httpUrl}"; set -gx ALL_PROXY "${socksUrl}"; set -gx NO_PROXY "${noProxy}"`;
    case "zsh":
    case "bash":
      return `export http_proxy="${httpUrl}" https_proxy="${httpUrl}" all_proxy="${socksUrl}" no_proxy="${noProxy}" HTTP_PROXY="${httpUrl}" HTTPS_PROXY="${httpUrl}" ALL_PROXY="${socksUrl}" NO_PROXY="${noProxy}"`;
  }
}

export function buildGlobalPreAccelShellSnippet(
  port: number,
  shell: "posix" | "fish" | "powershell"
): string {
  const socksUrl = `socks5h://127.0.0.1:${port}`;
  const noProxy = "localhost,127.0.0.1,::1";
  switch (shell) {
    case "fish":
      return `set -gx all_proxy "${socksUrl}"; set -gx ALL_PROXY "${socksUrl}"; set -gx no_proxy "${noProxy}"; set -gx NO_PROXY "${noProxy}"`;
    case "powershell":
      return `$env:ALL_PROXY="${socksUrl}"; $env:NO_PROXY="${noProxy}"; $env:no_proxy="${noProxy}"`;
    case "posix":
      return `export all_proxy="${socksUrl}" ALL_PROXY="${socksUrl}" no_proxy="${noProxy}" NO_PROXY="${noProxy}"`;
  }
}
