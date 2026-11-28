import type {
  AppConfig,
  FullAppConfig,
  GeoDataFileStatus,
  GeoDataStatusDto,
  MemoryTier,
  ResolvedTheme,
  ThemeMode,
  WebUiEntry,
} from "../../api/tauri";
import {
  type UiLanguage,
  formatI18nTemplate,
  getUiDictSync,
  normalizeUiLanguage,
} from "../../i18n";
import { appActions, appStore } from "../../store/appStore";
import { copyText as copyTextRaw } from "../../utils/clipboard";
import type { PlatformOs, ShellEnvKind } from "../../utils/platform";
import { buildReleasesFallbackUrl, normalizeUpdateRepo } from "../../utils/releaseUrl";
import { oneOfPref } from "../../utils/uiPrefs";

export { buildReleasesFallbackUrl, normalizeUpdateRepo };

export type SettingsTabId = "system" | "appearance" | "dns" | "core" | "updates";
export type LogLevel = "silent" | "error" | "warning" | "info" | "debug";
export type DnsEnhancedMode = "fake-ip" | "redir-host";
export type GeoKey = "geoip" | "geosite" | "mmdb" | "asn";

export interface ExtendedSettings {
  bypassDomains: string;
  domesticDirectEnabled: boolean;
  blockQuicUdp443: boolean;
  allowLan: boolean;
  controllerSecret: string;
  webuiUrls: WebUiEntry[];
  logLevel: LogLevel;
  overrideDns: boolean;
  dnsListen: string;
  useHosts: boolean;
  useSystemHosts: boolean;
  respectRules: boolean;
  preferH3: boolean;
  enhancedMode: DnsEnhancedMode;
  fakeIpRange: string;
  fakeIpFilter: string;
  defaultNameserver: string;
  nameserverPolicy: string;
  nameserver: string;
  fallback: string;
  proxyServerNameserver: string;
  fallbackFilterGeoip: boolean;
  fallbackFilterGeoipCode: string;
  fallbackFilterIpcidr: string;
  fallbackFilterDomain: string;
  appendRules: string;
  overrideScriptPath: string;
  startupScriptPath: string;
  compileAllNodes: boolean;
  startupPage: string;
  trayClickAction: string;
  closeToWindowless: boolean;
  hotkeys: Record<string, string>;
}

export const DEFAULT_WEBUI_ENTRIES: WebUiEntry[] = [
  {
    name: "MetaCubeXD",
    url_template:
      "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}",
  },
  {
    name: "Yacd-meta",
    url_template:
      "https://yacd.metacubex.one/#/setup?hostname={host}&port={port}&secret={secret}",
  },
];

export const DEFAULT_EXTENDED: ExtendedSettings = {
  bypassDomains: "localhost, 127.0.0.1, [::1], 127.*, 10.*, 172.16.*, 192.168.*, *.local, <local>",
  domesticDirectEnabled: true,
  blockQuicUdp443: true,
  allowLan: false,
  controllerSecret: "",
  webuiUrls: DEFAULT_WEBUI_ENTRIES,
  logLevel: "info",
  overrideDns: true,
  dnsListen: "127.0.0.1:11053",
  useHosts: true,
  useSystemHosts: true,
  respectRules: true,
  preferH3: false,
  enhancedMode: "fake-ip",
  fakeIpRange: "198.18.0.1/16",
  fakeIpFilter: "*.lan, *.local, time.*.com, ntp.*.com, +.msftconnecttest.com",
  defaultNameserver:
    "https://223.5.5.5/dns-query, https://1.12.12.12/dns-query, tls://223.6.6.6:853, tls://120.53.53.53:853",
  nameserverPolicy:
    "geosite:cn,private: https://223.5.5.5/dns-query, https://1.12.12.12/dns-query",
  nameserver:
    "https://223.5.5.5/dns-query, https://1.12.12.12/dns-query, tls://223.6.6.6:853, tls://120.53.53.53:853",
  fallback: "https://1.1.1.1/dns-query, https://dns.google/dns-query",
  proxyServerNameserver:
    "https://223.5.5.5/dns-query, https://1.12.12.12/dns-query, tls://223.6.6.6:853, tls://120.53.53.53:853",
  fallbackFilterGeoip: true,
  fallbackFilterGeoipCode: "CN",
  fallbackFilterIpcidr: "240.0.0.0/4, 0.0.0.0/32, 198.51.100.0/24",
  fallbackFilterDomain: "+.google.com, +.github.com, +.youtube.com",
  appendRules: "",
  overrideScriptPath: "",
  startupScriptPath: "",
  compileAllNodes: false,
  startupPage: "overview",
  trayClickAction: "toggle_main_window",
  closeToWindowless: true,
  hotkeys: {
    toggleProxy: "",
    switchNextBest: "Alt+Shift+N",
    toggleMainWindow: "",
    toggleCapsule: "Alt+Shift+C",
    toggleTun: "",
  },
};

export function getShellEnvOptionsForOs(
  os: PlatformOs
): ReadonlyArray<{ value: ShellEnvKind; label: string }> {
  const all: Record<ShellEnvKind, { value: ShellEnvKind; label: string }> = {
    powershell: { value: "powershell", label: "PowerShell (Windows)" },
    cmd: { value: "cmd", label: "命令提示符 CMD (Windows)" },
    bash: { value: "bash", label: "Bash" },
    zsh: { value: "zsh", label: "Zsh (macOS / Linux)" },
    fish: { value: "fish", label: "Fish" },
  };
  if (os === "macos") {
    return [all.zsh, all.bash, all.fish, all.powershell, all.cmd];
  }
  if (os === "linux") {
    return [all.bash, all.zsh, all.fish, all.powershell, all.cmd];
  }
  return [all.powershell, all.cmd, all.bash, all.zsh, all.fish];
}

export const RESOLVED_THEME_LABELS: Record<ResolvedTheme, string> = {
  light: "浅色暖纸",
  "warm-dark": "深苔暖金",
  "midnight-blue": "午夜星蓝",
};

export const THEME_CARDS: ReadonlyArray<{
  id: ThemeMode;
  title: string;
  desc: string;
  bg: string;
  sidebar: string;
  card: string;
  accent: string;
  text: string;
  isAuto?: boolean;
}> = [
  {
    id: "light",
    title: "浅色暖纸",
    desc: "温和米白，白天清晰护眼",
    bg: "#f6f3ec",
    sidebar: "#efeae0",
    card: "#ffffff",
    accent: "#c4843d",
    text: "#27231e",
  },
  {
    id: "warm_dark",
    title: "深苔暖金",
    desc: "低饱和暗色，柔和不刺眼",
    bg: "#111313",
    sidebar: "#191c1c",
    card: "#202424",
    accent: "#dfb782",
    text: "#e2e5de",
  },
  {
    id: "midnight_blue",
    title: "午夜星蓝",
    desc: "深邃星蓝，深夜专注舒适",
    bg: "#0f172a",
    sidebar: "#16213e",
    card: "#1c294a",
    accent: "#60a5fa",
    text: "#e8eef9",
  },
  {
    id: "auto_time",
    title: "按时间自动",
    desc: "随北京时间自动昼夜换肤",
    bg: "linear-gradient(135deg, #f6f3ec 0%, #c4843d 42%, #191c1c 68%, #0f172a 100%)",
    sidebar: "rgba(255, 255, 255, 0.22)",
    card: "rgba(255, 255, 255, 0.25)",
    accent: "#dfb782",
    text: "#ffffff",
    isAuto: true,
  },
];

export const HOTKEY_LABELS: Record<string, string> = {
  toggleProxy: "切换系统代理",
  switchNextBest: "秒切下一优节点",
  toggleMainWindow: "显示 / 隐藏主窗口",
  toggleCapsule: "切换悬浮小窗",
  toggleTun: "切换虚拟网卡",
};

export const TRAY_CLICK_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "toggle_main_window", label: "显示 / 隐藏主窗口" },
  { value: "open_main_window", label: "始终展开主窗口" },
  { value: "toggle_capsule", label: "切换悬浮小窗" },
  { value: "toggle_system_proxy", label: "切换系统代理" },
  { value: "switch_next_best", label: "秒切下一优节点" },
  { value: "none", label: "无动作" },
];

export const LOG_LEVEL_OPTIONS: ReadonlyArray<{ value: LogLevel; label: string }> = [
  { value: "silent", label: "静默" },
  { value: "error", label: "仅错误" },
  { value: "warning", label: "警告" },
  { value: "info", label: "常规（推荐）" },
  { value: "debug", label: "调试" },
];

export const DIR_ITEMS: ReadonlyArray<readonly ["config" | "data" | "logs" | "core", string]> = [
  ["config", "配置目录"],
  ["data", "数据目录"],
  ["logs", "日志目录"],
  ["core", "内核目录"],
];

export const GEO_ITEMS: ReadonlyArray<
  readonly [GeoKey, keyof GeoDataStatusDto, string, string]
> = [
  ["mmdb", "country_mmdb", "Country.mmdb", "国家地区库"],
  ["geoip", "geoip_dat", "geoip.dat", "IP 归属地库"],
  ["geosite", "geosite_dat", "geosite.dat", "网站域名分流库"],
  ["asn", "asn_mmdb", "asn.mmdb", "网络运营商库"],
];

export const TAB_LABELS_BY_LANG: Record<UiLanguage, Record<SettingsTabId, string>> = {
  "zh-CN": {
    system: "常规与代理",
    appearance: "外观与壁纸",
    dns: "网络与 DNS",
    core: "进阶与维护",
    updates: "关于与更新",
  },
  en: {
    system: "General & Proxy",
    appearance: "Appearance & Language",
    dns: "Network & DNS",
    core: "Core & Tools",
    updates: "About & Updates",
  },
  ja: {
    system: "一般・プロキシ",
    appearance: "外観と言語",
    dns: "ネットワーク・DNS",
    core: "コアと保守",
    updates: "情報と更新",
  },
  ru: {
    system: "Общие и прокси",
    appearance: "Внешний вид и язык",
    dns: "Сеть и DNS",
    core: "Ядро и утилиты",
    updates: "О программе",
  },
};

export const SHELL_ENV_VALIDATOR = oneOfPref(["powershell", "cmd", "bash", "zsh", "fish"] as const);
export const WEB_UI_IDX_VALIDATOR = (raw: unknown): number | undefined =>
  typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? raw : undefined;

export const VALID_SETTINGS_TABS: readonly SettingsTabId[] = [
  "system",
  "appearance",
  "dns",
  "core",
  "updates",
];

export const SETTINGS_TAB_VALIDATOR = oneOfPref(VALID_SETTINGS_TABS);

export function isValidSettingsTab(value: string): value is SettingsTabId {
  return (VALID_SETTINGS_TABS as readonly string[]).includes(value);
}

export function formatGeoFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${Math.round(bytes)} B`;
}

export function formatGeoUpdatedAt(iso: string | null): string {
  if (!iso) return "时间未知";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

export function renderGeoStatusSummary(
  fileStatus: GeoDataFileStatus | undefined,
  loading: boolean
): { state: "loading" | "ready" | "missing"; text: string } {
  if (loading && !fileStatus) {
    return { state: "loading", text: "检测中…" };
  }
  if (!fileStatus || !fileStatus.exists) {
    return { state: "missing", text: "尚未下载" };
  }
  const sizeLabel = formatGeoFileSize(fileStatus.size_bytes);
  const timeLabel = formatGeoUpdatedAt(fileStatus.updated_at);
  return { state: "ready", text: `${sizeLabel} · ${timeLabel}` };
}

export function splitCsvOrLines(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function splitLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function extractWallpaperLabel(rawPath: string): string {
  if (/^https?:\/\//i.test(rawPath)) {
    try {
      const parsed = new URL(rawPath);
      const seg = parsed.pathname.split("/").filter(Boolean).pop();
      return seg ? `网络图片 · ${seg}` : `网络图片 · ${parsed.host}`;
    } catch {
      return "网络图片";
    }
  }
  if (/^data:image\//i.test(rawPath)) {
    return "自定义图片";
  }
  const parts = rawPath.split(/[/\\]/).filter(Boolean);
  return parts[parts.length - 1] ?? rawPath;
}

export function parseNameserverPolicy(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx <= 0) continue;
    const sepMatch =
      /^(.+?):\s+(system(?:\s*,.*)?|https?:\/\/.+|tls:\/\/.+|quic:\/\/.+|\d+\.\d+\.\d+\.\d+.*)$/i.exec(
        trimmed
      );
    const key = (sepMatch ? sepMatch[1] : trimmed.slice(0, colonIdx)).trim();
    const valStr = (sepMatch ? sepMatch[2] : trimmed.slice(colonIdx + 1)).trim();
    const servers = valStr
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (key && servers.length > 0) {
      out[key] = servers;
    }
  }
  return out;
}

export function formatNameserverPolicy(policy?: Record<string, string[]>): string {
  if (!policy) return "";
  return Object.entries(policy)
    .map(([k, list]) => `${k}: ${Array.isArray(list) ? list.join(", ") : String(list)}`)
    .join("\n");
}

export function stripIpv6Brackets(raw: string, fallbackHost: string): string {
  const t = raw.trim();
  if (!t) return fallbackHost;
  if (t.startsWith("[") && t.endsWith("]")) {
    return t.slice(1, -1).trim() || fallbackHost;
  }
  return t;
}

export function splitHostPort(
  raw: string,
  fallbackHost = "127.0.0.1"
): { host: string; port: number | null } {
  const trimmed = raw.trim();
  if (!trimmed) return { host: fallbackHost, port: null };
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon < 0) {
    return { host: stripIpv6Brackets(trimmed, fallbackHost), port: null };
  }
  const closeBracket = trimmed.lastIndexOf("]");
  if (closeBracket >= 0 && lastColon < closeBracket) {
    // Bracketed IPv6 without port (e.g. "[::1]") -> normalize to bare "::1"
    return { host: stripIpv6Brackets(trimmed, fallbackHost), port: null };
  }
  if (closeBracket < 0 && trimmed.indexOf(":") !== lastColon) {
    // Unbracketed IPv6 literal without port (e.g. "::1")
    return { host: trimmed, port: null };
  }
  const host = stripIpv6Brackets(trimmed.slice(0, lastColon), fallbackHost);
  const portRaw = trimmed.slice(lastColon + 1).trim();
  const parsedPort = portRaw ? Number(portRaw) : NaN;
  const port =
    Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535
      ? parsedPort
      : null;
  return { host, port };
}

export function formatDnsListenAddr(hostRaw: string, port: number): string {
  const host = hostRaw.trim() || "127.0.0.1";
  const formattedHost =
    host.includes(":") && !host.startsWith("[") && !host.endsWith("]")
      ? `[${host}]`
      : host;
  return `${formattedHost}:${port}`;
}

export function hydrateExtendedFromFullConfig(full: FullAppConfig): ExtendedSettings {
  const dns = full.dns;
  const sp = full.system_proxy;
  const rules = full.rules_override;
  const beh = full.behavior;
  const hk = beh?.hotkeys;
  const cr = full.core_runtime;

  const dnsHost = full.dns_listen_host ?? "127.0.0.1";
  const dnsPort = full.dns_listen_port ?? 11053;

  return {
    bypassDomains: Array.isArray(sp?.bypass)
      ? sp.bypass.join(", ")
      : DEFAULT_EXTENDED.bypassDomains,
    domesticDirectEnabled:
      rules?.domestic_direct_enabled ?? DEFAULT_EXTENDED.domesticDirectEnabled,
    blockQuicUdp443: rules?.block_quic_udp_443 ?? DEFAULT_EXTENDED.blockQuicUdp443,
    allowLan: full.allow_lan ?? DEFAULT_EXTENDED.allowLan,
    controllerSecret: full.controller_secret ?? "",
    webuiUrls:
      Array.isArray(full.webui_urls) && full.webui_urls.length > 0
        ? full.webui_urls
        : DEFAULT_WEBUI_ENTRIES,
    logLevel: (full.log_level as LogLevel | undefined) ?? DEFAULT_EXTENDED.logLevel,
    overrideDns: dns?.override_dns ?? DEFAULT_EXTENDED.overrideDns,
    dnsListen: formatDnsListenAddr(dnsHost, dnsPort),
    useHosts: dns?.use_hosts ?? DEFAULT_EXTENDED.useHosts,
    useSystemHosts: dns?.use_system_hosts ?? DEFAULT_EXTENDED.useSystemHosts,
    respectRules: dns?.respect_rules ?? DEFAULT_EXTENDED.respectRules,
    preferH3: dns?.prefer_h3 ?? DEFAULT_EXTENDED.preferH3,
    enhancedMode: dns?.mode === "redir-host" ? "redir-host" : "fake-ip",
    fakeIpRange: dns?.fake_ip_range ?? DEFAULT_EXTENDED.fakeIpRange,
    fakeIpFilter: Array.isArray(dns?.fake_ip_filter)
      ? dns.fake_ip_filter.join(", ")
      : DEFAULT_EXTENDED.fakeIpFilter,
    defaultNameserver: Array.isArray(dns?.default_nameserver)
      ? dns.default_nameserver.join(", ")
      : DEFAULT_EXTENDED.defaultNameserver,
    nameserverPolicy: formatNameserverPolicy(dns?.nameserver_policy),
    nameserver: Array.isArray(dns?.nameserver)
      ? dns.nameserver.join(", ")
      : DEFAULT_EXTENDED.nameserver,
    fallback: Array.isArray(dns?.fallback) ? dns.fallback.join(", ") : DEFAULT_EXTENDED.fallback,
    proxyServerNameserver: Array.isArray(dns?.proxy_server_nameserver)
      ? dns.proxy_server_nameserver.join(", ")
      : DEFAULT_EXTENDED.proxyServerNameserver,
    fallbackFilterGeoip: dns?.fallback_filter?.geoip ?? DEFAULT_EXTENDED.fallbackFilterGeoip,
    fallbackFilterGeoipCode:
      dns?.fallback_filter?.geoip_code ?? DEFAULT_EXTENDED.fallbackFilterGeoipCode,
    fallbackFilterIpcidr: Array.isArray(dns?.fallback_filter?.ipcidr)
      ? dns.fallback_filter.ipcidr.join(", ")
      : DEFAULT_EXTENDED.fallbackFilterIpcidr,
    fallbackFilterDomain: Array.isArray(dns?.fallback_filter?.domain)
      ? dns.fallback_filter.domain.join(", ")
      : DEFAULT_EXTENDED.fallbackFilterDomain,
    appendRules: Array.isArray(rules?.global_append_rules)
      ? rules.global_append_rules.join("\n")
      : "",
    overrideScriptPath: rules?.override_script_path ?? "",
    startupScriptPath: cr?.startup_script_path ?? "",
    compileAllNodes: cr?.compile_all_nodes ?? false,
    startupPage: (() => {
      const raw = beh?.startup_page?.trim().toLowerCase();
      if (!raw || raw === "home") return "overview";
      if (raw === "speedtest") return "nodes";
      return raw;
    })(),
    trayClickAction: beh?.tray_click_action ?? "toggle_main_window",
    closeToWindowless: beh?.minimize_to_tray_on_close ?? true,
    hotkeys: {
      toggleProxy: hk?.toggle_system_proxy ?? "",
      switchNextBest: hk !== undefined ? (hk.switch_next_best ?? "") : "Alt+Shift+N",
      toggleMainWindow: hk?.show_main_window ?? "",
      toggleCapsule: hk !== undefined ? (hk.toggle_capsule ?? "") : "Alt+Shift+C",
      toggleTun: hk?.toggle_tun ?? "",
    },
  };
}

export function buildExtendedPatch(
  ext: ExtendedSettings,
  includeAppendRules = false
): Record<string, unknown> {
  const { host: listenHost, port: listenPort } = splitHostPort(ext.dnsListen);
  return {
    allow_lan: ext.allowLan,
    log_level: ext.logLevel,
    controller_secret: ext.controllerSecret.trim() ? ext.controllerSecret.trim() : null,
    webui_urls: ext.webuiUrls,
    dns_listen_host: listenHost || "127.0.0.1",
    ...(listenPort !== null ? { dns_listen_port: listenPort } : {}),
    system_proxy: {
      bypass: splitCsvOrLines(ext.bypassDomains),
    },
    dns: {
      override_dns: ext.overrideDns,
      use_hosts: ext.useHosts,
      use_system_hosts: ext.useSystemHosts,
      respect_rules: ext.respectRules,
      prefer_h3: ext.preferH3,
      mode: ext.enhancedMode,
      fake_ip_range: ext.fakeIpRange.trim() || "198.18.0.1/16",
      fake_ip_filter: splitCsvOrLines(ext.fakeIpFilter),
      default_nameserver: splitCsvOrLines(ext.defaultNameserver),
      nameserver_policy: parseNameserverPolicy(ext.nameserverPolicy),
      nameserver: splitCsvOrLines(ext.nameserver),
      fallback: splitCsvOrLines(ext.fallback),
      proxy_server_nameserver: splitCsvOrLines(ext.proxyServerNameserver),
      fallback_filter: {
        geoip: ext.fallbackFilterGeoip,
        geoip_code: ext.fallbackFilterGeoipCode.trim() || "CN",
        ipcidr: splitCsvOrLines(ext.fallbackFilterIpcidr),
        domain: splitCsvOrLines(ext.fallbackFilterDomain),
      },
    },
    rules_override: {
      ...(includeAppendRules ? { global_append_rules: splitLines(ext.appendRules) } : {}),
      override_script_path: ext.overrideScriptPath.trim() ? ext.overrideScriptPath.trim() : null,
      domestic_direct_enabled: ext.domesticDirectEnabled,
      block_quic_udp_443: ext.blockQuicUdp443,
    },
    core_runtime: {
      compile_all_nodes: ext.compileAllNodes,
      startup_script_path: ext.startupScriptPath.trim() ? ext.startupScriptPath.trim() : null,
    },
    behavior: {
      minimize_to_tray_on_close: ext.closeToWindowless,
      startup_page: ext.startupPage,
      tray_click_action: ext.trayClickAction,
      hotkeys: {
        toggle_system_proxy: ext.hotkeys.toggleProxy?.trim() || null,
        switch_next_best: ext.hotkeys.switchNextBest?.trim() || null,
        show_main_window: ext.hotkeys.toggleMainWindow?.trim() || null,
        toggle_capsule: ext.hotkeys.toggleCapsule?.trim() || null,
        toggle_tun: ext.hotkeys.toggleTun?.trim() || null,
      },
    },
  };
}

export function tierFromMb(mb: 0 | 48 | 64 | 96): MemoryTier {
  if (mb === 48) return "mb48";
  if (mb === 64) return "mb64";
  if (mb === 96) return "mb96";
  return "auto";
}

export function fullMemoryTierFromMb(mb: 0 | 48 | 64 | 96): string {
  if (mb === 48) return "48MiB";
  if (mb === 64) return "64MiB";
  if (mb === 96) return "96MiB";
  return "auto";
}

export function buildMergedSettingsPatch(
  draft: AppConfig,
  ext: ExtendedSettings,
  includeAppendRules = false
): Record<string, unknown> {
  const baseExt = buildExtendedPatch(ext, includeAppendRules);
  const extSystemProxy = (baseExt.system_proxy as Record<string, unknown>) ?? {};
  const extDns = (baseExt.dns as Record<string, unknown>) ?? {};
  const extCoreRuntime = (baseExt.core_runtime as Record<string, unknown>) ?? {};
  const extBehavior = (baseExt.behavior as Record<string, unknown>) ?? {};

  const resolvedDnsPort =
    typeof baseExt.dns_listen_port === "number" ? baseExt.dns_listen_port : draft.dns_listen_port;
  return {
    ...baseExt,
    mixed_port: draft.mixed_port,
    controller_port: draft.controller_port,
    dns_listen_port: resolvedDnsPort,
    proxy_mode: draft.proxy_mode,
    unified_delay: draft.unified_delay,
    core_ipv6: draft.ipv6_core_enabled,
    system_proxy: {
      ...extSystemProxy,
      proxy_guard: {
        enabled: draft.proxy_guard_enabled,
        interval_sec: draft.proxy_guard_interval_sec,
      },
    },
    tun: {
      stack_mode: draft.tun_stack_mode,
    },
    dns: {
      ...extDns,
      ipv6: draft.ipv6_dns_enabled,
    },
    core_runtime: {
      ...extCoreRuntime,
      memory_tier: fullMemoryTierFromMb(draft.gomemlimit_mb),
    },
    behavior: {
      ...extBehavior,
      autostart: draft.autostart_enabled,
      silent_start: draft.silent_start,
    },
    update: {
      repo: normalizeUpdateRepo(draft.update.repo),
      mode: draft.update.mode,
      check_interval_min: draft.update.check_interval_min,
      include_prerelease: draft.update.include_prerelease,
      auto_download: draft.update.auto_download ?? true,
    },
  };
}

export async function copySettingText(text: string, label: string): Promise<void> {
  const dict = getUiDictSync(
    normalizeUiLanguage(appStore.getState().config.personalization.ui_language)
  );
  const copiedMsg = formatI18nTemplate(dict.settings.copiedItemToast, { label });
  const copyFailedMsg = formatI18nTemplate(dict.settings.copyFailedToast, { label });
  const ok = await copyTextRaw(text);
  appActions.showToast(ok ? copiedMsg : copyFailedMsg, ok ? "ok" : "warn");
}

export function buildFallbackYaml(cfg: AppConfig, ext: ExtendedSettings): string {
  const list = (raw: string, pad: string) =>
    raw
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => `${pad}- "${s}"`)
      .join("\n");
  return `# CatCloud Compiled Mihomo Preview (Sanitized)
mixed-port: ${cfg.mixed_port}
allow-lan: ${ext.allowLan}
mode: ${cfg.proxy_mode}
log-level: ${ext.logLevel}
ipv6: ${cfg.ipv6_core_enabled}
unified-delay: ${cfg.unified_delay}
external-controller: 127.0.0.1:${cfg.controller_port}
tun:
  enable: ${cfg.tun_enabled}
  stack: ${cfg.tun_stack_mode}
dns:
  enable: ${ext.overrideDns}
  listen: ${ext.dnsListen}
  ipv6: ${cfg.ipv6_dns_enabled}
  use-hosts: ${ext.useHosts}
  use-system-hosts: ${ext.useSystemHosts}
  respect-rules: ${ext.respectRules}
  prefer-h3: ${ext.preferH3}
  enhanced-mode: ${ext.enhancedMode}
  fake-ip-range: ${ext.fakeIpRange}
  fake-ip-filter:
${list(ext.fakeIpFilter, "    ")}
  default-nameserver:
${list(ext.defaultNameserver, "    ")}
  nameserver:
${list(ext.nameserver, "    ")}
  fallback:
${list(ext.fallback, "    ")}
  proxy-server-nameserver:
${list(ext.proxyServerNameserver, "    ")}
  fallback-filter:
    geoip: ${ext.fallbackFilterGeoip}
    geoip-code: ${ext.fallbackFilterGeoipCode}
    ipcidr:
${list(ext.fallbackFilterIpcidr, "      ")}
    domain:
${list(ext.fallbackFilterDomain, "      ")}
# GOMEMLIMIT=${cfg.gomemlimit_mb === 0 ? "auto" : `${cfg.gomemlimit_mb}MiB`} | override=${ext.overrideScriptPath || "none"}`;
}
