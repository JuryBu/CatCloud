import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  CloudDownload,
  Code2,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  Eye,
  EyeOff,
  FolderOpen,
  Globe,
  Image,
  Keyboard,
  Palette,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  RotateCw,
  Save,
  Shield,
  SlidersHorizontal,
  Square,
  Terminal,
  Upload,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  type AppConfig,
  type FullAppConfig,
  type GeoDataFileStatus,
  type GeoDataStatusDto,
  type MemoryTier,
  type ResolvedTheme,
  type ThemeMode,
  type TrayIconMode,
  type TunStackMode,
  type WebUiEntry,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import {
  BUILTIN_WALLPAPER_PRESETS,
  appActions,
  getBeijingTimeLabel,
  useAppSelector,
} from "../store/appStore";

type SettingsTabId = "system" | "appearance" | "dns" | "core" | "updates";
type LogLevel = "silent" | "error" | "warning" | "info" | "debug";
type DnsEnhancedMode = "fake-ip" | "redir-host";
type GeoKey = "geoip" | "geosite" | "mmdb" | "asn";

interface ExtendedSettings {
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
  fallbackFilterGeosite: string;
  fallbackFilterIpcidr: string;
  fallbackFilterDomain: string;
  appendRules: string;
  overrideScriptPath: string;
  startupScriptPath: string;
  startupPage: string;
  trayClickAction: string;
  closeToWindowless: boolean;
  hotkeys: Record<string, string>;
}

const DEFAULT_WEBUI_ENTRIES: WebUiEntry[] = [
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

const DEFAULT_EXTENDED: ExtendedSettings = {
  bypassDomains: "localhost, 127.*, 10.*, 172.16.*, 192.168.*, *.local, <local>",
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
  defaultNameserver: "223.5.5.5, 119.29.29.29",
  nameserverPolicy: "geosite:cn,private: https://223.5.5.5/dns-query",
  nameserver: "https://223.5.5.5/dns-query, https://doh.pub/dns-query",
  fallback: "https://1.1.1.1/dns-query, https://dns.google/dns-query",
  proxyServerNameserver: "https://223.5.5.5/dns-query",
  fallbackFilterGeoip: true,
  fallbackFilterGeoipCode: "CN",
  fallbackFilterGeosite: "gfw",
  fallbackFilterIpcidr: "240.0.0.0/4, 0.0.0.0/32, 198.51.100.0/24",
  fallbackFilterDomain: "+.google.com, +.github.com, +.youtube.com",
  appendRules: "",
  overrideScriptPath: "",
  startupScriptPath: "",
  startupPage: "overview",
  trayClickAction: "toggle_main_window",
  closeToWindowless: true,
  hotkeys: {
    toggleProxy: "Alt+Shift+P",
    switchNextBest: "Alt+Shift+N",
    toggleMainWindow: "Alt+Shift+M",
    toggleCapsule: "Alt+Shift+C",
    toggleTun: "Alt+Shift+T",
  },
};

const RESOLVED_THEME_LABELS: Record<ResolvedTheme, string> = {
  light: "浅色暖纸",
  "warm-dark": "深苔暖金",
  "midnight-blue": "午夜星蓝",
};

const THEME_CARDS: ReadonlyArray<{
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

const HOTKEY_LABELS: Record<string, string> = {
  toggleProxy: "切换系统代理",
  switchNextBest: "秒切下一优节点",
  toggleMainWindow: "显示 / 隐藏主窗口",
  toggleCapsule: "切换悬浮小窗",
  toggleTun: "切换虚拟网卡",
};

const STARTUP_PAGE_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "overview", label: "总览" },
  { value: "groups", label: "智能多选组" },
  { value: "speedtest", label: "节点测速" },
  { value: "preaccel", label: "国内提速" },
  { value: "nodes", label: "节点与订阅" },
  { value: "rules", label: "分流与连接" },
  { value: "logs", label: "运行日志" },
  { value: "settings", label: "设置" },
];

const TRAY_CLICK_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "toggle_main_window", label: "显示 / 隐藏主窗口" },
  { value: "open_main_window", label: "始终展开主窗口" },
  { value: "toggle_capsule", label: "切换悬浮小窗" },
  { value: "toggle_system_proxy", label: "切换系统代理" },
  { value: "switch_next_best", label: "秒切下一优节点" },
  { value: "none", label: "无动作" },
];

const LOG_LEVEL_OPTIONS: ReadonlyArray<{ value: LogLevel; label: string }> = [
  { value: "silent", label: "静默" },
  { value: "error", label: "仅错误" },
  { value: "warning", label: "警告" },
  { value: "info", label: "常规（推荐）" },
  { value: "debug", label: "调试" },
];

const DIR_ITEMS: ReadonlyArray<readonly ["config" | "data" | "logs" | "core", string]> = [
  ["config", "配置目录"],
  ["data", "数据目录"],
  ["logs", "日志目录"],
  ["core", "内核目录"],
];

const GEO_ITEMS: ReadonlyArray<
  readonly [GeoKey, keyof GeoDataStatusDto, string, string]
> = [
  ["mmdb", "country_mmdb", "Country.mmdb", "国家地区库"],
  ["geoip", "geoip_dat", "geoip.dat", "IP 归属地库"],
  ["geosite", "geosite_dat", "geosite.dat", "网站域名分流库"],
  ["asn", "asn_mmdb", "asn.mmdb", "网络运营商库"],
];

function formatGeoFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${Math.round(bytes)} B`;
}

function formatGeoUpdatedAt(iso: string | null): string {
  if (!iso) return "时间未知";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function renderGeoStatusSummary(
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

const AGENT_DOCS = [
  {
    id: "system",
    title: "1. 常规与代理",
    goal: "管理系统代理、防篡改守护、PAC 分流、虚拟网卡与本地监听端口。",
    keys: "mixed_port, controller_port, controller_secret, dns_listen_port, system_proxy_enabled, proxy_guard_*, tun_stack_mode",
    workflow: "确认端口空闲后开启系统代理；仅需接管非代理软件时再提权开启虚拟网卡。",
    guardrails: "Windows 启用虚拟网卡需管理员权限；改动端口后记得刷新终端代理变量。",
  },
  {
    id: "dns",
    title: "2. 网络与 DNS",
    goal: "独立控制核心与 DNS 的 IPv6 行为，精细配置 Fake-IP 与防污染上游。",
    keys: "ipv6_core_enabled, ipv6_dns_enabled, enhanced-mode, fake-ip-filter, nameserver-policy, fallback-filter",
    workflow: "开启 DNS 覆写与分流协同；内网与校时域名写入排除列表，国内走策略直连。",
    guardrails: "遇到 IPv6 卡顿时先关闭 DNS 返回 IPv6，再单独排查核心 IPv6 转发。",
  },
  {
    id: "core",
    title: "3. 内核与工具",
    goal: "维护附加规则、覆写/启动脚本、地理数据库更新及内核内存上限与热换。",
    keys: "gomemlimit_mb (auto/48/64/96), append_rules, override_script_path, startup_script_path, compile_preview_yaml",
    workflow: "改动规则或 DNS 后先预览最终编译配置，再重载内核或导出本地备份。",
    guardrails: "日常轻载推荐自动或 48 MB 挡位；大规则集或高速下载可调至 64/96 MB。",
  },
  {
    id: "groups",
    title: "4. 多选组与测速",
    goal: "配置粘性最优、条件池与负载均衡策略，配合隔离测速稳态选路。",
    keys: "mode, hard_gates, trigger_rules, formula_expr, fallback_policy, cooldown_sec, hysteresis_pct",
    workflow: "先执行隔离测速获取节点指标，再调整评分权重、冷却时间与切换门槛。",
    guardrails: "保持冷却秒数与切换门槛，避免短时网络波动触发频繁来回切换。",
  },
  {
    id: "preaccel",
    title: "5. 国内提速",
    goal: "为非原生 443 节点提供国内中转加速，自动豁免原生 443 并防门户误判。",
    keys: "preaccel.enabled, skip_443_native, probe_url, fallback_probe_url",
    workflow: "先测通中转节点再按优先级启用，故障时自动切换备线或回落直连。",
    guardrails: "导出备份与诊断快照会自动脱敏，不会泄露真实中转地址与密钥。",
  },
  {
    id: "ui-cli",
    title: "6. 外观与 CLI",
    goal: "支持昼夜自动主题、本地壁纸与毛玻璃、无窗省内存及无头命令行。",
    keys: "personalization.*, startup_page, tray_click_action, update.repo (JuryBu/CatCloud), catcloud CLI",
    workflow: "日常建议开启关闭进无窗；自动化脚本与 AI 协作统一使用 catcloud --json。",
    guardrails: "恢复纯色背景时自动关闭毛玻璃滤镜，保持零额外显存占用。",
  },
] as const;

const CLI_SNIPPETS = [
  { cmd: "catcloud status --json", desc: "查看核心运行状态、当前节点与端口" },
  { cmd: "catcloud config reload --json", desc: "校验并热重载当前配置" },
  { cmd: "catcloud group list --json", desc: "列出所有智能多选组及活跃节点" },
  { cmd: "catcloud group switch <group_id> --json", desc: "一键切换分组至下一优节点" },
  { cmd: "catcloud preaccel pool --json", desc: "查看国内提速中转池状态" },
  { cmd: "catcloud probe list --json", desc: "查看已注册的测速探针列表" },
  { cmd: "catcloud config diag --json", desc: "导出完整脱敏诊断信息" },
  { cmd: "catcloud docs export all --json", desc: "导出全套 6 模块 AI 协作文档" },
] as const;

const INPUT_CLS =
  "w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]";
const BTN_CLS =
  "inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50";

function splitCsvOrLines(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function extractWallpaperLabel(rawPath: string): string {
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

function parseNameserverPolicy(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx <= 0) continue;
    const sepMatch = /^(.+?):\s+(https?:\/\/.+|tls:\/\/.+|quic:\/\/.+|\d+\.\d+\.\d+\.\d+.*)$/i.exec(
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

function formatNameserverPolicy(policy?: Record<string, string[]>): string {
  if (!policy) return "";
  return Object.entries(policy)
    .map(([k, list]) => `${k}: ${Array.isArray(list) ? list.join(", ") : String(list)}`)
    .join("\n");
}

function hydrateExtendedFromFullConfig(full: FullAppConfig): ExtendedSettings {
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
    dnsListen: `${dnsHost}:${dnsPort}`,
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
    fallbackFilterGeosite: Array.isArray(dns?.fallback_filter?.geosite)
      ? dns.fallback_filter.geosite.join(", ")
      : DEFAULT_EXTENDED.fallbackFilterGeosite,
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
    startupPage:
      !beh?.startup_page || beh.startup_page === "home" ? "overview" : beh.startup_page,
    trayClickAction: beh?.tray_click_action ?? "toggle_main_window",
    closeToWindowless: beh?.minimize_to_tray_on_close ?? true,
    hotkeys: {
      toggleProxy: hk?.toggle_system_proxy ?? "",
      switchNextBest: hk?.switch_next_best ?? "Alt+Shift+N",
      toggleMainWindow: hk?.show_main_window ?? "",
      toggleCapsule: hk?.toggle_capsule ?? "Alt+Shift+C",
      toggleTun: hk?.toggle_tun ?? "",
    },
  };
}

function buildExtendedPatch(ext: ExtendedSettings): Record<string, unknown> {
  const [listenHost, listenPortRaw] = ext.dnsListen.split(":");
  const listenPort = Number(listenPortRaw);
  return {
    allow_lan: ext.allowLan,
    log_level: ext.logLevel,
    controller_secret: ext.controllerSecret.trim() ? ext.controllerSecret.trim() : null,
    webui_urls: ext.webuiUrls,
    dns_listen_host: listenHost?.trim() || "127.0.0.1",
    ...(Number.isFinite(listenPort) && listenPort > 0 ? { dns_listen_port: listenPort } : {}),
    system_proxy: {
      bypass: splitCsvOrLines(ext.bypassDomains),
      pac: {
        enabled: false,
      },
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
        geosite: splitCsvOrLines(ext.fallbackFilterGeosite),
        ipcidr: splitCsvOrLines(ext.fallbackFilterIpcidr),
        domain: splitCsvOrLines(ext.fallbackFilterDomain),
      },
    },
    rules_override: {
      global_append_rules: splitLines(ext.appendRules),
      override_script_path: ext.overrideScriptPath.trim() ? ext.overrideScriptPath.trim() : null,
      domestic_direct_enabled: ext.domesticDirectEnabled,
      block_quic_udp_443: ext.blockQuicUdp443,
    },
    core_runtime: {
      startup_script_path: ext.startupScriptPath.trim() ? ext.startupScriptPath.trim() : null,
    },
    behavior: {
      minimize_to_tray_on_close: ext.closeToWindowless,
      startup_page: ext.startupPage,
      tray_click_action: ext.trayClickAction,
      hotkeys: {
        enabled: true,
        toggle_system_proxy: ext.hotkeys.toggleProxy?.trim() || null,
        switch_next_best: ext.hotkeys.switchNextBest?.trim() || null,
        show_main_window: ext.hotkeys.toggleMainWindow?.trim() || null,
        toggle_capsule: ext.hotkeys.toggleCapsule?.trim() || null,
        toggle_tun: ext.hotkeys.toggleTun?.trim() || null,
      },
    },
  };
}

function tierFromMb(mb: 0 | 48 | 64 | 96): MemoryTier {
  if (mb === 48) return "mb48";
  if (mb === 64) return "mb64";
  if (mb === 96) return "mb96";
  return "auto";
}

function fullMemoryTierFromMb(mb: 0 | 48 | 64 | 96): string {
  if (mb === 48) return "48MiB";
  if (mb === 64) return "64MiB";
  if (mb === 96) return "96MiB";
  return "auto";
}

function buildMergedSettingsPatch(
  draft: AppConfig,
  ext: ExtendedSettings
): Record<string, unknown> {
  const baseExt = buildExtendedPatch(ext);
  const extSystemProxy = (baseExt.system_proxy as Record<string, unknown>) ?? {};
  const extDns = (baseExt.dns as Record<string, unknown>) ?? {};
  const extCoreRuntime = (baseExt.core_runtime as Record<string, unknown>) ?? {};
  const extBehavior = (baseExt.behavior as Record<string, unknown>) ?? {};

  return {
    ...baseExt,
    mixed_port: draft.mixed_port,
    controller_port: draft.controller_port,
    dns_listen_port: draft.dns_listen_port,
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
      repo: draft.update.repo,
      mode: draft.update.mode,
      check_interval_min: draft.update.check_interval_min,
      include_prerelease: draft.update.include_prerelease,
    },
  };
}

async function copyText(text: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    appActions.showToast(`已复制${label}`, "ok");
  } catch {
    appActions.showToast(`剪贴板不可用，请手动复制${label}`, "warn");
  }
}

function buildFallbackYaml(cfg: AppConfig, ext: ExtendedSettings): string {
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
    geosite:
${list(ext.fallbackFilterGeosite, "      ")}
    ipcidr:
${list(ext.fallbackFilterIpcidr, "      ")}
    domain:
${list(ext.fallbackFilterDomain, "      ")}
# GOMEMLIMIT=${cfg.gomemlimit_mb === 0 ? "auto" : `${cfg.gomemlimit_mb}MiB`} | override=${ext.overrideScriptPath || "none"}`;
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors"
      style={{
        backgroundColor: checked ? "var(--accent)" : "var(--bg-elevated)",
        borderColor: checked ? "var(--accent)" : "var(--line-strong)",
      }}
    >
      <span
        className="inline-block h-3.5 w-3.5 rounded-full transition-transform"
        style={{
          backgroundColor: checked ? "var(--accent-ink)" : "var(--muted)",
          transform: checked ? "translateX(17px)" : "translateX(2px)",
        }}
      />
    </button>
  );
}

function Card({
  title,
  sub,
  action,
  children,
}: {
  title: string;
  sub?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="cc-card cc-glass space-y-3 rounded-2xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text)]">{title}</h3>
          {sub && <p className="text-[11px] text-[var(--muted)]">{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function SwitchRow({
  title,
  desc,
  checked,
  onChange,
  badge,
}: {
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  badge?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-xs font-medium text-[var(--text)]">
          <span>{title}</span>
          {badge}
        </div>
        <p className="mt-0.5 text-[11px] text-[var(--muted)]">{desc}</p>
      </div>
      <Toggle checked={checked} onChange={onChange} label={title} />
    </div>
  );
}

function SegButtons<T extends string | number>({
  options,
  value,
  onChange,
  mono = false,
}: {
  options: ReadonlyArray<readonly [T, string]>;
  value: T;
  onChange: (v: T) => void;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([opt, text]) => {
        const on = value === opt;
        return (
          <button
            key={String(opt)}
            type="button"
            onClick={() => onChange(opt)}
            className={`rounded-lg px-2.5 py-1 text-xs transition-colors ${mono ? "cc-mono" : ""}`}
            style={{
              backgroundColor: on ? "var(--accent-soft)" : "var(--bg-elevated)",
              color: on ? "var(--accent)" : "var(--muted)",
              border: `1px solid ${on ? "var(--accent)" : "var(--line)"}`,
            }}
          >
            {text}
          </button>
        );
      })}
    </div>
  );
}

export function SettingsPage() {
  const storeConfig = useAppSelector((s) => s.config);
  const runtime = useAppSelector((s) => s.runtime);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const wallpaperPreviewUrl = useAppSelector((s) => s.wallpaperPreviewUrl);
  const wallpaperError = useAppSelector((s) => s.wallpaperError);
  const settingsTabHint = useAppSelector((s) => s.settingsTabHint);
  const inTauri = isTauriEnv();

  const [tab, setTab] = useState<SettingsTabId>(() => settingsTabHint ?? "system");

  useEffect(() => {
    if (settingsTabHint) {
      setTab(settingsTabHint);
      appActions.consumeSettingsTabHint();
    }
  }, [settingsTabHint]);
  const [draft, setDraft] = useState<AppConfig>(() => structuredClone(storeConfig));
  const [ext, setExt] = useState<ExtendedSettings>(DEFAULT_EXTENDED);
  const [showSecret, setShowSecret] = useState(false);
  const [selectedWebUiIdx, setSelectedWebUiIdx] = useState(0);
  const [newWebUiName, setNewWebUiName] = useState("");
  const [newWebUiTpl, setNewWebUiTpl] = useState("");
  const [coreBinaryPath, setCoreBinaryPath] = useState("");
  const [coreOpBusy, setCoreOpBusy] = useState<string | null>(null);
  const [draftDirty, setDraftDirty] = useState(false);
  const [extDirty, setExtDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [pickingWallpaper, setPickingWallpaper] = useState(false);
  const [showUrlInput, setShowUrlInput] = useState(false);
  const [wallpaperUrlInput, setWallpaperUrlInput] = useState("");
  const [imgLoadFailed, setImgLoadFailed] = useState(false);
  const [showAdvancedDns, setShowAdvancedDns] = useState(false);
  const [showDevTools, setShowDevTools] = useState(false);
  const [yamlPreview, setYamlPreview] = useState<string | null>(null);
  const [yamlSha, setYamlSha] = useState<string | null>(null);
  const [yamlLoading, setYamlLoading] = useState(false);
  const [geoBusy, setGeoBusy] = useState<GeoKey | "all" | null>(null);
  const [geoStatus, setGeoStatus] = useState<GeoDataStatusDto | null>(null);
  const [geoStatusLoading, setGeoStatusLoading] = useState(true);
  const [confirmImportBackupOpen, setConfirmImportBackupOpen] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const [activeDocId, setActiveDocId] = useState<string>(AGENT_DOCS[0].id);

  const dirty = draftDirty || extDirty;
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const sliderCommitTimerRef = useRef<number | null>(null);
  const pendingSliderPatchRef = useRef<Partial<AppConfig["personalization"]>>({});

  useEffect(() => {
    return () => {
      if (sliderCommitTimerRef.current !== null) {
        window.clearTimeout(sliderCommitTimerRef.current);
        sliderCommitTimerRef.current = null;
      }
      const pending = pendingSliderPatchRef.current;
      if (Object.keys(pending).length > 0) {
        pendingSliderPatchRef.current = {};
        void appActions.updatePersonalization(pending);
      }
    };
  }, []);

  // Preserve unsaved network/core edits when theme, wallpaper, or live toggles update storeConfig
  useEffect(() => {
    if (dirtyRef.current) {
      setDraft((prev) => ({
        ...prev,
        personalization: structuredClone(storeConfig.personalization),
        system_proxy_enabled: storeConfig.system_proxy_enabled,
        tun_enabled: storeConfig.tun_enabled,
        proxy_mode: storeConfig.proxy_mode,
      }));
      return;
    }
    setDraft(structuredClone(storeConfig));
  }, [storeConfig]);

  useEffect(() => {
    const raw = storeConfig.personalization.wallpaper_path?.trim() ?? "";
    setImgLoadFailed(false);
    if (/^https?:\/\//i.test(raw)) {
      setWallpaperUrlInput(raw);
    } else if (!raw) {
      setWallpaperUrlInput("");
    }
  }, [storeConfig.personalization.wallpaper_path]);

  useEffect(() => {
    let active = true;
    void catcloudApi
      .getFullConfig()
      .then((full) => {
        if (!active) return;
        setExt(hydrateExtendedFromFullConfig(full));
        if (full.core_runtime?.custom_binary_path) {
          setCoreBinaryPath(full.core_runtime.custom_binary_path);
        }
      })
      .catch(() => {
        /* keep default extended fields if backend config read fails */
      });

    setGeoStatusLoading(true);
    void catcloudApi
      .getGeodataStatus()
      .then((status) => {
        if (active) setGeoStatus(status);
      })
      .catch(() => {
        /* ignore geodata status query errors */
      })
      .finally(() => {
        if (active) setGeoStatusLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!confirmImportBackupOpen) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setConfirmImportBackupOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [confirmImportBackupOpen]);

  const patchDraft = (patch: Partial<AppConfig>) => {
    setDraft((prev) => ({ ...prev, ...patch }));
    setDraftDirty(true);
  };

  const patchExt = <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => {
    setExt((prev) => ({ ...prev, [k]: v }));
    setExtDirty(true);
  };

  const handleDnsPortChange = (nextPort: number) => {
    patchDraft({ dns_listen_port: nextPort });
    setExt((prev) => {
      const host = prev.dnsListen.split(":")[0]?.trim() || "127.0.0.1";
      return { ...prev, dnsListen: `${host}:${nextPort}` };
    });
  };

  const handleDnsListenChange = (nextAddr: string) => {
    patchExt("dnsListen", nextAddr);
    const portPart = Number(nextAddr.split(":")[1]);
    if (Number.isFinite(portPart) && portPart > 0 && portPart <= 65535) {
      setDraft((prev) => ({ ...prev, dns_listen_port: portPart }));
    }
  };

  const commitSliderPersonalization = () => {
    if (sliderCommitTimerRef.current !== null) {
      window.clearTimeout(sliderCommitTimerRef.current);
      sliderCommitTimerRef.current = null;
    }
    const pending = pendingSliderPatchRef.current;
    if (Object.keys(pending).length === 0) return;
    pendingSliderPatchRef.current = {};
    void appActions.updatePersonalization(pending);
  };

  const handleSliderPreview = (patch: Partial<AppConfig["personalization"]>) => {
    pendingSliderPatchRef.current = {
      ...pendingSliderPatchRef.current,
      ...patch,
    };
    appActions.previewPersonalization(patch);
    if (sliderCommitTimerRef.current !== null) {
      window.clearTimeout(sliderCommitTimerRef.current);
    }
    sliderCommitTimerRef.current = window.setTimeout(() => {
      commitSliderPersonalization();
    }, 250);
  };

  const handleSave = async () => {
    if (!draftDirty && !extDirty) {
      appActions.showToast("当前没有待保存的更改", "info");
      return;
    }
    setSaving(true);
    try {
      const payload: AppConfig = {
        ...draft,
        memory_tier: tierFromMb(draft.gomemlimit_mb),
        personalization: storeConfig.personalization,
      };
      let savedBasic: AppConfig;
      if (draftDirty && !extDirty) {
        savedBasic = await catcloudApi.saveConfig(payload);
      } else if (!draftDirty && extDirty) {
        await catcloudApi.saveExtendedSettings(buildExtendedPatch(ext));
        savedBasic = inTauri ? await catcloudApi.getConfig() : payload;
      } else if (inTauri) {
        // Single merged submission avoids back-to-back saveConfig + saveExtendedSettings double core reloads
        await catcloudApi.saveExtendedSettings(buildMergedSettingsPatch(payload, ext));
        savedBasic = await catcloudApi.getConfig();
      } else {
        savedBasic = await catcloudApi.saveConfig(payload);
        await catcloudApi.saveExtendedSettings(buildExtendedPatch(ext));
      }
      dirtyRef.current = false;
      setDraftDirty(false);
      setExtDirty(false);
      appActions.syncConfig(savedBasic);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast("设置已保存并生效", "ok");
    } catch (err) {
      appActions.showToast(`保存设置失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSaving(false);
    }
  };

  const handlePickWallpaper = async () => {
    if (pickingWallpaper) return;
    setPickingWallpaper(true);
    try {
      await appActions.pickWallpaperImage();
    } finally {
      setPickingWallpaper(false);
    }
  };

  const handleApplyWallpaperUrl = async () => {
    const trimmed = wallpaperUrlInput.trim();
    if (!trimmed) {
      await appActions.setWallpaperPath(null, "已恢复纯色背景");
      return;
    }
    if (!/^(https?:\/\/|data:image\/(?:png|jpe?g|webp|gif|bmp);base64,)/i.test(trimmed)) {
      appActions.showToast("请输入以 http:// 或 https:// 开头的图片链接", "warn");
      return;
    }
    setImgLoadFailed(false);
    await appActions.setWallpaperPath(trimmed, "已更换为网络图片壁纸");
  };

  const handleCoreAction = async (action: "start" | "stop" | "restart" | "reload") => {
    if (coreOpBusy) return;
    setCoreOpBusy(action);
    try {
      if (action === "reload") {
        const outcome = await catcloudApi.reloadCoreConfig(false);
        const rt = await catcloudApi.getRuntimeInfo();
        appActions.syncRuntime(rt);
        if (outcome.rejected || outcome.error) {
          appActions.showToast(`热重载未生效：${outcome.error ?? "配置校验未通过"}`, "warn");
        } else {
          appActions.showToast("配置已热重载", "ok");
        }
      } else {
        const rt =
          action === "start"
            ? await catcloudApi.startCore()
            : action === "stop"
              ? await catcloudApi.stopCore()
              : await catcloudApi.restartCore();
        appActions.syncRuntime(rt);
        const labels = { start: "内核已启动", stop: "内核已停止", restart: "内核已重启" };
        appActions.showToast(labels[action], "ok");
      }
    } catch (err) {
      appActions.showToast(`内核操作失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCoreOpBusy(null);
    }
  };

  const handleHotSwapCore = async () => {
    const path = coreBinaryPath.trim();
    if (!path) {
      appActions.showToast("请先输入内核程序的完整路径", "warn");
      return;
    }
    setCoreOpBusy("hotswap");
    try {
      const res = await catcloudApi.hotSwapCore(path);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast(
        res.ok
          ? `内核热换成功：${res.version ?? res.binary_path}`
          : `内核热换失败：${res.message}`,
        res.ok ? "ok" : "warn"
      );
    } catch (err) {
      appActions.showToast(`内核热换失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCoreOpBusy(null);
    }
  };

  const handleCompileYaml = async () => {
    setYamlLoading(true);
    try {
      if (inTauri) {
        const res = await catcloudApi.compilePreviewYaml();
        const text = typeof res === "string" ? res : (res?.yaml ?? "");
        const sha =
          typeof res === "object" && res !== null && "sha256" in res ? res.sha256 : null;
        setYamlPreview(text);
        setYamlSha(sha);
        appActions.showToast("已生成最新配置预览", "ok");
      } else {
        setYamlPreview(buildFallbackYaml(draft, ext));
        setYamlSha("browser-preview");
        appActions.showToast("已生成预览配置", "info");
      }
    } catch (err) {
      appActions.showToast(`生成配置预览失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setYamlLoading(false);
    }
  };

  const handleRefreshGeo = async (target: GeoKey | "all") => {
    setGeoBusy(target);
    try {
      const res = await catcloudApi.refreshGeoDb(target === "all" ? null : [target]);
      try {
        const latest = await catcloudApi.getGeodataStatus();
        setGeoStatus(latest);
      } catch {
        /* ignore secondary status refresh error */
      }
      appActions.showToast(res.message || "地理数据库已更新", res.ok ? "ok" : "warn");
    } catch (err) {
      appActions.showToast(`更新地理数据库失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setGeoBusy(null);
    }
  };

  const handleCheckUpdate = async () => {
    setCheckingUpdate(true);
    try {
      const res = await catcloudApi.checkAppUpdate();
      if (res.error) {
        setUpdateMsg(`检查失败：${res.error}`);
        appActions.showToast(`检查更新失败：${res.error}`, "warn");
      } else if (res.has_update) {
        setUpdateMsg(`发现新版本 v${res.latest_version}（当前 v${res.current_version}）`);
        appActions.showToast(`发现新版本 v${res.latest_version}`, "ok");
      } else {
        setUpdateMsg(`当前 v${res.current_version} 已是最新版本`);
        appActions.showToast("当前已是最新版本", "info");
      }
    } catch (err) {
      const msg = formatErrorMessage(err);
      setUpdateMsg(`检查更新异常：${msg}`);
      appActions.showToast(`检查更新失败：${msg}`, "warn");
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleExportBackup = async () => {
    if (inTauri) {
      try {
        const saved = await catcloudApi.exportBackupBundle(null);
        appActions.showToast(`已导出脱敏备份：${saved.path} (${saved.bytes} B)`, "ok");
      } catch (err) {
        appActions.showToast(`导出备份失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }

    const json = JSON.stringify(
      {
        exported_at: new Date().toISOString(),
        app_version: runtime.app_version,
        config: draft,
        extended: ext,
      },
      null,
      2
    );
    const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), {
      href: url,
      download: "catcloud-settings-backup.json",
    });
    a.click();
    URL.revokeObjectURL(url);
    appActions.showToast("已下载配置备份文件", "ok");
  };

  const openImportBackupPicker = () => {
    const input = Object.assign(document.createElement("input"), {
      type: "file",
      accept: "application/json,.json",
    });
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      void file.text().then(async (raw) => {
        if (inTauri) {
          try {
            const res = await catcloudApi.importBackupBundle(raw);
            dirtyRef.current = false;
            setDraftDirty(false);
            setExtDirty(false);
            await appActions.refreshAllData();
            const full = await catcloudApi.getFullConfig();
            setExt(hydrateExtendedFromFullConfig(full));
            appActions.showToast(
              res.message || `已恢复备份（分组 ${res.restored_groups} / 中转 ${res.restored_relays}）`,
              "ok"
            );
          } catch (err) {
            appActions.showToast(`导入备份失败：${formatErrorMessage(err)}`, "warn");
          }
          return;
        }
        try {
          const parsed = JSON.parse(raw) as {
            config?: AppConfig;
            extended?: Partial<ExtendedSettings>;
          };
          if (parsed.config) {
            setDraft(parsed.config);
            setDraftDirty(true);
          }
          if (parsed.extended) {
            setExt((prev) => ({ ...prev, ...parsed.extended }));
            setExtDirty(true);
          }
          appActions.showToast("已导入备份配置，点击右上角保存后生效", "ok");
        } catch {
          appActions.showToast("备份文件格式无效", "warn");
        }
      });
    };
    input.click();
  };

  const handleOpenDir = async (dir: "config" | "data" | "logs" | "core") => {
    const names = { config: "配置", data: "数据", logs: "日志", core: "内核" };
    try {
      const opened = await catcloudApi.openAppDir(dir);
      appActions.showToast(`已打开${names[dir]}目录：${opened}`, "info");
    } catch (err) {
      appActions.showToast(`打开${names[dir]}目录失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleOpenWebUi = async () => {
    const entry = ext.webuiUrls[selectedWebUiIdx] ?? ext.webuiUrls[0];
    const rawTemplate = entry?.url_template?.trim() || null;
    try {
      await catcloudApi.openWebUi(rawTemplate);
      appActions.showToast("已在浏览器打开面板", "info");
    } catch (err) {
      appActions.showToast(`打开外部面板失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleAddWebUiBookmark = () => {
    const name = newWebUiName.trim();
    const tpl = newWebUiTpl.trim();
    if (!name || !tpl) {
      appActions.showToast("请填写面板名称和链接模板", "warn");
      return;
    }
    const nextList = [...ext.webuiUrls, { name, url_template: tpl }];
    patchExt("webuiUrls", nextList);
    setSelectedWebUiIdx(nextList.length - 1);
    setNewWebUiName("");
    setNewWebUiTpl("");
    appActions.showToast(`已添加面板「${name}」，记得点击顶部保存`, "ok");
  };

  const handleLaunchUwp = async () => {
    try {
      const res = await catcloudApi.launchUwpLoopback();
      appActions.showToast(
        res.message || "已检查本机应用网络放行状态",
        res.launched ? "ok" : "info"
      );
    } catch (err) {
      appActions.showToast(`查看本机应用网络放行状态失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleCopyShellEnv = async (sh: "powershell" | "cmd" | "bash") => {
    const fallback = {
      powershell: `$env:HTTP_PROXY="http://127.0.0.1:${draft.mixed_port}"; $env:HTTPS_PROXY="http://127.0.0.1:${draft.mixed_port}"; $env:ALL_PROXY="socks5://127.0.0.1:${draft.mixed_port}"`,
      cmd: `set HTTP_PROXY=http://127.0.0.1:${draft.mixed_port} && set HTTPS_PROXY=http://127.0.0.1:${draft.mixed_port}`,
      bash: `export http_proxy="http://127.0.0.1:${draft.mixed_port}" https_proxy="http://127.0.0.1:${draft.mixed_port}" all_proxy="socks5://127.0.0.1:${draft.mixed_port}"`,
    }[sh];
    let text = fallback;
    if (inTauri) {
      try {
        const res = await catcloudApi.exportShellEnv(sh);
        if (res && res.trim()) text = res;
      } catch {
        /* fallback */
      }
    }
    await copyText(text, `${sh.toUpperCase()} 代理命令`);
  };

  const handleCopyDiagnostics = async () => {
    let text = [
      `CatCloud Diagnostic Snapshot (Sanitized)`,
      `App: v${runtime.app_version} (${runtime.os_label}) | Core: ${runtime.core_name} ${runtime.core_version}`,
      `Ports: mixed=${draft.mixed_port}, controller=127.0.0.1:${draft.controller_port}, dns=${draft.dns_listen_port}`,
      `Mode: ${draft.proxy_mode} | SystemProxy=${draft.system_proxy_enabled} (guard=${draft.proxy_guard_enabled}/${draft.proxy_guard_interval_sec}s)`,
      `TUN: ${draft.tun_enabled} (${draft.tun_stack_mode}, admin=${runtime.tun_admin_ready}) | UnifiedDelay=${draft.unified_delay}`,
      `IPv6: core=${draft.ipv6_core_enabled}, dns=${draft.ipv6_dns_enabled} | GOMEMLIMIT=${draft.gomemlimit_mb === 0 ? "auto" : `${draft.gomemlimit_mb}MiB`}`,
    ].join("\n");
    if (inTauri) {
      try {
        const diag = await catcloudApi.exportSanitizedDiagnostics();
        text = JSON.stringify(diag, null, 2);
      } catch (err) {
        appActions.showToast(`采集诊断报告失败：${formatErrorMessage(err)}`, "warn");
        return;
      }
    }
    await copyText(text, "脱敏诊断报告");
  };

  const handleCopyAgentDoc = async (moduleId: string, label: string, fallbackMd: string) => {
    let text = fallbackMd;
    if (inTauri) {
      try {
        const res = await catcloudApi.exportAgentDocs(moduleId, false);
        if (res && res.trim()) text = res;
      } catch {
        /* fallback */
      }
    }
    await copyText(text, label);
  };

  const activeDoc = useMemo(
    () => AGENT_DOCS.find((d) => d.id === activeDocId) ?? AGENT_DOCS[0],
    [activeDocId]
  );
  const docMd = (d: (typeof AGENT_DOCS)[number]) =>
    `### ${d.title}\n- **目标能力**：${d.goal}\n- **关键配置项**：\`${d.keys}\`\n- **推荐操作路径**：${d.workflow}\n- **排障与边界**：${d.guardrails}`;

  const tabs: ReadonlyArray<{ id: SettingsTabId; label: string; icon: LucideIcon }> = [
    { id: "system", label: "常规与代理", icon: SlidersHorizontal },
    { id: "appearance", label: "外观与壁纸", icon: Palette },
    { id: "dns", label: "网络与 DNS", icon: Globe },
    { id: "core", label: "进阶与维护", icon: Cpu },
    { id: "updates", label: "关于与更新", icon: CloudDownload },
  ];

  const p = storeConfig.personalization;
  const rawWallpaper = p.wallpaper_path?.trim() ?? "";
  const hasWallpaper = rawWallpaper.length > 0;
  const activePreset =
    BUILTIN_WALLPAPER_PRESETS.find((preset) => preset.id === rawWallpaper) ?? null;
  const isDirectImageUrl =
    /^(https?:\/\/|data:image\/(?:png|jpe?g|webp|gif|bmp);base64,)/i.test(rawWallpaper);
  const wallpaperThumbSrc = !hasWallpaper || activePreset
    ? null
    : isDirectImageUrl
      ? rawWallpaper
      : wallpaperPreviewUrl;
  const effectiveWallpaperError =
    wallpaperError || (imgLoadFailed ? "背景图片加载失败，请检查链接或重新选择图片" : null);
  const currentThemeName = RESOLVED_THEME_LABELS[resolvedTheme];
  const beijingClock = getBeijingTimeLabel().replace(" BJT", "");

  return (
    <div className="space-y-4">
      {/* Top 5-Tab Bar + Save Button */}
      <div className="cc-card cc-glass flex flex-wrap items-center justify-between gap-2 rounded-2xl px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          {tabs.map(({ id, label, icon: Icon }) => {
            const on = tab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className="inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium transition-colors"
                style={{
                  backgroundColor: on ? "var(--accent-soft)" : "transparent",
                  color: on ? "var(--accent)" : "var(--muted)",
                  border: on ? "1px solid var(--accent)" : "1px solid transparent",
                }}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{label}</span>
              </button>
            );
          })}
        </div>
        <button
          type="button"
          onClick={() => void handleSave()}
          disabled={saving}
          className="inline-flex items-center gap-1.5 rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-60"
          style={{
            backgroundColor: dirty ? "var(--accent)" : "var(--surface)",
            color: dirty ? "var(--accent-ink)" : "var(--text)",
            border: "1px solid var(--line-strong)",
          }}
        >
          {dirty ? <Save className="h-3.5 w-3.5" /> : <Check className="h-3.5 w-3.5" />}
          <span>{saving ? "保存中..." : dirty ? "保存更改" : "已保存"}</span>
        </button>
      </div>

      {/* Tab 1: 常规与代理 */}
      {tab === "system" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="系统代理与分流接管" sub="控制电脑上网流量如何经过猫猫云梯">
              <SwitchRow
                title="启用系统代理"
                desc={`将系统流量转发至本地代理端口 :${draft.mixed_port}`}
                checked={runtime.system_proxy_enabled}
                onChange={(v) => void appActions.toggleSystemProxy(v)}
              />
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_126px]">
                <SwitchRow
                  title="系统代理守护"
                  desc="定期自动恢复被其他软件改掉的系统代理"
                  checked={draft.proxy_guard_enabled}
                  onChange={(v) => patchDraft({ proxy_guard_enabled: v })}
                />
                <label className="rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2 text-[11px] text-[var(--muted)]">
                  检查间隔（秒）
                  <input
                    type="number"
                    min={5}
                    max={300}
                    value={draft.proxy_guard_interval_sec}
                    onChange={(e) =>
                      patchDraft({
                        proxy_guard_interval_sec: Math.max(5, Number(e.target.value) || 30),
                      })
                    }
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
              <SwitchRow
                title="国内网站与局域网自动直连"
                desc="微信、QQ、国内网站、高校内网和局域网直连不绕代理"
                checked={ext.domesticDirectEnabled}
                onChange={(v) => patchExt("domesticDirectEnabled", v)}
              />
              <SwitchRow
                title="自动拦截 QUIC (UDP 443)"
                desc="防止 Chrome / Google / AI 走 UDP 443 经中转黑洞卡顿"
                checked={ext.blockQuicUdp443}
                onChange={(v) => patchExt("blockQuicUdp443", v)}
              />
              <div className="flex items-center justify-between gap-3 rounded-xl border border-dashed border-[var(--line)] bg-[var(--bg-elevated)]/55 px-3 py-2 opacity-75">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-xs font-medium text-[var(--muted)]">
                    <span>本地 PAC 分流</span>
                    <span className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                      规划中
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    本地 PAC 服务正在规划中，推荐使用规则模式或虚拟网卡
                  </p>
                </div>
              </div>
              <label className="block text-[11px] text-[var(--muted)]">
                不走代理的地址（逗号分隔）
                <textarea
                  rows={2}
                  value={ext.bypassDomains}
                  onChange={(e) => patchExt("bypassDomains", e.target.value)}
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
            </Card>

            <Card title="虚拟网卡接管与端口设置" sub="接管全电脑软件、自定义监听端口与口令">
              <SwitchRow
                title="虚拟网卡接管"
                desc={
                  runtime.tun_admin_ready
                    ? "已具备管理员权限，可接管游戏和终端等全部软件"
                    : "需要管理员权限，开启时将弹出系统授权提示"
                }
                checked={runtime.tun_enabled}
                onChange={(v) => void appActions.toggleTun(v)}
                badge={
                  <span
                    className="rounded-md px-1.5 py-0.5 text-[10px]"
                    style={{
                      backgroundColor: runtime.tun_admin_ready
                        ? "var(--green-soft)"
                        : "var(--amber-soft)",
                      color: runtime.tun_admin_ready ? "var(--green)" : "var(--amber)",
                    }}
                  >
                    {runtime.tun_admin_ready ? "权限就绪" : "需管理员"}
                  </span>
                }
              />
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
                <div className="text-xs font-medium text-[var(--text)]">虚拟网卡接管引擎</div>
                <SegButtons<TunStackMode>
                  value={draft.tun_stack_mode}
                  onChange={(v) => patchDraft({ tun_stack_mode: v })}
                  options={[
                    ["mixed", "默认引擎（推荐）"],
                    ["system", "系统内核引擎"],
                    ["gvisor", "独立兼容引擎"],
                  ]}
                />
              </div>
              <div className="grid grid-cols-3 gap-2">
                <label className="text-[11px] text-[var(--muted)]">
                  混合端口
                  <input
                    type="number"
                    value={draft.mixed_port}
                    onChange={(e) =>
                      patchDraft({ mixed_port: Number(e.target.value) || 17890 })
                    }
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="text-[11px] text-[var(--muted)]">
                  控制端口
                  <input
                    type="number"
                    value={draft.controller_port}
                    onChange={(e) =>
                      patchDraft({ controller_port: Number(e.target.value) || 19090 })
                    }
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="text-[11px] text-[var(--muted)]">
                  DNS 端口
                  <input
                    type="number"
                    value={draft.dns_listen_port}
                    onChange={(e) =>
                      handleDnsPortChange(Number(e.target.value) || 11053)
                    }
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
              <label className="block text-[11px] text-[var(--muted)]">
                外部控制口令（可选）
                <div className="mt-1 flex items-center gap-1.5">
                  <input
                    type={showSecret ? "text" : "password"}
                    value={ext.controllerSecret}
                    onChange={(e) => patchExt("controllerSecret", e.target.value)}
                    placeholder="留空由内核自动生成，仅外部面板需要固定密码时填写"
                    className={`${INPUT_CLS} cc-mono`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecret((v) => !v)}
                    className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                    title={showSecret ? "隐藏口令" : "显示口令"}
                    aria-label={showSecret ? "隐藏口令" : "显示口令"}
                  >
                    {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </label>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <SwitchRow
                  title="允许局域网连接"
                  desc="供局域网设备共用代理"
                  checked={ext.allowLan}
                  onChange={(v) => patchExt("allowLan", v)}
                />
                <SwitchRow
                  title="统一测速延迟"
                  desc="延迟测速更贴近真实"
                  checked={draft.unified_delay}
                  onChange={(v) => patchDraft({ unified_delay: v })}
                />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <label className="flex items-center gap-2 text-xs text-[var(--muted)]">
                  <span>日志详细度</span>
                  <select
                    value={ext.logLevel}
                    onChange={(e) => patchExt("logLevel", e.target.value as LogLevel)}
                    className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-xs text-[var(--text)]"
                  >
                    {LOG_LEVEL_OPTIONS.map((lv) => (
                      <option key={lv.value} value={lv.value}>
                        {lv.label}
                      </option>
                    ))}
                  </select>
                </label>
                <button type="button" onClick={() => void handleLaunchUwp()} className={BTN_CLS}>
                  <Shield className="h-3.5 w-3.5" />
                  <span>查看本机应用网络放行状态</span>
                </button>
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card
              title="启动与托盘行为"
              sub="管理开机启动、默认首页与关闭窗口时的驻留方式"
              action={
                <button
                  type="button"
                  onClick={() =>
                    void catcloudApi
                      .enterWindowlessMode()
                      .then(() => appActions.showToast("已切换为无窗省内存模式", "info"))
                      .catch((err) =>
                        appActions.showToast(`进入无窗模式失败：${formatErrorMessage(err)}`, "warn")
                      )
                  }
                  className="text-xs font-medium text-[var(--accent)] hover:underline"
                >
                  立即无窗驻留
                </button>
              }
            >
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <SwitchRow
                  title="开机自启"
                  desc="开机自动启动猫猫云梯"
                  checked={draft.autostart_enabled}
                  onChange={(v) => patchDraft({ autostart_enabled: v })}
                />
                <SwitchRow
                  title="静默启动"
                  desc="启动后静默藏于托盘"
                  checked={draft.silent_start}
                  onChange={(v) => patchDraft({ silent_start: v })}
                />
                <div className="sm:col-span-2">
                  <SwitchRow
                    title="关闭进无窗"
                    desc="关闭主窗口时不退出，仅留托盘图标以省内存"
                    checked={ext.closeToWindowless}
                    onChange={(v) => patchExt("closeToWindowless", v)}
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="text-[11px] text-[var(--muted)]">
                  启动默认页面
                  <select
                    value={ext.startupPage}
                    onChange={(e) => patchExt("startupPage", e.target.value)}
                    className={`${INPUT_CLS} mt-1`}
                  >
                    {STARTUP_PAGE_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-[11px] text-[var(--muted)]">
                  单击托盘图标
                  <select
                    value={ext.trayClickAction}
                    onChange={(e) => patchExt("trayClickAction", e.target.value)}
                    className={`${INPUT_CLS} mt-1`}
                  >
                    {TRAY_CLICK_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </Card>

            <Card title="全局快捷键" sub="随时一键切换代理、节点或窗口，留空表示禁用">
              <div className="space-y-2">
                {Object.entries(ext.hotkeys).map(([k, val]) => (
                  <label
                    key={k}
                    className="flex items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-1.5 text-xs text-[var(--text-secondary)]"
                  >
                    <span className="inline-flex min-w-0 flex-1 items-center gap-2 whitespace-nowrap">
                      <Keyboard className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                      <span className="font-medium text-[var(--text)]">{HOTKEY_LABELS[k] ?? k}</span>
                    </span>
                    <input
                      value={val}
                      placeholder="未绑定"
                      onChange={(e) =>
                        patchExt("hotkeys", { ...ext.hotkeys, [k]: e.target.value })
                      }
                      className="w-[152px] shrink-0 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-right text-[11px] cc-mono text-[var(--text)] outline-none focus:border-[var(--accent)]"
                    />
                  </label>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* Tab 2: 外观与壁纸 */}
      {tab === "appearance" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Theme Palette 4 Visual Cards */}
            <Card
              title="主题配色"
              sub={`当前生效：${currentThemeName} · 点选即刻换肤`}
            >
              <div className="grid grid-cols-2 gap-2.5">
                {THEME_CARDS.map((item) => {
                  const selected = p.theme_mode === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => void appActions.setThemeMode(item.id)}
                      aria-pressed={selected}
                      className="group relative flex flex-col overflow-hidden rounded-2xl border p-2.5 text-left transition-all"
                      style={{
                        borderColor: selected ? "var(--accent)" : "var(--line)",
                        backgroundColor: selected ? "var(--accent-soft)" : "var(--surface)",
                        boxShadow: selected ? "0 0 0 1px var(--accent)" : "none",
                      }}
                    >
                      {/* Visual mini-window swatch */}
                      <div
                        className="relative mb-2 h-14 w-full overflow-hidden rounded-xl border border-black/15"
                        style={{ background: item.bg }}
                      >
                        {item.isAuto ? (
                          <div className="flex h-full w-full items-end justify-between p-2">
                            <span className="rounded-md bg-black/35 px-1.5 py-0.5 text-[10px] font-medium text-white backdrop-blur-xs">
                              日 / 暮 / 夜
                            </span>
                            <div className="flex items-center gap-1">
                              <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#f6f3ec]" />
                              <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#191c1c]" />
                              <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#16213e]" />
                            </div>
                          </div>
                        ) : (
                          <div className="flex h-full w-full">
                            <div
                              className="flex w-7 shrink-0 flex-col gap-1 p-1.5"
                              style={{ backgroundColor: item.sidebar }}
                            >
                              <span
                                className="h-1.5 w-full rounded-full"
                                style={{ backgroundColor: item.accent }}
                              />
                              <span
                                className="h-1 w-3/4 rounded-full opacity-35"
                                style={{ backgroundColor: item.text }}
                              />
                              <span
                                className="h-1 w-2/3 rounded-full opacity-25"
                                style={{ backgroundColor: item.text }}
                              />
                            </div>
                            <div className="flex flex-1 flex-col justify-between p-2">
                              <div className="flex items-center justify-between gap-1">
                                <span
                                  className="h-1.5 w-10 rounded-full opacity-70"
                                  style={{ backgroundColor: item.text }}
                                />
                                <span
                                  className="h-2 w-4 rounded-full"
                                  style={{ backgroundColor: item.accent }}
                                />
                              </div>
                              <div
                                className="h-5 w-full rounded-md border border-black/10 p-1"
                                style={{ backgroundColor: item.card }}
                              >
                                <span
                                  className="block h-1 w-1/2 rounded-full opacity-40"
                                  style={{ backgroundColor: item.text }}
                                />
                              </div>
                            </div>
                          </div>
                        )}
                        {selected && (
                          <span
                            className="absolute right-1.5 top-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full shadow-sm"
                            style={{
                              backgroundColor: "var(--accent)",
                              color: "var(--accent-ink)",
                            }}
                          >
                            <Check className="h-3 w-3 stroke-[2.5]" />
                          </span>
                        )}
                      </div>

                      <div className="text-xs font-semibold text-[var(--text)]">{item.title}</div>
                      <div className="mt-0.5 text-[11px] text-[var(--muted)]">{item.desc}</div>
                    </button>
                  );
                })}
              </div>

              {/* Show 3 clock inputs ONLY when auto_time is selected */}
              {p.theme_mode === "auto_time" && (
                <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/75 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-[var(--muted)]">
                    <span>定时切换时刻（北京时间 {beijingClock}）</span>
                    <span className="font-medium text-[var(--accent)]">
                      当前：{currentThemeName}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    {(
                      [
                        ["light_start", "浅色开始"],
                        ["warm_dark_start", "深苔暖金开始"],
                        ["midnight_start", "午夜蓝开始"],
                      ] as const
                    ).map(([field, label]) => (
                      <label key={field} className="text-[11px] text-[var(--muted)]">
                        {label}
                        <input
                          type="time"
                          value={p.theme_schedule[field]}
                          onChange={(e) =>
                            void appActions.updatePersonalization({
                              theme_schedule: {
                                ...p.theme_schedule,
                                [field]: e.target.value,
                              },
                            })
                          }
                          className={`${INPUT_CLS} mt-1 cc-mono`}
                        />
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </Card>

            {/* Wallpaper Picker + Preview + 4 Presets + Sliders + Collapsible URL */}
            <Card
              title="背景壁纸"
              sub="支持本地图片与内置氛围渐变，纯色模式零额外开销"
              action={
                hasWallpaper ? (
                  <button
                    type="button"
                    onClick={() => {
                      setWallpaperUrlInput("");
                      void appActions.setWallpaperPath(null, "已恢复纯色背景");
                    }}
                    className={BTN_CLS}
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>恢复纯色</span>
                  </button>
                ) : undefined
              }
            >
              {/* Primary action: Pick local image from computer */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={pickingWallpaper}
                  onClick={() => void handlePickWallpaper()}
                  className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-xs font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
                  style={{
                    backgroundColor: "var(--accent)",
                    color: "var(--accent-ink)",
                  }}
                >
                  <Image className="h-4 w-4 shrink-0" />
                  <span>{pickingWallpaper ? "正在打开文件选择…" : "从电脑选择图片"}</span>
                </button>
              </div>

              {/* Current wallpaper thumbnail preview */}
              {hasWallpaper ? (
                <div className="relative h-24 w-full overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)]">
                  {activePreset ? (
                    <div
                      className="h-full w-full"
                      style={{ background: activePreset.cssBackground }}
                    />
                  ) : effectiveWallpaperError ? (
                    <div className="flex h-full w-full flex-col items-center justify-center gap-1.5 bg-[var(--amber-soft)]/50 px-3 text-center">
                      <div className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--amber)]">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                        <span className="line-clamp-1">{effectiveWallpaperError}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setImgLoadFailed(false);
                          setWallpaperUrlInput("");
                          void appActions.setWallpaperPath(null, "已恢复纯色背景");
                        }}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                      >
                        <RotateCcw className="h-3 w-3" />
                        <span>恢复纯色背景</span>
                      </button>
                    </div>
                  ) : wallpaperThumbSrc ? (
                    <img
                      src={wallpaperThumbSrc}
                      alt="当前背景壁纸预览"
                      onError={() => setImgLoadFailed(true)}
                      className="h-full w-full object-cover"
                    />
                  ) : (
                    <div className="flex h-full w-full items-center justify-center text-xs text-[var(--muted)]">
                      正在加载壁纸预览…
                    </div>
                  )}
                  {!effectiveWallpaperError && (
                    <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-between gap-2 bg-gradient-to-t from-black/65 via-black/30 to-transparent px-3 py-1.5 text-[11px] text-white">
                      <span className="truncate font-medium" title={rawWallpaper}>
                        {activePreset
                          ? `内置壁纸 · ${activePreset.label}`
                          : extractWallpaperLabel(rawWallpaper)}
                      </span>
                      <span className="shrink-0 opacity-85">
                        透明 {Math.round(p.wallpaper_opacity * 100)}% · 柔和度 {p.glass_blur_px}
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-[var(--line-strong)] bg-[var(--surface)]/50 px-3 py-2.5 text-center text-[11px] text-[var(--muted)]">
                  当前使用纯色背景；选择本地图片或点下方内置氛围即可上墙
                </div>
              )}

              {/* 4 Built-in Gradient Wallpapers */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-[var(--muted)]">内置氛围壁纸</div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {BUILTIN_WALLPAPER_PRESETS.map((preset) => {
                    const active = rawWallpaper === preset.id;
                    return (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() =>
                          void appActions.setWallpaperPath(preset.id, `已更换壁纸：${preset.label}`)
                        }
                        aria-pressed={active}
                        className="group relative overflow-hidden rounded-xl border p-1 text-left transition-all"
                        style={{
                          borderColor: active ? "var(--accent)" : "var(--line)",
                          backgroundColor: active ? "var(--accent-soft)" : "var(--surface)",
                        }}
                      >
                        <div
                          className="h-11 w-full rounded-lg border border-black/10"
                          style={{ background: preset.cssBackground }}
                        />
                        <div className="mt-1 truncate px-0.5 text-center text-[11px] font-medium text-[var(--text)]">
                          {preset.label}
                        </div>
                        {active && (
                          <span
                            className="absolute right-2 top-2 inline-flex h-4 w-4 items-center justify-center rounded-full shadow-sm"
                            style={{
                              backgroundColor: "var(--accent)",
                              color: "var(--accent-ink)",
                            }}
                          >
                            <Check className="h-2.5 w-2.5 stroke-[2.5]" />
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Opacity & Glass Blur Sliders (Live Preview on drag, persist on release/debounce) */}
              <div className="space-y-1.5 pt-0.5">
                <div
                  className={`grid grid-cols-2 gap-3 text-[11px] text-[var(--muted)] transition-opacity ${
                    !hasWallpaper ? "opacity-50" : ""
                  }`}
                >
                  <label className={!hasWallpaper ? "cursor-not-allowed" : ""}>
                    壁纸透明度：{Math.round(p.wallpaper_opacity * 100)}%
                    <input
                      type="range"
                      min={0.05}
                      max={0.65}
                      step={0.01}
                      disabled={!hasWallpaper}
                      value={p.wallpaper_opacity}
                      onChange={(e) =>
                        handleSliderPreview({
                          wallpaper_opacity: Number(e.target.value),
                        })
                      }
                      onPointerUp={commitSliderPersonalization}
                      onTouchEnd={commitSliderPersonalization}
                      onKeyUp={commitSliderPersonalization}
                      className="mt-1 w-full accent-[var(--accent)] disabled:cursor-not-allowed"
                    />
                  </label>
                  <label className={!hasWallpaper ? "cursor-not-allowed" : ""}>
                    毛玻璃柔和度：{p.glass_blur_px === 0 ? "关闭（0）" : `${p.glass_blur_px} / 24`}
                    <input
                      type="range"
                      min={0}
                      max={24}
                      step={1}
                      disabled={!hasWallpaper}
                      value={p.glass_blur_px}
                      onChange={(e) =>
                        handleSliderPreview({
                          glass_blur_px: Number(e.target.value),
                        })
                      }
                      onPointerUp={commitSliderPersonalization}
                      onTouchEnd={commitSliderPersonalization}
                      onKeyUp={commitSliderPersonalization}
                      className="mt-1 w-full accent-[var(--accent)] disabled:cursor-not-allowed"
                    />
                  </label>
                </div>
                {!hasWallpaper && (
                  <p className="text-[10.5px] text-[var(--muted)]">
                    先选择一张背景壁纸后可调节
                  </p>
                )}
              </div>

              {/* Collapsible network image URL input */}
              <div className="border-t border-[var(--line)] pt-2">
                <button
                  type="button"
                  onClick={() => setShowUrlInput((open) => !open)}
                  className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)] transition-colors hover:text-[var(--accent)]"
                >
                  {showUrlInput ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                  <span>或输入网络图片地址</span>
                </button>
                {showUrlInput && (
                  <div className="mt-2 flex gap-2">
                    <input
                      value={wallpaperUrlInput}
                      placeholder="https://example.com/wallpaper.jpg"
                      onChange={(e) => setWallpaperUrlInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void handleApplyWallpaperUrl();
                        }
                      }}
                      className={`${INPUT_CLS} cc-mono`}
                    />
                    <button
                      type="button"
                      onClick={() => void handleApplyWallpaperUrl()}
                      className={`${BTN_CLS} shrink-0`}
                    >
                      应用
                    </button>
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* Interface animations & tray icon style */}
          <Card title="界面动效与托盘图标" sub="按喜好开关过渡动画，自定义右下角托盘图标样式">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <SwitchRow
                title="界面过渡动效"
                desc="切换页面与按钮的平滑过渡"
                checked={p.animations_enabled}
                onChange={(v) => void appActions.updatePersonalization({ animations_enabled: v })}
              />
              <SwitchRow
                title="看板猫猫动效"
                desc="界面与首页小猫的眨眼和状态动画"
                checked={p.mascot_enabled}
                onChange={(v) => void appActions.updatePersonalization({ mascot_enabled: v })}
              />
              <SwitchRow
                title="流量曲线动效"
                desc="左下角实时网速波形动画"
                checked={p.sparkline_enabled}
                onChange={(v) => void appActions.updatePersonalization({ sparkline_enabled: v })}
              />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
              <span className="text-xs font-medium text-[var(--text)]">托盘图标样式</span>
              <SegButtons<TrayIconMode>
                value={p.tray_icon_mode}
                onChange={(m) =>
                  void appActions.updatePersonalization({ tray_icon_mode: m }, "托盘图标样式已更新")
                }
                options={[
                  ["auto_ac", "随状态自动"],
                  ["always_a", "简约猫标"],
                  ["always_c", "高亮猫标"],
                  ["always_pixel", "像素猫饼"],
                ]}
              />
            </div>
          </Card>
        </div>
      )}

      {/* Tab 3: 网络与 DNS */}
      {tab === "dns" && (
        <div className="space-y-4">
          <Card title="IPv6 独立开关" sub="核心转发与域名解析分开控制，互不干扰">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <SwitchRow
                title="核心 IPv6 转发"
                desc="允许代理内核使用 IPv6 线路建立连接"
                checked={draft.ipv6_core_enabled}
                onChange={(v) => patchDraft({ ipv6_core_enabled: v })}
              />
              <SwitchRow
                title="DNS 返回 IPv6 地址"
                desc="控制域名解析是否同时查询并返回 IPv6 地址"
                checked={draft.ipv6_dns_enabled}
                onChange={(v) => patchDraft({ ipv6_dns_enabled: v })}
              />
            </div>
          </Card>

          <Card title="常用 DNS 开关" sub="推荐保持默认开启，自动防域名解析异常并配合分流">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <SwitchRow
                title="接管并覆写 DNS"
                desc="使用统一防污染 DNS 替代订阅自带配置"
                checked={ext.overrideDns}
                onChange={(v) => patchExt("overrideDns", v)}
              />
              <SwitchRow
                title="遵循分流规则"
                desc="让域名解析自动配合你的网站分流规则"
                checked={ext.respectRules}
                onChange={(v) => patchExt("respectRules", v)}
              />
              <SwitchRow
                title="启用自定义 Hosts"
                desc="加载配置文件内的域名与地址映射"
                checked={ext.useHosts}
                onChange={(v) => patchExt("useHosts", v)}
              />
              <SwitchRow
                title="同步系统 Hosts"
                desc="同时读取本机系统的域名映射表"
                checked={ext.useSystemHosts}
                onChange={(v) => patchExt("useSystemHosts", v)}
              />
            </div>
          </Card>

          {/* Collapsible Advanced DNS Settings */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <button
              type="button"
              onClick={() => setShowAdvancedDns((open) => !open)}
              className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
            >
              <div>
                <div className="text-sm font-semibold text-[var(--text)]">
                  高级 DNS 设置（普通用户无需修改）
                </div>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  自定义解析模式、排除域名、上游加密 DNS 与海外防污染过滤规则
                </p>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
                {showAdvancedDns ? "收起" : "展开"}
                {showAdvancedDns ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
              </span>
            </button>

            {showAdvancedDns && (
              <div className="grid grid-cols-1 gap-4 border-t border-[var(--line)] p-4 lg:grid-cols-2">
                <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/50 p-3.5">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    解析模式与本地监听
                  </div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <SwitchRow
                      title="优先 HTTP/3"
                      desc="加密 DNS 优先走 HTTP/3 通道"
                      checked={ext.preferH3}
                      onChange={(v) => patchExt("preferH3", v)}
                    />
                    <div className="flex flex-col justify-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
                      <span className="text-[11px] text-[var(--muted)]">解析模式</span>
                      <SegButtons<DnsEnhancedMode>
                        value={ext.enhancedMode}
                        onChange={(v) => patchExt("enhancedMode", v)}
                        options={[
                          ["fake-ip", "虚拟 IP（推荐）"],
                          ["redir-host", "真实 IP"],
                        ]}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <label className="text-[11px] text-[var(--muted)]">
                      DNS 监听地址
                      <input
                        value={ext.dnsListen}
                        onChange={(e) => handleDnsListenChange(e.target.value)}
                        className={`${INPUT_CLS} mt-1 cc-mono`}
                      />
                    </label>
                    <label className="text-[11px] text-[var(--muted)]">
                      虚拟 IP 网段
                      <input
                        value={ext.fakeIpRange}
                        onChange={(e) => patchExt("fakeIpRange", e.target.value)}
                        className={`${INPUT_CLS} mt-1 cc-mono`}
                      />
                    </label>
                  </div>
                  <label className="block text-[11px] text-[var(--muted)]">
                    虚拟 IP 排除域名（逗号分隔）
                    <textarea
                      rows={3}
                      value={ext.fakeIpFilter}
                      onChange={(e) => patchExt("fakeIpFilter", e.target.value)}
                      className={`${INPUT_CLS} mt-1 cc-mono`}
                    />
                  </label>
                </div>

                <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/50 p-3.5">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    上游 DNS 与防污染过滤
                  </div>
                  <div className="space-y-2">
                    {(
                      [
                        ["defaultNameserver", "基础引导 DNS（用于解析加密 DNS 域名）"],
                        ["nameserverPolicy", "按域名指定 DNS（每行一条策略）"],
                        ["nameserver", "默认上游 DNS（常规查询）"],
                        ["fallback", "备用海外 DNS（防污染回退）"],
                        ["proxyServerNameserver", "节点域名专用 DNS"],
                      ] as const
                    ).map(([key, label]) => (
                      <label key={key} className="block text-[11px] text-[var(--muted)]">
                        {label}
                        <input
                          value={ext[key]}
                          onChange={(e) => patchExt(key, e.target.value)}
                          className={`${INPUT_CLS} mt-1 cc-mono`}
                        />
                      </label>
                    ))}
                  </div>
                  <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
                    <div className="flex items-center justify-between text-xs font-medium text-[var(--text)]">
                      <span>海外防污染过滤</span>
                      <Toggle
                        checked={ext.fallbackFilterGeoip}
                        onChange={(v) => patchExt("fallbackFilterGeoip", v)}
                        label="启用地区过滤"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <label className="text-[11px] text-[var(--muted)]">
                        直连地区代码
                        <input
                          value={ext.fallbackFilterGeoipCode}
                          onChange={(e) => patchExt("fallbackFilterGeoipCode", e.target.value)}
                          className={`${INPUT_CLS} mt-1 cc-mono`}
                        />
                      </label>
                      <label className="text-[11px] text-[var(--muted)]">
                        防污染域名集合
                        <input
                          value={ext.fallbackFilterGeosite}
                          onChange={(e) => patchExt("fallbackFilterGeosite", e.target.value)}
                          className={`${INPUT_CLS} mt-1 cc-mono`}
                        />
                      </label>
                    </div>
                    <label className="block text-[11px] text-[var(--muted)]">
                      异常 IP 网段过滤
                      <input
                        value={ext.fallbackFilterIpcidr}
                        onChange={(e) => patchExt("fallbackFilterIpcidr", e.target.value)}
                        className={`${INPUT_CLS} mt-1 cc-mono`}
                      />
                    </label>
                    <label className="block text-[11px] text-[var(--muted)]">
                      强制走备用 DNS 的域名
                      <input
                        value={ext.fallbackFilterDomain}
                        onChange={(e) => patchExt("fallbackFilterDomain", e.target.value)}
                        className={`${INPUT_CLS} mt-1 cc-mono`}
                      />
                    </label>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      )}

      {/* Tab 4: 内核与工具 */}
      {tab === "core" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card
              title="全局附加规则与脚本"
              sub="补充自定义分流规则，或预览最终生效配置"
              action={
                <button
                  type="button"
                  onClick={() => void handleCompileYaml()}
                  disabled={yamlLoading}
                  className={BTN_CLS}
                >
                  <Code2 className="h-3.5 w-3.5" />
                  <span>{yamlLoading ? "生成中..." : "预览最终配置"}</span>
                </button>
              }
            >
              <label className="block text-[11px] text-[var(--muted)]">
                全局附加规则（每行一条）
                <textarea
                  rows={3}
                  value={ext.appendRules}
                  onChange={(e) => patchExt("appendRules", e.target.value)}
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="block text-[11px] text-[var(--muted)]">
                  配置覆写脚本路径（可选）
                  <input
                    value={ext.overrideScriptPath}
                    placeholder="如 data/scripts/override.js"
                    onChange={(e) => patchExt("overrideScriptPath", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="block text-[11px] text-[var(--muted)]">
                  启动前执行脚本（可选）
                  <input
                    value={ext.startupScriptPath}
                    placeholder="内核启动前自动运行"
                    onChange={(e) => patchExt("startupScriptPath", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
              {yamlPreview !== null && (
                <div className="rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] p-2.5">
                  <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--muted)]">
                    <span className="truncate">
                      最终配置预览（已脱敏）{yamlSha ? ` · ${yamlSha.slice(0, 10)}` : ""}
                    </span>
                    <div className="flex shrink-0 items-center gap-2">
                      <button
                        type="button"
                        onClick={() => void copyText(yamlPreview, "配置预览")}
                        className="text-[var(--accent)] hover:underline"
                      >
                        复制
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setYamlPreview(null);
                          setYamlSha(null);
                        }}
                        aria-label="关闭预览"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                  <pre className="cc-mono cc-selectable max-h-44 overflow-auto text-[11px] text-[var(--text-secondary)]">
                    {yamlPreview}
                  </pre>
                </div>
              )}
            </Card>

            <Card
              title="内核控制与地理数据库"
              sub={`${runtime.core_name} ${runtime.core_version} · ${runtime.running ? "运行中" : "已停止"}`}
              action={
                <button
                  type="button"
                  onClick={() => void handleRefreshGeo("all")}
                  disabled={geoBusy !== null}
                  className={BTN_CLS}
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${geoBusy === "all" ? "animate-spin" : ""}`} />
                  <span>更新全部数据库</span>
                </button>
              }
            >
              <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
                <button
                  type="button"
                  disabled={coreOpBusy !== null || runtime.running}
                  onClick={() => void handleCoreAction("start")}
                  className={BTN_CLS}
                >
                  <Play className="h-3.5 w-3.5 text-[var(--green)]" />
                  <span>启动内核</span>
                </button>
                <button
                  type="button"
                  disabled={coreOpBusy !== null || !runtime.running}
                  onClick={() => void handleCoreAction("stop")}
                  className={BTN_CLS}
                >
                  <Square className="h-3.5 w-3.5 text-[var(--red)]" />
                  <span>停止内核</span>
                </button>
                <button
                  type="button"
                  disabled={coreOpBusy !== null}
                  onClick={() => void handleCoreAction("restart")}
                  className={BTN_CLS}
                >
                  <RotateCw
                    className={`h-3.5 w-3.5 ${coreOpBusy === "restart" ? "animate-spin" : ""}`}
                  />
                  <span>重启内核</span>
                </button>
                <button
                  type="button"
                  disabled={coreOpBusy !== null}
                  onClick={() => void handleCoreAction("reload")}
                  className={BTN_CLS}
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${coreOpBusy === "reload" ? "animate-spin" : ""}`}
                  />
                  <span>热重载配置</span>
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2">
                {GEO_ITEMS.map(([key, dtoKey, fileName, desc]) => {
                  const statusSummary = renderGeoStatusSummary(
                    geoStatus?.[dtoKey],
                    geoStatusLoading
                  );
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate cc-mono text-xs font-medium text-[var(--text)]">
                            {fileName}
                          </span>
                          <span
                            className={`shrink-0 rounded px-1 py-0.5 text-[9px] font-medium ${
                              statusSummary.state === "ready"
                                ? "bg-[var(--green-soft)] text-[var(--green)]"
                                : statusSummary.state === "loading"
                                  ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                                  : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                            }`}
                          >
                            {statusSummary.state === "ready"
                              ? "已就绪"
                              : statusSummary.state === "loading"
                                ? "检测中"
                                : "未下载"}
                          </span>
                        </div>
                        <div className="mt-0.5 truncate text-[10px] text-[var(--muted)]">
                          {desc} · <span className="cc-mono">{statusSummary.text}</span>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleRefreshGeo(key)}
                        disabled={geoBusy !== null}
                        title={`更新 ${fileName}`}
                        className="shrink-0 rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                      >
                        <Database className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>

              <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-medium text-[var(--text)]">内核内存上限</div>
                  <SegButtons<0 | 48 | 64 | 96>
                    mono
                    value={draft.gomemlimit_mb}
                    onChange={(v) => patchDraft({ gomemlimit_mb: v, memory_tier: tierFromMb(v) })}
                    options={[
                      [0, "自动"],
                      [48, "48 MB"],
                      [64, "64 MB"],
                      [96, "96 MB"],
                    ]}
                  />
                </div>
                <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)]/60 pt-2">
                  <input
                    value={coreBinaryPath}
                    onChange={(e) => setCoreBinaryPath(e.target.value)}
                    placeholder="填写本地内核程序路径（如 C:\path\to\mihomo.exe）"
                    className={`${INPUT_CLS} flex-1 cc-mono`}
                  />
                  <button
                    type="button"
                    disabled={coreOpBusy !== null}
                    onClick={() => void handleHotSwapCore()}
                    className={BTN_CLS}
                  >
                    <Cpu className="h-3.5 w-3.5" />
                    <span>热换内核</span>
                  </button>
                </div>
              </div>
            </Card>
          </div>

          <Card
            title="快捷目录、配置备份与外部工具"
            sub="直达本地目录、导入导出备份、打开外部面板或复制终端代理命令"
          >
            <div className="flex flex-wrap items-center gap-2">
              {DIR_ITEMS.map(([dir, label]) => (
                <button
                  key={dir}
                  type="button"
                  onClick={() => void handleOpenDir(dir)}
                  className={BTN_CLS}
                >
                  <FolderOpen className="h-3.5 w-3.5" />
                  <span>{label}</span>
                </button>
              ))}
              <button type="button" onClick={() => void handleExportBackup()} className={BTN_CLS}>
                <Download className="h-3.5 w-3.5" />
                <span>导出备份</span>
              </button>
              <button
                type="button"
                onClick={() => setConfirmImportBackupOpen(true)}
                className={BTN_CLS}
              >
                <Upload className="h-3.5 w-3.5" />
                <span>导入备份</span>
              </button>
            </div>

            <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium text-[var(--text)]">外部控制面板：</span>
                  <select
                    value={Math.min(selectedWebUiIdx, Math.max(0, ext.webuiUrls.length - 1))}
                    onChange={(e) => setSelectedWebUiIdx(Number(e.target.value) || 0)}
                    className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  >
                    {ext.webuiUrls.map((item, idx) => (
                      <option key={`${item.name}-${idx}`} value={idx}>
                        {item.name}
                      </option>
                    ))}
                  </select>
                </div>
                <button type="button" onClick={() => void handleOpenWebUi()} className={BTN_CLS}>
                  <ExternalLink className="h-3.5 w-3.5" />
                  <span>打开面板</span>
                </button>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                <input
                  value={newWebUiName}
                  onChange={(e) => setNewWebUiName(e.target.value)}
                  placeholder="新增面板名称（如 Zashboard）"
                  className={`${INPUT_CLS} sm:col-span-3`}
                />
                <input
                  value={newWebUiTpl}
                  onChange={(e) => setNewWebUiTpl(e.target.value)}
                  placeholder="粘贴外部面板网址，打开时自动填入本机端口与口令"
                  className={`${INPUT_CLS} sm:col-span-7`}
                />
                <button
                  type="button"
                  onClick={handleAddWebUiBookmark}
                  className={`${BTN_CLS} justify-center sm:col-span-2`}
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>添加书签</span>
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)] pt-2.5">
              <span className="text-xs text-[var(--muted)]">终端代理命令：</span>
              {(["powershell", "cmd", "bash"] as const).map((sh) => (
                <button
                  key={sh}
                  type="button"
                  onClick={() => void handleCopyShellEnv(sh)}
                  className={BTN_CLS}
                >
                  <Terminal className="h-3.5 w-3.5" />
                  <span>{sh.toUpperCase()}</span>
                </button>
              ))}
              <button
                type="button"
                onClick={() => void handleCopyDiagnostics()}
                className={BTN_CLS}
              >
                <Copy className="h-3.5 w-3.5" />
                <span>复制脱敏诊断报告</span>
              </button>
            </div>
          </Card>
        </div>
      )}

      {/* Tab 5: 关于与更新 */}
      {tab === "updates" && (
        <div className="space-y-4">
          <Card
            title="关于猫猫云梯与软件更新"
            sub={`当前版本 v${runtime.app_version} · ${runtime.os_label} · 更新来源 ${draft.update.repo}`}
            action={
              <button
                type="button"
                onClick={() => void handleCheckUpdate()}
                disabled={checkingUpdate}
                className={BTN_CLS}
              >
                <CloudDownload className="h-3.5 w-3.5" />
                <span>{checkingUpdate ? "检查中..." : "检查更新"}</span>
              </button>
            }
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <label className="text-[11px] text-[var(--muted)]">
                更新源仓库
                <input
                  value={draft.update.repo}
                  onChange={(e) =>
                    patchDraft({ update: { ...draft.update, repo: e.target.value } })
                  }
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
              <label className="text-[11px] text-[var(--muted)]">
                自动更新模式
                <select
                  value={draft.update.mode}
                  onChange={(e) =>
                    patchDraft({
                      update: {
                        ...draft.update,
                        mode: e.target.value as AppConfig["update"]["mode"],
                      },
                    })
                  }
                  className={`${INPUT_CLS} mt-1`}
                >
                  <option value="next_launch">下次启动自动更新（推荐）</option>
                  <option value="manual">仅手动检查提醒</option>
                  <option value="auto_restart">下载后自动重启</option>
                </select>
              </label>
              <label className="text-[11px] text-[var(--muted)]">
                自动检查间隔（分钟）
                <input
                  type="number"
                  min={30}
                  value={draft.update.check_interval_min}
                  onChange={(e) =>
                    patchDraft({
                      update: {
                        ...draft.update,
                        check_interval_min: Math.max(30, Number(e.target.value) || 360),
                      },
                    })
                  }
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--muted)]">
              <label className="inline-flex items-center gap-2">
                <Toggle
                  checked={draft.update.include_prerelease}
                  onChange={(v) =>
                    patchDraft({ update: { ...draft.update, include_prerelease: v } })
                  }
                  label="接收测试版更新"
                />
                <span>接收测试版更新</span>
              </label>
              <span className="text-[11px]">
                {updateMsg ?? `上次检查：${runtime.last_update_check ?? "尚未检查"}`}
              </span>
            </div>
          </Card>

          {/* Collapsible Developer & AI Assistant Integration Tools */}
          <section className="cc-card cc-glass overflow-hidden rounded-2xl">
            <button
              type="button"
              onClick={() => setShowDevTools((open) => !open)}
              className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
            >
              <div>
                <div className="text-sm font-semibold text-[var(--text)]">
                  开发者与 AI 助手集成工具
                </div>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  包含 AI 协作说明文档与命令行速查，普通使用无需展开
                </p>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
                {showDevTools ? "收起" : "展开"}
                {showDevTools ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
              </span>
            </button>

            {showDevTools && (
              <div className="grid grid-cols-1 gap-4 border-t border-[var(--line)] p-4 lg:grid-cols-2">
                <Card
                  title="AI 协作说明文档"
                  sub="点选模块预览，或一键复制发给 AI 辅助排障与配置"
                  action={
                    <div className="flex gap-1.5">
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopyAgentDoc(activeDoc.id, "本节说明", docMd(activeDoc))
                        }
                        className={BTN_CLS}
                      >
                        <Copy className="h-3.5 w-3.5" />
                        <span>复制本节</span>
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopyAgentDoc(
                            "all",
                            "全套说明文档",
                            AGENT_DOCS.map(docMd).join("\n\n")
                          )
                        }
                        className={BTN_CLS}
                      >
                        <Copy className="h-3.5 w-3.5" />
                        <span>复制全部</span>
                      </button>
                    </div>
                  }
                >
                  <SegButtons<string>
                    value={activeDoc.id}
                    onChange={setActiveDocId}
                    options={AGENT_DOCS.map((d) => [d.id, d.title] as const)}
                  />
                  <div className="cc-selectable space-y-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-3 text-xs">
                    <div>
                      <span className="font-semibold text-[var(--accent)]">目标能力：</span>
                      {activeDoc.goal}
                    </div>
                    <div>
                      <span className="font-semibold text-[var(--accent)]">关键配置项：</span>
                      <code className="cc-mono text-[11px] text-[var(--text-secondary)]">
                        {activeDoc.keys}
                      </code>
                    </div>
                    <div>
                      <span className="font-semibold text-[var(--accent)]">推荐操作路径：</span>
                      {activeDoc.workflow}
                    </div>
                    <div>
                      <span className="font-semibold text-[var(--accent)]">排障与边界：</span>
                      {activeDoc.guardrails}
                    </div>
                  </div>
                </Card>

                <Card
                  title="命令行速查（CLI）"
                  sub="适合脚本与 AI 助手直接调用的无界面命令"
                  action={
                    <button
                      type="button"
                      onClick={() =>
                        void copyText(
                          CLI_SNIPPETS.map((s) => `${s.cmd}  # ${s.desc}`).join("\n"),
                          "全套命令行速查"
                        )
                      }
                      className={BTN_CLS}
                    >
                      <Terminal className="h-3.5 w-3.5" />
                      <span>复制全套</span>
                    </button>
                  }
                >
                  <div className="space-y-1.5">
                    {CLI_SNIPPETS.map((item) => (
                      <div
                        key={item.cmd}
                        className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-1.5"
                      >
                        <div className="min-w-0">
                          <div className="truncate cc-mono cc-selectable text-xs text-[var(--text)]">
                            {item.cmd}
                          </div>
                          <div className="text-[11px] text-[var(--muted)]">{item.desc}</div>
                        </div>
                        <button
                          type="button"
                          onClick={() => void copyText(item.cmd, "命令")}
                          title="复制命令"
                          className="shrink-0 rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            )}
          </section>
        </div>
      )}

      {/* Backup Import Two-Step Confirmation Modal */}
      {confirmImportBackupOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
          onClick={() => setConfirmImportBackupOpen(false)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label="确认导入备份配置"
            onClick={(e) => e.stopPropagation()}
            className="cc-surface w-full max-w-md rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--amber-soft)] text-[var(--amber)]">
                  <AlertTriangle className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-[var(--text)]">
                    确认导入配置备份？
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                    导入备份将会覆盖当前的代理参数、智能多选组和国内中转配置。建议先点「导出备份」保留一份当前配置，再继续导入。
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConfirmImportBackupOpen(false)}
                className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
                aria-label="关闭弹窗"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmImportBackupOpen(false)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)]"
              >
                取消
              </button>
              <button
                type="button"
                onClick={() => {
                  setConfirmImportBackupOpen(false);
                  openImportBackupPicker();
                }}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <Upload className="h-3.5 w-3.5" />
                <span>确认覆盖并选择文件</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
