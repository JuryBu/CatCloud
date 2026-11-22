import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Check, CloudDownload, Code2, Copy, Cpu, Database, Download, ExternalLink, Eye, EyeOff,
  FolderOpen, Globe, Keyboard, Network, Palette, Play, Plus, RefreshCw, RotateCw, Save, Shield, Square, Terminal, Upload, X,
} from "lucide-react";
import {
  type AppConfig, type FullAppConfig, type MemoryTier, type ThemeMode, type TrayIconMode,
  type TunStackMode, type WebUiEntry, catcloudApi, formatErrorMessage, isTauriEnv,
} from "../api/tauri";
import { appActions, getBeijingTimeLabel, useAppSelector } from "../store/appStore";

type SettingsTabId = "system" | "dns" | "core" | "appearance" | "updates";
type LogLevel = "silent" | "error" | "warning" | "info" | "debug";
type DnsEnhancedMode = "fake-ip" | "redir-host";
type GeoKey = "geoip" | "geosite" | "mmdb" | "asn";

interface ExtendedSettings {
  pacEnabled: boolean;
  pacPort: number;
  pacUrl: string;
  bypassDomains: string;
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
    url_template: "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}",
  },
  {
    name: "Yacd-meta",
    url_template: "https://yacd.metacubex.one/#/setup?hostname={host}&port={port}&secret={secret}",
  },
];

const DEFAULT_EXTENDED: ExtendedSettings = {
  pacEnabled: false,
  pacPort: 17891,
  pacUrl: "",
  bypassDomains: "localhost, 127.*, 10.*, 172.16.*, 192.168.*, *.local, <local>",
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

const HOTKEY_LABELS: Record<string, string> = {
  toggleProxy: "切换系统代理",
  switchNextBest: "秒切下一优节点",
  toggleMainWindow: "呼出 / 隐藏主窗口",
  toggleCapsule: "切换悬浮胶囊微窗",
  toggleTun: "切换 TUN 虚拟网卡",
};

const STARTUP_PAGE_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "overview", label: "总览仪表盘" },
  { value: "groups", label: "智能多选组" },
  { value: "speedtest", label: "零干扰隔离测速" },
  { value: "preaccel", label: "国内预加速" },
  { value: "nodes", label: "节点与多订阅" },
  { value: "rules", label: "规则与连接" },
  { value: "logs", label: "实时内核日志" },
  { value: "settings", label: "设置与 CLI" },
];

const TRAY_CLICK_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "toggle_main_window", label: "显示 / 隐藏主窗口" },
  { value: "open_main_window", label: "始终展开主窗口" },
  { value: "toggle_capsule", label: "切换悬浮胶囊微窗" },
  { value: "toggle_system_proxy", label: "切换系统代理开关" },
  { value: "switch_next_best", label: "秒切下一优节点" },
  { value: "none", label: "无动作" },
];

const AGENT_DOCS = [
  {
    id: "system",
    title: "1. 系统与网络",
    goal: "管理系统代理、Proxy Guard 守护、PAC 旁路、TUN 协议栈与混合/控制/DNS 端口。",
    keys: "mixed_port, controller_port, controller_secret, dns_listen_port, system_proxy_enabled, proxy_guard_*, tun_stack_mode",
    workflow: "先确认端口空闲，再开启系统代理与 Proxy Guard；仅需接管非代理进程时提权开 TUN。",
    guardrails: "Windows 启用 TUN 需管理员 UAC；修改端口后同步刷新终端代理环境变量。",
  },
  {
    id: "dns",
    title: "2. IPv6 与进阶 DNS",
    goal: "将核心 IPv6 与 DNS IPv6 独立分离，细粒度编排 Fake-IP/Redir-Host 与 Fallback 过滤。",
    keys: "ipv6_core_enabled, ipv6_dns_enabled, enhanced-mode, fake-ip-filter, nameserver-policy, fallback-filter",
    workflow: "开启覆写 DNS 与 respect-rules；内网和授时域名写入 fake-ip-filter，国内走 policy 分流。",
    guardrails: "IPv6 异常时先关 ipv6_dns_enabled 止住 AAAA 空等，再单独排查 ipv6_core_enabled。",
  },
  {
    id: "core",
    title: "3. 规则、地理与内核",
    goal: "管理全局附加规则、覆写脚本、启动脚本、GeoIP/GeoSite/MMDB/ASN 刷新与 Mihomo 内存挡位热换。",
    keys: "gomemlimit_mb (auto/48/64/96), append_rules, override_script_path, startup_script_path, compile_preview_yaml",
    workflow: "改动规则或 DNS 后先执行 YAML 实时预览核对产物，再热换内核或导出本地脱敏备份。",
    guardrails: "自动挡位或 48 MiB 适合轻载常驻；大规则集或高并发下载建议切换 64/96 MiB 降低 GC 抖动。",
  },
  {
    id: "groups",
    title: "4. 多组调度与测速",
    goal: "维护粘性最优、条件池与受控均衡策略，结合硬门槛、权重公式和跨池升级稳态选路。",
    keys: "mode, hard_gates, trigger_rules, formula_expr, fallback_policy, cooldown_sec, hysteresis_pct",
    workflow: "先运行隔离探针校验指标，再调整评分公式、冷却秒数与迟滞百分比。",
    guardrails: "保持冷却与迟滞门槛，避免短时链路波动导致节点高频乒乓切换。",
  },
  {
    id: "preaccel",
    title: "5. 前置加速与豁免",
    goal: "为非原生 443 节点提供前置中转，自动跳过原生 443 并隔离门户探测异常。",
    keys: "preaccel.enabled, skip_443_native, probe_url, fallback_probe_url",
    workflow: "用纯 IP :443 无 SNI 跳板核验连通后启用优先级排序，失活时自动故障切换或回落直连。",
    guardrails: "导出备份与诊断快照时严格脱敏，禁止泄露真实中继地址与凭据。",
  },
  {
    id: "ui-cli",
    title: "6. 主题、更新与 CLI",
    goal: "提供北京时间三段自动主题、无窗省内存驻留、GitHub Releases 更新与无头 CLI。",
    keys: "personalization.*, startup_page, tray_click_action, update.repo (JuryBu/CatCloud), catcloud CLI",
    workflow: "日常启用关闭进无窗省内存；脚本与 Agent 统一调用 catcloud --json 幂等操作。",
    guardrails: "未设壁纸时自动关闭毛玻璃，保持纯色主题零 backdrop-filter GPU 额外开销。",
  },
] as const;

const CLI_SNIPPETS = [
  { cmd: "catcloud status --json", desc: "输出核心状态、活跃节点与端口 JSON" },
  { cmd: "catcloud config reload --json", desc: "校验配置并触发三级热重载" },
  { cmd: "catcloud group list --json", desc: "列出全部智能多选组与活跃节点" },
  { cmd: "catcloud group switch <group_id> --json", desc: "秒切指定多选组至下一优可用节点" },
  { cmd: "catcloud preaccel pool --json", desc: "列出国内 443 预加速双活跳板池" },
  { cmd: "catcloud probe list --json", desc: "查看已注册的内置与自定义探针" },
  { cmd: "catcloud config diag --json", desc: "输出 100% 脱敏诊断快照 JSON" },
  { cmd: "catcloud docs export all --json", desc: "导出全套 6 模块 Agent 辅助文档" },
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

function parseNameserverPolicy(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx <= 0) continue;
    // Handle `geosite:cn,private: https://...` by finding the last `: ` or `:http`
    const sepMatch = /^(.+?):\s+(https?:\/\/.+|tls:\/\/.+|quic:\/\/.+|\d+\.\d+\.\d+\.\d+.*)$/i.exec(trimmed);
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
    pacEnabled: sp?.pac?.enabled ?? DEFAULT_EXTENDED.pacEnabled,
    pacPort: sp?.pac?.port ?? DEFAULT_EXTENDED.pacPort,
    pacUrl: sp?.pac?.script_override ?? "",
    bypassDomains: Array.isArray(sp?.bypass)
      ? sp.bypass.join(", ")
      : DEFAULT_EXTENDED.bypassDomains,
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
    fallback: Array.isArray(dns?.fallback)
      ? dns.fallback.join(", ")
      : DEFAULT_EXTENDED.fallback,
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
        enabled: ext.pacEnabled,
        port: ext.pacPort,
        script_override: ext.pacUrl.trim() ? ext.pacUrl.trim() : null,
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

function resolveWebUiTemplate(entry: WebUiEntry, controllerPort: number, secret: string): string {
  return entry.url_template
    .replace(/\{host\}/g, "127.0.0.1")
    .replace(/\{port\}/g, String(controllerPort))
    .replace(/\{secret\}/g, encodeURIComponent(secret));
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
    raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean).map((s) => `${pad}- "${s}"`).join("\n");
  return `# CatCloud Compiled Mihomo Preview (Sanitized / RFC 5737)
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

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button" role="switch" aria-checked={checked} aria-label={label}
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

function Card({ title, sub, action, children }: { title: string; sub?: string; action?: ReactNode; children: ReactNode }) {
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
  title, desc, checked, onChange, badge,
}: {
  title: string; desc: string; checked: boolean; onChange: (v: boolean) => void; badge?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-xs font-medium text-[var(--text)]">
          <span>{title}</span>{badge}
        </div>
        <p className="mt-0.5 text-[11px] text-[var(--muted)]">{desc}</p>
      </div>
      <Toggle checked={checked} onChange={onChange} label={title} />
    </div>
  );
}

function SegButtons<T extends string | number>({
  options, value, onChange, mono = false,
}: {
  options: ReadonlyArray<readonly [T, string]>; value: T; onChange: (v: T) => void; mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([opt, text]) => {
        const on = value === opt;
        return (
          <button
            key={String(opt)} type="button" onClick={() => onChange(opt)}
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
  const inTauri = isTauriEnv();

  const [tab, setTab] = useState<SettingsTabId>("system");
  const [draft, setDraft] = useState<AppConfig>(() => structuredClone(storeConfig));
  const [ext, setExt] = useState<ExtendedSettings>(DEFAULT_EXTENDED);
  const [showSecret, setShowSecret] = useState(false);
  const [selectedWebUiIdx, setSelectedWebUiIdx] = useState(0);
  const [newWebUiName, setNewWebUiName] = useState("");
  const [newWebUiTpl, setNewWebUiTpl] = useState("");
  const [coreBinaryPath, setCoreBinaryPath] = useState("");
  const [coreOpBusy, setCoreOpBusy] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [yamlPreview, setYamlPreview] = useState<string | null>(null);
  const [yamlSha, setYamlSha] = useState<string | null>(null);
  const [yamlLoading, setYamlLoading] = useState(false);
  const [geoBusy, setGeoBusy] = useState<GeoKey | "all" | null>(null);
  const [geoStamp, setGeoStamp] = useState<Record<GeoKey, string>>({
    geoip: inTauri ? "未刷新" : "2026-11-22",
    geosite: inTauri ? "未刷新" : "2026-11-22",
    mmdb: inTauri ? "未刷新" : "2026-11-20",
    asn: inTauri ? "未刷新" : "2026-11-18",
  });
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const [activeDocId, setActiveDocId] = useState<string>(AGENT_DOCS[0].id);

  useEffect(() => {
    setDraft(structuredClone(storeConfig));
    setDirty(false);
  }, [storeConfig]);

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
    return () => {
      active = false;
    };
  }, []);

  const patchDraft = (patch: Partial<AppConfig>) => {
    setDraft((prev) => ({ ...prev, ...patch }));
    setDirty(true);
  };
  const patchExt = <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => {
    setExt((prev) => ({ ...prev, [k]: v }));
    setDirty(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: AppConfig = {
        ...draft,
        memory_tier: tierFromMb(draft.gomemlimit_mb),
        personalization: storeConfig.personalization,
      };
      const savedBasic = await catcloudApi.saveConfig(payload);
      appActions.syncConfig(savedBasic);
      await catcloudApi.saveExtendedSettings(buildExtendedPatch(ext));
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      setDirty(false);
      appActions.showToast("设置已保存并同步内核配置", "ok");
    } catch (err) {
      appActions.showToast(`保存设置失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSaving(false);
    }
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
          appActions.showToast(`热重载未生效：${outcome.error ?? "配置校验拒绝"}`, "warn");
        } else {
          appActions.showToast(`配置热重载完成 (${outcome.level})`, "ok");
        }
      } else {
        const rt =
          action === "start"
            ? await catcloudApi.startCore()
            : action === "stop"
              ? await catcloudApi.stopCore()
              : await catcloudApi.restartCore();
        appActions.syncRuntime(rt);
        const labels = { start: "核心已启动", stop: "核心已停止", restart: "核心已重启" };
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
      appActions.showToast("请先输入待热换的内核可执行文件绝对路径", "warn");
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
        const sha = typeof res === "object" && res !== null && "sha256" in res ? res.sha256 : null;
        setYamlPreview(text);
        setYamlSha(sha);
        appActions.showToast("已获取内核实时编译 YAML", "ok");
      } else {
        setYamlPreview(buildFallbackYaml(draft, ext));
        setYamlSha("browser-preview");
        appActions.showToast("已生成预览模式编译 YAML", "info");
      }
    } catch (err) {
      appActions.showToast(`编译 YAML 预览失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setYamlLoading(false);
    }
  };

  const handleRefreshGeo = async (target: GeoKey | "all") => {
    setGeoBusy(target);
    try {
      const res = await catcloudApi.refreshGeoDb(target === "all" ? null : [target]);
      const today = new Date().toISOString().slice(0, 10);
      if (res.ok) {
        const updatedKeys = res.updated_targets.length > 0
          ? res.updated_targets
          : target === "all"
            ? (["geoip", "geosite", "mmdb", "asn"] as GeoKey[])
            : [target];
        setGeoStamp((prev) => {
          const next = { ...prev };
          for (const k of updatedKeys) {
            if (k === "geoip" || k === "geosite" || k === "mmdb" || k === "asn") {
              next[k] = today;
            }
          }
          return next;
        });
      }
      appActions.showToast(res.message || "地理库刷新完成", res.ok ? "ok" : "warn");
    } catch (err) {
      appActions.showToast(`刷新地理库失败：${formatErrorMessage(err)}`, "warn");
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
        setUpdateMsg(`当前 v${res.current_version} 已是 ${draft.update.repo} 最新版本`);
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
        appActions.showToast(
          `已导出本地脱敏备份：${saved.path} (${saved.bytes} B)`,
          "ok"
        );
      } catch (err) {
        appActions.showToast(`导出备份失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }

    const json = JSON.stringify(
      { exported_at: new Date().toISOString(), app_version: runtime.app_version, config: draft, extended: ext },
      null,
      2
    );
    const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "catcloud-settings-backup.json" });
    a.click();
    URL.revokeObjectURL(url);
    appActions.showToast("已下载预览配置备份 JSON", "ok");
  };

  const handleImportBackup = async () => {
    const input = Object.assign(document.createElement("input"), { type: "file", accept: "application/json,.json" });
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      void file.text().then(async (raw) => {
        if (inTauri) {
          try {
            const res = await catcloudApi.importBackupBundle(raw);
            await appActions.refreshAllData();
            const full = await catcloudApi.getFullConfig();
            setExt(hydrateExtendedFromFullConfig(full));
            appActions.showToast(
              res.message || `已恢复备份（组 ${res.restored_groups} / 跳板 ${res.restored_relays}）`,
              "ok"
            );
          } catch (err) {
            appActions.showToast(`导入备份失败：${formatErrorMessage(err)}`, "warn");
          }
          return;
        }
        try {
          const parsed = JSON.parse(raw) as { config?: AppConfig; extended?: Partial<ExtendedSettings> };
          if (parsed.config) setDraft(parsed.config);
          if (parsed.extended) setExt((prev) => ({ ...prev, ...parsed.extended }));
          setDirty(true);
          appActions.showToast("已导入备份配置，点击保存后写入", "ok");
        } catch {
          appActions.showToast("备份文件 JSON 格式无效", "warn");
        }
      });
    };
    input.click();
  };

  const handleOpenDir = async (dir: "config" | "data" | "logs" | "core") => {
    try {
      const opened = await catcloudApi.openAppDir(dir);
      appActions.showToast(`已打开 ${dir} 目录：${opened}`, "info");
    } catch (err) {
      appActions.showToast(`打开 ${dir} 目录失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleOpenWebUi = async () => {
    const entry = ext.webuiUrls[selectedWebUiIdx] ?? ext.webuiUrls[0];
    const resolvedUrl = entry
      ? resolveWebUiTemplate(entry, draft.controller_port, ext.controllerSecret.trim())
      : `http://127.0.0.1:${draft.controller_port}/ui`;
    try {
      const opened = await catcloudApi.openWebUi(resolvedUrl);
      appActions.showToast(`已打开 Web UI：${opened}`, "info");
    } catch (err) {
      appActions.showToast(`打开 Web UI 失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleAddWebUiBookmark = () => {
    const name = newWebUiName.trim();
    const tpl = newWebUiTpl.trim();
    if (!name || !tpl) {
      appActions.showToast("请填写书签名称与 URL 模板", "warn");
      return;
    }
    const nextList = [...ext.webuiUrls, { name, url_template: tpl }];
    patchExt("webuiUrls", nextList);
    setSelectedWebUiIdx(nextList.length - 1);
    setNewWebUiName("");
    setNewWebUiTpl("");
    appActions.showToast(`已添加 Web UI 书签「${name}」，记得点击顶部保存`, "ok");
  };

  const handleLaunchUwp = async () => {
    try {
      const res = await catcloudApi.launchUwpLoopback();
      appActions.showToast(res.message || "已处理 UWP 回环请求", res.launched ? "ok" : "info");
    } catch (err) {
      appActions.showToast(`启动 UWP 回环解除失败：${formatErrorMessage(err)}`, "warn");
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
    await copyText(text, `${sh.toUpperCase()} 环境变量`);
  };

  const handleCopyDiagnostics = async () => {
    let text = [
      `CatCloud Diagnostic Snapshot (Sanitized / RFC 5737)`,
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
        appActions.showToast(`采集脱敏诊断失败：${formatErrorMessage(err)}`, "warn");
        return;
      }
    }
    await copyText(text, "脱敏诊断信息");
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

  const activeDoc = useMemo(() => AGENT_DOCS.find((d) => d.id === activeDocId) ?? AGENT_DOCS[0], [activeDocId]);
  const docMd = (d: (typeof AGENT_DOCS)[number]) =>
    `### ${d.title}\n- **目标能力**：${d.goal}\n- **关键配置项**：\`${d.keys}\`\n- **推荐操作路径**：${d.workflow}\n- **排障与边界**：${d.guardrails}`;

  const tabs: Array<{ id: SettingsTabId; label: string; icon: typeof Network }> = [
    { id: "system", label: "系统与网络", icon: Network },
    { id: "dns", label: "IPv6 与进阶 DNS", icon: Globe },
    { id: "core", label: "规则、地理与内核", icon: Cpu },
    { id: "appearance", label: "个性化、动效与热键", icon: Palette },
    { id: "updates", label: "自动更新与 Agent CLI", icon: CloudDownload },
  ];
  const p = storeConfig.personalization;

  return (
    <div className="space-y-4">
      <div className="cc-card cc-glass flex flex-wrap items-center justify-between gap-2 rounded-2xl px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          {tabs.map(({ id, label, icon: Icon }) => {
            const on = tab === id;
            return (
              <button
                key={id} type="button" onClick={() => setTab(id)}
                className="inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium transition-colors"
                style={{
                  backgroundColor: on ? "var(--accent-soft)" : "transparent",
                  color: on ? "var(--accent)" : "var(--muted)",
                  border: on ? "1px solid var(--accent)" : "1px solid transparent",
                }}
              >
                <Icon className="h-3.5 w-3.5" /><span>{label}</span>
              </button>
            );
          })}
        </div>
        <button
          type="button" onClick={() => void handleSave()} disabled={saving}
          className="inline-flex items-center gap-1.5 rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-60"
          style={{
            backgroundColor: dirty ? "var(--accent)" : "var(--surface)",
            color: dirty ? "var(--accent-ink)" : "var(--text)",
            border: "1px solid var(--line-strong)",
          }}
        >
          {dirty ? <Save className="h-3.5 w-3.5" /> : <Check className="h-3.5 w-3.5" />}
          <span>{saving ? "保存中..." : dirty ? "保存更改" : "已同步"}</span>
        </button>
      </div>

      {tab === "system" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card title="系统代理、守护与 PAC" sub="系统级代理接管、防篡改守护及 Bypass 排除域名">
            <SwitchRow
              title="启用系统代理" desc={`将系统流量指向 127.0.0.1:${draft.mixed_port}`}
              checked={runtime.system_proxy_enabled} onChange={(v) => void appActions.toggleSystemProxy(v)}
            />
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_126px]">
              <SwitchRow
                title="Proxy Guard 守护" desc="定时校回被覆盖的系统代理"
                checked={draft.proxy_guard_enabled} onChange={(v) => patchDraft({ proxy_guard_enabled: v })}
              />
              <label className="rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2 text-[11px] text-[var(--muted)]">
                守护间隔 (秒)
                <input
                  type="number" min={5} max={300} value={draft.proxy_guard_interval_sec}
                  onChange={(e) => patchDraft({ proxy_guard_interval_sec: Math.max(5, Number(e.target.value) || 30) })}
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
            </div>
            <SwitchRow
              title="PAC 自动配置模式" desc={`通过本地 PAC 端口 :${ext.pacPort} 按规则分发浏览器请求`}
              checked={ext.pacEnabled} onChange={(v) => patchExt("pacEnabled", v)}
            />
            {ext.pacEnabled && (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-[120px_1fr]">
                <label className="block text-[11px] text-[var(--muted)]">
                  PAC 端口
                  <input
                    type="number" min={1024} max={65535} value={ext.pacPort}
                    onChange={(e) => patchExt("pacPort", Number(e.target.value) || 17891)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="block text-[11px] text-[var(--muted)]">
                  PAC 脚本覆写路径/内容（可选）
                  <input
                    value={ext.pacUrl} placeholder="留空使用内置自动生成 PAC"
                    onChange={(e) => patchExt("pacUrl", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
            )}
            <label className="block text-[11px] text-[var(--muted)]">
              排除域名 Bypass（逗号分隔）
              <textarea rows={2} value={ext.bypassDomains} onChange={(e) => patchExt("bypassDomains", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
            </label>
          </Card>

          <Card title="TUN 虚拟网卡与网络参数" sub="驱动接管、端口映射、外部控制密钥与 UWP 回环">
            <SwitchRow
              title="启用 TUN 虚拟网卡"
              desc={runtime.tun_admin_ready ? "管理员权限已就绪，可接管非代理应用" : "开启 TUN 需要管理员提权（UAC），点击将触发提权提示"}
              checked={runtime.tun_enabled} onChange={(v) => void appActions.toggleTun(v)}
              badge={
                <span className="rounded-md px-1.5 py-0.5 text-[10px]" style={{
                  backgroundColor: runtime.tun_admin_ready ? "var(--green-soft)" : "var(--amber-soft)",
                  color: runtime.tun_admin_ready ? "var(--green)" : "var(--amber)",
                }}>
                  {runtime.tun_admin_ready ? "提权就绪" : "需管理员"}
                </span>
              }
            />
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
              <div className="text-xs font-medium text-[var(--text)]">TUN 协议栈模式</div>
              <SegButtons<TunStackMode>
                mono value={draft.tun_stack_mode} onChange={(v) => patchDraft({ tun_stack_mode: v })}
                options={[["mixed", "mixed"], ["system", "system"], ["gvisor", "gvisor"]]}
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              {(
                [["mixed_port", "混合端口", 17890], ["controller_port", "控制端口", 19090], ["dns_listen_port", "DNS 端口", 11053]] as const
              ).map(([field, label, defVal]) => (
                <label key={field} className="text-[11px] text-[var(--muted)]">
                  {label}
                  <input
                    type="number" value={draft[field]}
                    onChange={(e) => patchDraft({ [field]: Number(e.target.value) || defVal })}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              ))}
            </div>
            <label className="block text-[11px] text-[var(--muted)]">
              外部控制密钥（controller_secret · 留空由核心随机生成）
              <div className="mt-1 flex items-center gap-1.5">
                <input
                  type={showSecret ? "text" : "password"}
                  value={ext.controllerSecret}
                  onChange={(e) => patchExt("controllerSecret", e.target.value)}
                  placeholder="留空自动托管，建议仅在外部 Web UI 需要固定口令时填写"
                  className={`${INPUT_CLS} cc-mono`}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret((v) => !v)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                  title={showSecret ? "隐藏密钥" : "明文查看密钥"}
                  aria-label={showSecret ? "隐藏密钥" : "明文查看密钥"}
                >
                  {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </button>
              </div>
            </label>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <SwitchRow title="允许局域网" desc="向同网段设备共享代理端口" checked={ext.allowLan} onChange={(v) => patchExt("allowLan", v)} />
              <SwitchRow title="统一延迟" desc="去除握手开销，测速更贴近 RTT" checked={draft.unified_delay} onChange={(v) => patchDraft({ unified_delay: v })} />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
              <label className="flex items-center gap-2 text-xs text-[var(--muted)]">
                <span>日志等级</span>
                <select value={ext.logLevel} onChange={(e) => patchExt("logLevel", e.target.value as LogLevel)} className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-xs text-[var(--text)]">
                  {(["silent", "error", "warning", "info", "debug"] as LogLevel[]).map((lv) => <option key={lv} value={lv}>{lv}</option>)}
                </select>
              </label>
              <button type="button" onClick={() => void handleLaunchUwp()} className={BTN_CLS}>
                <Shield className="h-3.5 w-3.5" /><span>UWP 回环解除入口</span>
              </button>
            </div>
          </Card>
        </div>
      )}

      {tab === "dns" && (
        <div className="space-y-4">
          <Card title="IPv6 独立双控" sub="核心 IPv6 与 DNS IPv6 严格分开控制，互不联动">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <SwitchRow title="核心 IPv6 (ipv6)" desc="控制内核转发与出站 IPv6 能力" checked={draft.ipv6_core_enabled} onChange={(v) => patchDraft({ ipv6_core_enabled: v })} />
              <SwitchRow title="DNS IPv6 (dns.ipv6)" desc="独立控制 DNS 解析是否返回 AAAA 记录" checked={draft.ipv6_dns_enabled} onChange={(v) => patchDraft({ ipv6_dns_enabled: v })} />
            </div>
          </Card>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="基础 DNS 与增强模式" sub="覆写、监听、Hosts、respect-rules、HTTP/3 与 Fake-IP 过滤">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <SwitchRow title="覆写 DNS" desc="接管订阅内原始 DNS 配置" checked={ext.overrideDns} onChange={(v) => patchExt("overrideDns", v)} />
                <SwitchRow title="respect-rules" desc="DNS 查询遵循路由分流规则" checked={ext.respectRules} onChange={(v) => patchExt("respectRules", v)} />
                <SwitchRow title="启用 Hosts" desc="启用配置自定义 Hosts" checked={ext.useHosts} onChange={(v) => patchExt("useHosts", v)} />
                <SwitchRow title="使用系统 Hosts" desc="同步加载操作系统 Hosts" checked={ext.useSystemHosts} onChange={(v) => patchExt("useSystemHosts", v)} />
                <SwitchRow title="prefer-h3" desc="DoH 上游优先走 HTTP/3" checked={ext.preferH3} onChange={(v) => patchExt("preferH3", v)} />
                <div className="flex flex-col justify-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
                  <span className="text-[11px] text-[var(--muted)]">增强模式</span>
                  <SegButtons<DnsEnhancedMode> mono value={ext.enhancedMode} onChange={(v) => patchExt("enhancedMode", v)} options={[["fake-ip", "fake-ip"], ["redir-host", "redir-host"]]} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <label className="text-[11px] text-[var(--muted)]">DNS 监听地址<input value={ext.dnsListen} onChange={(e) => patchExt("dnsListen", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
                <label className="text-[11px] text-[var(--muted)]">Fake-IP 网段<input value={ext.fakeIpRange} onChange={(e) => patchExt("fakeIpRange", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
              </div>
              <label className="block text-[11px] text-[var(--muted)]">
                Fake-IP 过滤 (fake-ip-filter)
                <textarea rows={2} value={ext.fakeIpFilter} onChange={(e) => patchExt("fakeIpFilter", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
              </label>
            </Card>

            <Card title="上游解析与 Fallback 过滤" sub="五类解析组与 GeoIP/CN/GeoSite/IP/域名防污染过滤">
              <div className="space-y-2">
                {(
                  [
                    ["defaultNameserver", "default-nameserver"],
                    ["nameserverPolicy", "nameserver-policy"],
                    ["nameserver", "nameserver"],
                    ["fallback", "fallback"],
                    ["proxyServerNameserver", "proxy-server-nameserver"],
                  ] as const
                ).map(([key, label]) => (
                  <label key={key} className="block text-[11px] text-[var(--muted)]">
                    {label}
                    <input value={ext[key]} onChange={(e) => patchExt(key, e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
                  </label>
                ))}
              </div>
              <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
                <div className="flex items-center justify-between text-xs font-medium text-[var(--text)]">
                  <span>Fallback 过滤 (GeoIP / GeoSite / IP / 域名)</span>
                  <Toggle checked={ext.fallbackFilterGeoip} onChange={(v) => patchExt("fallbackFilterGeoip", v)} label="Fallback GeoIP 过滤" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <label className="text-[11px] text-[var(--muted)]">GeoIP 国家码<input value={ext.fallbackFilterGeoipCode} onChange={(e) => patchExt("fallbackFilterGeoipCode", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
                  <label className="text-[11px] text-[var(--muted)]">GeoSite<input value={ext.fallbackFilterGeosite} onChange={(e) => patchExt("fallbackFilterGeosite", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
                </div>
                <label className="block text-[11px] text-[var(--muted)]">IP CIDR 过滤（RFC 5737 示例）<input value={ext.fallbackFilterIpcidr} onChange={(e) => patchExt("fallbackFilterIpcidr", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
                <label className="block text-[11px] text-[var(--muted)]">强制 Fallback 域名<input value={ext.fallbackFilterDomain} onChange={(e) => patchExt("fallbackFilterDomain", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} /></label>
              </div>
            </Card>
          </div>
        </div>
      )}

      {tab === "core" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card
              title="全局附加规则、覆写与启动脚本" sub="编辑全局覆写、启动脚本路径并实时检视编译结果"
              action={
                <button type="button" onClick={() => void handleCompileYaml()} disabled={yamlLoading} className={BTN_CLS}>
                  <Code2 className="h-3.5 w-3.5" /><span>{yamlLoading ? "编译中..." : "编译 YAML 实时预览"}</span>
                </button>
              }
            >
              <label className="block text-[11px] text-[var(--muted)]">
                全局附加规则（每行一条）
                <textarea rows={3} value={ext.appendRules} onChange={(e) => patchExt("appendRules", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
              </label>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="block text-[11px] text-[var(--muted)]">
                  覆写脚本路径 (override_script_path)
                  <input value={ext.overrideScriptPath} placeholder="可选，如 data/scripts/override.js" onChange={(e) => patchExt("overrideScriptPath", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
                </label>
                <label className="block text-[11px] text-[var(--muted)]">
                  启动脚本路径 (startup_script_path)
                  <input value={ext.startupScriptPath} placeholder="可选，核心拉起前执行脚本" onChange={(e) => patchExt("startupScriptPath", e.target.value)} className={`${INPUT_CLS} mt-1 cc-mono`} />
                </label>
              </div>
              {yamlPreview !== null && (
                <div className="rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] p-2.5">
                  <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--muted)]">
                    <span className="truncate">
                      实时编译 YAML 预览（脱敏）{yamlSha ? ` · ${yamlSha.slice(0, 10)}` : ""}
                    </span>
                    <div className="flex shrink-0 items-center gap-2">
                      <button type="button" onClick={() => void copyText(yamlPreview, "编译 YAML")} className="text-[var(--accent)] hover:underline">复制</button>
                      <button type="button" onClick={() => { setYamlPreview(null); setYamlSha(null); }} aria-label="关闭预览"><X className="h-3.5 w-3.5" /></button>
                    </div>
                  </div>
                  <pre className="cc-mono cc-selectable max-h-44 overflow-auto text-[11px] text-[var(--text-secondary)]">{yamlPreview}</pre>
                </div>
              )}
            </Card>

            <Card
              title="地理数据库与 Mihomo 内核治理" sub={`核心：${runtime.core_name} ${runtime.core_version} · ${runtime.running ? "运行中" : "已停止"}`}
              action={
                <button type="button" onClick={() => void handleRefreshGeo("all")} disabled={geoBusy !== null} className={BTN_CLS}>
                  <RefreshCw className={`h-3.5 w-3.5 ${geoBusy === "all" ? "animate-spin" : ""}`} /><span>全部更新</span>
                </button>
              }
            >
              {/* Core lifecycle actions */}
              <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
                <button type="button" disabled={coreOpBusy !== null || runtime.running} onClick={() => void handleCoreAction("start")} className={BTN_CLS}>
                  <Play className="h-3.5 w-3.5 text-[var(--green)]" /><span>启动核心</span>
                </button>
                <button type="button" disabled={coreOpBusy !== null || !runtime.running} onClick={() => void handleCoreAction("stop")} className={BTN_CLS}>
                  <Square className="h-3.5 w-3.5 text-[var(--red)]" /><span>停止核心</span>
                </button>
                <button type="button" disabled={coreOpBusy !== null} onClick={() => void handleCoreAction("restart")} className={BTN_CLS}>
                  <RotateCw className={`h-3.5 w-3.5 ${coreOpBusy === "restart" ? "animate-spin" : ""}`} /><span>重启核心</span>
                </button>
                <button type="button" disabled={coreOpBusy !== null} onClick={() => void handleCoreAction("reload")} className={BTN_CLS}>
                  <RefreshCw className={`h-3.5 w-3.5 ${coreOpBusy === "reload" ? "animate-spin" : ""}`} /><span>热重载配置</span>
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2">
                {([["geoip", "GeoIP.dat"], ["geosite", "GeoSite.dat"], ["mmdb", "Country.mmdb"], ["asn", "GeoLite2-ASN.mmdb"]] as const).map(([key, name]) => (
                  <div key={key} className="flex items-center justify-between rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
                    <div>
                      <div className="text-xs font-medium text-[var(--text)]">{name}</div>
                      <div className="text-[10px] cc-mono text-[var(--muted)]">{geoStamp[key]}</div>
                    </div>
                    <button type="button" onClick={() => void handleRefreshGeo(key)} disabled={geoBusy !== null} title={`刷新 ${name}`} className="rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]">
                      <Database className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
              <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-medium text-[var(--text)]">Mihomo 内存挡位 (MiB)</div>
                  <SegButtons<0 | 48 | 64 | 96>
                    mono
                    value={draft.gomemlimit_mb}
                    onChange={(v) => patchDraft({ gomemlimit_mb: v, memory_tier: tierFromMb(v) })}
                    options={[[0, "自动"], [48, "48"], [64, "64"], [96, "96"]]}
                  />
                </div>
                <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)]/60 pt-2">
                  <input
                    value={coreBinaryPath}
                    onChange={(e) => setCoreBinaryPath(e.target.value)}
                    placeholder="自定义核心路径（如 C:\\path\\to\\mihomo.exe）"
                    className={`${INPUT_CLS} flex-1 cc-mono`}
                  />
                  <button type="button" disabled={coreOpBusy !== null} onClick={() => void handleHotSwapCore()} className={BTN_CLS}>
                    <Cpu className="h-3.5 w-3.5" /><span>热换内核</span>
                  </button>
                </div>
              </div>
            </Card>
          </div>

          <Card title="目录直达、备份导入导出、Web UI 书签与运维复制" sub="快速打开目录、切换外部控制 Web UI 与复制脱敏诊断/代理变量">
            <div className="flex flex-wrap items-center gap-2">
              {(["config", "data", "logs", "core"] as const).map((dir) => (
                <button key={dir} type="button" onClick={() => void handleOpenDir(dir)} className={BTN_CLS}>
                  <FolderOpen className="h-3.5 w-3.5" /><span>{dir} 目录</span>
                </button>
              ))}
              <button type="button" onClick={() => void handleExportBackup()} className={BTN_CLS}><Download className="h-3.5 w-3.5" /><span>导出备份</span></button>
              <button type="button" onClick={() => void handleImportBackup()} className={BTN_CLS}><Upload className="h-3.5 w-3.5" /><span>导入备份</span></button>
            </div>

            {/* WebUI Bookmarks Selector & Quick Add */}
            <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium text-[var(--text)]">Web UI 书签：</span>
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
                  <ExternalLink className="h-3.5 w-3.5" /><span>打开所选 Web UI</span>
                </button>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                <input
                  value={newWebUiName}
                  onChange={(e) => setNewWebUiName(e.target.value)}
                  placeholder="新增书签名称（如 Zashboard）"
                  className={`${INPUT_CLS} sm:col-span-3`}
                />
                <input
                  value={newWebUiTpl}
                  onChange={(e) => setNewWebUiTpl(e.target.value)}
                  placeholder="https://example.invalid/#/setup?hostname={host}&port={port}&secret={secret}"
                  className={`${INPUT_CLS} cc-mono sm:col-span-7`}
                />
                <button
                  type="button"
                  onClick={handleAddWebUiBookmark}
                  className={`${BTN_CLS} justify-center sm:col-span-2`}
                >
                  <Plus className="h-3.5 w-3.5" /><span>添加书签</span>
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)] pt-2.5">
              <span className="text-xs text-[var(--muted)]">终端环境变量：</span>
              {(["powershell", "cmd", "bash"] as const).map((sh) => (
                <button key={sh} type="button" onClick={() => void handleCopyShellEnv(sh)} className={BTN_CLS}>
                  <Terminal className="h-3.5 w-3.5" /><span>{sh.toUpperCase()}</span>
                </button>
              ))}
              <button type="button" onClick={() => void handleCopyDiagnostics()} className={BTN_CLS}>
                <Copy className="h-3.5 w-3.5" /><span>复制脱敏诊断信息</span>
              </button>
            </div>
          </Card>
        </div>
      )}

      {tab === "appearance" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card title="昼夜三段自动主题与壁纸毛玻璃" sub={`北京时间 ${getBeijingTimeLabel()} · 生效主题：${resolvedTheme}`}>
            <SwitchRow
              title="按北京时间自动三段切换" desc="07:00 浅色 / 18:30 暖暗 / 22:30 午夜蓝"
              checked={p.theme_mode === "auto_time"}
              onChange={(auto) => void appActions.updatePersonalization({ theme_mode: auto ? "auto_time" : "warm_dark" }, auto ? "已开启三段自动主题" : "已切回手动主题")}
            />
            <div className="grid grid-cols-3 gap-2">
              {([["light_start", "浅色起点"], ["warm_dark_start", "暖暗起点"], ["midnight_start", "午夜起点"]] as const).map(([f, label]) => (
                <label key={f} className="text-[11px] text-[var(--muted)]">
                  {label}
                  <input type="time" value={p.theme_schedule[f]} onChange={(e) => void appActions.updatePersonalization({ theme_schedule: { ...p.theme_schedule, [f]: e.target.value } })} className={`${INPUT_CLS} mt-1 cc-mono`} />
                </label>
              ))}
            </div>
            <SegButtons<ThemeMode>
              value={p.theme_mode}
              onChange={(m) => void appActions.updatePersonalization({ theme_mode: m }, "主题已切换")}
              options={[["light", "清爽暖纸"], ["warm_dark", "深苔暖金"], ["midnight_blue", "午夜星蓝"]]}
            />
            <label className="block text-[11px] text-[var(--muted)]">
              壁纸路径 / URL（留空关闭壁纸与毛玻璃）
              <div className="mt-1 flex gap-2">
                <input value={p.wallpaper_path ?? ""} placeholder="留空使用纯色零开销模式" onChange={(e) => void appActions.updatePersonalization({ wallpaper_path: e.target.value || null })} className={`${INPUT_CLS} cc-mono`} />
                {p.wallpaper_path && <button type="button" onClick={() => void appActions.updatePersonalization({ wallpaper_path: null }, "已清除壁纸")} className={BTN_CLS}>清除</button>}
              </div>
            </label>
            <div className="grid grid-cols-2 gap-3 text-[11px] text-[var(--muted)]">
              <label>壁纸透明度：{Math.round(p.wallpaper_opacity * 100)}%
                <input type="range" min={0.05} max={0.65} step={0.01} value={p.wallpaper_opacity} onChange={(e) => void appActions.updatePersonalization({ wallpaper_opacity: Number(e.target.value) })} className="mt-1 w-full accent-[var(--accent)]" />
              </label>
              <label>毛玻璃强度：{p.glass_blur_px} px
                <input type="range" min={0} max={24} step={1} value={p.glass_blur_px} onChange={(e) => void appActions.updatePersonalization({ glass_blur_px: Number(e.target.value) })} className="mt-1 w-full accent-[var(--accent)]" />
              </label>
            </div>
          </Card>

          <Card title="动效、托盘图标、启动行为与热键" sub="按需开关动效、启动页、托盘动作与全局快捷键">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <SwitchRow title="全局动效" desc="界面过渡" checked={p.animations_enabled} onChange={(v) => void appActions.updatePersonalization({ animations_enabled: v })} />
              <SwitchRow title="猫猫动效" desc="看板精灵" checked={p.mascot_enabled} onChange={(v) => void appActions.updatePersonalization({ mascot_enabled: v })} />
              <SwitchRow title="曲线动效" desc="流量曲线" checked={p.sparkline_enabled} onChange={(v) => void appActions.updatePersonalization({ sparkline_enabled: v })} />
            </div>
            <div className="space-y-1">
              <div className="text-[11px] text-[var(--muted)]">托盘图标模式</div>
              <SegButtons<TrayIconMode>
                value={p.tray_icon_mode}
                onChange={(m) => void appActions.updatePersonalization({ tray_icon_mode: m }, "托盘图标模式已更新")}
                options={[["auto_ac", "A/C 自动"], ["always_a", "固定 A"], ["always_c", "固定 C"], ["always_pixel", "像素猫饼"]]}
              />
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <label className="text-[11px] text-[var(--muted)]">
                启动默认页面 (startup_page)
                <select
                  value={ext.startupPage}
                  onChange={(e) => patchExt("startupPage", e.target.value)}
                  className={`${INPUT_CLS} mt-1`}
                >
                  {STARTUP_PAGE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </label>
              <label className="text-[11px] text-[var(--muted)]">
                托盘单击动作 (tray_click_action)
                <select
                  value={ext.trayClickAction}
                  onChange={(e) => patchExt("trayClickAction", e.target.value)}
                  className={`${INPUT_CLS} mt-1`}
                >
                  {TRAY_CLICK_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <SwitchRow title="静默启动" desc="仅驻留托盘" checked={draft.silent_start} onChange={(v) => patchDraft({ silent_start: v })} />
              <SwitchRow title="关闭进无窗" desc="省内存驻留" checked={ext.closeToWindowless} onChange={(v) => patchExt("closeToWindowless", v)} />
              <SwitchRow title="开机自启" desc="随系统拉起" checked={draft.autostart_enabled} onChange={(v) => patchDraft({ autostart_enabled: v })} />
            </div>
            <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
              <div className="flex items-center justify-between text-xs font-medium text-[var(--text)]">
                <span className="inline-flex items-center gap-1.5"><Keyboard className="h-3.5 w-3.5 text-[var(--accent)]" />全局热键</span>
                <button
                  type="button"
                  onClick={() =>
                    void catcloudApi
                      .enterWindowlessMode()
                      .then(() => appActions.showToast("已请求进入无窗省内存模式", "info"))
                      .catch((err) => appActions.showToast(`进入无窗模式失败：${formatErrorMessage(err)}`, "warn"))
                  }
                  className="text-[11px] text-[var(--accent)] hover:underline"
                >
                  立即无窗驻留
                </button>
              </div>
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                {Object.entries(ext.hotkeys).map(([k, val]) => (
                  <label key={k} className="flex items-center justify-between gap-2 text-[11px] text-[var(--muted)]">
                    <span className="truncate">{HOTKEY_LABELS[k] ?? k}</span>
                    <input value={val} onChange={(e) => patchExt("hotkeys", { ...ext.hotkeys, [k]: e.target.value })} className="w-28 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-right text-[11px] cc-mono text-[var(--text)]" />
                  </label>
                ))}
              </div>
            </div>
          </Card>
        </div>
      )}

      {tab === "updates" && (
        <div className="space-y-4">
          <Card
            title="GitHub Releases 自动更新" sub={`仓库：${draft.update.repo} · 当前 v${runtime.app_version}`}
            action={
              <button type="button" onClick={() => void handleCheckUpdate()} disabled={checkingUpdate} className={BTN_CLS}>
                <CloudDownload className="h-3.5 w-3.5" /><span>{checkingUpdate ? "检查中..." : "检查更新"}</span>
              </button>
            }
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <label className="text-[11px] text-[var(--muted)]">
                发布仓库
                <input value={draft.update.repo} onChange={(e) => patchDraft({ update: { ...draft.update, repo: e.target.value } })} className={`${INPUT_CLS} mt-1 cc-mono`} />
              </label>
              <label className="text-[11px] text-[var(--muted)]">
                更新策略
                <select value={draft.update.mode} onChange={(e) => patchDraft({ update: { ...draft.update, mode: e.target.value as AppConfig["update"]["mode"] } })} className={`${INPUT_CLS} mt-1`}>
                  <option value="next_launch">下次启动自动更新（默认）</option>
                  <option value="manual">仅手动检查提醒</option>
                  <option value="auto_restart">下载后自动重启</option>
                </select>
              </label>
              <label className="text-[11px] text-[var(--muted)]">
                轮询间隔（分钟）
                <input type="number" min={30} value={draft.update.check_interval_min} onChange={(e) => patchDraft({ update: { ...draft.update, check_interval_min: Math.max(30, Number(e.target.value) || 360) } })} className={`${INPUT_CLS} mt-1 cc-mono`} />
              </label>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--muted)]">
              <label className="inline-flex items-center gap-2">
                <Toggle checked={draft.update.include_prerelease} onChange={(v) => patchDraft({ update: { ...draft.update, include_prerelease: v } })} label="包含预发布版本" />
                <span>包含 Pre-release 预发布版本</span>
              </label>
              <span className="text-[11px]">{updateMsg ?? `上次检查：${runtime.last_update_check ?? "尚未检查"}`}</span>
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card
              title="Agent 辅助友好文档（6 模块四段式）" sub="点击预览或一键复制 Markdown 喂给 AI 协作"
              action={
                <div className="flex gap-1.5">
                  <button type="button" onClick={() => void handleCopyAgentDoc(activeDoc.id, "本节 Markdown", docMd(activeDoc))} className={BTN_CLS}><Copy className="h-3.5 w-3.5" /><span>复制本节</span></button>
                  <button type="button" onClick={() => void handleCopyAgentDoc("all", "全套 6 模块 Markdown", AGENT_DOCS.map(docMd).join("\n\n"))} className={BTN_CLS}><Copy className="h-3.5 w-3.5" /><span>复制全部</span></button>
                </div>
              }
            >
              <SegButtons<string> value={activeDoc.id} onChange={setActiveDocId} options={AGENT_DOCS.map((d) => [d.id, d.title] as const)} />
              <div className="cc-selectable space-y-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-3 text-xs">
                <div><span className="font-semibold text-[var(--accent)]">目标能力：</span>{activeDoc.goal}</div>
                <div><span className="font-semibold text-[var(--accent)]">关键配置项：</span><code className="cc-mono text-[11px] text-[var(--text-secondary)]">{activeDoc.keys}</code></div>
                <div><span className="font-semibold text-[var(--accent)]">推荐操作路径：</span>{activeDoc.workflow}</div>
                <div><span className="font-semibold text-[var(--accent)]">排障与边界：</span>{activeDoc.guardrails}</div>
              </div>
            </Card>

            <Card
              title="无头 catcloud CLI 速查" sub="适用于脚本与 Agent 自动化的零 UI 命令"
              action={
                <button type="button" onClick={() => void copyText(CLI_SNIPPETS.map((s) => `${s.cmd}  # ${s.desc}`).join("\n"), "CLI 速查")} className={BTN_CLS}>
                  <Terminal className="h-3.5 w-3.5" /><span>复制全套</span>
                </button>
              }
            >
              <div className="space-y-1.5">
                {CLI_SNIPPETS.map((item) => (
                  <div key={item.cmd} className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-1.5">
                    <div className="min-w-0">
                      <div className="truncate cc-mono cc-selectable text-xs text-[var(--text)]">{item.cmd}</div>
                      <div className="text-[11px] text-[var(--muted)]">{item.desc}</div>
                    </div>
                    <button type="button" onClick={() => void copyText(item.cmd, "CLI 命令")} title="复制命令" className="shrink-0 rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]">
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
