/**
 * Browser-preview-only mock data and fallback API implementation.
 *
 * IMPORTANT: Never statically import this module from `tauri.ts` or desktop runtime paths.
 * It is dynamically loaded via `await import("./previewMock")` ONLY when `!isTauriEnv()`,
 * keeping ~57 kB of sanitized preview fixtures out of the desktop initial bundle.
 */

import {
  buildShellEnvFallback,
  detectNavigatorOs,
  type ShellEnvKind,
} from "../utils/platform";
import { normalizeUiLanguage, type UiLanguage } from "../i18n/types";
import { formatErrorMessage } from "./errors";
import {
  getPreviewQueryParam,
  hasPreviewTunNeedsAdminFlag,
  hasPreviewUpdateModalFlag,
  isTauriEnv,
} from "./ipc";
import { DEFAULT_APP_CONFIG } from "./normalizers";
import type {
  ProxyMode,
  CoreHealthStatus,
  PreAccelOverrideMode,
  GlobalPreAccelScope,
  AgentPromptMode,
  ProbeKind,
  PreAccelConfig,
  GlobalPreAccelStatus,
  UpdateConfig,
  AppConfig,
  QuickCheckSiteConfig,
  RulesOverrideConfig,
  GatewayExportOptions,
  GatewayExportOutput,
  BulkRulesParseResult,
  FullAppConfig,
  SubscriptionRecord,
  ProxyNode,
  ProbeDefinition,
  ProbeSnapshot,
  MultiGroup,
  StrategySwitchEvent,
  PreAccelRelay,
  TrafficSample,
  SanitizedDiagnosticsDto,
  CoreRuntimeInfo,
  RuntimeInfoDto,
  ExitIpInfo,
  SiteCheckItem,
  SwitchResult,
  ReloadOutcome,
  RunIsolatedProbesResult,
  ProbeProgressEvent,
  PickWallpaperResult,
  RefreshSubscriptionResult,
  RefreshAllSubscriptionsResult,
  PreAccelTestResult,
  PreAccelSpeedTestResult,
  PreAccelComparisonResult,
  CampusPortalStatus,
  ConnectionsSnapshotDto,
  CoreLogLineDto,
  AgentModuleDoc,
  SubscriptionUpdateMode,
  SubscriptionNodesUpdateResult,
  MergeSubscriptionsResult,
  ShareBundlePreview,
  ShareBundleExportOutcome,
  ShareBundleImportOutcome,
  SyncSendSessionDto,
  SyncReceiveSessionDto,
  SyncEncryptedFileExportDto,
  SyncPreviewDto,
  SyncReceivedEvent,
  SyncSessionUpdatedEvent,
  ExportAgentDocOutcome,
  AgentBootstrapPromptDto,
  GithubIssueDraftDto,
  GroupEvaluationReport,
  CompiledYamlPreview,
  MigrationPreviewDto,
  MigrationTextPreviewResult,
  ProcessCandidateDto,
  ProcessInspectResult,
  DesktopAppCandidate,
  LiveCaptureStartDto,
  LiveCaptureEventItem,
  LiveCaptureStatusDto,
  LiveCaptureOutcomeDto,
  RefreshGeoDbResult,
  GeoDataStatusDto,
  AppUpdateCheckResult,
  DownloadAndStageUpdateResult,
  PendingUpdatePromptDto,
  MigrationApplyOutcome,
  DanglingRuleGroupSummary,
  DanglingRulesAudit,
  DanglingRuleRepairReport,
  SkipUpdateResultDto,
  ApplyUpdateRestartResultDto,
  ExportBackupResult,
  ImportBackupResult,
  UwpLoopbackResult,
  HotSwapCoreResult,
} from "./types";

const MOCK_SYNC_QR_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" fill="#fff"/><path fill="#111" d="M2 2h7v7H2zm2 2v3h3V4zm11-2h7v7h-7zm2 2v3h3V4zM2 15h7v7H2zm2 2v3h3v-3zm8-5h4v4h-4zm5 5h5v5h-5z"/></svg>';

const MOCK_SUBSCRIPTIONS: SubscriptionRecord[] = [
  {
    id: "sub-alpha",
    name: "Demo Cloud Alpha",
    kind: "url",
    url_or_cmd: "https://example.invalid/sub/alpha.yaml",
    refresh_interval_sec: 21600,
    traffic_used_bytes: 128 * 1024 * 1024 * 1024,
    traffic_total_bytes: 512 * 1024 * 1024 * 1024,
    expires_at: "2027-06-01",
    last_ok_at: "2026-11-23T04:40:00+08:00",
    last_error: null,
    enabled: true,
  },
  {
    id: "sub-backup",
    name: "Demo Native Pool",
    kind: "file",
    url_or_cmd: "data/subs/demo-native.yaml",
    refresh_interval_sec: 43200,
    traffic_used_bytes: 24 * 1024 * 1024 * 1024,
    traffic_total_bytes: 200 * 1024 * 1024 * 1024,
    expires_at: "2027-09-15",
    last_ok_at: "2026-11-23T04:30:00+08:00",
    last_error: null,
    enabled: true,
  },
];

const MOCK_NODES: ProxyNode[] = [
  {
    id: "node-jp-01",
    sub_id: "sub-alpha",
    name: "JP-Tokyo-01 · 1x",
    protocol: "vless",
    server: "jp01.example.invalid",
    port: 443,
    region_code: "JP",
    multiplier: 1.0,
    is_443_native: true,
    preaccel_override: null,
    tags: ["clean-google", "ai-ready", "native-443"],
    enabled: true,
  },
  {
    id: "node-sg-02",
    sub_id: "sub-alpha",
    name: "SG-Edge-02 · 1x",
    protocol: "trojan",
    server: "sg02.example.invalid",
    port: 8443,
    region_code: "SG",
    multiplier: 1.0,
    is_443_native: false,
    preaccel_override: null,
    tags: ["clean-google", "preaccel"],
    enabled: true,
  },
  {
    id: "node-us-03",
    sub_id: "sub-alpha",
    name: "US-West-03 · 1x",
    protocol: "anytls",
    server: "us03.example.invalid",
    port: 443,
    region_code: "US",
    multiplier: 1.0,
    is_443_native: true,
    preaccel_override: null,
    tags: ["clean-google", "ai-ready"],
    enabled: true,
  },
  {
    id: "node-tw-04",
    sub_id: "sub-backup",
    name: "TW-Home-04 · 3x",
    protocol: "vless",
    server: "tw04.example.invalid",
    port: 443,
    region_code: "TW",
    multiplier: 3.0,
    is_443_native: true,
    preaccel_override: null,
    tags: ["clean-google", "backup-pool"],
    enabled: true,
  },
];

const MOCK_UNLOCKED_ALL: Record<string, boolean> = {
  gemini: true,
  google_ai: true,
  chatgpt: true,
  claude: true,
  windsurf: true,
};
const MOCK_PROBE_BASE = {
  tested_at: "2026-11-23T04:48:00+08:00",
  ok: true,
  loss_pct: 0,
  google_clean: true,
  google_risk_mismatch: false,
  keepalive_60s_ok: true,
  ip_clean: true,
  ip_risk_level: "clean" as const,
  ip_asn: "AS15169 Example Residential ISP",
  ip_risk_flags: null as string | null,
  unlocked_sites: MOCK_UNLOCKED_ALL,
  per_probe_ok: { builtin_unlock_windsurf: true },
  per_probe_detail: {
    builtin_unlock_windsurf: "semantic_windsurf(status=415, ip_risk=clean)",
  },
};
const makeMockProbe = (
  node_id: string,
  latency_ms: number,
  jitter_ms: number,
  up_mbps: number,
  down_mbps: number,
  cf_loc: string,
  yt_gl: string,
  chatgptPing: number
): ProbeSnapshot => ({
  ...MOCK_PROBE_BASE,
  node_id,
  latency_ms,
  jitter_ms,
  up_mbps,
  down_mbps,
  cf_loc,
  yt_gl,
  per_probe_up_mbps: { antigravity: up_mbps },
  per_probe_down_mbps: { dl: down_mbps },
  per_probe_ping_ms: { builtin_latency: latency_ms, chatgpt: chatgptPing },
  per_probe_tested_at: {
    builtin_latency: MOCK_PROBE_BASE.tested_at,
    builtin_upload: MOCK_PROBE_BASE.tested_at,
    builtin_download: MOCK_PROBE_BASE.tested_at,
  },
});

const MOCK_PROBES: Record<string, ProbeSnapshot> = {
  "node-jp-01": makeMockProbe("node-jp-01", 68, 4.2, 14.8, 186.4, "NRT", "JP", 72),
  "node-sg-02": makeMockProbe("node-sg-02", 82, 5.8, 12.1, 162.0, "SIN", "SG", 88),
  "node-us-03": makeMockProbe("node-us-03", 144, 7.5, 11.4, 154.2, "SJC", "US", 148),
  "node-tw-04": makeMockProbe("node-tw-04", 56, 3.1, 24.5, 248.0, "TPE", "TW", 61),
};

const makeMockProbeDef = (
  id: string,
  name: string,
  kind: ProbeKind,
  target_url: string,
  timeout_ms: number,
  expected_status: number | null = 204,
  method = "GET",
  body_regex: string | null = null,
  payload_bytes: number | null = null
): ProbeDefinition => ({
  id,
  name,
  kind,
  target_url,
  method,
  expected_status,
  body_regex,
  payload_bytes,
  timeout_ms,
  builtin: true,
});

const MOCK_PROBE_DEFINITIONS: ProbeDefinition[] = [
  makeMockProbeDef("builtin_latency", "标准连通延迟 204", "latency", "https://cp.cloudflare.com/generate_204", 5000),
  makeMockProbeDef("builtin_google_cn", "Google 侧真值防送中", "google_cn", "https://www.google.com/generate_204", 6000),
  makeMockProbeDef("builtin_upload", "上行吞吐 (512KB 快熔断)", "upload", "https://speed.cloudflare.com/__up", 12000, 200, "POST", null, 512 * 1024),
  makeMockProbeDef("builtin_download", "下行吞吐测速", "download", "https://speed.cloudflare.com/__down?bytes=2097152", 12000, 200, "GET", null, 2 * 1024 * 1024),
  makeMockProbeDef("builtin_keepalive_60s", "60s 静默长连接黑洞检测", "keepalive", "https://cp.cloudflare.com/generate_204", 65000),
  makeMockProbeDef(
    "builtin_unlock_windsurf",
    "Windsurf / Devin AI 纯净解锁",
    "unlock_regex",
    "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage",
    9000,
    null,
    "POST",
    null
  ),
];

const MOCK_GROUPS: MultiGroup[] = [
  {
    id: "grp-ai",
    name: "AI 专线粘性组",
    mode: "sticky_best",
    independent_routing: false,
    match_rules: ["DOMAIN-SUFFIX,googleapis.com", "DOMAIN-SUFFIX,openai.com"],
    member_node_ids: ["node-jp-01", "node-sg-02", "node-us-03"],
    dynamic_filter: { expr: "multiplier <= 1 && google_clean == 1", require_google_clean: true },
    primary_probe_id: "antigravity",
    hard_gates: ["google_clean == 1", "keepalive_ok == 1"],
    trigger_rules: [
      {
        expr: 'probe_up("antigravity") < 2.0',
        consecutive_failures: 2,
        bypass_cooldown_on_disconnect: true,
      },
    ],
    trigger_expr: 'probe_up("antigravity") < 2.0',
    formula_expr:
      "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)",
    fallback_policy: "cross_pool_escalate",
    fallback_pool_id: "grp-backup-3x",
    escalated_since: null,
    recover_probe_interval_sec: 120,
    switch_mode: "force_close_old",
    cooldown_sec: 60,
    hysteresis_pct: 20,
    active_node_id: "node-jp-01",
  },
  {
    id: "grp-media",
    name: "影音下载均衡组",
    mode: "load_balance_consistent_hash",
    independent_routing: false,
    match_rules: ["DOMAIN-SUFFIX,github.com", "DOMAIN-SUFFIX,youtube.com"],
    member_node_ids: ["node-jp-01", "node-sg-02"],
    dynamic_filter: { expr: "multiplier <= 1.5 && google_clean == 1", require_google_clean: true },
    primary_probe_id: "dl",
    hard_gates: ["google_clean == 1"],
    trigger_rules: [],
    trigger_expr: null,
    formula_expr: "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1",
    fallback_policy: "degrade_best_warn",
    fallback_pool_id: null,
    escalated_since: null,
    recover_probe_interval_sec: 120,
    switch_mode: "graceful_new_only",
    cooldown_sec: 60,
    hysteresis_pct: 20,
    active_node_id: "node-sg-02",
  },
  {
    id: "grp-backup-3x",
    name: "备用精选组",
    mode: "sticky_best",
    independent_routing: false,
    match_rules: [],
    member_node_ids: ["node-tw-04"],
    dynamic_filter: null,
    primary_probe_id: "antigravity",
    hard_gates: ["google_clean == 1"],
    trigger_rules: [],
    trigger_expr: null,
    formula_expr: "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1",
    fallback_policy: "strict_circuit_break",
    fallback_pool_id: null,
    escalated_since: null,
    recover_probe_interval_sec: 120,
    switch_mode: "force_close_old",
    cooldown_sec: 60,
    hysteresis_pct: 20,
    active_node_id: "node-tw-04",
  },
];

const MOCK_PREACCEL_RELAYS: PreAccelRelay[] = [
  {
    id: "relay-cn-east",
    name: "CN-East-443 Primary",
    provider: "Demo Relay A",
    region: "CN-East",
    server: "198.51.100.10",
    port: 443,
    protocol: "anytls",
    sni: null,
    skip_cert_verify: true,
    priority: 1,
    expires_at: "2027-05-01",
    enabled: true,
    last_probe_ms: 19,
    last_mbps: 18.6,
    last_up_mbps: 18.6,
    last_down_mbps: 94.2,
  },
  {
    id: "relay-cn-south",
    name: "CN-South-443 Standby",
    provider: "Demo Relay B",
    region: "CN-South",
    server: "198.51.100.11",
    port: 443,
    protocol: "trojan",
    sni: null,
    skip_cert_verify: true,
    priority: 2,
    expires_at: "2027-08-12",
    enabled: true,
    last_probe_ms: 28,
    last_mbps: null,
    last_up_mbps: null,
    last_down_mbps: null,
  },
];

const MOCK_EXIT_IP: ExitIpInfo = {
  ip_masked: "203.0.113.***",
  ip_raw: "203.0.113.10",
  isp: "东京示例线路",
  location: "Tokyo, JP",
  timezone: "Asia/Tokyo (UTC+9)",
  google_clean: true,
  core_running: true,
};

const MOCK_QUICK_SITES: SiteCheckItem[] = [
  { id: "site-google", name: "Google 连通", url: "https://www.google.com/generate_204", latency_ms: 69, ok: true },
  { id: "site-github", name: "GitHub", url: "https://github.com", latency_ms: 112, ok: true },
  { id: "site-youtube", name: "YouTube", url: "https://www.youtube.com", latency_ms: 84, ok: true },
  { id: "site-chatgpt", name: "OpenAI", url: "https://chatgpt.com/cdn-cgi/trace", latency_ms: 95, ok: true },
];

const previewTunNeedsAdmin = !isTauriEnv() && hasPreviewTunNeedsAdminFlag();
const previewUpdateModal = !isTauriEnv() && hasPreviewUpdateModalFlag();

const MOCK_UPDATE_VERSION = "0.1.1";
const MOCK_UPDATE_SHA256 =
  "8f4e2a91c6d07b3f5e1a84c29d0b7e63f1a24c8b9e0d3f5a7c1b2d4e6f8a9012";
const MOCK_UPDATE_SIZE_BYTES = 28_521_267;
const MOCK_UPDATE_NOTES =
  "• 新增后台静默预下载与开屏更新询问弹窗，支持便携版热更新与安装版向导拉起。\n• 支持「跳过此版本」并立即删除预下载包释放磁盘空间。\n• Added SHA-256 verified background pre-download & launch update prompt.";

function setMockSkippedVersion(ver: string | null): void {
  mockConfig.update.skipped_version = ver;
  if (mockFullConfig.update) mockFullConfig.update.skipped_version = ver;
}

function buildMockPendingUpdateDto(
  currentVersion: string,
  repo: string
): PendingUpdatePromptDto {
  const os = detectNavigatorOs();
  const useInstaller = getPreviewQueryParam("update_modal_kind") === "installer" || os !== "windows";
  const cleanRepo = repo.trim().replace(/^\/+|\/+$/g, "") || "JuryBu/CatCloud";
  const platformKey =
    os === "macos"
      ? "darwin-aarch64"
      : os === "linux"
        ? "linux-x86_64"
        : useInstaller
          ? "windows-x86_64"
          : "windows-x86_64-portable";
  const installerFilename = useInstaller
    ? `CatCloud-${MOCK_UPDATE_VERSION}-${os === "macos" ? "darwin-arm64.dmg" : os === "linux" ? "linux-x86_64.AppImage" : "windows-x64-setup.exe"}`
    : null;
  return {
    current_version: currentVersion,
    target_version: MOCK_UPDATE_VERSION,
    kind: useInstaller ? "installer_package" : "portable_zip",
    apply_action: !useInstaller
      ? "portable_restart"
      : os === "linux"
        ? "reveal_archive"
        : "installer_launch",
    archive_sha256: MOCK_UPDATE_SHA256,
    package_size_bytes: MOCK_UPDATE_SIZE_BYTES,
    staged_at: new Date().toISOString(),
    release_notes: MOCK_UPDATE_NOTES,
    release_url: `https://github.com/${cleanRepo}/releases/tag/v${MOCK_UPDATE_VERSION}`,
    platform_key: platformKey,
    installer_filename: installerFilename,
    dismissed_in_session: false,
    is_elevated: getPreviewQueryParam("update_modal_elevated") === "1",
    silent_badge_only: getPreviewQueryParam("update_modal_silent") === "1",
  };
}

let mockPendingUpdate: PendingUpdatePromptDto | null = previewUpdateModal
  ? buildMockPendingUpdateDto("0.1.0", DEFAULT_APP_CONFIG.update.repo)
  : null;
let mockPowerOffTakeoverMemory: [boolean, boolean] | null = null;
const mockUpdateReadyListeners = new Set<(payload: PendingUpdatePromptDto) => void>();
const mockGroupsUpdatedListeners = new Set<() => void>();
const mockRelaysUpdatedListeners = new Set<() => void>();
const mockNodesUpdatedListeners = new Set<() => void>();
const mockNavigateListeners = new Set<(nav: string) => void>();

function emitMockGroupsUpdated(): void {
  for (const listener of mockGroupsUpdatedListeners) {
    try {
      listener();
    } catch {
      /* ignore mock listener error */
    }
  }
}

function emitMockRelaysUpdated(): void {
  for (const listener of mockRelaysUpdatedListeners) {
    try {
      listener();
    } catch {
      /* ignore mock listener error */
    }
  }
}

function emitMockNodesUpdated(): void {
  for (const listener of mockNodesUpdatedListeners) {
    try {
      listener();
    } catch {
      /* ignore mock listener error */
    }
  }
}

let mockConfig: AppConfig = {
  ...structuredClone(DEFAULT_APP_CONFIG),
  system_proxy_enabled: previewTunNeedsAdmin ? true : DEFAULT_APP_CONFIG.system_proxy_enabled,
  tun_enabled: previewTunNeedsAdmin ? true : DEFAULT_APP_CONFIG.tun_enabled,
};
let mockFullConfig: FullAppConfig = {
  allow_lan: false,
  tun: {
    enabled: mockConfig.tun_enabled,
    stack_mode: mockConfig.tun_stack_mode,
  },
  controller_host: "127.0.0.1",
  controller_port: DEFAULT_APP_CONFIG.controller_port,
  controller_secret: null,
  webui_urls: [
    {
      name: "MetaCubeXD",
      url_template: "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}",
    },
    {
      name: "Yacd-meta",
      url_template: "https://yacd.metacubex.one/#/setup?hostname={host}&port={port}&secret={secret}",
    },
  ],
  dns_listen_host: "127.0.0.1",
  dns_listen_port: DEFAULT_APP_CONFIG.dns_listen_port,
  log_level: "info",
  behavior: {
    autostart: DEFAULT_APP_CONFIG.autostart_enabled,
    silent_start: DEFAULT_APP_CONFIG.silent_start,
    minimize_to_tray_on_close: true,
    startup_page: "overview",
    tray_click_action: "toggle_main_window",
  },
  core_runtime: {
    memory_tier: "48MiB",
    compile_all_nodes: false,
    startup_script_path: null,
    quick_check_sites: MOCK_QUICK_SITES.map((s) => ({ id: s.id, name: s.name, url: s.url })),
  },
  preaccel: {
    ...DEFAULT_APP_CONFIG.preaccel,
  },
  rules_override: {
    global_prepend_rules: [],
    global_append_rules: [],
    override_mode: "disabled",
    override_merge_path: null,
    override_script_path: null,
    block_quic_udp_443: true,
    domestic_direct_enabled: true,
    custom_rules_only: false,
    inline_override_yaml: null,
  },
  update: {
    ...DEFAULT_APP_CONFIG.update,
    last_checked_at: null,
  },
};
let mockGroups: MultiGroup[] = structuredClone(MOCK_GROUPS);
let mockNodes: ProxyNode[] = structuredClone(MOCK_NODES);
let mockProbes: Record<string, ProbeSnapshot> = structuredClone(MOCK_PROBES);
let mockProbeDefs: ProbeDefinition[] = structuredClone(MOCK_PROBE_DEFINITIONS);
let mockSubscriptions: SubscriptionRecord[] = structuredClone(MOCK_SUBSCRIPTIONS);
let mockRelays: PreAccelRelay[] = structuredClone(MOCK_PREACCEL_RELAYS);
let mockQuickSites: SiteCheckItem[] = structuredClone(MOCK_QUICK_SITES);
let mockActiveNodeIdx = 0;
let mockUpTotal = 186 * 1024 * 1024;
let mockDownTotal = 1.42 * 1024 * 1024 * 1024;

const MOCK_LOGICAL_RULE_TYPES = new Set(["AND", "OR", "NOT"]);
const MOCK_REGEX_RULE_TYPES = new Set([
  "DOMAIN-REGEX",
  "PROCESS-NAME-REGEX",
  "PROCESS-PATH-REGEX",
]);

function locateMockMihomoRuleTarget(
  trimmed: string
): { target: string; start: number; end: number } | null {
  const firstComma = trimmed.indexOf(",");
  if (firstComma < 0) return null;
  const ruleType = trimmed.slice(0, firstComma).trim().toUpperCase();
  if (!ruleType || ruleType === "SUB-RULE") return null;

  if (ruleType === "MATCH" || ruleType === "FINAL") {
    let start = firstComma + 1;
    while (start < trimmed.length && /\s/.test(trimmed[start])) start += 1;
    const end = trimmed.length;
    const target = trimmed.slice(start, end).trim();
    return target ? { target, start, end } : null;
  }

  if (MOCK_LOGICAL_RULE_TYPES.has(ruleType)) {
    let i = firstComma + 1;
    while (i < trimmed.length && /\s/.test(trimmed[i])) i += 1;
    if (i >= trimmed.length || trimmed[i] !== "(") return null;
    let depth = 0;
    let closeIdx = -1;
    for (; i < trimmed.length; i++) {
      const ch = trimmed[i];
      if (ch === "(") {
        depth += 1;
      } else if (ch === ")") {
        depth -= 1;
        if (depth < 0) return null;
        if (depth === 0) {
          closeIdx = i;
          break;
        }
      }
    }
    if (closeIdx < 0) return null;
    let after = closeIdx + 1;
    while (after < trimmed.length && /\s/.test(trimmed[after])) after += 1;
    if (after >= trimmed.length || trimmed[after] !== ",") return null;
    let targetStart = after + 1;
    while (targetStart < trimmed.length && /\s/.test(trimmed[targetStart])) targetStart += 1;
    const target = trimmed.slice(targetStart).trim();
    if (!target || target.includes(",") || /^(no-resolve|src)$/i.test(target)) {
      return null;
    }
    return { target, start: targetStart, end: trimmed.length };
  }

  // Regex rules and standard rules: scan trailing flags from the right
  let end = trimmed.length;
  while (end > firstComma + 1) {
    const prevComma = trimmed.lastIndexOf(",", end - 1);
    if (prevComma <= firstComma) break;
    const seg = trimmed.slice(prevComma + 1, end).trim();
    if (/^(no-resolve|src)$/i.test(seg)) {
      end = prevComma;
      continue;
    }
    break;
  }
  const targetComma = trimmed.lastIndexOf(",", end - 1);
  if (targetComma <= firstComma) return null;
  if (!MOCK_REGEX_RULE_TYPES.has(ruleType)) {
    const valSegment = trimmed.slice(firstComma + 1, targetComma).trim();
    if (!valSegment) return null;
  }
  let targetStart = targetComma + 1;
  while (targetStart < end && /\s/.test(trimmed[targetStart])) targetStart += 1;
  let targetEnd = end;
  while (targetEnd > targetStart && /\s/.test(trimmed[targetEnd - 1])) targetEnd -= 1;
  const target = trimmed.slice(targetStart, targetEnd);
  return target ? { target, start: targetStart, end: targetEnd } : null;
}

let mockGlobalPreAccel: GlobalPreAccelStatus = {
  running: false,
  mode: "off",
  socks_port: null,
  windivert_available: detectNavigatorOs() === "windows",
  windivert_path: detectNavigatorOs() === "windows" ? "bin/WinDivert64.dll" : null,
  is_elevated: !previewTunNeedsAdmin,
  active_connections: 0,
  total_connections: 0,
  up_bytes: 0,
  down_bytes: 0,
  accelerated_processes: [],
  active_relays: MOCK_PREACCEL_RELAYS.filter((r) => r.enabled).map((r) => r.name),
  last_error: null,
  is_windivert_active: false,
  install_state:
    detectNavigatorOs() === "windows"
      ? previewTunNeedsAdmin
        ? "need_elevation"
        : "ready"
      : "idle",
  process_stats: [],
  verify_state: "idle",
  verify_latency_ms: null,
  verify_message: null,
  verify_checked_at_ms: null,
  detected_security_products:
    detectNavigatorOs() === "windows" ? ["Windows 安全中心（Defender）"] : [],
  security_guidance: null,
  bound_physical_interface: detectNavigatorOs() === "windows" ? "WLAN" : null,
};

let mockRuntime: CoreRuntimeInfo = {
  running: true,
  status: "preaccel",
  core_name: "Mihomo Meta",
  core_version: "v1.19.12-alpha",
  proxy_mode: mockConfig.proxy_mode,
  mixed_port: mockConfig.mixed_port,
  controller_addr: `127.0.0.1:${mockConfig.controller_port}`,
  uptime_sec: 4820,
  rule_count: 1428,
  route_mode: "group",
  active_group_id: "grp-ai",
  active_group_name: "AI 专线粘性组",
  active_node_id: MOCK_NODES[0].id,
  active_node_name: MOCK_NODES[0].name,
  active_node_region: MOCK_NODES[0].region_code,
  active_node_latency_ms: 68,
  active_node_up_mbps: 14.8,
  preaccel_active: true,
  preaccel_enabled: mockConfig.preaccel.enabled,
  preaccel_relay_name: "CN-East-443 Primary",
  preaccel_effective_carrier: mockConfig.preaccel.enabled ? "main_core_proxy_only" : "off",
  standalone_tunnel_suspended_for_tun: false,
  global_preaccel_active: false,
  global_preaccel_mode: "off",
  global_preaccel_socks_port: null,
  global_preaccel_connections: 0,
  global_windivert_active: false,
  preaccel_install_state:
    detectNavigatorOs() === "windows"
      ? previewTunNeedsAdmin
        ? "need_elevation"
        : "ready"
      : "idle",
  global_preaccel_verify_state: "idle",
  global_preaccel_verify_ms: null,
  dns_tls_diagnostics: null,
  node_health_hints: {
    "node-jp-01": { latency_ms: 68, status: "healthy", cooldown_remaining_sec: 0, reason: "", stage: "healthy" },
    "node-sg-02": { latency_ms: 82, status: "healthy", cooldown_remaining_sec: 0, reason: "", stage: "healthy" },
    "node-us-03": { latency_ms: 144, status: "healthy", cooldown_remaining_sec: 0, reason: "", stage: "healthy" },
  },
  captive_portal_required: false,
  system_proxy_enabled: mockConfig.system_proxy_enabled,
  tun_enabled: mockConfig.tun_enabled && !previewTunNeedsAdmin,
  tun_configured: mockConfig.tun_enabled,
  tun_needs_elevation: mockConfig.tun_enabled && previewTunNeedsAdmin,
  tun_admin_ready: !previewTunNeedsAdmin,
  app_version: "0.1.0",
  os_label: "Windows 11 x64",
  autostart_enabled: true,
  portable_mode: true,
  last_update_check: "2026-11-23 04:30",
};

function syncMockPreAccelRuntime(): void {
  const tunConfigured = mockConfig.tun_enabled;
  const tunAdminReady = mockRuntime.tun_admin_ready;
  const effectiveTunEnabled = tunConfigured && tunAdminReady;
  const tunNeedsElevation = tunConfigured && !tunAdminReady;
  const proxyActive =
    mockRuntime.running && (mockRuntime.system_proxy_enabled || effectiveTunEnabled);
  const proxyPreAccelActive = mockRuntime.running && mockConfig.preaccel.enabled;
  const globalActive = mockGlobalPreAccel.running;
  const isWindivertActive = globalActive && mockGlobalPreAccel.mode === "windivert";
  const preaccelActive = proxyPreAccelActive || globalActive;
  const nextStatus: CoreHealthStatus =
    (proxyActive && mockConfig.preaccel.enabled) || globalActive || proxyPreAccelActive
      ? "preaccel"
      : mockRuntime.running
        ? "ok"
        : "idle";

  const activeRelays = mockRelays.filter((r) => r.enabled).map((r) => r.name);
  const suspendedForTun = Boolean(
    effectiveTunEnabled && mockRuntime.running && mockConfig.preaccel.enabled
  );
  const effectiveCarrier = !mockConfig.preaccel.enabled
    ? "off"
    : suspendedForTun
      ? "main_core_tun_suspended_standalone"
      : proxyActive && proxyPreAccelActive
        ? "main_core_proxy_only"
        : isWindivertActive
          ? "standalone_windivert"
          : globalActive && mockGlobalPreAccel.mode === "local_socks5"
            ? "standalone_socks5"
            : "off";
  mockGlobalPreAccel = {
    ...mockGlobalPreAccel,
    mode: suspendedForTun ? "suspended_for_tun" : mockGlobalPreAccel.mode,
    active_relays: activeRelays,
    is_windivert_active: suspendedForTun ? false : isWindivertActive,
  };
  mockRuntime = {
    ...mockRuntime,
    tun_enabled: effectiveTunEnabled,
    tun_configured: tunConfigured,
    tun_needs_elevation: tunNeedsElevation,
    preaccel_enabled: mockConfig.preaccel.enabled,
    preaccel_active: preaccelActive,
    preaccel_relay_name: activeRelays[0] ?? null,
    preaccel_effective_carrier: effectiveCarrier,
    standalone_tunnel_suspended_for_tun: suspendedForTun,
    global_preaccel_active: suspendedForTun ? false : globalActive,
    global_preaccel_mode: mockGlobalPreAccel.mode,
    global_preaccel_socks_port: mockGlobalPreAccel.socks_port,
    global_preaccel_connections: mockGlobalPreAccel.active_connections,
    global_windivert_active: suspendedForTun ? false : isWindivertActive,
    preaccel_install_state: mockGlobalPreAccel.install_state ?? "idle",
    global_preaccel_verify_state: mockGlobalPreAccel.verify_state ?? "idle",
    global_preaccel_verify_ms: mockGlobalPreAccel.verify_latency_ms ?? null,
    status: nextStatus,
  };
}

function startMockGlobalPreAccel(): void {
  const enabledRelays = mockRelays.filter((r) => r.enabled);
  if (enabledRelays.length === 0) {
    throw new Error("请先添加并启用至少一条国内中转线路");
  }
  const os = detectNavigatorOs();
  const useWinDivert =
    os === "windows" && mockGlobalPreAccel.windivert_available && mockGlobalPreAccel.is_elevated;
  const targetSample = (mockConfig.preaccel.global_target_processes ?? []).slice(0, 2);
  const activeProcs = useWinDivert
    ? targetSample.length > 0
      ? targetSample
      : ["mihomo.exe", "xray.exe"]
    : [];
  const nowMs = Date.now();
  mockGlobalPreAccel = {
    ...mockGlobalPreAccel,
    running: true,
    mode: useWinDivert ? "windivert" : "local_socks5",
    socks_port: 17895,
    active_connections: useWinDivert ? 3 : 0,
    total_connections: Math.max(mockGlobalPreAccel.total_connections, useWinDivert ? 14 : 2),
    up_bytes: Math.max(mockGlobalPreAccel.up_bytes, useWinDivert ? 48 * 1024 * 1024 : 0),
    down_bytes: Math.max(mockGlobalPreAccel.down_bytes, useWinDivert ? 12 * 1024 * 1024 : 0),
    accelerated_processes: activeProcs,
    active_relays: enabledRelays.map((r) => r.name),
    last_error: null,
    is_windivert_active: useWinDivert,
    install_state: mockGlobalPreAccel.windivert_available
      ? mockGlobalPreAccel.is_elevated
        ? "ready"
        : "need_elevation"
      : "idle",
    process_stats: useWinDivert
      ? activeProcs.map((procName, idx) => ({
          process_name: procName,
          pid: 14200 + idx * 120,
          detected_by: "local_proxy_listener",
          active_connections: idx === 0 ? 2 : 1,
          total_connections: idx === 0 ? 9 : 5,
          tx_bytes: (32 - idx * 12) * 1024 * 1024,
          rx_bytes: (8 - idx * 3) * 1024 * 1024,
          last_seen_ms: nowMs,
        }))
      : [],
    verify_state: useWinDivert ? "verified" : "idle",
    verify_latency_ms: useWinDivert ? 36 : null,
    verify_message: useWinDivert
      ? "演示模式：实测经由透明拦截与国内 443 中转连通正常（36 ms）"
      : null,
    verify_checked_at_ms: useWinDivert ? nowMs : null,
    detected_security_products:
      os === "windows" ? ["Windows 安全中心（Defender）"] : [],
    security_guidance: null,
    bound_physical_interface: os === "windows" ? "WLAN" : null,
  };
}

function stopMockGlobalPreAccel(): void {
  mockGlobalPreAccel = {
    ...mockGlobalPreAccel,
    running: false,
    mode: "off",
    socks_port: null,
    active_connections: 0,
    last_error: null,
    is_windivert_active: false,
    process_stats: [],
    verify_state: "idle",
    verify_latency_ms: null,
    verify_message: null,
    verify_checked_at_ms: null,
    security_guidance: null,
  };
}

const MOCK_DESKTOP_APPS: DesktopAppCandidate[] = [
  {
    pid: 16420,
    window_title: "OpenProxy Desktop",
    friendly_name: "OpenProxy Desktop",
    process_name: "mihomo-gui.exe",
    exe_path: "C:\\Users\\<USER>\\Apps\\OpenProxy\\mihomo-gui.exe",
    working_dir: "C:\\Users\\<USER>\\AppData\\Roaming\\openproxy",
    related_pids: [16420, 16508],
    is_newly_opened: false,
    likely_proxy_client: true,
  },
  {
    pid: 21804,
    window_title: "Private Tunnel App",
    friendly_name: "Private Tunnel App",
    process_name: "opaque-tunnel.exe",
    exe_path: "C:\\Users\\<USER>\\Apps\\PrivateTunnel\\opaque-tunnel.exe",
    working_dir: "C:\\Users\\<USER>\\AppData\\Local\\private-tunnel",
    related_pids: [21804],
    is_newly_opened: false,
    likely_proxy_client: true,
  },
  {
    pid: 9312,
    window_title: "Windows Terminal",
    friendly_name: "Windows Terminal",
    process_name: "WindowsTerminal.exe",
    exe_path: "C:\\Program Files\\WindowsApps\\WindowsTerminal.exe",
    working_dir: null,
    related_pids: [9312],
    is_newly_opened: false,
    likely_proxy_client: false,
  },
];

interface MockLiveCaptureState {
  sessionId: string;
  targetPid: number;
  targetName: string;
  watchDirs: string[];
  startedAtMs: number;
  supportsPlainNodes: boolean;
}

let mockLiveCapture: MockLiveCaptureState | null = null;

function buildMockCapturedNodes(sessionId: string, targetName: string): ProxyNode[] {
  const safePrefix = targetName.replace(/\s+/g, "-").slice(0, 18) || "Captured";
  return [
    {
      id: `${sessionId}-jp-01`,
      sub_id: sessionId,
      name: `${safePrefix} · JP-Tokyo-01 · 1x`,
      protocol: "vless",
      server: "203.0.113.81",
      port: 443,
      region_code: "JP",
      multiplier: 1.0,
      is_443_native: true,
      preaccel_override: null,
      tags: ["captured", "native-443"],
      enabled: true,
    },
    {
      id: `${sessionId}-sg-02`,
      sub_id: sessionId,
      name: `${safePrefix} · SG-Edge-02 · 1x`,
      protocol: "trojan",
      server: "198.51.100.82",
      port: 8443,
      region_code: "SG",
      multiplier: 1.0,
      is_443_native: false,
      preaccel_override: null,
      tags: ["captured"],
      enabled: true,
    },
    {
      id: `${sessionId}-us-03`,
      sub_id: sessionId,
      name: `${safePrefix} · US-West-03 · 1.5x`,
      protocol: "anytls",
      server: "203.0.113.83",
      port: 443,
      region_code: "US",
      multiplier: 1.5,
      is_443_native: true,
      preaccel_override: null,
      tags: ["captured", "native-443"],
      enabled: true,
    },
  ];
}

/** Generate deterministic-looking smooth mock traffic history for browser preview */
export function generateSeedTrafficSamples(count = 75, intervalMs = 2000): TrafficSample[] {
  const now = Date.now();
  const samples: TrafficSample[] = [];
  let upAccum = mockUpTotal - count * 95_000;
  let downAccum = mockDownTotal - count * 520_000;

  for (let i = count - 1; i >= 0; i--) {
    const t = now - i * intervalMs;
    const phase = (count - i) * 0.19;
    const burst = Math.max(0, Math.sin(phase * 0.45) * 0.6 + Math.cos(phase * 0.21) * 0.4);
    const up = Math.round(42_000 + burst * 290_000 + Math.abs(Math.sin(phase * 1.3)) * 85_000);
    const down = Math.round(180_000 + burst * 1_680_000 + Math.abs(Math.cos(phase * 0.9)) * 420_000);
    upAccum += up * (intervalMs / 1000);
    downAccum += down * (intervalMs / 1000);
    samples.push({
      up_bps: up,
      down_bps: down,
      up_total_bytes: Math.round(upAccum),
      down_total_bytes: Math.round(downAccum),
      connections: 18 + Math.round(burst * 24),
      tunnel_connections: mockConfig.preaccel.enabled ? 4 : 0,
      memory_mb: Number((34.2 + burst * 4.8).toFixed(1)),
      timestamp_ms: t,
    });
  }
  return samples;
}

export const previewApi = {
  async getConfig(): Promise<AppConfig> {
    return structuredClone(mockConfig);
  },

  async saveConfig(next: AppConfig): Promise<AppConfig> {
    const preservedSkippedVersion = mockConfig.update.skipped_version ?? null;
    mockConfig = {
          ...structuredClone(next),
          update: {
            ...structuredClone(next.update),
            skipped_version: preservedSkippedVersion,
          },
        };
    if (!next.preaccel.enabled) {
          stopMockGlobalPreAccel();
        }
    mockRuntime = {
          ...mockRuntime,
          proxy_mode: next.proxy_mode,
          system_proxy_enabled: next.system_proxy_enabled,
          tun_enabled: next.tun_enabled && mockRuntime.tun_admin_ready,
          tun_configured: next.tun_enabled,
          tun_needs_elevation: next.tun_enabled && !mockRuntime.tun_admin_ready,
          mixed_port: next.mixed_port,
        };
    syncMockPreAccelRuntime();
    return structuredClone(mockConfig);
  },

  async markOnboardingCompleted(): Promise<void> {
    mockConfig = {
          ...mockConfig,
          personalization: {
            ...mockConfig.personalization,
            onboarding_completed: true,
          },
        };
  },

  async getFullConfig(): Promise<FullAppConfig> {
    return structuredClone(mockFullConfig);
  },

  async saveFullConfig(next: FullAppConfig): Promise<FullAppConfig> {
    mockFullConfig = structuredClone(next);
    return structuredClone(mockFullConfig);
  },

  async saveExtendedSettings(patch: Record<string, unknown>): Promise<FullAppConfig> {
    if (patch.rules_override && typeof patch.rules_override === "object") {
          const ro = patch.rules_override as RulesOverrideConfig;
          if (typeof ro.inline_override_yaml === "string" && ro.inline_override_yaml.trim().length > 0) {
            const mod = await import("./gatewayMock");
            const yamlErr = mod.validateInlineOverrideYamlMock(ro.inline_override_yaml);
            if (yamlErr) {
              throw new Error(`内联 YAML 覆写校验失败：${yamlErr}`);
            }
          }
        }
    mockFullConfig = {
          ...mockFullConfig,
          ...patch,
          behavior:
            patch.behavior && typeof patch.behavior === "object"
              ? { ...mockFullConfig.behavior, ...(patch.behavior as FullAppConfig["behavior"]) }
              : mockFullConfig.behavior,
          core_runtime:
            patch.core_runtime && typeof patch.core_runtime === "object"
              ? {
                  ...mockFullConfig.core_runtime,
                  ...(patch.core_runtime as FullAppConfig["core_runtime"]),
                }
              : mockFullConfig.core_runtime,
          preaccel:
            patch.preaccel && typeof patch.preaccel === "object"
              ? { ...mockFullConfig.preaccel, ...(patch.preaccel as FullAppConfig["preaccel"]) }
              : mockFullConfig.preaccel,
          rules_override:
            patch.rules_override && typeof patch.rules_override === "object"
              ? {
                  ...mockFullConfig.rules_override,
                  ...(patch.rules_override as RulesOverrideConfig),
                }
              : mockFullConfig.rules_override,
          update:
            patch.update && typeof patch.update === "object"
              ? {
                  ...mockFullConfig.update,
                  ...(patch.update as FullAppConfig["update"]),
                }
              : mockFullConfig.update,
        };
    if (patch.preaccel && typeof patch.preaccel === "object") {
          const prePatch = patch.preaccel as Partial<PreAccelConfig>;
          mockConfig = {
            ...mockConfig,
            preaccel: {
              ...mockConfig.preaccel,
              ...prePatch,
            },
          };
        }
    if (patch.update && typeof patch.update === "object") {
          const updPatch = patch.update as Partial<UpdateConfig>;
          mockConfig = {
            ...mockConfig,
            update: {
              ...mockConfig.update,
              ...updPatch,
            },
          };
        }
    const nestedSites =
          patch.core_runtime &&
          typeof patch.core_runtime === "object" &&
          "quick_check_sites" in patch.core_runtime
            ? (patch.core_runtime as { quick_check_sites?: unknown }).quick_check_sites
            : patch.quick_check_sites;
    if (Array.isArray(nestedSites)) {
          const list = nestedSites as QuickCheckSiteConfig[];
          mockQuickSites = list.map((s) => ({
            id: s.id,
            name: s.name,
            url: s.url,
            latency_ms: mockQuickSites.find((q) => q.id === s.id)?.latency_ms ?? null,
            ok: mockQuickSites.find((q) => q.id === s.id)?.ok ?? null,
          }));
        }
    return structuredClone(mockFullConfig);
  },

  async getRuntimeInfo(): Promise<CoreRuntimeInfo> {
    return { ...mockRuntime };
  },

  async startCore(): Promise<CoreRuntimeInfo> {
    mockRuntime = { ...mockRuntime, running: true };
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async stopCore(): Promise<CoreRuntimeInfo> {
    mockRuntime = { ...mockRuntime, running: false };
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async disableAllProxyAndStopCore(): Promise<RuntimeInfoDto> {
    mockPowerOffTakeoverMemory = [
          Boolean(mockRuntime.system_proxy_enabled || mockConfig.system_proxy_enabled),
          Boolean(mockRuntime.tun_enabled),
        ];
    mockConfig = {
          ...mockConfig,
          system_proxy_enabled: false,
          tun_enabled: false,
        };
    mockRuntime = {
          ...mockRuntime,
          running: false,
          system_proxy_enabled: false,
          tun_enabled: false,
          tun_configured: false,
          tun_needs_elevation: false,
        };
    if (mockConfig.preaccel.enabled && !mockGlobalPreAccel.running) {
          try {
            startMockGlobalPreAccel();
          } catch {
            /* no enabled relay in preview */
          }
        }
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async enableProxyPower(): Promise<CoreRuntimeInfo> {
    const remembered = mockPowerOffTakeoverMemory;
    mockPowerOffTakeoverMemory = null;
    const wantSys = remembered ? remembered[0] : true;
    const wantTun = Boolean(remembered?.[1] && mockRuntime.tun_admin_ready);
    const effSys = wantSys || !wantTun;
    mockConfig = {
          ...mockConfig,
          system_proxy_enabled: effSys,
          tun_enabled: wantTun,
        };
    mockRuntime = {
          ...mockRuntime,
          running: true,
          system_proxy_enabled: effSys,
          tun_enabled: wantTun,
          tun_configured: wantTun,
          tun_needs_elevation: false,
        };
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async consumePendingNav(): Promise<string | null> {
    return null;
  },

  async restartCore(): Promise<CoreRuntimeInfo> {
    mockRuntime = { ...mockRuntime, running: true, uptime_sec: 1 };
    return { ...mockRuntime };
  },

  async reloadCoreConfig(_forceDiskReload = false): Promise<ReloadOutcome> {
    return {
          applied: true,
          level: "l2_hot_reload",
          skipped_unchanged: false,
          rejected: false,
          config_hash: "preview-sha256",
          replayed_groups: mockGroups.length,
          shifted_ports: [],
          warnings: [],
          error: null,
          applied_at: new Date().toISOString(),
        };
  },

  async setProxyMode(mode: ProxyMode): Promise<ProxyMode> {
    mockConfig.proxy_mode = mode;
    mockRuntime.proxy_mode = mode;
    return mode;
  },

  async toggleSystemProxy(enabled: boolean): Promise<boolean> {
    mockConfig.system_proxy_enabled = enabled;
    mockRuntime.system_proxy_enabled = enabled;
    syncMockPreAccelRuntime();
    return enabled;
  },

  async toggleTun(enabled: boolean): Promise<boolean> {
    if (enabled && !mockRuntime.tun_admin_ready) {
          throw new Error("NEEDS_ADMIN: 需要管理员权限才能开启虚拟网卡");
        }
    mockConfig.tun_enabled = enabled;
    mockRuntime.tun_configured = enabled;
    mockRuntime.tun_enabled = enabled && mockRuntime.tun_admin_ready;
    mockRuntime.tun_needs_elevation = enabled && !mockRuntime.tun_admin_ready;
    syncMockPreAccelRuntime();
    return mockRuntime.tun_enabled;
  },

  async switchNextBestNode(groupId = "grp-ai"): Promise<SwitchResult> {
    const prev = mockNodes[mockActiveNodeIdx] ?? MOCK_NODES[0];
    mockActiveNodeIdx = (mockActiveNodeIdx + 1) % Math.max(1, Math.min(3, mockNodes.length));
    const next = mockNodes[mockActiveNodeIdx] ?? MOCK_NODES[0];
    const snap = mockProbes[next.id];
    mockRuntime = {
          ...mockRuntime,
          active_group_id: groupId,
          active_node_id: next.id,
          active_node_name: next.name,
          active_node_region: next.region_code,
          active_node_latency_ms: snap?.latency_ms ?? null,
          active_node_up_mbps: snap?.up_mbps ?? null,
        };
    return {
          group_id: groupId,
          previous_node_id: prev.id,
          active_node_id: next.id,
          active_node_name: next.name,
          active_node_region: next.region_code,
          latency_ms: snap?.latency_ms ?? null,
          up_mbps: snap?.up_mbps ?? null,
          closed_connections: 3,
        };
  },

  async selectGroupNode(groupId: string, nodeId: string, closeOld = true, activateGroup?: boolean): Promise<SwitchResult> {
    const group = mockGroups.find((g) => g.id === groupId);
    const prevId = group?.active_node_id ?? null;
    if (group) group.active_node_id = nodeId;
    const node = mockNodes.find((n) => n.id === nodeId) ?? mockNodes[0];
    const snap = mockProbes[nodeId];
    const shouldActivate =
          activateGroup !== undefined
            ? activateGroup
            : !(
                Boolean(group?.independent_routing) &&
                mockRuntime.route_mode === "group" &&
                Boolean(mockRuntime.active_group_id) &&
                mockRuntime.active_group_id !== groupId
              );
    if (shouldActivate) {
          mockRuntime = {
            ...mockRuntime,
            route_mode: "group",
            active_group_id: groupId,
            active_group_name: group?.name ?? mockRuntime.active_group_name,
            active_node_id: node.id,
            active_node_name: node.name,
            active_node_region: node.region_code,
            active_node_latency_ms: snap?.latency_ms ?? null,
            active_node_up_mbps: snap?.up_mbps ?? null,
          };
        }
    return {
          group_id: groupId,
          previous_node_id: prevId,
          active_node_id: node.id,
          active_node_name: node.name,
          active_node_region: node.region_code,
          latency_ms: snap?.latency_ms ?? null,
          up_mbps: snap?.up_mbps ?? null,
          closed_connections: closeOld ? 2 : 0,
        };
  },

  async setActiveGroup(groupId: string): Promise<CoreRuntimeInfo> {
    const group = mockGroups.find((g) => g.id === groupId);
    if (group) {
          const node =
            mockNodes.find((n) => n.id === group.active_node_id) ??
            mockNodes.find((n) => group.member_node_ids.includes(n.id)) ??
            mockNodes[0];
          const snap = node ? mockProbes[node.id] : undefined;
          mockRuntime = {
            ...mockRuntime,
            route_mode: "group",
            active_group_id: group.id,
            active_group_name: group.name,
            active_node_id: node?.id ?? "",
            active_node_name: node?.name ?? "待选节点",
            active_node_region: node?.region_code ?? "--",
            active_node_latency_ms: snap?.latency_ms ?? null,
            active_node_up_mbps: snap?.up_mbps ?? null,
          };
        }
    return { ...mockRuntime };
  },

  async selectSingleNode(nodeId: string): Promise<CoreRuntimeInfo> {
    const node = mockNodes.find((n) => n.id === nodeId) ?? mockNodes[0];
    if (node) {
          const snap = mockProbes[node.id];
          mockRuntime = {
            ...mockRuntime,
            route_mode: "single",
            active_node_id: node.id,
            active_node_name: node.name,
            active_node_region: node.region_code,
            active_node_latency_ms: snap?.latency_ms ?? null,
            active_node_up_mbps: snap?.up_mbps ?? null,
          };
        }
    return { ...mockRuntime };
  },

  async toggleCapsuleWindow(): Promise<boolean> {
    return false;
  },

  async showMainWindow(): Promise<void> {
    /* no-op in browser preview */
  },

  async enterWindowlessMode(): Promise<void> {
    /* no-op in browser preview */
  },

  async listGroups(): Promise<MultiGroup[]> {
    return structuredClone(mockGroups);
  },

  async upsertMultiGroup(group: MultiGroup): Promise<MultiGroup> {
    const idx = mockGroups.findIndex((g) => g.id === group.id);
    if (idx >= 0) mockGroups[idx] = structuredClone(group);
        else mockGroups.push(structuredClone(group));
    emitMockGroupsUpdated();
    return structuredClone(group);
  },

  async deleteMultiGroup(groupId: string): Promise<boolean> {
    const before = mockGroups.length;
    mockGroups = mockGroups.filter((g) => g.id !== groupId);
    const deleted = mockGroups.length < before;
    if (deleted) emitMockGroupsUpdated();
    return deleted;
  },

  async updateMultiGroupMembers(groupId: string, memberNodeIds: string[]): Promise<MultiGroup> {
    const found = mockGroups.find((g) => g.id === groupId);
    if (!found) throw new Error(`Group ${groupId} not found`);
    found.member_node_ids = [...memberNodeIds];
    emitMockGroupsUpdated();
    return structuredClone(found);
  },

  async listNodes(): Promise<ProxyNode[]> {
    return structuredClone(mockNodes);
  },

  async setNodesPreAccelOverride(nodeIds: string[], overrideMode: PreAccelOverrideMode): Promise<number> {
    const idSet = new Set(nodeIds);
    const val: boolean | null =
          overrideMode === "inherit" ? null : overrideMode === "force_on" ? true : false;
    let updated = 0;
    mockNodes = mockNodes.map((n) => {
          if (!idSet.has(n.id)) return n;
          updated += 1;
          return { ...n, preaccel_override: val };
        });
    return updated;
  },

  async listProbeDefinitions(): Promise<ProbeDefinition[]> {
    return structuredClone(mockProbeDefs);
  },

  async upsertProbeDefinition(probe: ProbeDefinition): Promise<ProbeDefinition> {
    const idx = mockProbeDefs.findIndex((p) => p.id === probe.id);
    if (idx >= 0) mockProbeDefs[idx] = structuredClone(probe);
        else mockProbeDefs.push(structuredClone(probe));
    return structuredClone(probe);
  },

  async deleteProbeDefinition(probeId: string): Promise<boolean> {
    const before = mockProbeDefs.length;
    mockProbeDefs = mockProbeDefs.filter((p) => p.id !== probeId);
    return mockProbeDefs.length < before;
  },

  async listProbeSnapshots(): Promise<Record<string, ProbeSnapshot>> {
    return structuredClone(mockProbes);
  },

  async runIsolatedProbes(nodeIds: string[], _probeIds: string[], maxTier: "latency" | "unlock" | "full" = "full", includeKeepalive = false, usePreaccel?: boolean): Promise<RunIsolatedProbesResult> {
    const nowIso = new Date().toISOString();
    const targetIds = nodeIds.length > 0 ? nodeIds : mockNodes.map((n) => n.id);
    const out: Record<string, ProbeSnapshot> = {};
    const activeRelay = mockRelays.find((r) => r.enabled) ?? null;
    const usedPreaccel = Boolean(usePreaccel && activeRelay);
    for (const id of targetIds) {
          const existing = mockProbes[id];
          out[id] = {
            node_id: id,
            tested_at: nowIso,
            ok: true,
            latency_ms: existing?.latency_ms ?? 72,
            jitter_ms: existing?.jitter_ms ?? 4.1,
            loss_pct: existing?.loss_pct ?? 0,
            up_mbps: maxTier === "full" ? (existing?.up_mbps ?? 12.0) : (existing?.up_mbps ?? null),
            down_mbps: maxTier === "full" ? (existing?.down_mbps ?? 150.0) : (existing?.down_mbps ?? null),
            cf_loc: maxTier === "latency" ? (existing?.cf_loc ?? null) : (existing?.cf_loc ?? "NRT"),
            yt_gl: maxTier === "latency" ? (existing?.yt_gl ?? null) : (existing?.yt_gl ?? "JP"),
            google_clean: maxTier === "latency" ? (existing?.google_clean ?? null) : (existing?.google_clean ?? true),
            google_risk_mismatch: existing?.google_risk_mismatch ?? false,
            keepalive_60s_ok: includeKeepalive ? (existing?.keepalive_60s_ok ?? true) : (existing?.keepalive_60s_ok ?? null),
            unlocked_sites:
              maxTier === "latency"
                ? (existing?.unlocked_sites ?? {})
                : (existing?.unlocked_sites ?? { gemini: true, chatgpt: true, claude: true, windsurf: true }),
            per_probe_ok: {
              ...(existing?.per_probe_ok ?? {}),
              builtin_latency: true,
              ...(maxTier === "full" ? { builtin_upload: true, builtin_download: true } : {}),
            },
            per_probe_up_mbps: existing?.per_probe_up_mbps ?? {},
            per_probe_down_mbps: existing?.per_probe_down_mbps ?? {},
            per_probe_ping_ms: {
              ...(existing?.per_probe_ping_ms ?? {}),
              builtin_latency: existing?.latency_ms ?? 72,
            },
            per_probe_tested_at: {
              ...(existing?.per_probe_tested_at ?? {}),
              builtin_latency: nowIso,
              ...(maxTier === "full"
                ? { builtin_upload: nowIso, builtin_download: nowIso }
                : {}),
            },
          };
          mockProbes[id] = out[id];
        }
    const latencyOkCount = Object.values(out).filter((s) => s.ok && s.latency_ms !== null).length;
    const bandwidthOkCount = Object.values(out).filter(
          (s) => s.ok && s.up_mbps !== null && s.down_mbps !== null
        ).length;
    const keepaliveOkCount = Object.values(out).filter((s) => s.keepalive_60s_ok === true).length;
    const failedCount = Object.values(out).filter((s) => !s.ok).length;
    const untestedCount = Math.max(0, mockNodes.length - Object.keys(mockProbes).length);
    return {
          probed_count: targetIds.length,
          total_count: targetIds.length,
          cancelled: false,
          snapshots: out,
          errors: [],
          core_available: true,
          used_preaccel: usedPreaccel,
          preaccel_relay_name: usedPreaccel ? activeRelay?.name ?? null : null,
          latency_ok_count: latencyOkCount,
          bandwidth_ok_count: bandwidthOkCount,
          keepalive_ok_count: keepaliveOkCount,
          failed_count: failedCount,
          exec_error_count: 0,
          untested_count: untestedCount,
        };
  },

  async cancelIsolatedProbes(): Promise<boolean> {
    return true;
  },

  async pickWallpaperImage(): Promise<PickWallpaperResult> {
    if (typeof document === "undefined" || typeof window === "undefined") {
          throw new Error("当前浏览器预览环境不支持选择本地图片");
        }
    return new Promise<PickWallpaperResult>((resolve, reject) => {
          const input = document.createElement("input");
          input.type = "file";
          input.accept = "image/png,image/jpeg,image/webp,image/gif,image/bmp";
          input.style.position = "fixed";
          input.style.left = "-9999px";
          input.style.opacity = "0";
    
          let settled = false;
          const cleanup = () => {
            window.removeEventListener("focus", onWindowFocus);
            input.remove();
          };
          const finish = (res: PickWallpaperResult) => {
            if (settled) return;
            settled = true;
            cleanup();
            resolve(res);
          };
          const fail = (err: Error) => {
            if (settled) return;
            settled = true;
            cleanup();
            reject(err);
          };
    
          const onWindowFocus = () => {
            window.setTimeout(() => {
              if (!settled && (!input.files || input.files.length === 0)) {
                finish({ cancelled: true, path: null, data_url: null });
              }
            }, 400);
          };
    
          input.addEventListener("cancel", () => {
            finish({ cancelled: true, path: null, data_url: null });
          });
    
          input.addEventListener("change", () => {
            const file = input.files?.[0];
            if (!file) {
              finish({ cancelled: true, path: null, data_url: null });
              return;
            }
            if (!/^image\/(png|jpe?g|webp|gif|bmp)$/i.test(file.type)) {
              fail(new Error("仅支持 PNG、JPG、WebP、GIF 或 BMP 格式图片"));
              return;
            }
            if (file.size > 16 * 1024 * 1024) {
              fail(new Error("图片体积超过 16 MB，请换一张更轻量的图片"));
              return;
            }
            const reader = new FileReader();
            reader.onload = () => {
              const dataUrl = typeof reader.result === "string" ? reader.result : null;
              if (!dataUrl || !/^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i.test(dataUrl)) {
                fail(new Error("读取图片失败或格式不受支持"));
                return;
              }
              mockConfig.personalization.wallpaper_path = dataUrl;
              finish({ cancelled: false, path: dataUrl, data_url: dataUrl });
            };
            reader.onerror = () => {
              fail(new Error("读取本地图片文件失败"));
            };
            reader.readAsDataURL(file);
          });
    
          document.body.appendChild(input);
          window.addEventListener("focus", onWindowFocus, { once: true });
          input.click();
        });
  },

  async resolveWallpaperDataUrl(path: string): Promise<string | null> {
    const trimmed = path.trim();
    if (!trimmed) return null;
    if (/^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i.test(trimmed)) {
          return trimmed;
        }
    return null;
  },

  async listSubscriptions(): Promise<SubscriptionRecord[]> {
    return structuredClone(mockSubscriptions);
  },

  async upsertSubscription(record: SubscriptionRecord): Promise<SubscriptionRecord> {
    const { source: legacySource, ...cleanRecord } = record as SubscriptionRecord & {
          source?: string;
        };
    const payloadRecord: SubscriptionRecord = {
          ...cleanRecord,
          url_or_cmd: cleanRecord.url_or_cmd || legacySource || "",
        };
    const idx = mockSubscriptions.findIndex((s) => s.id === payloadRecord.id);
    if (idx >= 0) mockSubscriptions[idx] = structuredClone(payloadRecord);
        else mockSubscriptions.push(structuredClone(payloadRecord));
    return structuredClone(payloadRecord);
  },

  async deleteSubscription(subId: string): Promise<boolean> {
    const before = mockSubscriptions.length;
    mockSubscriptions = mockSubscriptions.filter((s) => s.id !== subId);
    mockNodes = mockNodes.filter((n) => n.sub_id !== subId);
    const validNodeIds = new Set(mockNodes.map((n) => n.id));
    mockGroups = mockGroups.map((group) => {
          const member_node_ids = group.member_node_ids.filter((id) => validNodeIds.has(id));
          const active_node_id =
            group.active_node_id && validNodeIds.has(group.active_node_id)
              ? group.active_node_id
              : (member_node_ids[0] ?? null);
          return { ...group, member_node_ids, active_node_id };
        });
    const deleted = mockSubscriptions.length < before;
    if (deleted) {
          emitMockNodesUpdated();
          emitMockGroupsUpdated();
        }
    return deleted;
  },

  async renameSubscription(subId: string, newName: string): Promise<SubscriptionRecord> {
    const trimmed = newName.trim();
    if (!trimmed) {
          throw new Error("订阅组名称不能为空");
        }
    const target = mockSubscriptions.find((s) => s.id === subId);
    if (!target) throw new Error(`未找到订阅组：${subId}`);
    target.name = trimmed;
    return structuredClone(target);
  },

  async applyNodesToExistingSubscription(targetSubId: string, nodes: ProxyNode[], mode: SubscriptionUpdateMode): Promise<SubscriptionNodesUpdateResult> {
    const existing = mockNodes.filter((n) => n.sub_id === targetSubId);
    const incomingWithSub = nodes.map((n) => ({ ...n, sub_id: targetSubId }));
    if (mode === "replace_latest") {
          mockNodes = [
            ...mockNodes.filter((n) => n.sub_id !== targetSubId),
            ...incomingWithSub,
          ];
          return {
            sub_id: targetSubId,
            kept_count: 0,
            added_count: incomingWithSub.length,
            replaced_count: existing.length,
            total_count: incomingWithSub.length,
            id_remap: {},
          };
        }
    const existingKeys = new Set(
          existing.map((n) => `${n.protocol}|${n.server.toLowerCase()}|${n.port}`)
        );
    const dedupNew = incomingWithSub.filter(
          (n) => !existingKeys.has(`${n.protocol}|${n.server.toLowerCase()}|${n.port}`)
        );
    mockNodes = [...mockNodes, ...dedupNew];
    return {
          sub_id: targetSubId,
          kept_count: existing.length,
          added_count: dedupNew.length,
          replaced_count: 0,
          total_count: existing.length + dedupNew.length,
          id_remap: {},
        };
  },

  async mergeSubscriptions(params: {
    sourceSubId: string;
    targetSubId: string;
    newTargetName?: string | null;
    deduplicate?: boolean;
    convertTargetToMigrated?: boolean;
  }): Promise<MergeSubscriptionsResult> {
    const target = mockSubscriptions.find((s) => s.id === params.targetSubId);
    if (!target) throw new Error("未找到目标组");
    if (params.newTargetName?.trim()) {
          target.name = params.newTargetName.trim();
        }
    const targetNodes = mockNodes.filter((n) => n.sub_id === params.targetSubId);
    const sourceNodes = mockNodes.filter((n) => n.sub_id === params.sourceSubId);
    const seen = new Set(
          targetNodes.map((n) => `${n.protocol}|${n.server.toLowerCase()}|${n.port}`)
        );
    let moved = 0;
    let deduped = 0;
    const nextNodes: ProxyNode[] = mockNodes.filter((n) => n.sub_id !== params.sourceSubId);
    for (const node of sourceNodes) {
          const fp = `${node.protocol}|${node.server.toLowerCase()}|${node.port}`;
          if ((params.deduplicate ?? true) && seen.has(fp)) {
            deduped += 1;
          } else {
            seen.add(fp);
            moved += 1;
            nextNodes.push({ ...node, sub_id: params.targetSubId });
          }
        }
    mockNodes = nextNodes;
    mockSubscriptions = mockSubscriptions.filter((s) => s.id !== params.sourceSubId);
    return {
          target_sub_id: params.targetSubId,
          source_sub_id: params.sourceSubId,
          moved_count: moved,
          deduplicated_count: deduped,
          total_count: targetNodes.length + moved,
          id_remap: {},
        };
  },

  async exportShareBundleDialog(params: {
    name: string;
    description?: string | null;
    nodeIds: string[];
    relayIds: string[];
  }): Promise<ShareBundleExportOutcome> {
    return {
          cancelled: false,
          path: `${params.name.trim() || "catcloud-share"}.zip`,
          manifest: {
            schema: "catcloud-share/v1",
            name: params.name.trim() || "猫猫云梯分享包",
            created_at: new Date().toISOString(),
            node_count: params.nodeIds.length,
            relay_count: params.relayIds.length,
            description: params.description?.trim() || null,
            sanitized_notice:
              "该分享包仅包含选中的节点与中转连接配置，不含本机日志或订阅原链接；请仅私发给信任的朋友。",
          },
        };
  },

  async pickAndPreviewShareBundle(): Promise<ShareBundlePreview | null> {
    return {
          zip_path: "demo-friend-share.zip",
          manifest: {
            schema: "catcloud-share/v1",
            name: "朋友分享包（演示预览）",
            created_at: new Date().toISOString(),
            node_count: 2,
            relay_count: 1,
            description: "含 2 个示例节点与 1 条国内 443 中转线路",
            sanitized_notice:
              "该分享包采用 catcloud-share/v1 标准格式，请仅导入来自信任朋友的分享包。",
          },
          nodes: structuredClone(MOCK_NODES.slice(0, 2)),
          relays: structuredClone(MOCK_PREACCEL_RELAYS.slice(0, 1)),
          warnings: ["浏览器预览模式：展示模拟 .zip 分享包解析结果"],
          has_readme: true,
        };
  },

  async importShareBundle(params: {
    zipPath: string;
    selectedNodeIds: string[];
    selectedRelayIds: string[];
    targetSubId?: string | null;
    newSubName?: string | null;
    updateMode?: SubscriptionUpdateMode;
  }): Promise<ShareBundleImportOutcome> {
    return {
          imported_nodes: params.selectedNodeIds.length,
          imported_relays: params.selectedRelayIds.length,
          target_sub_id: params.targetSubId ?? "sub-share-preview",
          target_sub_name: params.newSubName?.trim() || "朋友分享包",
          warnings: [],
        };
  },

  async startSyncSendSession(params: {
    name?: string | null;
    description?: string | null;
    nodeIds: string[];
    relayIds: string[];
    includeGroups?: boolean;
    customEndpoint?: string | null;
    ttlSec?: number | null;
    allowMultiple?: boolean;
  }): Promise<SyncSendSessionDto> {
    const customEndpoint = params.customEndpoint?.trim() || null;
    const ttlSec = params.ttlSec ?? 180;
    const allowMultiple = params.allowMultiple ?? false;
    const lanUrl = "http://198.51.100.12:38192";
    return {
          session_id: `mock-send-${Date.now()}`,
          pin_code: "482916",
          lan_urls: [lanUrl],
          custom_endpoint: customEndpoint,
          port: 38192,
          fingerprint: "a1b2c3d4e5f60718293a",
          qr_uri: `catcloud://sync/v1?role=send&u=${encodeURIComponent(customEndpoint || lanUrl)}&pin=482916`,
          qr_svg: MOCK_SYNC_QR_SVG,
          expires_at_unix: Math.floor(Date.now() / 1000) + Math.max(30, ttlSec),
          payload_bytes: 2048 + params.nodeIds.length * 320 + params.relayIds.length * 240,
          allow_multiple: allowMultiple,
        };
  },

  async cancelSyncSendSession(sessionId: string): Promise<boolean> {
    return Boolean(sessionId);
  },

  async exportEncryptedSyncFile(params: {
    name?: string | null;
    description?: string | null;
    nodeIds: string[];
    relayIds: string[];
    includeGroups?: boolean;
  }): Promise<SyncEncryptedFileExportDto> {
    const name = params.name?.trim() || "CatCloud Sync";
    return {
          cancelled: false,
          path: `${name}.ccsync`,
          fingerprint: "f0e1d2c3b4a596877869",
          key_uri: "catcloud://sync-key/v1?fp=f0e1d2c3b4a5&k=MOCK_PREVIEW",
          qr_svg: MOCK_SYNC_QR_SVG,
          payload_bytes: 2304 + params.nodeIds.length * 320 + params.relayIds.length * 240,
          node_count: params.nodeIds.length,
          relay_count: params.relayIds.length,
          group_count: params.includeGroups === false ? 0 : mockGroups.length,
        };
  },

  async startSyncReceiveListener(params?: {
    customEndpoint?: string | null;
    ttlSec?: number | null;
    allowMultiple?: boolean;
  }): Promise<SyncReceiveSessionDto> {
    const customEndpoint = params?.customEndpoint?.trim() || null;
    const ttlSec = params?.ttlSec ?? 180;
    const allowMultiple = params?.allowMultiple ?? false;
    const lanUrl = "http://198.51.100.12:38193";
    return {
          session_id: `mock-recv-${Date.now()}`,
          pin_code: "739154",
          lan_urls: [lanUrl],
          custom_endpoint: customEndpoint,
          port: 38193,
          qr_uri: `catcloud://sync/v1?role=recv&u=${encodeURIComponent(customEndpoint || lanUrl)}&pin=739154`,
          qr_svg: MOCK_SYNC_QR_SVG,
          expires_at_unix: Math.floor(Date.now() / 1000) + Math.max(30, ttlSec),
          allow_multiple: allowMultiple,
        };
  },

  async cancelSyncReceiveSession(sessionId: string): Promise<boolean> {
    return Boolean(sessionId);
  },

  async previewSyncSource(params: {
    sourceInput?: string | null;
    pin?: string | null;
    pendingToken?: string | null;
    pickCcsyncFile?: boolean;
  }): Promise<SyncPreviewDto | null> {
    const nodes = structuredClone(MOCK_NODES.slice(0, 2));
    const relays = structuredClone(MOCK_PREACCEL_RELAYS.slice(0, 1));
    return {
          pending_token: params.pendingToken?.trim() || `mock-pending-${Date.now()}`,
          fingerprint: "a1b2c3d4e5f60718293a",
          group_count: mockGroups.length > 0 ? 1 : 0,
          group_names: mockGroups.length > 0 ? [mockGroups[0].name] : [],
          preview: {
            zip_path: params.pickCcsyncFile ? "demo-sync.ccsync" : params.sourceInput || "lan-sync",
            manifest: {
              schema: "catcloud-share/v1",
              name: "CatCloud Sync",
              created_at: new Date().toISOString(),
              node_count: nodes.length,
              relay_count: relays.length,
              description: null,
              sanitized_notice: "",
            },
            nodes,
            relays,
            warnings: [],
            has_readme: false,
          },
        };
  },

  async applySyncImport(params: {
    pendingToken: string;
    selectedNodeIds: string[];
    selectedRelayIds: string[];
    importGroups?: boolean;
    targetSubId?: string | null;
    newSubName?: string | null;
    updateMode?: SubscriptionUpdateMode;
  }): Promise<ShareBundleImportOutcome> {
    return {
          imported_nodes: params.selectedNodeIds.length,
          imported_relays: params.selectedRelayIds.length,
          target_sub_id: params.targetSubId ?? "sub-sync-preview",
          target_sub_name: params.newSubName?.trim() || "CatCloud Sync",
          warnings: [],
        };
  },

  async refreshSubscription(subId: string, _options?: { bearerSecret?: string | null; endpointUrl?: string | null }): Promise<RefreshSubscriptionResult> {
    const nowIso = new Date().toISOString();
    mockSubscriptions = mockSubscriptions.map((s) =>
          s.id === subId ? { ...s, last_ok_at: nowIso, last_error: null } : s
        );
    return {
          sub_id: subId,
          node_count: mockNodes.filter((n) => n.sub_id === subId).length,
          updated_at: nowIso,
          warnings: [],
        };
  },

  async refreshAllSubscriptions(): Promise<RefreshAllSubscriptionsResult> {
    const nowIso = new Date().toISOString();
    let refreshed = 0;
    mockSubscriptions = mockSubscriptions.map((s) => {
          if (!s.enabled) return s;
          refreshed += 1;
          return { ...s, last_ok_at: nowIso, last_error: null };
        });
    return { refreshed, total_nodes: mockNodes.length, errors: [] };
  },

  async listPreAccelRelays(): Promise<PreAccelRelay[]> {
    return structuredClone(mockRelays);
  },

  async upsertPreAccelRelay(relay: PreAccelRelay): Promise<PreAccelRelay> {
    const idx = mockRelays.findIndex((r) => r.id === relay.id);
    if (idx >= 0) mockRelays[idx] = structuredClone(relay);
        else mockRelays.push(structuredClone(relay));
    emitMockRelaysUpdated();
    return structuredClone(relay);
  },

  async deletePreAccelRelay(relayId: string): Promise<boolean> {
    const before = mockRelays.length;
    mockRelays = mockRelays.filter((r) => r.id !== relayId);
    const deleted = mockRelays.length < before;
    if (deleted) emitMockRelaysUpdated();
    return deleted;
  },

  async togglePreAccel(enabled: boolean): Promise<boolean> {
    if (enabled && !mockRelays.some((r) => r.enabled)) {
          throw new Error(formatErrorMessage("NO_ENABLED_RELAY"));
        }
    mockConfig.preaccel.enabled = enabled;
    if (!enabled) {
          stopMockGlobalPreAccel();
        } else {
          const proxyRunning =
            mockRuntime.running && (mockRuntime.system_proxy_enabled || mockRuntime.tun_enabled);
          if (!proxyRunning) {
            mockConfig.preaccel.global_bypass_enabled = true;
            startMockGlobalPreAccel();
          }
        }
    syncMockPreAccelRuntime();
    return enabled;
  },

  async getGlobalPreAccelStatus(): Promise<GlobalPreAccelStatus> {
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async toggleGlobalPreAccel(enabled: boolean): Promise<GlobalPreAccelStatus> {
    mockConfig.preaccel.global_bypass_enabled = enabled;
    if (enabled) {
          mockConfig.preaccel.enabled = true;
          startMockGlobalPreAccel();
        } else {
          stopMockGlobalPreAccel();
        }
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async updateGlobalPreAccelSettings(scope: GlobalPreAccelScope, targetProcesses: string[], windivertDir: string | null = null): Promise<GlobalPreAccelStatus> {
    const cleanedProcesses = Array.from(
          new Set(targetProcesses.map((s) => s.trim()).filter(Boolean))
        );
    mockConfig.preaccel.global_scope = scope;
    mockConfig.preaccel.global_target_processes = cleanedProcesses;
    mockConfig.preaccel.windivert_dir = windivertDir?.trim() || null;
    if (mockFullConfig.preaccel) {
          mockFullConfig.preaccel.global_scope = scope;
          mockFullConfig.preaccel.global_target_processes = cleanedProcesses;
          mockFullConfig.preaccel.windivert_dir = windivertDir?.trim() || null;
        }
    if (mockGlobalPreAccel.running && mockGlobalPreAccel.mode === "windivert") {
          mockGlobalPreAccel = {
            ...mockGlobalPreAccel,
            accelerated_processes: cleanedProcesses.slice(0, 2),
          };
        }
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async installWinDivertDriver(): Promise<GlobalPreAccelStatus> {
    mockGlobalPreAccel = {
          ...mockGlobalPreAccel,
          windivert_available: true,
          windivert_path: "bin/WinDivert64.dll",
          last_error: null,
        };
    if (mockGlobalPreAccel.running && mockGlobalPreAccel.is_elevated) {
          startMockGlobalPreAccel();
        }
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async relaunchAsAdminForGlobalPreAccel(): Promise<boolean> {
    mockRuntime.tun_admin_ready = true;
    mockGlobalPreAccel = {
          ...mockGlobalPreAccel,
          is_elevated: true,
          windivert_available: true,
          windivert_path: mockGlobalPreAccel.windivert_path ?? "bin/WinDivert64.dll",
        };
    mockConfig.preaccel.enabled = true;
    mockConfig.preaccel.global_bypass_enabled = true;
    startMockGlobalPreAccel();
    syncMockPreAccelRuntime();
    return true;
  },

  async verifyGlobalPreAccel(): Promise<GlobalPreAccelStatus> {
    const nowMs = Date.now();
    if (!mockGlobalPreAccel.running && mockConfig.preaccel.enabled) {
          try {
            startMockGlobalPreAccel();
          } catch {
            /* preserve current mock state when no enabled relay exists */
          }
        }
    mockGlobalPreAccel = {
          ...mockGlobalPreAccel,
          verify_state: "verified",
          verify_latency_ms: 36,
          verify_message: "演示模式：实测经由透明拦截与国内 443 中转连通正常（36 ms）",
          verify_checked_at_ms: nowMs,
          detected_security_products: ["Windows 安全中心（Defender）"],
          security_guidance: null,
          bound_physical_interface: "WLAN",
        };
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async failoverPreAccel(): Promise<string | null> {
    const enabledRelays = [...mockRelays]
          .filter((r) => r.enabled)
          .sort((a, b) => a.priority - b.priority);
    if (enabledRelays.length < 2) return enabledRelays[0]?.id ?? null;
    const next = enabledRelays[1];
    mockConfig = {
          ...mockConfig,
          preaccel: {
            ...mockConfig.preaccel,
            active_relay_id: next.id,
          },
        };
    mockRuntime.preaccel_relay_name = next.name;
    return next.id;
  },

  async selectPreAccelRelay(relayId: string): Promise<string> {
    const found = mockRelays.find((r) => r.id === relayId);
    mockConfig = {
          ...mockConfig,
          preaccel: {
            ...mockConfig.preaccel,
            active_relay_id: relayId,
          },
        };
    if (found) mockRuntime.preaccel_relay_name = found.name;
    return relayId;
  },

  async importMmRelayInput(_raw: string): Promise<PreAccelRelay[]> {
    return structuredClone(mockRelays);
  },

  async testPreAccelRelays(relayIds: string[] | null = null): Promise<PreAccelTestResult[]> {
    const targets = relayIds
          ? mockRelays.filter((r) => relayIds.includes(r.id))
          : mockRelays;
    return targets.map((r) => ({
          relay_id: r.id,
          ok: true,
          latency_ms: r.last_probe_ms ?? 22,
          error: null,
        }));
  },

  async testPreAccelRelaySpeeds(relayIds: string[] | null = null, nodeId: string | null = null): Promise<PreAccelSpeedTestResult[]> {
    const targets = relayIds
          ? mockRelays.filter((r) => relayIds.includes(r.id))
          : mockRelays;
    const chosenNode =
          (nodeId ? mockNodes.find((n) => n.id === nodeId) : null) ??
          (mockRuntime.active_node_id
            ? mockNodes.find((n) => n.id === mockRuntime.active_node_id)
            : null) ??
          mockNodes.find((n) => n.enabled) ??
          mockNodes[0] ??
          null;
    return targets.map((r, idx) => {
          const isPrimary = r.id === "relay-cn-east" || idx === 0;
          const latencyMs = Math.max(12, Math.round(r.last_probe_ms ?? (isPrimary ? 19 : 28)));
          const upMbps = isPrimary ? 18.6 : 12.4;
          const downMbps = isPrimary ? 94.2 : 76.8;
          r.last_probe_ms = latencyMs;
          r.last_up_mbps = upMbps;
          r.last_down_mbps = downMbps;
          r.last_mbps = upMbps;
          return {
            relay_id: r.id,
            relay_name: r.name,
            ok: true,
            latency_ms: latencyMs,
            chain_latency_ms: chosenNode ? latencyMs + 138 : null,
            up_mbps: upMbps,
            down_mbps: downMbps,
            mode: chosenNode ? "via_node" : "relay_direct",
            reference_node_name: chosenNode ? chosenNode.name : null,
            error: null,
          };
        });
  },

  async benchmarkPreAccelComparison(relayId?: string | null, nodeId?: string | null): Promise<PreAccelComparisonResult> {
    const chosenRelay =
          (relayId ? mockRelays.find((r) => r.id === relayId) : null) ??
          mockRelays.find((r) => r.enabled) ??
          mockRelays[0];
    const isUdpOnlyProto = (proto: string) => {
          const p = proto.trim().toLowerCase();
          return p === "hysteria2" || p === "hy2" || p === "hysteria" || p === "tuic" || p === "wireguard";
        };
    const activeRuntimeNode = mockRuntime.active_node_id
          ? mockNodes.find((n) => n.id === mockRuntime.active_node_id) ?? null
          : null;
    let fallbackReason: string | null = null;
    let chosenNode: ProxyNode | undefined;
    if (nodeId) {
          chosenNode =
            mockNodes.find((n) => n.id === nodeId) ??
            activeRuntimeNode ??
            mockNodes.find((n) => n.enabled) ??
            mockNodes[0];
        } else if (activeRuntimeNode && !isUdpOnlyProto(activeRuntimeNode.protocol)) {
          chosenNode = activeRuntimeNode;
        } else {
          chosenNode =
            mockNodes.find((n) => n.enabled && !isUdpOnlyProto(n.protocol)) ??
            mockNodes.find((n) => n.enabled) ??
            mockNodes[0];
          if (activeRuntimeNode && isUdpOnlyProto(activeRuntimeNode.protocol) && chosenNode) {
            fallbackReason = `首页当前节点「${activeRuntimeNode.name}」是纯 UDP 协议无法套 TCP 中转，已自动改测「${chosenNode.name}」`;
          }
        }
    return {
          ok: true,
          relay_id: chosenRelay?.id ?? "relay-cn-east",
          relay_name: chosenRelay?.name ?? "CN-East-443 Primary",
          node_id: chosenNode?.id ?? "node-jp-01",
          node_name: chosenNode?.name ?? "JP-Tokyo-01 · 1x",
          accelerated: {
            ok: true,
            latency_ms: 48,
            up_mbps: 28.4,
            down_mbps: 146.2,
            error: null,
          },
          direct: {
            ok: true,
            latency_ms: 82,
            up_mbps: 3.1,
            down_mbps: 64.8,
            error: null,
          },
          up_boost_ratio: 9.2,
          down_boost_ratio: 2.3,
          fallback_reason: fallbackReason,
          tested_at: new Date().toISOString(),
        };
  },

  async checkCampusPortal(): Promise<CampusPortalStatus> {
    return {
          captive_portal_required: false,
          status_code: 204,
          redirect_location: null,
          bypass_hosts: [],
          checked_at: new Date().toISOString(),
        };
  },

  async getExitIpInfo(): Promise<ExitIpInfo> {
    return { ...MOCK_EXIT_IP };
  },

  async checkQuickSites(): Promise<SiteCheckItem[]> {
    return mockQuickSites.map((s) => ({
          ...s,
          latency_ms: s.latency_ms ?? 85,
          ok: s.ok ?? true,
        }));
  },

  async getActiveConnections(): Promise<ConnectionsSnapshotDto> {
    return {
          download_total: 0,
          upload_total: 0,
          memory: 0,
          connections: [],
        };
  },

  async closeConnection(_id: string): Promise<boolean> {
    return true;
  },

  async closeGroupConnections(_groupName: string): Promise<number> {
    return 0;
  },

  async closeAllConnections(): Promise<number> {
    return 0;
  },

  async getRecentLogs(_limit: number | null = 300): Promise<CoreLogLineDto[]> {
    return [];
  },

  async listAgentDocs(lang?: UiLanguage): Promise<AgentModuleDoc[]> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    const isEn = normalizedLang === "en";
    const docLang = normalizedLang ?? "zh-CN";
    const makePreviewDoc = (
          id: string,
          file_name: string,
          title: string,
          summary: string
        ): AgentModuleDoc => ({
          id,
          module_id: id,
          file_name,
          lang: docLang,
          title,
          summary,
          when_to_use_and_signals: [],
          external_prereqs_and_schema: [],
          gui_and_cli_verification: [],
          rollback_and_troubleshooting: [],
          contract_example: "",
        });
    return [
          makePreviewDoc(
            "troubleshooting",
            "00-general-troubleshooting.md",
            isEn ? "00 · General Troubleshooting & Issue Guide" : "00 · 通用排障总纲与问题反馈",
            isEn
              ? "6-layer read-only diagnostic checklist, competitor conflict checks, and GitHub Issue workflow."
              : "六层只读听诊顺序、竞品残留与端口冲突定位，以及一键向官方仓库反馈 Issue 指引。"
          ),
          makePreviewDoc(
            "onboarding",
            "01-onboarding.md",
            isEn ? "01 · First-Time Setup & Core Concepts" : "01 · 新手从零上手总纲",
            isEn
              ? "Car vs. Fuel analogy, 5 startup states, importing subscriptions/share bundles, and going online."
              : "「猫云是车、订阅是油」核心心智、5 种常见开局状态判断、节点导入与开启代理指南。"
          ),
          makePreviewDoc(
            "preaccel",
            "02-domestic-preaccel.md",
            isEn ? "02 · Domestic 443 Acceleration (0 to 1)" : "02 · 国内提速从 0 到 1 指南",
            isEn
              ? "Self-hosted 443 relay deployment, empty SNI rule, one-click mmrelay://v1 import, and WinDivert verification."
              : "买机选区、放行 443 端口、纯 IP 留空 SNI、服务端一键部署与第三方代理穿透实测。"
          ),
          makePreviewDoc(
            "multigroup",
            "03-multigroup.md",
            isEn ? "03 · Smart Multi-Groups & Failover" : "03 · 智能多选组与自动切线",
            isEn
              ? "Sticky-best anti-IP-hopping for AI tools, plain-language scoring rules, and fallback pools."
              : "粘性最优防 AI 频繁换 IP、大白话规则与公式对照、备用池兜底与健康池冷却机制。"
          ),
          makePreviewDoc(
            "nodes_probes",
            "04-nodes-and-probes.md",
            isEn ? "04 · Nodes, Subscriptions & Background Probes" : "04 · 节点管理与后台测速",
            isEn
              ? "Three probe tiers, Google CN detection, AI unlock checks, and safe subscription update/merge."
              : "三档后台测速（延迟 / 送中+AI / 上下行）、订阅刷新保护、更新已有组与合并去重。"
          ),
          makePreviewDoc(
            "routing_conns",
            "05-routing-and-connections.md",
            isEn ? "05 · Routing Rules, DNS & Live Connections" : "05 · 分流规则、DNS 与实时连接",
            isEn
              ? "Rule vs. Global vs. Direct modes, domestic direct rules, QUIC/DNS guardrails, and connection audit."
              : "规则/全局/直连模式选择、国内软件直连与防漏、实时连接筛选与断开旧连接操作。"
          ),
          makePreviewDoc(
            "network_lifecycle",
            "06-network-and-lifecycle.md",
            isEn ? "06 · Network Stack, Backup & Updates" : "06 · 网络接管、备份与安全更新",
            isEn
              ? "System proxy vs. TUN, memory optimization, sanitized backup/restore, and portable updates."
              : "系统代理与虚拟网卡协同、内核内存优化、一键备份还原与便携版安全升级说明。"
          ),
          makePreviewDoc(
            "share_bundle",
            "07-share-bundle.md",
            isEn ? "07 · Share Bundle (.zip) Spec" : "07 · 好友分享包（.zip）格式与导入",
            isEn
              ? "Human & Agent friendly catcloud-share/v1 zip bundle export, selective import, and privacy rules."
              : "勾选节点与国内中转打包成 .zip 分享给朋友、一键预览导入与隐私安全红线。"
          ),
        ];
  },

  async exportAgentDocs(moduleId: string, _asJson = false, lang?: UiLanguage): Promise<string> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    return `# CatCloud Guide (${moduleId} · ${normalizedLang ?? "zh-CN"})\n\n浏览器预览模式示例文档内容。`;
  },

  async buildAgentBootstrapPrompt(lang?: UiLanguage, currentPage?: string, mode: AgentPromptMode = "autopilot"): Promise<AgentBootstrapPromptDto> {
    const normalizedLang = normalizeUiLanguage(lang ?? mockConfig.personalization.ui_language);
    const resolvedMode: AgentPromptMode =
          mode === "readonly"
            ? "readonly"
            : mode === "troubleshoot_issue"
              ? "troubleshoot_issue"
              : "autopilot";
    const cliPath = "C:\\Users\\<USER>\\Apps\\CatCloud\\cli\\catcloud.exe";
    const dataDir = "C:\\Users\\<USER>\\Apps\\CatCloud\\data";
    const docsIndex = `${dataDir}\\agent_docs\\${normalizedLang}\\INDEX.md`;
    const langDisplay =
          normalizedLang === "en"
            ? "English"
            : normalizedLang === "ja"
              ? "日本語"
              : normalizedLang === "ru"
                ? "Русский"
                : "简体中文";
    const prompt =
          resolvedMode === "readonly"
            ? [
                `请全程使用「${langDisplay}」向我解释，仅执行只读体检与排查，不要擅自改动猫猫云梯（CatCloud）配置。`,
                "",
                `- 可执行 CLI：\`${cliPath}\``,
                `- 数据目录：\`${dataDir}\``,
                `- 随装手册索引：\`${docsIndex}\``,
                `- 当前所在界面：${currentPage || "overview"}`,
                "",
                "## 只读体检约定",
                "1. 先阅读随装手册索引并运行 `catcloud status --json`、`catcloud net doctor --json`、`catcloud config diag --json`。",
                "2. 严禁修改配置、节点、分流或中转，给出清晰的人话诊断结论与可选下一步建议即可。",
                "3. 隐私红线：严禁在回复中复述明文密码、UUID、订阅完整 URL 或真实公网中转 IP。",
              ].join("\n")
            : resolvedMode === "troubleshoot_issue"
              ? [
                  `请全程使用「${langDisplay}」作为我的本机猫猫云梯（CatCloud）排障与反馈 AI 助手，先帮我定位并尝试修复问题，若确认为软件缺陷请帮我整理脱敏 GitHub Issue 提交到 JuryBu/CatCloud。`,
                  "",
                  `- 可执行 CLI：\`${cliPath}\``,
                  `- 数据目录：\`${dataDir}\``,
                  `- 排障手册索引：\`${docsIndex}\`（优先看 \`00-general-troubleshooting.md\`）`,
                  `- 当前所在界面：${currentPage || "overview"}`,
                  "",
                  "## 排障与反馈步骤",
                  "1. 先运行 `status --json`、`config validate --json`、`net doctor --json`、`logs tail --lines 80 --since 30m --json`。",
                  "2. 若检测到悬空分流规则等可安全自愈的配置异常，请用 `config repair-rules` + `config reload --json` 直接修好。",
                  "3. 若为软件本身 Bug，整理脱敏复现报告与诊断摘要，经我确认后可用 `gh issue create --repo JuryBu/CatCloud` 提交（严禁泄露任何密码、UUID、订阅链接或真实中转 IP）。",
                ].join("\n")
              : [
                  `请全程使用「${langDisplay}」与我沟通，我现在授权你作为本机 AI Agent（Codex / Claude Code / Antigravity）全权帮我配置与排查猫猫云梯（CatCloud）。`,
                  "",
                  `- 可执行 CLI：\`${cliPath}\``,
                  `- 数据目录：\`${dataDir}\``,
                  `- 随装手册索引：\`${docsIndex}\``,
                `- 当前所在界面：${currentPage || "overview"}`,
                "",
                "## 全权托管约定",
                "1. 先快速自查：读取随装手册索引并运行 `catcloud status --json` 与 `catcloud net doctor --json` 摸清现状。",
                "2. 直接帮我办好：按我的需求直接调用 CLI 完成订阅导入/旧客户端无损搬家、节点测速优选、智能多选组建立、国内 443 提速部署与网络排障，并在完成后用 CLI 复核验证。",
                "3. 涉及删除数据或外部账号凭据时先向我确认；隐私红线：严禁在回复中复述明文密码、UUID、订阅完整 URL 或真实公网中转 IP。",
              ].join("\n");
    return {
          prompt,
          cli_path: cliPath,
          data_dir: dataDir,
          docs_index_path: docsIndex,
          lang: normalizedLang,
        };
  },

  async exportAgentDocFileDialog(moduleId: string, lang?: UiLanguage): Promise<ExportAgentDocOutcome> {
    const normalizedLang = normalizeUiLanguage(lang ?? mockConfig.personalization.ui_language);
    return {
          cancelled: false,
          path: `catcloud-guide-${moduleId}-${normalizedLang}.md`,
          bytes: 2048,
        };
  },

  async buildGithubIssueUrl(summary?: string | null, _lang?: UiLanguage): Promise<GithubIssueDraftDto> {
    const title = summary?.trim()
          ? `[反馈] ${summary.trim().slice(0, 60)}`
          : "[反馈] 猫猫云梯使用问题反馈";
    const body = [
          "### 问题描述",
          summary?.trim() || "（请简述遇到的问题及复现步骤）",
          "",
          "### 自动脱敏诊断摘要",
          "（已自动复制到剪贴板，请直接在此处按 Ctrl+V 粘贴）",
        ].join("\n");
    const issueUrl = `https://github.com/JuryBu/CatCloud/issues/new?title=${encodeURIComponent(
          title
        )}&body=${encodeURIComponent(body)}`;
    return {
          issue_url: issueUrl,
          clipboard_markdown: `# CatCloud 脱敏环境摘要\n- 版本：v${mockRuntime.app_version}\n- 系统：${mockRuntime.os_label}\n- 模式：${mockRuntime.proxy_mode}\n`,
          title,
        };
  },

  async validateFormulaExpr(expr: string): Promise<boolean> {
    return expr.trim().length > 0;
  },

  async evaluateMultiGroup(groupId: string): Promise<GroupEvaluationReport> {
    const g = mockGroups.find((item) => item.id === groupId) ?? mockGroups[0];
    return {
          group_id: g.id,
          mode: g.mode,
          pool_size: g.member_node_ids.length,
          gate_passed: [],
          healthy_candidates: [],
          gate_rejected: [],
          active_assessment: null,
          all_failed_hard_gates: false,
          all_below_threshold: false,
        };
  },

  async compilePreviewYaml(): Promise<CompiledYamlPreview> {
    const ro = mockFullConfig.rules_override;
    const customOnly = Boolean(ro?.custom_rules_only);
    const prepend = ro?.global_prepend_rules ?? [];
    const append = ro?.global_append_rules ?? [];
    const inlineYaml = (ro?.inline_override_yaml ?? "").trim();
    const previewRules = [
          "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
          "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
          ...prepend,
          ...(customOnly ? [] : ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"]),
          ...append,
          `MATCH,${mockGroups[0]?.name || "DIRECT"}`,
        ];
    const yamlLines = [
          "# CatCloud Browser Preview YAML",
          `mixed-port: ${mockConfig.mixed_port}`,
          `mode: ${mockConfig.proxy_mode}`,
          `# custom_rules_only: ${customOnly ? "true" : "false"}`,
          "rules:",
          ...previewRules.map((r) => `  - ${r}`),
          ...(inlineYaml ? ["", "# --- 内联 YAML 覆写片段 ---", inlineYaml] : []),
        ];
    return {
          yaml: `${yamlLines.join("\n")}\n`,
          sha256: "browser-preview",
          stats: {
            total_rules: previewRules.length,
            total_proxies: mockNodes.length,
            proxy_groups: mockGroups.length,
          },
          validation: { ok: true, issues: [] },
        };
  },

  async exportGatewayYaml(options: GatewayExportOptions): Promise<GatewayExportOutput> {
    const mod = await import("./gatewayMock");
    return mod.buildMockGatewayExportOutput(options, {
          relays: mockRelays,
          nodes: mockNodes,
          groups: mockGroups,
          config: mockConfig,
          fullConfig: mockFullConfig,
        });
  },

  async saveGatewayYamlDialog(options: GatewayExportOptions): Promise<string | null> {
    const mod = await import("./gatewayMock");
    const exported = mod.buildMockGatewayExportOutput(options, {
          relays: mockRelays,
          nodes: mockNodes,
          groups: mockGroups,
          config: mockConfig,
          fullConfig: mockFullConfig,
        });
    const filename =
          options.profile === "relay_fragment"
            ? "catcloud-relay-fragment.yaml"
            : options.profile === "transparent_gateway"
              ? "catcloud-transparent-gateway.yaml"
              : "catcloud-preferred-nodes.yaml";
    if (typeof document !== "undefined" && typeof URL !== "undefined") {
          const blob = new Blob([exported.yaml], { type: "text/yaml;charset=utf-8" });
          const blobUrl = URL.createObjectURL(blob);
          try {
            const link = document.createElement("a");
            link.href = blobUrl;
            link.download = filename;
            link.style.display = "none";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
          } finally {
            window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
          }
        }
    return filename;
  },

  async parseBulkRulesPreview(rawText: string): Promise<BulkRulesParseResult> {
    const mod = await import("./gatewayMock");
    return mod.parseBulkRulesTextFallback(rawText);
  },

  async scanLocalMigrations(): Promise<MigrationPreviewDto[]> {
    return [];
  },

  async pickMigrationDirectory(title = "选择已有代理软件配置目录（只读，不改动原软件）"): Promise<string | null> {
    void title;
    return null;
  },

  async pickMigrationFile(title = "选择代理配置文件（只读，不改动原文件）"): Promise<string | null> {
    void title;
    return null;
  },

  async scanMigrationPath(path: string): Promise<MigrationPreviewDto[]> {
    const cleanPath = path.trim() || "C:\\Users\\<USER>\\Desktop\\demo-profiles\\custom.yaml";
    const segs = cleanPath.split(/[/\\]/).filter(Boolean);
    const folderLabel = segs[segs.length - 1] || "自定义配置";
    return [
          {
            source_kind: "local_file",
            source_path: cleanPath,
            display_name: `自定义目录 · ${folderLabel}`,
            nodes: [
              {
                id: "mig-custom-jp-01",
                sub_id: "sub-mig-custom",
                name: "JP-Tokyo-Custom · 1x",
                protocol: "vless",
                server: "203.0.113.91",
                port: 443,
                region_code: "JP",
                multiplier: 1.0,
                is_443_native: true,
                preaccel_override: null,
                tags: ["migrated", "native-443"],
                enabled: true,
              },
              {
                id: "mig-custom-sg-02",
                sub_id: "sub-mig-custom",
                name: "SG-Edge-Custom · 1.5x",
                protocol: "trojan",
                server: "198.51.100.92",
                port: 8443,
                region_code: "SG",
                multiplier: 1.5,
                is_443_native: false,
                preaccel_override: null,
                tags: ["migrated"],
                enabled: true,
              },
            ],
            prepend_rules: ["DOMAIN-SUFFIX,campus.example.invalid,DIRECT"],
            append_rules: [],
            warnings: ["浏览器预览模式：展示自定义目录只读扫描的模拟结果"],
          },
        ];
  },

  async previewMigrationFromText(name: string, _rawYaml: string): Promise<MigrationTextPreviewResult> {
    return { name, node_count: 0, nodes: [], warnings: [] };
  },

  async applyMigrationNodes(sourceName: string, nodes: ProxyNode[]): Promise<number> {
    const outcome = await this.applyMigrationNodesWithMeta(sourceName, nodes);
    return outcome.imported_count;
  },

  async applyMigrationNodesWithMeta(sourceName: string, nodes: ProxyNode[], options?: {
      includeRules?: boolean;
      prependRules?: string[];
      appendRules?: string[];
      danglingRulePolicy?: "drop" | "rewrite";
    }): Promise<MigrationApplyOutcome> {
    const cleanName = sourceName.trim() || "迁移导入";
    const subId = `sub-migrated-${Date.now()}`;
    const nowIso = new Date().toISOString();
    mockSubscriptions.push({
          id: subId,
          name: cleanName,
          kind: "migrated",
          url_or_cmd: `migrated://${subId}`,
          refresh_interval_sec: 0,
          traffic_used_bytes: 0,
          traffic_total_bytes: 0,
          expires_at: null,
          last_ok_at: nowIso,
          last_error: null,
          enabled: true,
        });
    const reboundNodes = nodes.map((n, idx) => ({
          ...structuredClone(n),
          id: `${subId}-n-${idx + 1}`,
          sub_id: subId,
        }));
    mockNodes.push(...reboundNodes);
    const savedRulesCount = options?.includeRules
          ? (options.prependRules?.length ?? 0) + (options.appendRules?.length ?? 0)
          : 0;
    return {
          imported_count: reboundNodes.length,
          sub_id: subId,
          saved_rules_count: savedRulesCount,
          dropped_dangling_rules_count: 0,
          rewritten_dangling_rules_count: 0,
          dropped_dangling_targets: [],
        };
  },

  async auditDanglingRules(): Promise<DanglingRulesAudit> {
    const validTargets = new Set<string>([
          "DIRECT",
          "REJECT",
          "REJECT-DROP",
          "PASS",
          "COMPATIBLE",
          "🐱 猫猫云梯",
          "单节点直选",
          ...mockGroups.map((g) => g.name.trim()).filter(Boolean),
          ...mockNodes.filter((n) => n.enabled).map((n) => n.name.trim()).filter(Boolean),
        ]);
    const rules = [
          ...(mockFullConfig.rules_override?.global_prepend_rules ?? []),
          ...(mockFullConfig.rules_override?.global_append_rules ?? []),
        ];
    const counts = new Map<string, { count: number; samples: string[] }>();
    let total = 0;
    for (const raw of rules) {
          const trimmed = raw.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          const span = locateMockMihomoRuleTarget(trimmed);
          if (!span) continue;
          const target = span.target;
          if (!target || validTargets.has(target) || validTargets.has(target.toUpperCase())) continue;
          total += 1;
          const cur = counts.get(target) ?? { count: 0, samples: [] };
          cur.count += 1;
          if (cur.samples.length < 3) cur.samples.push(trimmed);
          counts.set(target, cur);
        }
    const groups: DanglingRuleGroupSummary[] = Array.from(counts.entries())
          .map(([target, v]) => ({ target, count: v.count, sample_rules: v.samples }))
          .sort((a, b) => b.count - a.count || a.target.localeCompare(b.target));
    const fallbackGroup =
          mockGroups.find((g) => g.id === mockRuntime.active_group_id)?.name ??
          mockGroups[0]?.name ??
          "🐱 猫猫云梯";
    return {
          total_dangling: total,
          groups,
          default_fallback_group: fallbackGroup,
        };
  },

  async repairDanglingRules(mode: "remove" | "rewrite", targetGroup?: string | null, _restartCoreIfNeeded = true): Promise<DanglingRuleRepairReport> {
    const audit = await this.auditDanglingRules();
    const affected = audit.groups.map((g) => g.target);
    const badSet = new Set(affected);
    const dest = (targetGroup ?? "").trim() || audit.default_fallback_group;
    let removed = 0;
    let rewritten = 0;
    const processList = (list: string[]) => {
          const next: string[] = [];
          for (const raw of list) {
            const trimmed = raw.trim();
            const span = locateMockMihomoRuleTarget(trimmed);
            if (span && badSet.has(span.target)) {
              if (mode === "rewrite") {
                next.push(`${trimmed.slice(0, span.start)}${dest}${trimmed.slice(span.end)}`);
                rewritten += 1;
              } else {
                removed += 1;
              }
            } else {
              next.push(raw);
            }
          }
          return next;
        };
    if (mockFullConfig.rules_override) {
          mockFullConfig.rules_override.global_prepend_rules = processList(
            mockFullConfig.rules_override.global_prepend_rules ?? []
          );
          mockFullConfig.rules_override.global_append_rules = processList(
            mockFullConfig.rules_override.global_append_rules ?? []
          );
        }
    return {
          removed_count: removed,
          rewritten_count: rewritten,
          target_group: mode === "rewrite" ? dest : null,
          affected_targets: affected,
        };
  },

  async listRunningProcesses(_onlyLikelyProxy: boolean): Promise<ProcessCandidateDto[]> {
    return [];
  },

  async inspectProcessSource(pid: number): Promise<ProcessInspectResult> {
    return {
          pid,
          name: "preview-process",
          config_path: null,
          controller_addr: null,
          node_count: 0,
          warnings: [],
        };
  },

  async listDesktopAppCandidates(baselinePids?: number[]): Promise<DesktopAppCandidate[]> {
    const baselineSet =
          Array.isArray(baselinePids) && baselinePids.length > 0
            ? new Set(baselinePids)
            : null;
    return MOCK_DESKTOP_APPS.map((item) => ({
          ...item,
          related_pids: [...item.related_pids],
          is_newly_opened: baselineSet ? !baselineSet.has(item.pid) : false,
        }));
  },

  async startLiveCaptureSession(targetPid: number): Promise<LiveCaptureStartDto> {
    const matched =
          MOCK_DESKTOP_APPS.find((item) => item.pid === targetPid) ?? MOCK_DESKTOP_APPS[0];
    const sessionId = `mock-capture-${Date.now()}`;
    const watchDirs = matched.working_dir ? [matched.working_dir] : [];
    const supportsPlainNodes = matched.process_name !== "opaque-tunnel.exe";
    mockLiveCapture = {
          sessionId,
          targetPid,
          targetName: matched.friendly_name || matched.process_name,
          watchDirs,
          startedAtMs: Date.now(),
          supportsPlainNodes,
        };
    return {
          session_id: sessionId,
          target_pid: targetPid,
          target_name: mockLiveCapture.targetName,
          watch_dirs: [...watchDirs],
        };
  },

  async pollLiveCaptureSession(sessionId: string): Promise<LiveCaptureStatusDto> {
    const session = mockLiveCapture;
    if (!session || session.sessionId !== sessionId) {
          return {
            session_id: sessionId,
            active: false,
            timed_out: false,
            step_app_ready: false,
            step_activity_seen: false,
            step_nodes_ready: false,
            elapsed_sec: 0,
            captured_node_count: 0,
            opaque_change_detected: false,
            target_name: "未知软件",
            watch_dirs: [],
            events: [],
            preview_nodes: [],
            unsupported_reason: null,
          };
        }
    const elapsedSec = Math.max(0, Math.floor((Date.now() - session.startedAtMs) / 1000));
    const timedOut = elapsedSec >= 180;
    const activitySeen = elapsedSec >= 1;
    const nodesReady = session.supportsPlainNodes && elapsedSec >= 2;
    const opaqueDetected = !session.supportsPlainNodes && elapsedSec >= 2;
    const previewNodes = nodesReady
          ? buildMockCapturedNodes(session.sessionId, session.targetName)
          : [];
    const events: LiveCaptureEventItem[] = [
          {
            timestamp_ms: session.startedAtMs,
            kind: "session",
            message: `已锁定「${session.targetName}」并开始只读监听配置变化`,
          },
        ];
    if (activitySeen) {
          events.push({
            timestamp_ms: session.startedAtMs + 1000,
            kind: "activity",
            message: "检测到目标软件正在写入新配置文件…",
          });
        }
    if (nodesReady) {
          events.push({
            timestamp_ms: session.startedAtMs + 2000,
            kind: "nodes",
            message: `已成功抢读 ${previewNodes.length} 个明文节点（演示预览）`,
          });
        } else if (opaqueDetected) {
          events.push({
            timestamp_ms: session.startedAtMs + 2000,
            kind: "opaque",
            message: "检测到加密或私有格式配置变动，暂未读取到明文节点",
          });
        }
    if (timedOut) {
          events.push({
            timestamp_ms: session.startedAtMs + 180_000,
            kind: "warn",
            message: "已达 3 分钟捕捉上限，已自动暂停监控；若已抓到内容可直接点击整理查看结果",
          });
        }
    return {
          session_id: session.sessionId,
          active: !timedOut,
          timed_out: timedOut,
          step_app_ready: true,
          step_activity_seen: activitySeen,
          step_nodes_ready: nodesReady,
          elapsed_sec: elapsedSec,
          captured_node_count: previewNodes.length,
          opaque_change_detected: opaqueDetected,
          target_name: session.targetName,
          watch_dirs: [...session.watchDirs],
          events,
          preview_nodes: previewNodes,
          unsupported_reason: opaqueDetected
            ? "仅检测到加密/非明文配置变动，无法提取节点"
            : null,
        };
  },

  async finishLiveCaptureSession(sessionId: string): Promise<LiveCaptureOutcomeDto> {
    const session = mockLiveCapture;
    mockLiveCapture = null;
    if (!session || session.sessionId !== sessionId || !session.supportsPlainNodes) {
          return {
            session_id: sessionId,
            supported: false,
            target_name: session?.targetName ?? "目标软件",
            source_kind: "none",
            source_path: null,
            is_ephemeral_source: false,
            nodes: [],
            unsupported_reason: "未在目标软件配置变动中检测到可读取的明文节点",
          };
        }
    const nodes = buildMockCapturedNodes(session.sessionId, session.targetName);
    return {
          session_id: sessionId,
          supported: true,
          target_name: session.targetName,
          source_kind: "migrated",
          source_path: session.watchDirs[0] ? `${session.watchDirs[0]}\\runtime.yaml` : null,
          is_ephemeral_source: true,
          nodes,
          unsupported_reason: null,
        };
  },

  async cancelLiveCaptureSession(sessionId: string): Promise<boolean> {
    if (mockLiveCapture?.sessionId === sessionId) {
          mockLiveCapture = null;
        }
    return true;
  },

  async capsuleDragStart(): Promise<boolean> {
    return true;
  },

  async capsuleDragStep(): Promise<boolean> {
    return true;
  },

  async capsuleDragEnd(): Promise<boolean> {
    return true;
  },

  async exportShellEnv(shell: string): Promise<string> {
    const normalized = shell.trim().toLowerCase();
    const kind: ShellEnvKind =
          normalized === "powershell" ||
          normalized === "cmd" ||
          normalized === "bash" ||
          normalized === "zsh" ||
          normalized === "fish"
            ? normalized
            : "bash";
    return buildShellEnvFallback(kind, mockConfig.mixed_port);
  },

  async buildAiOnboardingPrompt(_lang?: UiLanguage, _moduleId?: string | null): Promise<string> {
    const modeLabel =
          mockRuntime.proxy_mode === "rule"
            ? "规则模式（国内直连、海外走代理）"
            : mockRuntime.proxy_mode === "global"
              ? "全局模式（全部走代理）"
              : "直连模式（不走代理）";
    const routeSummary =
          mockRuntime.route_mode === "single"
            ? `单节点模式 → ${mockRuntime.active_node_name || "未选择"}`
            : `智能多选组（${mockRuntime.active_group_name || "未启用"}）→ 当前出口：${mockRuntime.active_node_name || "待选择"}`;
    const proxyOn =
          mockRuntime.running && (mockRuntime.system_proxy_enabled || mockRuntime.tun_enabled);
    const preaccelSummary = mockGlobalPreAccel.is_windivert_active
          ? `已开启（猫猫代理与其它代理软件均在提速中，绑定网卡：${mockGlobalPreAccel.bound_physical_interface ?? "自动"}）`
          : mockRuntime.preaccel_active
            ? `已开启（当前主力中转：${mockRuntime.preaccel_relay_name ?? "已启用中转"}）`
            : "未开启";
    return [
          "# 你好，请做我的「猫猫云梯（CatCloud）」一对一新手向导",
          "",
          "## 给 AI 的引导要求（请务必遵守）",
          "- 我可能是第一次接触代理软件的新手，**不要甩源码、代码术语或命令行黑话**，请全程用通俗大白话解释。",
          "- 请严格结合最下方「我当前的真实进度快照」，先判断我现在卡在哪一步，**每次只教我当下最需要做的下一小步**（最多 2～3 个清晰动作），等我做完反馈你再继续下一步。",
          "- 指路时请直接使用下方列出的**猫猫云梯界面准确中文菜单与按钮名称**，方便我一眼找到。",
          "- 以下信息均已自动隐私脱敏，不包含真实订阅链接、密码或公网 IP。",
          "",
          "## 猫猫云梯 5 大核心玩法与界面准确路径",
          "1. **导入节点（第一步，没有节点时先做这个）**",
          "   - 路径：左侧菜单「**节点与测速**」→ 顶部切到「**订阅与导入**」标签页。",
          "   - 方式 1「**粘贴订阅链接**」：贴入 `https://` 订阅链接或 `clash://install-config?url=...` 一键订阅链接，点「**一键导入**」；若贴的是单节点链接（如 `vless://`、`vmess://`、`trojan://` 等），点提示里的「**转到「粘贴配置文本」导入**」。",
          "   - 方式 2「**从电脑已有梯子导入**」：点「**自动扫描并导入**」，只读复制电脑上已有 Clash Verge / FlClash / v2rayN 的配置，或切到「**粘贴配置文本 / 节点链接**」直接粘贴，绝不改动原软件。",
          "   - 方式 3「**从正在运行的软件抓节点**」：点「**打开 1→2→3 实时捕捉向导**」，选定正在运行（含缩在系统托盘）的专用软件，切去点一次「更新订阅」或「连接」，就能自动抢读可用节点。",
          "2. **节点测速与 AI 解锁体检**",
          "   - 路径：左侧菜单「**节点与测速**」→「**节点与测速**」主表。",
          "   - 特点：所有测速都在独立隔离通道运行，不影响正在打开的网页。支持省流快测延迟、测「延迟 + 谷歌防送中 + ChatGPT / Claude / Gemini / Windsurf 解锁」，或完整测上下行网速。",
          "   - 单节点直用：看中哪条节点直接点行尾「**用它**」固定使用。",
          "3. **智能多选组（混池省流量 + 稳连防 AI 封号）**",
          "   - 路径：左侧菜单「**智能多选组**」。",
          "   - 玩法：把多家订阅的低倍率日常节点放进同一个池子，默认「粘性最优」锁住最快且谷歌不送中的节点（避免 AI 工具因频繁换 IP 触发风控）；异常时自动秒切，主池全掉线时可临时借用高倍率备用组并自动回切。",
          "4. **国内提速（破宽带上传限速 + 加速其它代理软件）**",
          "   - 路径：左侧菜单「**国内提速**」（或在「**总览**」直接点「**国内提速**」开关）。",
          "   - 玩法：导入国内 443 纯 IP 中转后，自动加速非 443 海外节点的上传速度并跳过已是高速通道的原生 443 节点；开启后不仅加速猫猫云梯本身，Windows 下还能自动加速电脑上正在运行的其它代理软件。",
          "5. **总览日常开关、虚拟网卡与省内存**",
          "   - 路径：左侧菜单「**总览**」。",
          "   - 开关：点左上角大按钮「**点击开启代理**」即可上网；日常选「**规则**」模式（国内直连、海外走代理）。",
          "   - 接管方式：「**系统代理**」覆盖浏览器和大多数常见软件；「**虚拟网卡**」可接管终端、游戏与不走系统代理的桌面软件（首次开启按提示授权即可）。",
          "   - 轻量常驻：顶部操作区提供「**悬浮小窗**」和「**托盘省内存**」（关闭主界面仅留右下角托盘图标，大幅降内存）。",
          "",
          "## 我当前的实时进度快照（浏览器演示预览）",
          `- 版本与系统：猫猫云梯 v${mockRuntime.app_version}（${mockRuntime.os_label}）`,
          `- 节点与测速：已导入 **${mockNodes.length}** 个节点，来自 **${mockSubscriptions.length}** 个订阅来源，已有 **${mockGroups.length}** 个智能多选组`,
          `- 代理总开关：**${proxyOn ? "已开启" : "未开启"}**（核心：${mockRuntime.running ? "运行中" : "未启动"} | 模式：${modeLabel}）`,
          `- 接管状态：系统代理 ${mockRuntime.system_proxy_enabled ? "已开启" : "未开启"} ｜ 虚拟网卡 ${mockRuntime.tun_enabled ? "已开启" : mockRuntime.tun_needs_elevation ? "未生效（需管理员权限）" : "未开启"}`,
          `- 当前路线：${routeSummary}`,
          `- 国内提速：${preaccelSummary}`,
          "",
          "请根据我上面的进度，用温和清晰的语言告诉我：**我现在最应该先点哪里、下一步做什么？**",
        ].join("\n");
  },

  async exportSanitizedDiagnostics(): Promise<SanitizedDiagnosticsDto> {
    const aiPromptMarkdown = [
          "# 请帮我排查猫猫云梯（CatCloud）当前问题",
          "",
          "> 以下为自动脱敏后的运行状态与排障指引（演示预览环境）。",
          "",
          "## 1. 当前运行状态摘要",
          `- 版本：v${mockRuntime.app_version}（${mockRuntime.os_label}）`,
          `- 代理核心：${mockRuntime.core_name} ${mockRuntime.core_version}（${mockRuntime.running ? "运行中" : "已停止"}）`,
          `- 代理模式：${mockRuntime.proxy_mode} | 系统代理：${mockRuntime.system_proxy_enabled ? "已开启" : "未开启"} | 虚拟网卡：${mockRuntime.tun_enabled ? "已开启" : mockRuntime.tun_needs_elevation ? "未生效（需管理员权限）" : "未开启"}`,
          `- 当前路线：${mockRuntime.route_mode === "single" ? "单节点模式" : `智能多选组（${mockRuntime.active_group_name}）`} → ${mockRuntime.active_node_name}`,
          `- 国内提速：${mockRuntime.preaccel_active ? `已开启（${mockRuntime.preaccel_relay_name ?? "主力中转"}）` : "未开启"}`,
          `- 本地端口：混合 ${mockConfig.mixed_port} / 控制 127.0.0.1:${mockConfig.controller_port} / DNS ${mockConfig.dns_listen_port}`,
          "",
          "## 2. 本机只读排查 CLI 命令参考",
          "- 查看状态：`catcloud status --json`",
          "- 导出诊断：`catcloud config diag --json`",
          "- 查看多选组：`catcloud group list --json`",
          "- 校验配置：`catcloud config validate --json`",
        ].join("\n");
    return {
          sanitized: true,
          preview: true,
          mixed_port: mockConfig.mixed_port,
          ai_prompt_markdown: aiPromptMarkdown,
        };
  },

  async refreshGeoDb(targets: string[] | null = null): Promise<RefreshGeoDbResult> {
    return {
          ok: true,
          updated_targets: targets ?? ["geoip", "geosite", "mmdb", "asn"],
          message: "浏览器预览模式：已模拟刷新地理库",
          reloaded: true,
        };
  },

  async getGeodataStatus(): Promise<GeoDataStatusDto> {
    return {
          country_mmdb: {
            exists: true,
            size_bytes: 6_420_000,
            updated_at: "2026-11-20T08:00:00Z",
          },
          geoip_dat: {
            exists: true,
            size_bytes: 9_850_000,
            updated_at: "2026-11-22T08:00:00Z",
          },
          geosite_dat: {
            exists: true,
            size_bytes: 4_120_000,
            updated_at: "2026-11-22T08:00:00Z",
          },
          asn_mmdb: {
            exists: true,
            size_bytes: 7_310_000,
            updated_at: "2026-11-18T08:00:00Z",
          },
        };
  },

  async relaunchAsAdmin(enableTun = true): Promise<boolean> {
    mockRuntime.tun_admin_ready = true;
    mockGlobalPreAccel = {
          ...mockGlobalPreAccel,
          is_elevated: true,
          install_state: mockGlobalPreAccel.windivert_available ? "ready" : mockGlobalPreAccel.install_state,
        };
    if (enableTun) {
          mockConfig.tun_enabled = true;
        }
    mockRuntime.tun_configured = mockConfig.tun_enabled;
    mockRuntime.tun_enabled = mockConfig.tun_enabled;
    mockRuntime.tun_needs_elevation = false;
    syncMockPreAccelRuntime();
    return true;
  },

  async checkAppUpdate(): Promise<AppUpdateCheckResult> {
    const os = detectNavigatorOs();
    const platformKey =
          os === "macos"
            ? "darwin-aarch64"
            : os === "linux"
              ? "linux-x86_64"
              : mockRuntime.portable_mode
                ? "windows-x86_64-portable"
                : "windows-x86_64";
    const skippedVersion = mockConfig.update.skipped_version ?? null;
    const baseUrl = `https://github.com/${mockConfig.update.repo}/releases`;
    const simulate = previewUpdateModal || mockPendingUpdate !== null || skippedVersion !== null;
    const tagUrl = `${baseUrl}/tag/v${MOCK_UPDATE_VERSION}`;
    return {
          has_update: simulate,
          current_version: mockRuntime.app_version,
          latest_version: simulate ? MOCK_UPDATE_VERSION : mockRuntime.app_version,
          release_url: simulate ? tagUrl : baseUrl,
          notes: simulate ? MOCK_UPDATE_NOTES : "",
          checked_at: new Date().toISOString(),
          staged_version: simulate ? (mockPendingUpdate?.target_version ?? null) : null,
          platform_key: mockPendingUpdate?.platform_key ?? platformKey,
          can_auto_stage: true,
          download_url: simulate ? tagUrl : null,
          skipped: simulate && skippedVersion === MOCK_UPDATE_VERSION,
          skipped_version: skippedVersion,
        };
  },

  async downloadAndStageUpdate(): Promise<DownloadAndStageUpdateResult> {
    const nextPending = buildMockPendingUpdateDto(mockRuntime.app_version, mockConfig.update.repo);
    mockPendingUpdate = nextPending;
    setMockSkippedVersion(null);
    for (const cb of mockUpdateReadyListeners) {
          try {
            cb(structuredClone(nextPending));
          } catch {
            /* ignore */
          }
        }
    const releaseUrl =
          nextPending.release_url ?? `https://github.com/${mockConfig.update.repo}/releases`;
    return {
          staged: true,
          already_latest: false,
          can_auto_stage: true,
          target_version: nextPending.target_version,
          archive_sha256: nextPending.archive_sha256,
          release_url: releaseUrl,
          download_url: releaseUrl,
          message: `预览：已校验 v${nextPending.target_version}，可确认更新`,
        };
  },

  async getPendingStagedUpdate(): Promise<PendingUpdatePromptDto | null> {
    return mockPendingUpdate ? structuredClone(mockPendingUpdate) : null;
  },

  async dismissUpdatePromptForSession(version: string): Promise<boolean> {
    const v = version.trim().replace(/^[vV]/, "");
    if (mockPendingUpdate && (!v || mockPendingUpdate.target_version === v)) {
          mockPendingUpdate = { ...mockPendingUpdate, dismissed_in_session: true };
        }
    return true;
  },

  async skipUpdateVersion(version: string): Promise<SkipUpdateResultDto> {
    const v = version.trim().replace(/^[vV]/, "") || MOCK_UPDATE_VERSION;
    const purged = mockPendingUpdate !== null;
    const freed_bytes = mockPendingUpdate?.package_size_bytes ?? 0;
    mockPendingUpdate = null;
    setMockSkippedVersion(v);
    return {
          skipped_version: v,
          purged_staged: purged,
          freed_bytes,
          message: purged ? `已跳过 v${v} 并删除预下载包` : `已跳过 v${v}`,
        };
  },

  async clearSkippedUpdateVersion(): Promise<boolean> {
    setMockSkippedVersion(null);
    return true;
  },

  async applyStagedUpdateAndRestart(): Promise<ApplyUpdateRestartResultDto> {
    if (!mockPendingUpdate) throw new Error("当前没有已校验的预下载更新包");
    if (getPreviewQueryParam("update_modal_error") === "1") {
          throw new Error("预览模拟：安装包被占用");
        }
    const cancelled = getPreviewQueryParam("update_modal_cancel") === "1";
    return {
          started: !cancelled,
          exiting: false,
          cancelled,
          kind: mockPendingUpdate.kind,
          apply_action: mockPendingUpdate.apply_action,
          target_version: mockPendingUpdate.target_version,
          message: cancelled
            ? "已取消安装，当前代理未受影响"
            : `预览：已模拟启动 v${mockPendingUpdate.target_version} 更新流程`,
        };
  },

  async exportBackupBundle(targetPath: string | null = null): Promise<ExportBackupResult> {
    return {
          path: targetPath ?? "catcloud-backup.json",
          bytes: 0,
          sha256: "browser-preview",
          exported_at: new Date().toISOString(),
        };
  },

  async importBackupBundle(_bundleJson: string): Promise<ImportBackupResult> {
    return {
          restored_config: true,
          restored_groups: mockGroups.length,
          restored_relays: mockRelays.length,
          message: "浏览器预览模式：已模拟导入备份",
        };
  },

  async launchUwpLoopback(): Promise<UwpLoopbackResult> {
    return {
          supported: false,
          launched: false,
          message: "浏览器预览模式无法拉起本机 UWP 回环工具",
        };
  },

  async hotSwapCore(binaryPath: string): Promise<HotSwapCoreResult> {
    return {
          ok: true,
          version: mockRuntime.core_version,
          sha256: "browser-preview",
          binary_path: binaryPath,
          message: "浏览器预览模式：已模拟内核热换",
        };
  },

  async openAppDir(kind: string): Promise<string> {
    return `data/${kind}`;
  },

  async openWebUi(url: string | null = null): Promise<string> {
    return url ?? `http://127.0.0.1:${mockConfig.controller_port}/ui`;
  },

  async openExternalUrl(url: string): Promise<string> {
    const trimmed = url.trim();
    if (!trimmed) {
          throw new Error("外部链接不能为空");
        }
    if (typeof window !== "undefined") {
          window.open(trimmed, "_blank", "noopener,noreferrer");
        }
    return trimmed;
  },

  async getTrafficHistory(): Promise<TrafficSample[]> {
    return [];
  },

  subscribeTraffic(onSample: (sample: TrafficSample) => void): () => void {
    let disposed = false;
    let step = 80;
    const mockTimer = window.setInterval(() => {
      if (disposed || document.visibilityState !== "visible") return;
      step += 1;
      const wave = Math.max(0, Math.sin(step * 0.17) * 0.55 + Math.cos(step * 0.09) * 0.45);
      const jitter = Math.random();
      const up = Math.round(38_000 + wave * 340_000 + jitter * 90_000);
      const down = Math.round(145_000 + wave * 1_950_000 + jitter * 520_000);
      mockUpTotal += up * 2;
      mockDownTotal += down * 2;
      onSample({
        up_bps: up,
        down_bps: down,
        up_total_bytes: Math.round(mockUpTotal),
        down_total_bytes: Math.round(mockDownTotal),
        connections: 16 + Math.round(wave * 26 + jitter * 4),
        tunnel_connections: mockConfig.preaccel.enabled ? 4 : 0,
        memory_mb: Number((34.4 + wave * 4.5 + jitter * 0.6).toFixed(1)),
        timestamp_ms: Date.now(),
      });
    }, 2000);
    return () => {
      disposed = true;
      window.clearInterval(mockTimer);
    };
  },

  subscribeRuntimeUpdate(_onUpdate: (info: CoreRuntimeInfo) => void): () => void {
    return () => {};
  },

  subscribeProbeProgress(_onProgress: (ev: ProbeProgressEvent) => void): () => void {
    return () => {};
  },

  subscribeStrategySwitch(_onSwitch: (ev: StrategySwitchEvent) => void): () => void {
    return () => {};
  },

  subscribeConfigUpdate(_onUpdate: (cfg: AppConfig) => void): () => void {
    return () => {};
  },

  subscribeSyncReceived(_onReceived: (ev: SyncReceivedEvent) => void): () => void {
    return () => {};
  },

  subscribeSyncSessionUpdated(_onUpdate: (ev: SyncSessionUpdatedEvent) => void): () => void {
    return () => {};
  },

  subscribeUpdateReady(cb: (payload: PendingUpdatePromptDto) => void): () => void {
    mockUpdateReadyListeners.add(cb);
    return () => {
      mockUpdateReadyListeners.delete(cb);
    };
  },

  subscribeGroupsUpdated(onUpdate: () => void): () => void {
    mockGroupsUpdatedListeners.add(onUpdate);
    return () => {
      mockGroupsUpdatedListeners.delete(onUpdate);
    };
  },

  subscribeRelaysUpdated(onUpdate: () => void): () => void {
    mockRelaysUpdatedListeners.add(onUpdate);
    return () => {
      mockRelaysUpdatedListeners.delete(onUpdate);
    };
  },

  subscribeNodesUpdated(handler: () => void): () => void {
    mockNodesUpdatedListeners.add(handler);
    return () => {
      mockNodesUpdatedListeners.delete(handler);
    };
  },

  subscribeNavigate(handler: (nav: string) => void): () => void {
    mockNavigateListeners.add(handler);
    return () => {
      mockNavigateListeners.delete(handler);
    };
  },
};
