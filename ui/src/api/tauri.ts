/**
 * CatCloud Strongly-Typed Tauri v2 IPC Client with Browser Preview Mock Fallback.
 *
 * - In Tauri runtime (`window.__TAURI_INTERNALS__`), delegates directly to `@tauri-apps/api/core`
 *   and `@tauri-apps/api/event`, surfacing backend IPC errors instead of silently returning null.
 * - In standalone browser preview (`pnpm dev` / `pnpm preview`), serves sanitized demo data using
 *   RFC 5737 documentation IP ranges and placeholder provider labels only.
 */

export type ThemeMode = "auto_time" | "light" | "warm_dark" | "midnight_blue";
export type ResolvedTheme = "light" | "warm-dark" | "midnight-blue";
export type TrayIconMode = "auto_ac" | "always_a" | "always_c" | "always_pixel";
export type ProxyMode = "rule" | "global" | "direct";
export type TunStackMode = "mixed" | "system" | "gvisor";
export type CoreHealthStatus = "idle" | "ok" | "preaccel" | "warn" | "error";
export type MemoryTier = "auto" | "mb48" | "mb64" | "mb96" | "48MiB" | "64MiB" | "96MiB";
export type PreAccelOverrideMode = "inherit" | "force_on" | "force_off";
export type RouteTargetMode = "single" | "group";

export type MultiGroupMode =
  | "sticky_best"
  | "conditional_pool"
  | "load_balance_consistent_hash"
  | "load_balance_round_robin";

export type FallbackPolicy =
  | "degrade_best_warn"
  | "cross_pool_escalate"
  | "strict_circuit_break";

export type SwitchMode = "force_close_old" | "graceful_new_only";

export type ProbeKind =
  | "latency"
  | "upload"
  | "download"
  | "keepalive"
  | "google_cn"
  | "unlock_regex"
  | "external_cmd";

export interface ThemeSchedule {
  light_start: string;
  warm_dark_start: string;
  midnight_start: string;
}

export interface PersonalizationConfig {
  theme_mode: ThemeMode;
  theme_schedule: ThemeSchedule;
  wallpaper_path: string | null;
  wallpaper_opacity: number;
  glass_blur_px: number;
  animations_enabled: boolean;
  mascot_enabled: boolean;
  sparkline_enabled: boolean;
  tray_icon_mode: TrayIconMode;
}

export interface PreAccelConfig {
  enabled: boolean;
  skip_443_native: boolean;
  probe_url: string;
  fallback_probe_url: string;
  campus_portal_guard?: boolean;
}

export interface UpdateConfig {
  repo: string;
  mode: "next_launch" | "manual" | "auto_restart";
  check_interval_min: number;
  include_prerelease: boolean;
}

export interface AppConfig {
  mixed_port: number;
  controller_port: number;
  dns_listen_port: number;
  proxy_mode: ProxyMode;
  system_proxy_enabled: boolean;
  proxy_guard_enabled: boolean;
  proxy_guard_interval_sec: number;
  tun_enabled: boolean;
  tun_stack_mode: TunStackMode;
  unified_delay: boolean;
  ipv6_core_enabled: boolean;
  ipv6_dns_enabled: boolean;
  autostart_enabled: boolean;
  silent_start: boolean;
  gomemlimit_mb: 0 | 48 | 64 | 96;
  memory_tier?: MemoryTier;
  preaccel: PreAccelConfig;
  personalization: PersonalizationConfig;
  update: UpdateConfig;
}

export type UiAppConfigDto = AppConfig;

export interface WebUiEntry {
  name: string;
  url_template: string;
}

export interface QuickCheckSiteConfig {
  id: string;
  name: string;
  url: string;
  expected_status?: number | null;
}

export interface RulesOverrideConfig {
  global_prepend_rules?: string[];
  global_append_rules?: string[];
  override_script_path?: string | null;
  block_quic_udp_443?: boolean;
  domestic_direct_enabled?: boolean;
}

export interface FullAppConfig {
  schema_version?: number;
  proxy_mode?: ProxyMode;
  mixed_port?: number;
  allow_lan?: boolean;
  bind_address?: string;
  controller_host?: string;
  controller_port?: number;
  controller_secret?: string | null;
  webui_urls?: WebUiEntry[];
  dns_listen_host?: string;
  dns_listen_port?: number;
  unified_delay?: boolean;
  log_level?: string;
  core_ipv6?: boolean;
  system_proxy?: {
    enabled?: boolean;
    proxy_guard?: { enabled?: boolean; interval_sec?: number };
    bypass?: string[];
    pac?: { enabled?: boolean; port?: number; script_override?: string | null };
  };
  tun?: {
    enabled?: boolean;
    stack_mode?: TunStackMode;
  };
  dns?: {
    enable?: boolean;
    override_dns?: boolean;
    ipv6?: boolean;
    use_hosts?: boolean;
    use_system_hosts?: boolean;
    respect_rules?: boolean;
    prefer_h3?: boolean;
    mode?: "fake-ip" | "redir-host";
    fake_ip_range?: string;
    fake_ip_filter?: string[];
    default_nameserver?: string[];
    nameserver_policy?: Record<string, string[]>;
    nameserver?: string[];
    fallback?: string[];
    proxy_server_nameserver?: string[];
    fallback_filter?: {
      geoip?: boolean;
      geoip_code?: string;
      geosite?: string[];
      ipcidr?: string[];
      domain?: string[];
    };
  };
  rules_override?: RulesOverrideConfig;
  core_runtime?: {
    custom_binary_path?: string | null;
    memory_tier?: string;
    startup_script_path?: string | null;
    quick_check_sites?: QuickCheckSiteConfig[];
  };
  preaccel?: Partial<PreAccelConfig> & {
    probe_interval_sec?: number;
    active_relay_id?: string | null;
    auto_failover?: boolean;
    campus_direct_domains?: string[];
  };
  behavior?: {
    autostart?: boolean;
    silent_start?: boolean;
    minimize_to_tray_on_close?: boolean;
    startup_page?: string;
    tray_click_action?: string;
    tray_middle_click_action?: string;
    hotkeys?: {
      enabled?: boolean;
      switch_next_best?: string | null;
      toggle_capsule?: string | null;
      toggle_system_proxy?: string | null;
      toggle_tun?: string | null;
      show_main_window?: string | null;
      proxy_mode_rule?: string | null;
      proxy_mode_global?: string | null;
      proxy_mode_direct?: string | null;
    };
  };
  [key: string]: unknown;
}

export interface SubscriptionRecord {
  id: string;
  name: string;
  kind: "url" | "file" | "migrated" | "process_adapter";
  url_or_cmd: string;
  source?: string;
  refresh_interval_sec: number;
  traffic_used_bytes: number;
  traffic_total_bytes: number;
  expires_at: string | null;
  etag?: string | null;
  last_ok_at: string | null;
  last_error: string | null;
  enabled: boolean;
}

export interface ProxyNode {
  id: string;
  sub_id: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  raw_config?: unknown;
  region_code: string;
  multiplier: number;
  is_443_native: boolean;
  preaccel_eligible?: boolean;
  preaccel_override: boolean | null;
  tags: string[];
  enabled: boolean;
}

export interface ProbeDefinition {
  id: string;
  name: string;
  kind: ProbeKind;
  target_url: string;
  method: string;
  expected_status?: number | null;
  body_regex?: string | null;
  payload_bytes?: number | null;
  timeout_ms: number;
  builtin: boolean;
}

export interface ProbeSnapshot {
  node_id: string;
  tested_at: string;
  ok: boolean;
  latency_ms: number | null;
  jitter_ms: number | null;
  loss_pct: number | null;
  up_mbps: number | null;
  down_mbps: number | null;
  cf_loc: string | null;
  yt_gl: string | null;
  google_clean: boolean | null;
  google_risk_mismatch: boolean;
  keepalive_60s_ok: boolean | null;
  unlocked_sites: Record<string, boolean>;
  per_probe_ok?: Record<string, boolean>;
  per_probe_up_mbps: Record<string, number>;
  per_probe_down_mbps: Record<string, number>;
  per_probe_ping_ms: Record<string, number>;
  per_probe_detail?: Record<string, string>;
}

export interface DynamicFilterSpec {
  expr?: string | null;
  sub_ids?: string[];
  region_codes?: string[];
  max_multiplier?: number | null;
  protocols?: string[];
  require_google_clean?: boolean;
  require_443_native?: boolean | null;
}

export interface TriggerRule {
  expr: string;
  consecutive_failures: number;
  bypass_cooldown_on_disconnect: boolean;
}

export interface MultiGroup {
  id: string;
  name: string;
  mode: MultiGroupMode;
  independent_routing?: boolean;
  match_rules: string[];
  member_node_ids: string[];
  dynamic_filter: DynamicFilterSpec | Record<string, unknown> | string | null;
  primary_probe_id: string | null;
  hard_gates: string[];
  trigger_rules?: TriggerRule[];
  trigger_expr?: string | null;
  formula_expr: string;
  fallback_policy: FallbackPolicy;
  fallback_pool_id: string | null;
  escalated_since: string | null;
  recover_probe_interval_sec: number;
  switch_mode: SwitchMode;
  cooldown_sec: number;
  hysteresis_pct: number;
  active_node_id: string | null;
  state?: string;
}

export interface StrategySwitchEvent {
  group_name: string;
  from_node: string;
  to_node: string;
  reason: string;
}

export interface PreAccelRelay {
  id: string;
  name: string;
  provider: string;
  region: string;
  server: string;
  port: number;
  protocol: string;
  password?: string;
  sni: string | null;
  skip_cert_verify: boolean;
  priority: number;
  expires_at: string | null;
  enabled: boolean;
  last_probe_ms: number | null;
  last_mbps: number | null;
}

export interface TrafficSample {
  up_bps: number;
  down_bps: number;
  up_total_bytes: number;
  down_total_bytes: number;
  connections: number;
  memory_mb: number;
  timestamp_ms: number;
}

export interface CoreRuntimeInfo {
  running: boolean;
  status: CoreHealthStatus;
  core_name: string;
  core_version: string;
  proxy_mode: ProxyMode;
  mixed_port: number;
  controller_addr: string;
  uptime_sec: number;
  rule_count: number;
  route_mode?: RouteTargetMode;
  active_group_id: string;
  active_group_name: string;
  active_node_id: string;
  active_node_name: string;
  active_node_region: string;
  active_node_latency_ms: number | null;
  active_node_up_mbps: number | null;
  preaccel_active: boolean;
  preaccel_relay_name: string | null;
  captive_portal_required: boolean;
  system_proxy_enabled: boolean;
  tun_enabled: boolean;
  tun_admin_ready: boolean;
  app_version: string;
  os_label: string;
  autostart_enabled: boolean;
  portable_mode: boolean;
  last_update_check: string | null;
}

export type CoreRuntimeInfoDto = CoreRuntimeInfo;

export interface ExitIpInfo {
  ip_masked: string;
  ip_raw?: string | null;
  isp: string;
  location: string;
  timezone: string;
  google_clean: boolean | null;
  core_running?: boolean;
}

export type ExitIpInfoDto = ExitIpInfo;

export interface SiteCheckItem {
  id: string;
  name: string;
  url: string;
  latency_ms: number | null;
  ok: boolean | null;
}

export type SiteCheckItemDto = SiteCheckItem;

export interface SwitchResult {
  group_id: string;
  previous_node_id: string | null;
  active_node_id: string;
  active_node_name: string;
  active_node_region: string;
  latency_ms: number | null;
  up_mbps: number | null;
  closed_connections: number;
}

export type SwitchResultDto = SwitchResult;

export interface ReloadOutcome {
  applied: boolean;
  level: string;
  skipped_unchanged: boolean;
  rejected: boolean;
  config_hash: string | null;
  replayed_groups: number;
  shifted_ports: unknown[];
  warnings: string[];
  error: string | null;
  applied_at: string;
}

export interface RunIsolatedProbesResult {
  probed_count: number;
  total_count?: number;
  cancelled?: boolean;
  snapshots: Record<string, ProbeSnapshot>;
  errors: string[];
  core_available: boolean;
  used_preaccel?: boolean;
  preaccel_relay_name?: string | null;
}

export interface ProbeProgressEvent {
  node_id: string | null;
  node_name: string | null;
  completed: number;
  total: number;
  cancelled: boolean;
  done: boolean;
  snapshot: ProbeSnapshot | null;
  error: string | null;
}

export interface PickWallpaperResult {
  cancelled: boolean;
  path: string | null;
  data_url: string | null;
}

export interface RefreshSubscriptionResult {
  sub_id: string;
  node_count: number;
  updated_at: string;
  warnings: string[];
}

export interface RefreshAllSubscriptionsResult {
  refreshed: number;
  total_nodes: number;
  errors: string[];
}

export interface PreAccelTestResult {
  relay_id: string;
  ok: boolean;
  latency_ms: number | null;
  error: string | null;
}

export interface PreAccelSideSpeed {
  ok: boolean;
  latency_ms: number | null;
  up_mbps: number | null;
  down_mbps: number | null;
  error: string | null;
}

export interface PreAccelComparisonResult {
  ok: boolean;
  relay_id: string;
  relay_name: string;
  node_id: string;
  node_name: string;
  accelerated: PreAccelSideSpeed;
  direct: PreAccelSideSpeed;
  up_boost_ratio: number | null;
  down_boost_ratio: number | null;
  fallback_reason?: string | null;
  tested_at: string;
}

export interface CampusPortalStatus {
  captive_portal_required: boolean;
  status_code: number | null;
  redirect_location: string | null;
  bypass_hosts: string[];
  checked_at: string;
}

export interface ActiveConnectionDto {
  id: string;
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rule_payload: string;
  network: string;
  conn_type: string;
  source_ip: string;
  source_port: string;
  destination_ip: string;
  destination_port: string;
  host: string;
  process: string;
  process_path: string;
}

export interface ConnectionsSnapshotDto {
  download_total: number;
  upload_total: number;
  memory: number;
  connections: ActiveConnectionDto[];
}

export interface CoreLogLineDto {
  level: string;
  payload: string;
  timestamp: string;
}

export interface AgentModuleDoc {
  id: string;
  title: string;
  summary?: string;
  [key: string]: unknown;
}

export interface EvaluatedCandidate {
  node_id: string;
  node_name: string;
  region_code: string;
  multiplier: number;
  ok: boolean;
  passed_hard_gates: boolean;
  failed_hard_gates: string[];
  meets_thresholds: boolean;
  triggered_rule_indices: number[];
  score: number;
}

export interface ActiveNodeAssessment {
  node_id: string;
  in_candidate_pool: boolean;
  passed_hard_gates: boolean;
  failed_hard_gates: string[];
  score: number | null;
  is_disconnected: boolean;
  triggered_rules: Array<{
    rule_index: number;
    expr: string;
    triggered: boolean;
    consecutive_failures_required: number;
    bypass_cooldown_on_disconnect: boolean;
  }>;
  any_rule_triggered: boolean;
  required_consecutive_failures: number;
  bypass_cooldown: boolean;
}

export interface GroupEvaluationReport {
  group_id: string;
  mode: MultiGroupMode;
  pool_size: number;
  gate_passed: EvaluatedCandidate[];
  healthy_candidates: EvaluatedCandidate[];
  gate_rejected: EvaluatedCandidate[];
  active_assessment: ActiveNodeAssessment | null;
  all_failed_hard_gates: boolean;
  all_below_threshold: boolean;
}

export interface CompiledYamlPreview {
  yaml: string;
  sha256: string;
  stats: Record<string, unknown>;
  validation: Record<string, unknown>;
}

export interface MigrationPreviewDto {
  source_kind: string;
  source_path: string | null;
  nodes: ProxyNode[];
  prepend_rules: string[];
  append_rules: string[];
  warnings: string[];
}

export interface MigrationTextPreviewResult {
  name: string;
  node_count: number;
  nodes: ProxyNode[];
  prepend_rules?: string[];
  append_rules?: string[];
  warnings: string[];
}

export interface ProcessCandidateDto {
  pid: number;
  name: string;
  exe_path: string | null;
  cmdline: string[];
  detected_config_dir: string | null;
  detected_config_file: string | null;
  detected_controller_addr: string | null;
  likely_proxy_client: boolean;
}

export type ProcessAttachRecommendationDto =
  | {
      mode: "read_only_local_file";
      path: string;
      node_count: number;
      reason: string;
    }
  | {
      mode: "public_controller_api";
      endpoint_url: string;
      proxy_count: number;
      requires_secret: boolean;
      reason: string;
    }
  | {
      mode: "external_adapter_template";
      schema: string;
      suggested_command: string;
      template_script: string;
      reason: string;
    };

export interface ProcessInspectResult {
  pid: number;
  process_name?: string;
  name?: string;
  readable_yaml_file?: string | null;
  yaml_node_count?: number;
  controller_url?: string | null;
  controller_reachable?: boolean;
  controller_requires_secret?: boolean;
  controller_proxy_count?: number;
  recommendation?: ProcessAttachRecommendationDto;
  notes?: string[];
  config_path?: string | null;
  controller_addr?: string | null;
  node_count?: number;
  warnings?: string[];
  [key: string]: unknown;
}

export interface RefreshGeoDbResult {
  ok: boolean;
  updated_targets: string[];
  message: string;
}

export interface GeoDataFileStatus {
  exists: boolean;
  size_bytes: number;
  updated_at: string | null;
}

export interface GeoDataStatusDto {
  country_mmdb: GeoDataFileStatus;
  geoip_dat: GeoDataFileStatus;
  geosite_dat: GeoDataFileStatus;
  asn_mmdb: GeoDataFileStatus;
}

export interface AppUpdateCheckResult {
  has_update: boolean;
  current_version: string;
  latest_version: string;
  release_url: string;
  notes: string;
  checked_at: string;
  error?: string | null;
}

export interface ExportBackupResult {
  path: string;
  bytes: number;
  sha256: string;
  exported_at: string;
}

export interface ImportBackupResult {
  restored_config: boolean;
  restored_groups: number;
  restored_relays: number;
  message: string;
}

export interface UwpLoopbackResult {
  supported: boolean;
  launched: boolean;
  message: string;
}

export interface HotSwapCoreResult {
  ok: boolean;
  version: string | null;
  sha256: string | null;
  binary_path: string;
  message: string;
}

export function isTauriEnv(): boolean {
  return (
    typeof window !== "undefined" &&
    ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)
  );
}

export function formatErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err && typeof err.message === "string") {
    return err.message;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

async function tauriInvokeOrThrow<T>(
  cmd: string,
  args?: Record<string, unknown>
): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    throw new Error(formatErrorMessage(err));
  }
}

async function tauriListen<T>(
  event: string,
  handler: (payload: T) => void
): Promise<(() => void) | null> {
  if (!isTauriEnv()) return null;
  try {
    const { listen } = await import("@tauri-apps/api/event");
    const unlisten = await listen<T>(event, (ev) => handler(ev.payload));
    return unlisten;
  } catch {
    return null;
  }
}

/* ============================================================================
 * Sanitized Browser Preview Fallback Data (RFC 5737 IPs & Placeholder Labels)
 * ============================================================================ */

export const DEFAULT_APP_CONFIG: AppConfig = {
  mixed_port: 17890,
  controller_port: 19090,
  dns_listen_port: 11053,
  proxy_mode: "rule",
  system_proxy_enabled: true,
  proxy_guard_enabled: true,
  proxy_guard_interval_sec: 30,
  tun_enabled: false,
  tun_stack_mode: "mixed",
  unified_delay: true,
  ipv6_core_enabled: false,
  ipv6_dns_enabled: false,
  autostart_enabled: true,
  silent_start: false,
  gomemlimit_mb: 48,
  memory_tier: "mb48",
  preaccel: {
    enabled: true,
    skip_443_native: true,
    probe_url: "http://connectivitycheck.platform.hicloud.com/generate_204",
    fallback_probe_url: "http://connect.rom.miui.com/generate_204",
    campus_portal_guard: true,
  },
  personalization: {
    theme_mode: "auto_time",
    theme_schedule: {
      light_start: "07:00",
      warm_dark_start: "18:30",
      midnight_start: "22:30",
    },
    wallpaper_path: null,
    wallpaper_opacity: 0.22,
    glass_blur_px: 12,
    animations_enabled: true,
    mascot_enabled: true,
    sparkline_enabled: true,
    tray_icon_mode: "auto_ac",
  },
  update: {
    repo: "JuryBu/CatCloud",
    mode: "next_launch",
    check_interval_min: 360,
    include_prerelease: false,
  },
};

const MOCK_SUBSCRIPTIONS: SubscriptionRecord[] = [
  {
    id: "sub-alpha",
    name: "Demo Cloud Alpha",
    kind: "url",
    url_or_cmd: "https://example.invalid/sub/alpha.yaml",
    source: "https://example.invalid/sub/alpha.yaml",
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
    source: "data/subs/demo-native.yaml",
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

const MOCK_PROBES: Record<string, ProbeSnapshot> = {
  "node-jp-01": {
    node_id: "node-jp-01",
    tested_at: "2026-11-23T04:48:00+08:00",
    ok: true,
    latency_ms: 68,
    jitter_ms: 4.2,
    loss_pct: 0,
    up_mbps: 14.8,
    down_mbps: 186.4,
    cf_loc: "NRT",
    yt_gl: "JP",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: { gemini: true, google_ai: true, chatgpt: true, claude: true, windsurf: true },
    per_probe_ok: { builtin_unlock_windsurf: true },
    per_probe_up_mbps: { antigravity: 14.8 },
    per_probe_down_mbps: { dl: 186.4 },
    per_probe_ping_ms: { chatgpt: 72 },
  },
  "node-sg-02": {
    node_id: "node-sg-02",
    tested_at: "2026-11-23T04:48:00+08:00",
    ok: true,
    latency_ms: 82,
    jitter_ms: 5.8,
    loss_pct: 0,
    up_mbps: 12.1,
    down_mbps: 162.0,
    cf_loc: "SIN",
    yt_gl: "SG",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: { gemini: true, google_ai: true, chatgpt: true, claude: true, windsurf: true },
    per_probe_ok: { builtin_unlock_windsurf: true },
    per_probe_up_mbps: { antigravity: 12.1 },
    per_probe_down_mbps: { dl: 162.0 },
    per_probe_ping_ms: { chatgpt: 88 },
  },
  "node-us-03": {
    node_id: "node-us-03",
    tested_at: "2026-11-23T04:48:00+08:00",
    ok: true,
    latency_ms: 144,
    jitter_ms: 7.5,
    loss_pct: 0,
    up_mbps: 11.4,
    down_mbps: 154.2,
    cf_loc: "SJC",
    yt_gl: "US",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: { gemini: true, google_ai: true, chatgpt: true, claude: true, windsurf: true },
    per_probe_ok: { builtin_unlock_windsurf: true },
    per_probe_up_mbps: { antigravity: 11.4 },
    per_probe_down_mbps: { dl: 154.2 },
    per_probe_ping_ms: { chatgpt: 148 },
  },
  "node-tw-04": {
    node_id: "node-tw-04",
    tested_at: "2026-11-23T04:48:00+08:00",
    ok: true,
    latency_ms: 56,
    jitter_ms: 3.1,
    loss_pct: 0,
    up_mbps: 24.5,
    down_mbps: 248.0,
    cf_loc: "TPE",
    yt_gl: "TW",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: { gemini: true, google_ai: true, chatgpt: true, claude: true, windsurf: true },
    per_probe_ok: { builtin_unlock_windsurf: true },
    per_probe_up_mbps: { antigravity: 24.5 },
    per_probe_down_mbps: { dl: 248.0 },
    per_probe_ping_ms: { chatgpt: 61 },
  },
};

const MOCK_PROBE_DEFINITIONS: ProbeDefinition[] = [
  {
    id: "builtin_latency",
    name: "标准连通延迟 204",
    kind: "latency",
    target_url: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expected_status: 204,
    body_regex: null,
    payload_bytes: null,
    timeout_ms: 5000,
    builtin: true,
  },
  {
    id: "builtin_google_cn",
    name: "Google 侧真值防送中",
    kind: "google_cn",
    target_url: "https://www.google.com/generate_204",
    method: "GET",
    expected_status: 204,
    body_regex: null,
    payload_bytes: null,
    timeout_ms: 6000,
    builtin: true,
  },
  {
    id: "builtin_upload",
    name: "上行吞吐 (512KB 快熔断)",
    kind: "upload",
    target_url: "https://speed.cloudflare.com/__up",
    method: "POST",
    expected_status: 200,
    body_regex: null,
    payload_bytes: 512 * 1024,
    timeout_ms: 12000,
    builtin: true,
  },
  {
    id: "builtin_download",
    name: "下行吞吐测速",
    kind: "download",
    target_url: "https://speed.cloudflare.com/__down?bytes=2097152",
    method: "GET",
    expected_status: 200,
    body_regex: null,
    payload_bytes: 2 * 1024 * 1024,
    timeout_ms: 12000,
    builtin: true,
  },
  {
    id: "builtin_keepalive_60s",
    name: "60s 静默长连接黑洞检测",
    kind: "keepalive",
    target_url: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expected_status: 204,
    body_regex: null,
    payload_bytes: null,
    timeout_ms: 65000,
    builtin: true,
  },
  {
    id: "builtin_unlock_windsurf",
    name: "Windsurf / Codeium 解锁",
    kind: "unlock_regex",
    target_url: "https://windsurf.com",
    method: "GET",
    expected_status: 200,
    body_regex: "windsurf|codeium",
    payload_bytes: null,
    timeout_ms: 8000,
    builtin: true,
  },
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
    last_mbps: 192.5,
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
    last_mbps: 158.0,
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

let mockConfig: AppConfig = structuredClone(DEFAULT_APP_CONFIG);
let mockFullConfig: FullAppConfig = {
  allow_lan: false,
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
    startup_script_path: null,
    quick_check_sites: MOCK_QUICK_SITES.map((s) => ({ id: s.id, name: s.name, url: s.url })),
  },
  preaccel: {
    ...DEFAULT_APP_CONFIG.preaccel,
  },
  rules_override: {
    global_prepend_rules: [],
    global_append_rules: [],
    override_script_path: null,
    block_quic_udp_443: true,
    domestic_direct_enabled: true,
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
  preaccel_relay_name: "CN-East-443 Primary",
  captive_portal_required: false,
  system_proxy_enabled: mockConfig.system_proxy_enabled,
  tun_enabled: mockConfig.tun_enabled,
  tun_admin_ready: true,
  app_version: "0.1.0",
  os_label: "Windows 11 x64",
  autostart_enabled: true,
  portable_mode: true,
  last_update_check: "2026-11-23 04:30",
};

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
      memory_mb: Number((34.2 + burst * 4.8).toFixed(1)),
      timestamp_ms: t,
    });
  }
  return samples;
}

export const catcloudApi = {
  async getConfig(): Promise<AppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AppConfig>("get_app_config");
    }
    return structuredClone(mockConfig);
  },

  async saveConfig(next: AppConfig): Promise<AppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AppConfig>("save_app_config", { config: next });
    }
    mockConfig = structuredClone(next);
    mockRuntime = {
      ...mockRuntime,
      proxy_mode: next.proxy_mode,
      system_proxy_enabled: next.system_proxy_enabled,
      tun_enabled: next.tun_enabled,
      mixed_port: next.mixed_port,
      preaccel_active: next.preaccel.enabled,
      status: next.preaccel.enabled ? "preaccel" : "ok",
    };
    return structuredClone(mockConfig);
  },

  async getFullConfig(): Promise<FullAppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<FullAppConfig>("get_full_config");
    }
    return structuredClone(mockFullConfig);
  },

  async saveFullConfig(next: FullAppConfig): Promise<FullAppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<FullAppConfig>("save_full_config", { next });
    }
    mockFullConfig = structuredClone(next);
    return structuredClone(mockFullConfig);
  },

  async saveExtendedSettings(patch: Record<string, unknown>): Promise<FullAppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<FullAppConfig>("save_extended_settings", { patch });
    }
    mockFullConfig = {
      ...mockFullConfig,
      ...patch,
      behavior:
        patch.behavior && typeof patch.behavior === "object"
          ? { ...mockFullConfig.behavior, ...(patch.behavior as FullAppConfig["behavior"]) }
          : mockFullConfig.behavior,
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("get_runtime_info");
    }
    return { ...mockRuntime };
  },

  async startCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("start_core");
    }
    mockRuntime = { ...mockRuntime, running: true, status: mockConfig.preaccel.enabled ? "preaccel" : "ok" };
    return { ...mockRuntime };
  },

  async stopCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("stop_core");
    }
    mockRuntime = { ...mockRuntime, running: false, status: "idle" };
    return { ...mockRuntime };
  },

  async restartCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("restart_core");
    }
    mockRuntime = { ...mockRuntime, running: true, uptime_sec: 1 };
    return { ...mockRuntime };
  },

  async reloadCoreConfig(forceDiskReload = false): Promise<ReloadOutcome> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ReloadOutcome>("reload_core_config", { forceDiskReload });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProxyMode>("set_proxy_mode", { mode });
    }
    mockConfig.proxy_mode = mode;
    mockRuntime.proxy_mode = mode;
    return mode;
  },

  async toggleSystemProxy(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("set_system_proxy", { enabled });
    }
    mockConfig.system_proxy_enabled = enabled;
    mockRuntime.system_proxy_enabled = enabled;
    return enabled;
  },

  async toggleTun(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("set_tun_enabled", { enabled });
    }
    mockConfig.tun_enabled = enabled;
    mockRuntime.tun_enabled = enabled;
    return enabled;
  },

  async switchNextBestNode(groupId = "grp-ai"): Promise<SwitchResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SwitchResult>("switch_next_best_node", { groupId });
    }
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

  async selectGroupNode(groupId: string, nodeId: string, closeOld = true): Promise<SwitchResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SwitchResult>("select_group_node", { groupId, nodeId, closeOld });
    }
    const group = mockGroups.find((g) => g.id === groupId);
    const prevId = group?.active_node_id ?? null;
    if (group) group.active_node_id = nodeId;
    const node = mockNodes.find((n) => n.id === nodeId) ?? mockNodes[0];
    const snap = mockProbes[nodeId];
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("set_active_group", { groupId });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("select_single_node", { nodeId });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("toggle_capsule_window");
    }
    return false;
  },

  async showMainWindow(): Promise<void> {
    if (isTauriEnv()) {
      await tauriInvokeOrThrow<void>("show_main_window");
    }
  },

  async enterWindowlessMode(): Promise<void> {
    if (isTauriEnv()) {
      await tauriInvokeOrThrow<void>("enter_windowless_mode");
    }
  },

  async listGroups(): Promise<MultiGroup[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MultiGroup[]>("list_multi_groups");
    }
    return structuredClone(mockGroups);
  },

  async upsertMultiGroup(group: MultiGroup): Promise<MultiGroup> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MultiGroup>("upsert_multi_group", { group });
    }
    const idx = mockGroups.findIndex((g) => g.id === group.id);
    if (idx >= 0) mockGroups[idx] = structuredClone(group);
    else mockGroups.push(structuredClone(group));
    return structuredClone(group);
  },

  async deleteMultiGroup(groupId: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("delete_multi_group", { groupId });
    }
    const before = mockGroups.length;
    mockGroups = mockGroups.filter((g) => g.id !== groupId);
    return mockGroups.length < before;
  },

  async updateMultiGroupMembers(groupId: string, memberNodeIds: string[]): Promise<MultiGroup> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MultiGroup>("update_multi_group_members", { groupId, memberNodeIds });
    }
    const found = mockGroups.find((g) => g.id === groupId);
    if (!found) throw new Error(`Group ${groupId} not found`);
    found.member_node_ids = [...memberNodeIds];
    return structuredClone(found);
  },

  async listNodes(): Promise<ProxyNode[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProxyNode[]>("list_nodes");
    }
    return structuredClone(mockNodes);
  },

  async setNodesPreAccelOverride(
    nodeIds: string[],
    overrideMode: PreAccelOverrideMode
  ): Promise<number> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<number>("set_nodes_preaccel_override", { nodeIds, overrideMode });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProbeDefinition[]>("list_probe_definitions");
    }
    return structuredClone(mockProbeDefs);
  },

  async upsertProbeDefinition(probe: ProbeDefinition): Promise<ProbeDefinition> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProbeDefinition>("upsert_probe_definition", { probe });
    }
    const idx = mockProbeDefs.findIndex((p) => p.id === probe.id);
    if (idx >= 0) mockProbeDefs[idx] = structuredClone(probe);
    else mockProbeDefs.push(structuredClone(probe));
    return structuredClone(probe);
  },

  async deleteProbeDefinition(probeId: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("delete_probe_definition", { probeId });
    }
    const before = mockProbeDefs.length;
    mockProbeDefs = mockProbeDefs.filter((p) => p.id !== probeId);
    return mockProbeDefs.length < before;
  },

  async listProbeSnapshots(): Promise<Record<string, ProbeSnapshot>> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<Record<string, ProbeSnapshot>>("list_probe_snapshots");
    }
    return structuredClone(mockProbes);
  },

  async runIsolatedProbes(
    nodeIds: string[],
    probeIds: string[],
    maxTier: "latency" | "unlock" | "full" = "full",
    includeKeepalive = false,
    usePreaccel?: boolean
  ): Promise<RunIsolatedProbesResult> {
    if (isTauriEnv()) {
      const args: Record<string, unknown> = {
        nodeIds,
        probeIds,
        maxTier,
        includeKeepalive,
      };
      if (usePreaccel !== undefined) {
        args.usePreaccel = usePreaccel;
      }
      return tauriInvokeOrThrow<RunIsolatedProbesResult>("run_isolated_probes", args);
    }
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
        per_probe_ok: existing?.per_probe_ok ?? {},
        per_probe_up_mbps: existing?.per_probe_up_mbps ?? {},
        per_probe_down_mbps: existing?.per_probe_down_mbps ?? {},
        per_probe_ping_ms: existing?.per_probe_ping_ms ?? {},
      };
      mockProbes[id] = out[id];
    }
    return {
      probed_count: targetIds.length,
      total_count: targetIds.length,
      cancelled: false,
      snapshots: out,
      errors: [],
      core_available: true,
      used_preaccel: usedPreaccel,
      preaccel_relay_name: usedPreaccel ? activeRelay?.name ?? null : null,
    };
  },

  async cancelIsolatedProbes(): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("cancel_isolated_probes");
    }
    return true;
  },

  async pickWallpaperImage(): Promise<PickWallpaperResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PickWallpaperResult>("pick_wallpaper_image");
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string | null>("resolve_wallpaper_data_url", { path });
    }
    const trimmed = path.trim();
    if (!trimmed) return null;
    if (/^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i.test(trimmed)) {
      return trimmed;
    }
    return null;
  },

  async listSubscriptions(): Promise<SubscriptionRecord[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SubscriptionRecord[]>("list_subscriptions");
    }
    return structuredClone(mockSubscriptions);
  },

  async upsertSubscription(record: SubscriptionRecord): Promise<SubscriptionRecord> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SubscriptionRecord>("upsert_subscription", { record });
    }
    const normalized: SubscriptionRecord = {
      ...record,
      url_or_cmd: record.url_or_cmd || record.source || "",
      source: record.url_or_cmd || record.source || "",
    };
    const idx = mockSubscriptions.findIndex((s) => s.id === normalized.id);
    if (idx >= 0) mockSubscriptions[idx] = structuredClone(normalized);
    else mockSubscriptions.push(structuredClone(normalized));
    return structuredClone(normalized);
  },

  async deleteSubscription(subId: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("delete_subscription", { subId });
    }
    const before = mockSubscriptions.length;
    mockSubscriptions = mockSubscriptions.filter((s) => s.id !== subId);
    mockNodes = mockNodes.filter((n) => n.sub_id !== subId);
    return mockSubscriptions.length < before;
  },

  async refreshSubscription(
    subId: string,
    options?: { bearerSecret?: string | null; endpointUrl?: string | null }
  ): Promise<RefreshSubscriptionResult> {
    if (isTauriEnv()) {
      const args: Record<string, unknown> = { subId };
      if (options?.bearerSecret !== undefined) {
        args.bearerSecret = options.bearerSecret;
      }
      if (options?.endpointUrl !== undefined) {
        args.endpointUrl = options.endpointUrl;
      }
      return tauriInvokeOrThrow<RefreshSubscriptionResult>("refresh_subscription", args);
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<RefreshAllSubscriptionsResult>("refresh_all_subscriptions");
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelRelay[]>("list_preaccel_relays");
    }
    return structuredClone(mockRelays);
  },

  async upsertPreAccelRelay(relay: PreAccelRelay): Promise<PreAccelRelay> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelRelay>("upsert_preaccel_relay", { relay });
    }
    const idx = mockRelays.findIndex((r) => r.id === relay.id);
    if (idx >= 0) mockRelays[idx] = structuredClone(relay);
    else mockRelays.push(structuredClone(relay));
    return structuredClone(relay);
  },

  async deletePreAccelRelay(relayId: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("delete_preaccel_relay", { relayId });
    }
    const before = mockRelays.length;
    mockRelays = mockRelays.filter((r) => r.id !== relayId);
    return mockRelays.length < before;
  },

  async togglePreAccel(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("toggle_preaccel", { enabled });
    }
    mockConfig.preaccel.enabled = enabled;
    mockRuntime.preaccel_active = enabled;
    mockRuntime.status = enabled ? "preaccel" : "ok";
    return enabled;
  },

  async failoverPreAccel(): Promise<string | null> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string | null>("failover_preaccel");
    }
    const enabledRelays = [...mockRelays]
      .filter((r) => r.enabled)
      .sort((a, b) => a.priority - b.priority);
    if (enabledRelays.length < 2) return enabledRelays[0]?.id ?? null;
    const next = enabledRelays[1];
    mockRuntime.preaccel_relay_name = next.name;
    return next.id;
  },

  async selectPreAccelRelay(relayId: string): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("select_preaccel_relay", { relayId });
    }
    const found = mockRelays.find((r) => r.id === relayId);
    if (found) mockRuntime.preaccel_relay_name = found.name;
    return relayId;
  },

  async importMmRelayInput(raw: string): Promise<PreAccelRelay[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelRelay[]>("import_mmrelay_input", { raw });
    }
    return structuredClone(mockRelays);
  },

  async testPreAccelRelays(relayIds: string[] | null = null): Promise<PreAccelTestResult[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelTestResult[]>("test_preaccel_relays", { relayIds });
    }
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

  async benchmarkPreAccelComparison(
    relayId?: string | null,
    nodeId?: string | null
  ): Promise<PreAccelComparisonResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelComparisonResult>("benchmark_preaccel_comparison", {
        relayId: relayId ?? null,
        nodeId: nodeId ?? null,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CampusPortalStatus>("check_campus_portal");
    }
    return {
      captive_portal_required: false,
      status_code: 204,
      redirect_location: null,
      bypass_hosts: [],
      checked_at: new Date().toISOString(),
    };
  },

  async getExitIpInfo(): Promise<ExitIpInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ExitIpInfo>("get_exit_ip_info");
    }
    return { ...MOCK_EXIT_IP };
  },

  async checkQuickSites(): Promise<SiteCheckItem[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SiteCheckItem[]>("check_quick_sites");
    }
    return mockQuickSites.map((s) => ({
      ...s,
      latency_ms: s.latency_ms ?? 85,
      ok: s.ok ?? true,
    }));
  },

  async getActiveConnections(): Promise<ConnectionsSnapshotDto> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ConnectionsSnapshotDto>("get_active_connections");
    }
    return {
      download_total: 0,
      upload_total: 0,
      memory: 0,
      connections: [],
    };
  },

  async closeConnection(id: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("close_connection", { id });
    }
    return true;
  },

  async closeGroupConnections(groupName: string): Promise<number> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<number>("close_group_connections", { groupName });
    }
    return 0;
  },

  async closeAllConnections(): Promise<number> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<number>("close_all_connections");
    }
    return 0;
  },

  async getRecentLogs(limit: number | null = 300): Promise<CoreLogLineDto[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreLogLineDto[]>("get_recent_logs", { limit });
    }
    return [];
  },

  async listAgentDocs(): Promise<AgentModuleDoc[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AgentModuleDoc[]>("list_agent_docs");
    }
    return [];
  },

  async exportAgentDocs(moduleId: string, asJson = false): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("export_agent_docs", { moduleId, asJson });
    }
    return "";
  },

  async validateFormulaExpr(expr: string): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("validate_formula_expr", { expr });
    }
    return expr.trim().length > 0;
  },

  async evaluateMultiGroup(groupId: string): Promise<GroupEvaluationReport> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<GroupEvaluationReport>("evaluate_multi_group", { groupId });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CompiledYamlPreview>("compile_preview_yaml");
    }
    return {
      yaml: `# CatCloud Browser Preview YAML\nmixed-port: ${mockConfig.mixed_port}\nmode: ${mockConfig.proxy_mode}\n`,
      sha256: "browser-preview",
      stats: {},
      validation: { ok: true, issues: [] },
    };
  },

  async scanLocalMigrations(): Promise<MigrationPreviewDto[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MigrationPreviewDto[]>("scan_local_migrations");
    }
    return [];
  },

  async previewMigrationFromText(
    name: string,
    rawYaml: string
  ): Promise<MigrationTextPreviewResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MigrationTextPreviewResult>("preview_migration_from_text", {
        name,
        rawYaml,
      });
    }
    return { name, node_count: 0, nodes: [], warnings: [] };
  },

  async applyMigrationNodes(sourceName: string, nodes: ProxyNode[]): Promise<number> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<number>("apply_migration_nodes", { sourceName, nodes });
    }
    return nodes.length;
  },

  async listRunningProcesses(onlyLikelyProxy: boolean): Promise<ProcessCandidateDto[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProcessCandidateDto[]>("list_running_processes", {
        onlyLikelyProxy,
      });
    }
    return [];
  },

  async inspectProcessSource(pid: number): Promise<ProcessInspectResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProcessInspectResult>("inspect_process_source", { pid });
    }
    return {
      pid,
      name: "preview-process",
      config_path: null,
      controller_addr: null,
      node_count: 0,
      warnings: [],
    };
  },

  async exportShellEnv(shell: string): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("export_shell_env", { shell });
    }
    return `export http_proxy="http://127.0.0.1:${mockConfig.mixed_port}"`;
  },

  async exportSanitizedDiagnostics(): Promise<Record<string, unknown>> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<Record<string, unknown>>("export_sanitized_diagnostics");
    }
    return { sanitized: true, preview: true, mixed_port: mockConfig.mixed_port };
  },

  async refreshGeoDb(targets: string[] | null = null): Promise<RefreshGeoDbResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<RefreshGeoDbResult>("refresh_geo_db", { targets });
    }
    return {
      ok: true,
      updated_targets: targets ?? ["geoip", "geosite", "mmdb", "asn"],
      message: "浏览器预览模式：已模拟刷新地理库",
    };
  },

  async getGeodataStatus(): Promise<GeoDataStatusDto> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<GeoDataStatusDto>("get_geodata_status");
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("relaunch_as_admin", { enableTun });
    }
    mockRuntime.tun_admin_ready = true;
    if (enableTun) {
      mockConfig.tun_enabled = true;
      mockRuntime.tun_enabled = true;
    }
    return true;
  },

  async checkAppUpdate(): Promise<AppUpdateCheckResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AppUpdateCheckResult>("check_app_update");
    }
    return {
      has_update: false,
      current_version: mockRuntime.app_version,
      latest_version: mockRuntime.app_version,
      release_url: `https://github.com/${mockConfig.update.repo}/releases`,
      notes: "",
      checked_at: new Date().toISOString(),
    };
  },

  async exportBackupBundle(targetPath: string | null = null): Promise<ExportBackupResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ExportBackupResult>("export_backup_bundle", { targetPath });
    }
    return {
      path: targetPath ?? "catcloud-backup.json",
      bytes: 0,
      sha256: "browser-preview",
      exported_at: new Date().toISOString(),
    };
  },

  async importBackupBundle(bundleJson: string): Promise<ImportBackupResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ImportBackupResult>("import_backup_bundle", { bundleJson });
    }
    return {
      restored_config: true,
      restored_groups: mockGroups.length,
      restored_relays: mockRelays.length,
      message: "浏览器预览模式：已模拟导入备份",
    };
  },

  async launchUwpLoopback(): Promise<UwpLoopbackResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<UwpLoopbackResult>("launch_uwp_loopback");
    }
    return {
      supported: false,
      launched: false,
      message: "浏览器预览模式无法拉起本机 UWP 回环工具",
    };
  },

  async hotSwapCore(binaryPath: string): Promise<HotSwapCoreResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<HotSwapCoreResult>("hot_swap_core", { binaryPath });
    }
    return {
      ok: true,
      version: mockRuntime.core_version,
      sha256: "browser-preview",
      binary_path: binaryPath,
      message: "浏览器预览模式：已模拟内核热换",
    };
  },

  async openAppDir(kind: string): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("open_app_dir", { kind });
    }
    return `data/${kind}`;
  },

  async openWebUi(url: string | null = null): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("open_web_ui", { url });
    }
    return url ?? `http://127.0.0.1:${mockConfig.controller_port}/ui`;
  },

  async getTrafficHistory(): Promise<TrafficSample[]> {
    if (!isTauriEnv()) {
      return [];
    }
    type RawTrafficPayload = Partial<TrafficSample> & {
      active_connections?: number;
      core_memory_mb?: number;
    };
    let rows: RawTrafficPayload[];
    try {
      rows = await tauriInvokeOrThrow<RawTrafficPayload[]>("get_traffic_history");
    } catch {
      return [];
    }
    if (!Array.isArray(rows)) return [];
    const safeNum = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
    return rows
      .filter((r) => Boolean(r && typeof r === "object"))
      .map((r) => ({
        up_bps: safeNum(r.up_bps),
        down_bps: safeNum(r.down_bps),
        up_total_bytes: safeNum(r.up_total_bytes),
        down_total_bytes: safeNum(r.down_total_bytes),
        connections: safeNum(r.connections ?? r.active_connections),
        memory_mb: safeNum(r.memory_mb ?? r.core_memory_mb),
        timestamp_ms: safeNum(r.timestamp_ms),
      }))
      .filter((s) => s.timestamp_ms > 0);
  },

  /**
   * Subscribe to 2-second traffic telemetry.
   * Uses real Tauri event stream in desktop runtime; smooth mock ticker only in browser preview.
   */
  subscribeTraffic(onSample: (sample: TrafficSample) => void): () => void {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let mockTimer: number | null = null;
    let step = 80;

    const startMockTicker = () => {
      if (disposed || mockTimer !== null) return;
      mockTimer = window.setInterval(() => {
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
          memory_mb: Number((34.4 + wave * 4.5 + jitter * 0.6).toFixed(1)),
          timestamp_ms: Date.now(),
        });
      }, 2000);
    };

    if (isTauriEnv()) {
      type RawTrafficPayload = Partial<TrafficSample> & {
        active_connections?: number;
        core_memory_mb?: number;
      };
      void tauriListen<RawTrafficPayload>("catcloud://traffic", (payload) => {
        if (disposed || !payload) return;
        const safeNum = (v: unknown): number =>
          typeof v === "number" && Number.isFinite(v) ? v : 0;
        onSample({
          up_bps: safeNum(payload.up_bps),
          down_bps: safeNum(payload.down_bps),
          up_total_bytes: safeNum(payload.up_total_bytes),
          down_total_bytes: safeNum(payload.down_total_bytes),
          connections: safeNum(payload.connections ?? payload.active_connections),
          memory_mb: safeNum(payload.memory_mb ?? payload.core_memory_mb),
          timestamp_ms: safeNum(payload.timestamp_ms) || Date.now(),
        });
      }).then((fn) => {
        if (disposed) {
          fn?.();
          return;
        }
        unlisten = fn;
      });
    } else {
      startMockTicker();
    }

    return () => {
      disposed = true;
      unlisten?.();
      if (mockTimer !== null) {
        window.clearInterval(mockTimer);
        mockTimer = null;
      }
    };
  },

  subscribeRuntimeUpdate(onUpdate: (info: CoreRuntimeInfo) => void): () => void {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    if (isTauriEnv()) {
      void tauriListen<CoreRuntimeInfo>("catcloud://runtime", (payload) => {
        if (!disposed) onUpdate(payload);
      }).then((fn) => {
        if (disposed) {
          fn?.();
        } else {
          unlisten = fn;
        }
      });
    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  },

  subscribeProbeProgress(onProgress: (ev: ProbeProgressEvent) => void): () => void {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    if (isTauriEnv()) {
      void tauriListen<ProbeProgressEvent>("catcloud://probe-progress", (payload) => {
        if (!disposed && payload) onProgress(payload);
      }).then((fn) => {
        if (disposed) {
          fn?.();
        } else {
          unlisten = fn;
        }
      });
    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  },

  subscribeStrategySwitch(onSwitch: (ev: StrategySwitchEvent) => void): () => void {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    if (isTauriEnv()) {
      void tauriListen<StrategySwitchEvent>("catcloud://strategy-switch", (payload) => {
        if (!disposed && payload) onSwitch(payload);
      }).then((fn) => {
        if (disposed) {
          fn?.();
        } else {
          unlisten = fn;
        }
      });
    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  },
};
