/**
 * CatCloud Strongly-Typed Tauri v2 IPC Client with Browser Preview Mock Fallback.
 *
 * - In Tauri runtime (`window.__TAURI_INTERNALS__`), delegates directly to `@tauri-apps/api/core`
 *   and `@tauri-apps/api/event`, surfacing backend IPC errors instead of silently returning null.
 * - In standalone browser preview (`pnpm dev` / `pnpm preview`), serves sanitized demo data using
 *   RFC 5737 documentation IP ranges and placeholder provider labels only.
 */

import {
  DEFAULT_GLOBAL_TARGET_PROCESSES,
  buildShellEnvFallback,
  detectNavigatorOs,
  type ShellEnvKind,
} from "../utils/platform";
import { normalizeUiLanguage, type UiLanguage } from "../i18n";

export type { UiLanguage };

export type ThemeMode = "auto_time" | "light" | "warm_dark" | "midnight_blue";
export type ResolvedTheme = "light" | "warm-dark" | "midnight-blue";
export type TrayIconMode = "auto_ac" | "always_a" | "always_c" | "always_pixel";
export type ProxyMode = "rule" | "global" | "direct";
export type TunStackMode = "mixed" | "system" | "gvisor";
export type CoreHealthStatus = "idle" | "ok" | "preaccel" | "warn" | "error";
export type MemoryTier = "auto" | "mb48" | "mb64" | "mb96" | "48MiB" | "64MiB" | "96MiB";
export type PreAccelOverrideMode = "inherit" | "force_on" | "force_off";
export type RouteTargetMode = "single" | "group";
export type GlobalPreAccelScope = "proxy_apps_only" | "all_non_443_tcp";
export type GlobalPreAccelMode = "off" | "windivert" | "local_socks5";

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
  ui_language?: UiLanguage;
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
  global_bypass_enabled?: boolean;
  global_scope?: GlobalPreAccelScope;
  global_target_processes?: string[];
  windivert_dir?: string | null;
}

export type PreAccelInstallState =
  | "idle"
  | "downloading"
  | "verifying"
  | "ready"
  | "need_elevation"
  | "failed";

export type PreAccelVerifyState =
  | "idle"
  | "probing"
  | "verified"
  | "degraded"
  | "failed";

export interface AcceleratedProcessStat {
  process_name: string;
  pid: number;
  detected_by: string;
  active_connections: number;
  total_connections: number;
  tx_bytes: number;
  rx_bytes: number;
  last_seen_ms: number;
}

export interface GlobalPreAccelStatus {
  running: boolean;
  mode: GlobalPreAccelMode;
  socks_port: number | null;
  windivert_available: boolean;
  windivert_path: string | null;
  is_elevated: boolean;
  active_connections: number;
  total_connections: number;
  up_bytes: number;
  down_bytes: number;
  accelerated_processes: string[];
  active_relays: string[];
  last_error: string | null;
  is_windivert_active?: boolean;
  install_state?: PreAccelInstallState;
  process_stats?: AcceleratedProcessStat[];
  verify_state?: PreAccelVerifyState;
  verify_latency_ms?: number | null;
  verify_message?: string | null;
  verify_checked_at_ms?: number | null;
  detected_security_products?: string[];
  security_guidance?: string | null;
  bound_physical_interface?: string | null;
}

export const DEFAULT_GLOBAL_PREACCEL_STATUS: GlobalPreAccelStatus = {
  running: false,
  mode: "off",
  socks_port: null,
  windivert_available: false,
  windivert_path: null,
  is_elevated: false,
  active_connections: 0,
  total_connections: 0,
  up_bytes: 0,
  down_bytes: 0,
  accelerated_processes: [],
  active_relays: [],
  last_error: null,
  is_windivert_active: false,
  install_state: "idle",
  process_stats: [],
  verify_state: "idle",
  verify_latency_ms: null,
  verify_message: null,
  verify_checked_at_ms: null,
  detected_security_products: [],
  security_guidance: null,
  bound_physical_interface: null,
};

export interface UpdateConfig {
  repo: string;
  mode: "next_launch" | "manual" | "auto_restart";
  check_interval_min: number;
  include_prerelease: boolean;
  auto_download?: boolean;
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
  behavior?: {
    minimize_to_tray_on_close?: boolean;
  };
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
    compile_all_nodes?: boolean;
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
  update?: Partial<UpdateConfig> & {
    last_checked_at?: string | null;
  };
  [key: string]: unknown;
}

export interface SubscriptionRecord {
  id: string;
  name: string;
  kind: "url" | "file" | "migrated" | "process_adapter";
  url_or_cmd: string;
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
  last_up_mbps?: number | null;
  last_down_mbps?: number | null;
}

export interface TrafficSample {
  up_bps: number;
  down_bps: number;
  up_total_bytes: number;
  down_total_bytes: number;
  connections: number;
  tunnel_connections?: number;
  memory_mb: number;
  timestamp_ms: number;
}

export interface SanitizedDiagnosticsDto {
  ai_prompt_markdown?: string;
  [key: string]: unknown;
}

export interface NodeHealthHintDto {
  latency_ms: number | null;
  status: "healthy" | "degraded" | "cooldown" | "probation";
  cooldown_remaining_sec: number;
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
  preaccel_enabled?: boolean;
  preaccel_relay_name: string | null;
  global_preaccel_active?: boolean;
  global_preaccel_mode?: GlobalPreAccelMode;
  global_preaccel_socks_port?: number | null;
  global_preaccel_connections?: number;
  global_windivert_active?: boolean;
  preaccel_install_state?: string;
  global_preaccel_verify_state?: PreAccelVerifyState;
  global_preaccel_verify_ms?: number | null;
  node_health_hints?: Record<string, NodeHealthHintDto>;
  probing_active?: boolean;
  switching_active?: boolean;
  active_group_circuit_open?: boolean;
  active_group_state?: string | null;
  captive_portal_required: boolean;
  system_proxy_enabled: boolean;
  tun_enabled: boolean;
  tun_configured?: boolean;
  tun_needs_elevation?: boolean;
  tun_admin_ready: boolean;
  app_version: string;
  os_label: string;
  autostart_enabled: boolean;
  portable_mode: boolean;
  last_update_check: string | null;
}

export type CoreRuntimeInfoDto = CoreRuntimeInfo;
export type RuntimeInfoDto = CoreRuntimeInfo;

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

export interface PreAccelSpeedTestResult {
  relay_id: string;
  relay_name: string;
  ok: boolean;
  latency_ms: number | null;
  up_mbps: number | null;
  down_mbps: number | null;
  mode: "via_node" | "relay_direct";
  reference_node_name: string | null;
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
  module_id: string;
  file_name: string;
  lang: string;
  title: string;
  summary: string;
  when_to_use_and_signals: string[];
  external_prereqs_and_schema: string[];
  gui_and_cli_verification: string[];
  rollback_and_troubleshooting: string[];
  contract_example: string;
}

export type SubscriptionUpdateMode = "replace_latest" | "merge_dedup";

export interface SubscriptionNodesUpdateResult {
  sub_id: string;
  kept_count: number;
  added_count: number;
  replaced_count: number;
  total_count: number;
  id_remap: Record<string, string>;
}

export interface MergeSubscriptionsResult {
  target_sub_id: string;
  source_sub_id: string;
  moved_count: number;
  deduplicated_count: number;
  total_count: number;
  id_remap: Record<string, string>;
}

export interface ShareBundleManifest {
  schema: string;
  name: string;
  created_at: string;
  node_count: number;
  relay_count: number;
  description: string | null;
  sanitized_notice: string;
}

export interface ShareBundlePreview {
  zip_path: string;
  manifest: ShareBundleManifest;
  nodes: ProxyNode[];
  relays: PreAccelRelay[];
  warnings: string[];
  has_readme: boolean;
}

export interface ShareBundleExportOutcome {
  cancelled: boolean;
  path: string | null;
  manifest: ShareBundleManifest | null;
}

export interface ShareBundleImportOutcome {
  imported_nodes: number;
  imported_relays: number;
  target_sub_id: string | null;
  target_sub_name: string | null;
  warnings: string[];
}

export interface ExportAgentDocOutcome {
  cancelled: boolean;
  path: string | null;
  bytes: number;
}

export interface AgentBootstrapPromptDto {
  prompt: string;
  cli_path: string;
  data_dir: string;
  docs_index_path: string;
  lang: string;
}

export interface GithubIssueDraftDto {
  issue_url: string;
  clipboard_markdown: string;
  title: string;
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
  display_name?: string | null;
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

export interface DesktopAppCandidate {
  pid: number;
  window_title: string;
  friendly_name: string;
  process_name: string;
  exe_path: string | null;
  working_dir: string | null;
  related_pids: number[];
  is_newly_opened: boolean;
  likely_proxy_client: boolean;
}

export interface LiveCaptureStartDto {
  session_id: string;
  target_pid: number;
  target_name: string;
  watch_dirs: string[];
}

export interface LiveCaptureEventItem {
  timestamp_ms: number;
  kind: string;
  message: string;
}

export interface LiveCaptureStatusDto {
  session_id: string;
  active: boolean;
  timed_out?: boolean;
  step_app_ready: boolean;
  step_activity_seen: boolean;
  step_nodes_ready: boolean;
  elapsed_sec: number;
  captured_node_count: number;
  opaque_change_detected: boolean;
  target_name: string;
  watch_dirs: string[];
  events: LiveCaptureEventItem[];
  preview_nodes: ProxyNode[];
  unsupported_reason: string | null;
}

export type CaptureSessionStatus = LiveCaptureStatusDto;

export interface LiveCaptureOutcomeDto {
  session_id: string;
  supported: boolean;
  target_name: string;
  source_kind: "migrated" | "file" | "process_adapter" | "none";
  source_path: string | null;
  is_ephemeral_source: boolean;
  nodes: ProxyNode[];
  unsupported_reason: string | null;
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
  staged_version?: string | null;
  platform_key?: string;
  can_auto_stage?: boolean;
  download_url?: string | null;
  error?: string | null;
}

export interface DownloadAndStageUpdateResult {
  staged: boolean;
  already_latest?: boolean;
  can_auto_stage?: boolean;
  target_version?: string | null;
  archive_sha256?: string | null;
  release_url?: string | null;
  download_url?: string | null;
  message?: string;
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

const FRIENDLY_ERROR_RULES: ReadonlyArray<{ pattern: RegExp; message: string }> = [
  {
    pattern:
      /probe[_\s-]?running|another\s+probe.*running|probe\s+already\s+running|benchmark.*already\s+running/i,
    message: "已有测速或对比任务正在进行，请稍候完成后再试",
  },
  {
    pattern:
      /update_staging_lock|update.*already\s+(?:in\s+progress|downloading)|already\s+staging/i,
    message: "应用更新正在后台下载中，请稍候完成后再试",
  },
  {
    pattern: /address\s+already\s+in\s+use|os\s+error\s+10048\b|eaddrinuse/i,
    message: "本地端口已被其它程序占用，请在设置中更换端口后重试",
  },
  {
    pattern: /os\s+error\s+10061\b|connection\s+refused|econnrefused/i,
    message: "本地服务或目标端口拒绝连接，请确认核心已启动或目标地址可用",
  },
  {
    pattern:
      /os\s+error\s+10054\b|os\s+error\s+10053\b|connection\s+reset|econnreset|broken\s+pipe|connection\s+aborted/i,
    message: "网络连接被意外中断，请检查网络或切换节点后重试",
  },
  {
    pattern:
      /os\s+error\s+10060\b|timed\s*out|etimedout|deadline\s+has\s+elapsed|operation\s+timeout|request\s+timeout/i,
    message: "连接超时，请检查网络状况或切换节点后重试",
  },
  {
    pattern:
      /dns\s+error|failed\s+to\s+lookup\s+address|no\s+such\s+host|enotfound|name\s+or\s+service\s+not\s+known|could\s+not\s+resolve\s+host|os\s+error\s+11001\b/i,
    message: "域名解析失败，请检查网络连接或确认网址是否正确",
  },
  {
    pattern:
      /invalid\s+peer\s+certificate|certificate\s+(?:verify|expired|invalid|unknown)|unknown\s+issuer|tls\s+handshake|ssl\s+handshake|unexpected\s+eof\s+during\s+handshake/i,
    message: "安全连接（TLS / 证书）握手失败，请检查系统时间或证书配置",
  },
  {
    pattern: /socks[45]?\s+error|proxy\s+connect|http\s+status\s+407|tunnel\s+connection\s+failed/i,
    message: "代理通道连接失败，请检查核心状态或中转线路配置",
  },
  {
    pattern: /unexpected\s+eof|early\s+eof|incomplete\s+message|channel\s+closed|hyper::error/i,
    message: "远端提前断开连接，请稍后重试",
  },
  {
    pattern:
      /<!doctype\s+html|<html\b|returned\s+html|html\s+(?:page|document|response)|webpage\s+instead\s+of/i,
    message:
      "订阅链接返回了网页内容而不是节点列表（可能链接已失效、需要登录或被防火墙拦截），请确认复制的是原始订阅链接",
  },
  {
    pattern:
      /clash\s+yaml\s+document\s+does\s+not\s+contain\s+a\s+['"]?proxies['"]?\s+section|does\s+not\s+contain\s+a\s+['"]?proxies['"]?\s+section|missing\s+['"]?proxies['"]?\s+section/i,
    message:
      "订阅内容里没有找到节点列表（缺少 proxies 配置段），请确认这不是纯分流规则文件或失效链接",
  },
  {
    pattern: /expected\s+yaml\s+mapping\s+at\s+top\s+level/i,
    message:
      "订阅返回的内容不是有效的节点配置格式（可能返回了网页提示或链接已过期），请检查订阅链接是否正确",
  },
  {
    pattern:
      /subscription\s+payload\s+is\s+empty|empty\s+subscription|no\s+valid\s+proxy\s+nodes/i,
    message: "订阅返回的内容为空或未包含可用节点，已保留现有节点未覆盖",
  },
  {
    pattern:
      /invalid\s+subscription\s+url|unsupported\s+subscription\s+scheme|relative\s+url\s+without\s+a\s+base/i,
    message: "订阅链接格式无效，请粘贴以 http:// 或 https:// 开头的完整订阅地址",
  },
  {
    pattern:
      /non-2xx\s+status\s*401\b|\b401\s+unauthorized\b|status\s+code\s*401\b|http\s+401\b/i,
    message: "订阅或目标地址需要登录认证（401），链接可能已过期或缺少校验参数",
  },
  {
    pattern:
      /non-2xx\s+status\s*403\b|\b403\s+forbidden\b|status\s+code\s*403\b|http\s+403\b/i,
    message: "目标服务器拒绝访问（403），订阅链接可能已失效、过期或受地区限制",
  },
  {
    pattern:
      /non-2xx\s+status\s*404\b|\b404\s+not\s+found\b|status\s+code\s*404\b|http\s+404\b/i,
    message: "目标地址不存在（404），请检查订阅链接是否复制完整",
  },
  {
    pattern:
      /non-2xx\s+status\s*429\b|\b429\s+too\s+many\s+requests\b|status\s+code\s*429\b|http\s+429\b/i,
    message: "请求过于频繁（429），请稍等片刻后再试",
  },
  {
    pattern:
      /non-2xx\s+status\s*50[0234]\b|\b50[0234]\b.*(?:bad\s+gateway|service\s+unavailable|gateway\s+timeout|internal\s+server)|status\s+code\s*50[0234]\b|http\s+50[0234]\b/i,
    message: "远端服务器暂时繁忙或不可用（5xx），请稍后重试",
  },
  {
    pattern: /non-2xx\s+status\s+\d+/i,
    message: "订阅服务器返回异常状态，请确认链接有效或稍后重试",
  },
  {
    pattern:
      /error\s+sending\s+request\s+for\s+url|client\s+error\s*\(connect\)|tcp\s+connect\s+error|network\s+is\s+unreachable|host\s+is\s+unreachable|os\s+error\s+10051\b|os\s+error\s+10065\b/i,
    message: "无法连接到目标服务器，请检查网络连接或切换节点后重试",
  },
  {
    pattern: /no\s+such\s+file\s+or\s+directory|cannot\s+find\s+the\s+(?:file|path)|os\s+error\s+[23]\b|enoent/i,
    message: "找不到指定的文件或目录，请确认路径是否正确",
  },
  {
    pattern:
      /permission\s+denied|access\s+is\s+denied|os\s+error\s+5\b|eacces|eperm|requires\s+elevation|os\s+error\s+740\b/i,
    message: "系统权限不足，请检查文件权限或尝试以管理员身份运行",
  },
  {
    pattern:
      /being\s+used\s+by\s+another\s+process|os\s+error\s+32\b|text\s+file\s+busy|sharing\s+violation/i,
    message: "目标文件正被其它程序占用，请关闭相关程序后重试",
  },
  {
    pattern: /no\s+space\s+left|disk\s+full|os\s+error\s+112\b/i,
    message: "磁盘空间不足，请清理空间后重试",
  },
  {
    pattern:
      /eof\s+while\s+parsing|expected\s+value\s+at\s+line|serde_json|trailing\s+characters|invalid\s+json|unexpected\s+token.*json/i,
    message: "返回内容或配置文件格式有误，请检查内容是否完整",
  },
  {
    pattern: /serde_yaml|while\s+scanning|mapping\s+values\s+are\s+not\s+allowed|invalid\s+yaml/i,
    message: "配置文件 YAML 格式有误，请检查缩进与语法",
  },
  {
    pattern: /database\s+is\s+locked|sqlite.*(?:locked|busy)/i,
    message: "本地数据正在写入，请稍等片刻后重试",
  },
  {
    pattern: /poisonerror|lock\s+poisoned/i,
    message: "后台任务状态异常，请重试或重启猫猫云梯",
  },
];

function matchFriendlyErrorRule(text: string): string | null {
  for (const rule of FRIENDLY_ERROR_RULES) {
    if (rule.pattern.test(text)) {
      return rule.message;
    }
  }
  return null;
}

function translateRawErrorMessage(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "操作未完成，请稍后重试";
  // Preserve structured privilege elevation sentinel consumed by toggleTun / event handlers
  if (trimmed.includes("NEEDS_ADMIN:")) {
    return trimmed;
  }

  const cleaned = trimmed.replace(/^(?:Error|IPC error|invoke error):\s*/i, "").trim();
  const chinesePrefixMatch = /^([^\n:：]{2,32})[：:]\s*(.+)$/s.exec(cleaned);
  if (chinesePrefixMatch) {
    const prefix = chinesePrefixMatch[1].trim();
    const rest = chinesePrefixMatch[2].trim();
    const prefixHasChinese = /[\u4e00-\u9fa5]{2,}/.test(prefix);
    if (prefixHasChinese) {
      const mappedRest = matchFriendlyErrorRule(rest);
      if (mappedRest) {
        return `${prefix}：${mappedRest}`;
      }
    }
  }

  const mappedWhole = matchFriendlyErrorRule(cleaned);
  if (mappedWhole) {
    return mappedWhole;
  }

  return cleaned;
}

export function formatErrorMessage(err: unknown): string {
  let raw: string;
  if (err instanceof Error) {
    raw = err.message;
  } else if (typeof err === "string") {
    raw = err;
  } else if (err && typeof err === "object" && "message" in err && typeof err.message === "string") {
    raw = err.message;
  } else {
    try {
      raw = JSON.stringify(err);
    } catch {
      raw = String(err);
    }
  }
  return translateRawErrorMessage(raw);
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

function extractDialogSinglePath(raw: unknown): string | null {
  if (typeof raw === "string") {
    return raw.trim() || null;
  }
  if (Array.isArray(raw)) {
    const first = raw[0];
    if (typeof first === "string") return first.trim() || null;
    if (first && typeof first === "object" && "path" in first && typeof first.path === "string") {
      return first.path.trim() || null;
    }
    return null;
  }
  if (raw && typeof raw === "object" && "path" in raw && typeof raw.path === "string") {
    return raw.path.trim() || null;
  }
  return null;
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
  behavior: {
    minimize_to_tray_on_close: true,
  },
  preaccel: {
    enabled: true,
    skip_443_native: true,
    probe_url: "http://connectivitycheck.platform.hicloud.com/generate_204",
    fallback_probe_url: "http://connect.rom.miui.com/generate_204",
    campus_portal_guard: true,
    global_bypass_enabled: false,
    global_scope: "proxy_apps_only",
    global_target_processes: [...DEFAULT_GLOBAL_TARGET_PROCESSES],
    windivert_dir: null,
  },
  personalization: {
    ui_language: "zh-CN",
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
    auto_download: true,
  },
};

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

export function hasPreviewTunNeedsAdminFlag(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.get("preview_tun_needs_admin") === "1") return true;
    const hash = window.location.hash || "";
    const qIdx = hash.indexOf("?");
    if (qIdx >= 0) {
      const hashParams = new URLSearchParams(hash.slice(qIdx + 1));
      if (hashParams.get("preview_tun_needs_admin") === "1") return true;
    }
    return /(?:^|[?&#])preview_tun_needs_admin=1(?:$|&|#)/.test(hash);
  } catch {
    return false;
  }
}

const previewTunNeedsAdmin = !isTauriEnv() && hasPreviewTunNeedsAdminFlag();

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
    override_script_path: null,
    block_quic_udp_443: true,
    domestic_direct_enabled: true,
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
const VALID_PREACCEL_INSTALL_STATES = new Set<PreAccelInstallState>([
  "idle",
  "downloading",
  "verifying",
  "ready",
  "need_elevation",
  "failed",
]);

const VALID_PREACCEL_VERIFY_STATES = new Set<PreAccelVerifyState>([
  "idle",
  "probing",
  "verified",
  "degraded",
  "failed",
]);

const DETECTED_BY_PRIORITY: Record<string, number> = {
  system_proxy_host: 5,
  open_core_name: 4,
  local_proxy_listener: 3,
  manual: 2,
  scope_all: 1,
  runtime: 0,
};

function detectedByRank(kind: string): number {
  return DETECTED_BY_PRIORITY[kind.trim().toLowerCase()] ?? 0;
}

function normalizeAcceleratedProcessStats(raw: unknown): AcceleratedProcessStat[] {
  if (!Array.isArray(raw)) return [];
  const safeNum = (v: unknown): number =>
    typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
  const merged = new Map<string, AcceleratedProcessStat>();
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const processName = typeof rec.process_name === "string" ? rec.process_name.trim() : "";
    if (!processName) continue;
    const key = processName.toLowerCase();
    const detectedBy = typeof rec.detected_by === "string" ? rec.detected_by.trim() || "runtime" : "runtime";
    const pid = safeNum(rec.pid);
    const activeConnections = safeNum(rec.active_connections);
    const totalConnections = safeNum(rec.total_connections);
    const txBytes = safeNum(rec.tx_bytes);
    const rxBytes = safeNum(rec.rx_bytes);
    const lastSeenMs = safeNum(rec.last_seen_ms);

    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        process_name: processName,
        pid,
        detected_by: detectedBy,
        active_connections: activeConnections,
        total_connections: totalConnections,
        tx_bytes: txBytes,
        rx_bytes: rxBytes,
        last_seen_ms: lastSeenMs,
      });
    } else {
      const preferNewSource = detectedByRank(detectedBy) > detectedByRank(existing.detected_by);
      const preferNewPid = lastSeenMs >= existing.last_seen_ms && pid > 0;
      merged.set(key, {
        process_name: existing.process_name,
        pid: preferNewPid ? pid : existing.pid,
        detected_by: preferNewSource ? detectedBy : existing.detected_by,
        active_connections: existing.active_connections + activeConnections,
        total_connections: existing.total_connections + totalConnections,
        tx_bytes: existing.tx_bytes + txBytes,
        rx_bytes: existing.rx_bytes + rxBytes,
        last_seen_ms: Math.max(existing.last_seen_ms, lastSeenMs),
      });
    }
  }
  return Array.from(merged.values()).sort((a, b) => {
    if (b.active_connections !== a.active_connections) {
      return b.active_connections - a.active_connections;
    }
    return b.last_seen_ms - a.last_seen_ms;
  });
}

function normalizeGlobalPreAccelStatus(raw: unknown): GlobalPreAccelStatus {
  if (!raw || typeof raw !== "object") {
    return { ...DEFAULT_GLOBAL_PREACCEL_STATUS };
  }
  const r = raw as Partial<GlobalPreAccelStatus>;
  const mode: GlobalPreAccelMode =
    r.mode === "windivert" || r.mode === "local_socks5" || r.mode === "off"
      ? r.mode
      : r.running
        ? "local_socks5"
        : "off";
  const running = Boolean(r.running);
  const windivertAvailable = Boolean(r.windivert_available);
  const isElevated = Boolean(r.is_elevated);
  const isWindivertActive =
    typeof r.is_windivert_active === "boolean"
      ? r.is_windivert_active && running && mode === "windivert"
      : running && mode === "windivert";
  const installState: PreAccelInstallState =
    typeof r.install_state === "string" &&
    VALID_PREACCEL_INSTALL_STATES.has(r.install_state as PreAccelInstallState)
      ? (r.install_state as PreAccelInstallState)
      : windivertAvailable
        ? isElevated
          ? "ready"
          : "need_elevation"
        : "idle";
  const rawVerifyState =
    typeof r.verify_state === "string"
      ? (r.verify_state.trim().toLowerCase() as PreAccelVerifyState)
      : "idle";
  const verifyState: PreAccelVerifyState = VALID_PREACCEL_VERIFY_STATES.has(rawVerifyState)
    ? rawVerifyState
    : "idle";
  const safeNum = (v: unknown): number =>
    typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
  return {
    running,
    mode,
    socks_port:
      typeof r.socks_port === "number" && Number.isFinite(r.socks_port) && r.socks_port > 0
        ? r.socks_port
        : null,
    windivert_available: windivertAvailable,
    windivert_path: typeof r.windivert_path === "string" ? r.windivert_path : null,
    is_elevated: isElevated,
    active_connections: safeNum(r.active_connections),
    total_connections: safeNum(r.total_connections),
    up_bytes: safeNum(r.up_bytes),
    down_bytes: safeNum(r.down_bytes),
    accelerated_processes: Array.isArray(r.accelerated_processes)
      ? r.accelerated_processes.filter((x): x is string => typeof x === "string")
      : [],
    active_relays: Array.isArray(r.active_relays)
      ? r.active_relays.filter((x): x is string => typeof x === "string")
      : [],
    last_error: typeof r.last_error === "string" && r.last_error.trim() ? r.last_error : null,
    is_windivert_active: isWindivertActive,
    install_state: installState,
    process_stats: normalizeAcceleratedProcessStats(r.process_stats),
    verify_state: verifyState,
    verify_latency_ms:
      typeof r.verify_latency_ms === "number" &&
      Number.isFinite(r.verify_latency_ms) &&
      r.verify_latency_ms >= 0
        ? r.verify_latency_ms
        : null,
    verify_message:
      typeof r.verify_message === "string" && r.verify_message.trim()
        ? r.verify_message.trim()
        : null,
    verify_checked_at_ms:
      typeof r.verify_checked_at_ms === "number" &&
      Number.isFinite(r.verify_checked_at_ms) &&
      r.verify_checked_at_ms > 0
        ? r.verify_checked_at_ms
        : null,
    detected_security_products: Array.isArray(r.detected_security_products)
      ? r.detected_security_products
          .filter((x): x is string => typeof x === "string" && x.trim().length > 0)
          .map((x) => x.trim())
      : [],
    security_guidance:
      typeof r.security_guidance === "string" && r.security_guidance.trim()
        ? r.security_guidance.trim()
        : null,
    bound_physical_interface:
      typeof r.bound_physical_interface === "string" && r.bound_physical_interface.trim()
        ? r.bound_physical_interface.trim()
        : null,
  };
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
  node_health_hints: {
    "node-jp-01": { latency_ms: 68, status: "healthy", cooldown_remaining_sec: 0 },
    "node-sg-02": { latency_ms: 82, status: "healthy", cooldown_remaining_sec: 0 },
    "node-us-03": { latency_ms: 144, status: "healthy", cooldown_remaining_sec: 0 },
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
  mockGlobalPreAccel = {
    ...mockGlobalPreAccel,
    active_relays: activeRelays,
    is_windivert_active: isWindivertActive,
  };
  mockRuntime = {
    ...mockRuntime,
    tun_enabled: effectiveTunEnabled,
    tun_configured: tunConfigured,
    tun_needs_elevation: tunNeedsElevation,
    preaccel_enabled: mockConfig.preaccel.enabled,
    preaccel_active: preaccelActive,
    preaccel_relay_name: activeRelays[0] ?? null,
    global_preaccel_active: globalActive,
    global_preaccel_mode: mockGlobalPreAccel.mode,
    global_preaccel_socks_port: mockGlobalPreAccel.socks_port,
    global_preaccel_connections: mockGlobalPreAccel.active_connections,
    global_windivert_active: isWindivertActive,
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

function normalizeLiveCaptureStatus(
  raw: unknown,
  fallbackSessionId = ""
): LiveCaptureStatusDto {
  const safeNum = (v: unknown): number =>
    typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
  if (!raw || typeof raw !== "object") {
    return {
      session_id: fallbackSessionId,
      active: false,
      timed_out: false,
      step_app_ready: false,
      step_activity_seen: false,
      step_nodes_ready: false,
      elapsed_sec: 0,
      captured_node_count: 0,
      opaque_change_detected: false,
      target_name: "目标软件",
      watch_dirs: [],
      events: [],
      preview_nodes: [],
      unsupported_reason: null,
    };
  }
  const r = raw as Partial<LiveCaptureStatusDto>;
  const active = Boolean(r.active);
  const elapsedSec = safeNum(r.elapsed_sec);
  const timedOut =
    typeof r.timed_out === "boolean"
      ? r.timed_out
      : !active && elapsedSec >= 180;
  const previewNodes = Array.isArray(r.preview_nodes) ? r.preview_nodes : [];
  const rawEvents = Array.isArray(r.events) ? r.events : [];
  const events: LiveCaptureEventItem[] = rawEvents
    .filter((ev): ev is LiveCaptureEventItem => Boolean(ev && typeof ev === "object"))
    .map((ev) => ({
      timestamp_ms: safeNum(ev.timestamp_ms),
      kind: typeof ev.kind === "string" ? ev.kind : "info",
      message: typeof ev.message === "string" ? ev.message : "",
    }))
    .filter((ev) => ev.message.length > 0);
  return {
    session_id:
      typeof r.session_id === "string" && r.session_id.trim()
        ? r.session_id.trim()
        : fallbackSessionId,
    active,
    timed_out: timedOut,
    step_app_ready: Boolean(r.step_app_ready),
    step_activity_seen: Boolean(r.step_activity_seen),
    step_nodes_ready: Boolean(r.step_nodes_ready),
    elapsed_sec: elapsedSec,
    captured_node_count: Math.max(safeNum(r.captured_node_count), previewNodes.length),
    opaque_change_detected: Boolean(r.opaque_change_detected),
    target_name:
      typeof r.target_name === "string" && r.target_name.trim()
        ? r.target_name.trim()
        : "目标软件",
    watch_dirs: Array.isArray(r.watch_dirs)
      ? r.watch_dirs.filter((d): d is string => typeof d === "string" && d.trim().length > 0)
      : [],
    events,
    preview_nodes: previewNodes,
    unsupported_reason:
      typeof r.unsupported_reason === "string" && r.unsupported_reason.trim()
        ? r.unsupported_reason.trim()
        : null,
  };
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

export const catcloudApi = {
  async getConfig(): Promise<AppConfig> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AppConfig>("get_app_config");
    }
    return structuredClone(mockConfig);
  },

  async saveConfig(next: AppConfig): Promise<AppConfig> {
    if (isTauriEnv()) {
      const wireConfig: AppConfig = {
        ...next,
        update: {
          ...next.update,
          auto_download: next.update.auto_download ?? true,
        },
      };
      delete wireConfig.behavior;
      return tauriInvokeOrThrow<AppConfig>("save_app_config", { config: wireConfig });
    }
    mockConfig = structuredClone(next);
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("get_runtime_info");
    }
    return { ...mockRuntime };
  },

  async startCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("start_core");
    }
    mockRuntime = { ...mockRuntime, running: true };
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async stopCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<CoreRuntimeInfo>("stop_core");
    }
    mockRuntime = { ...mockRuntime, running: false };
    syncMockPreAccelRuntime();
    return { ...mockRuntime };
  },

  async disableAllProxyAndStopCore(): Promise<RuntimeInfoDto> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<RuntimeInfoDto>("disable_all_proxy_and_stop_core");
    }
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
    syncMockPreAccelRuntime();
    return enabled;
  },

  async toggleTun(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("set_tun_enabled", { enabled });
    }
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
    const { source: legacySource, ...cleanRecord } = record as SubscriptionRecord & {
      source?: string;
    };
    const payloadRecord: SubscriptionRecord = {
      ...cleanRecord,
      url_or_cmd: cleanRecord.url_or_cmd || legacySource || "",
    };
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SubscriptionRecord>("upsert_subscription", {
        record: payloadRecord,
      });
    }
    const idx = mockSubscriptions.findIndex((s) => s.id === payloadRecord.id);
    if (idx >= 0) mockSubscriptions[idx] = structuredClone(payloadRecord);
    else mockSubscriptions.push(structuredClone(payloadRecord));
    return structuredClone(payloadRecord);
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

  async renameSubscription(subId: string, newName: string): Promise<SubscriptionRecord> {
    const trimmed = newName.trim();
    if (!trimmed) {
      throw new Error("订阅组名称不能为空");
    }
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SubscriptionRecord>("rename_subscription", {
        subId,
        newName: trimmed,
      });
    }
    const target = mockSubscriptions.find((s) => s.id === subId);
    if (!target) throw new Error(`未找到订阅组：${subId}`);
    target.name = trimmed;
    return structuredClone(target);
  },

  async applyNodesToExistingSubscription(
    targetSubId: string,
    nodes: ProxyNode[],
    mode: SubscriptionUpdateMode
  ): Promise<SubscriptionNodesUpdateResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SubscriptionNodesUpdateResult>(
        "apply_nodes_to_existing_subscription",
        {
          targetSubId,
          nodes,
          mode,
        }
      );
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MergeSubscriptionsResult>("merge_subscriptions", {
        sourceSubId: params.sourceSubId,
        targetSubId: params.targetSubId,
        newTargetName: params.newTargetName?.trim() || null,
        deduplicate: params.deduplicate ?? true,
        convertTargetToMigrated: params.convertTargetToMigrated ?? false,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ShareBundleExportOutcome>("export_share_bundle_dialog", {
        name: params.name.trim() || "猫猫云梯分享包",
        description: params.description?.trim() || null,
        nodeIds: params.nodeIds,
        relayIds: params.relayIds,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ShareBundlePreview | null>("pick_and_preview_share_bundle");
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ShareBundleImportOutcome>("import_share_bundle", {
        zipPath: params.zipPath,
        selectedNodeIds: params.selectedNodeIds,
        selectedRelayIds: params.selectedRelayIds,
        targetSubId: params.targetSubId ?? null,
        newSubName: params.newSubName?.trim() || null,
        updateMode: params.updateMode ?? "merge_dedup",
      });
    }
    return {
      imported_nodes: params.selectedNodeIds.length,
      imported_relays: params.selectedRelayIds.length,
      target_sub_id: params.targetSubId ?? "sub-share-preview",
      target_sub_name: params.newSubName?.trim() || "朋友分享包",
      warnings: [],
    };
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
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("get_global_preaccel_status");
      return normalizeGlobalPreAccelStatus(raw);
    }
    syncMockPreAccelRuntime();
    return structuredClone(mockGlobalPreAccel);
  },

  async toggleGlobalPreAccel(enabled: boolean): Promise<GlobalPreAccelStatus> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("toggle_global_preaccel", { enabled });
      if (raw && typeof raw === "object" && "running" in raw) {
        return normalizeGlobalPreAccelStatus(raw);
      }
      return catcloudApi.getGlobalPreAccelStatus();
    }
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

  async updateGlobalPreAccelSettings(
    scope: GlobalPreAccelScope,
    targetProcesses: string[],
    windivertDir: string | null = null
  ): Promise<GlobalPreAccelStatus> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("update_global_preaccel_settings", {
        scope,
        targetProcesses,
        windivertDir,
      });
      if (raw && typeof raw === "object" && "running" in raw) {
        return normalizeGlobalPreAccelStatus(raw);
      }
      return catcloudApi.getGlobalPreAccelStatus();
    }
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
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("install_windivert_driver");
      if (raw && typeof raw === "object" && "running" in raw) {
        return normalizeGlobalPreAccelStatus(raw);
      }
      const latest = await catcloudApi.getGlobalPreAccelStatus();
      if (typeof raw === "string" && raw.trim() && !latest.windivert_path) {
        return { ...latest, windivert_available: true, windivert_path: raw.trim() };
      }
      return latest;
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("relaunch_as_admin_for_global_preaccel");
    }
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
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("verify_global_preaccel");
      return normalizeGlobalPreAccelStatus(raw);
    }
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

  async testPreAccelRelaySpeeds(
    relayIds: string[] | null = null,
    nodeId: string | null = null
  ): Promise<PreAccelSpeedTestResult[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelSpeedTestResult[]>("test_preaccel_relay_speeds", {
        relayIds,
        nodeId,
      });
    }
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
        up_mbps: upMbps,
        down_mbps: downMbps,
        mode: chosenNode ? "via_node" : "relay_direct",
        reference_node_name: chosenNode ? chosenNode.name : null,
        error: null,
      };
    });
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

  async listAgentDocs(lang?: UiLanguage): Promise<AgentModuleDoc[]> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AgentModuleDoc[]>("list_agent_docs", {
        lang: normalizedLang,
      });
    }
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

  async exportAgentDocs(
    moduleId: string,
    asJson = false,
    lang?: UiLanguage
  ): Promise<string> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("export_agent_docs", {
        moduleId,
        asJson,
        lang: normalizedLang,
      });
    }
    return `# CatCloud Guide (${moduleId} · ${normalizedLang ?? "zh-CN"})\n\n浏览器预览模式示例文档内容。`;
  },

  async buildAgentBootstrapPrompt(
    lang?: UiLanguage,
    currentPage?: string
  ): Promise<AgentBootstrapPromptDto> {
    const normalizedLang = normalizeUiLanguage(lang ?? mockConfig.personalization.ui_language);
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AgentBootstrapPromptDto>("build_agent_bootstrap_prompt", {
        lang: normalizedLang,
        currentPage: currentPage ?? null,
      });
    }
    const cliPath = "C:\\Users\\<USER>\\Apps\\CatCloud\\cli\\catcloud.exe";
    const dataDir = "C:\\Users\\<USER>\\Apps\\CatCloud\\data";
    const docsIndex = `${dataDir}\\agent_docs\\${normalizedLang}\\INDEX.md`;
    const prompt = [
      `请全程使用「${normalizedLang === "en" ? "English" : normalizedLang === "ja" ? "日本語" : normalizedLang === "ru" ? "Русский" : "简体中文"}」向我解释，并主动帮我使用本机工具检查猫猫云梯（CatCloud）。`,
      "",
      `- 可执行 CLI：\`${cliPath}\``,
      `- 数据目录：\`${dataDir}\``,
      `- 随装手册索引：\`${docsIndex}\``,
      `- 当前所在界面：${currentPage || "overview"}`,
      "",
      "## 协作约定",
      "1. 先只读自查：优先阅读随装手册索引并运行 `catcloud status --json`、`catcloud net doctor --json` 摸清现状。",
      "2. 改动前先确认：涉及修改配置、节点、分流或中转前，先用大白话告诉我方案并征得我同意，你可以直接帮我用 CLI 执行。",
      "3. 隐私红线：严禁在回复中复述明文密码、UUID、订阅完整 URL 或真实公网中转 IP。",
    ].join("\n");
    return {
      prompt,
      cli_path: cliPath,
      data_dir: dataDir,
      docs_index_path: docsIndex,
      lang: normalizedLang,
    };
  },

  async exportAgentDocFileDialog(
    moduleId: string,
    lang?: UiLanguage
  ): Promise<ExportAgentDocOutcome> {
    const normalizedLang = normalizeUiLanguage(lang ?? mockConfig.personalization.ui_language);
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ExportAgentDocOutcome>("export_agent_doc_file_dialog", {
        moduleId,
        lang: normalizedLang,
      });
    }
    return {
      cancelled: false,
      path: `catcloud-guide-${moduleId}-${normalizedLang}.md`,
      bytes: 2048,
    };
  },

  async buildGithubIssueUrl(
    summary?: string | null,
    lang?: UiLanguage
  ): Promise<GithubIssueDraftDto> {
    const normalizedLang = normalizeUiLanguage(lang ?? mockConfig.personalization.ui_language);
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<GithubIssueDraftDto>("build_github_issue_url", {
        summary: summary?.trim() || null,
        lang: normalizedLang,
      });
    }
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

  async pickMigrationDirectory(
    title = "选择已有代理软件配置目录（只读，不改动原软件）"
  ): Promise<string | null> {
    if (!isTauriEnv()) {
      return null;
    }
    const raw = await tauriInvokeOrThrow<unknown>("plugin:dialog|open", {
      options: {
        directory: true,
        multiple: false,
        title,
      },
    });
    return extractDialogSinglePath(raw);
  },

  async pickMigrationFile(
    title = "选择代理配置文件（只读，不改动原文件）"
  ): Promise<string | null> {
    if (!isTauriEnv()) {
      return null;
    }
    const raw = await tauriInvokeOrThrow<unknown>("plugin:dialog|open", {
      options: {
        directory: false,
        multiple: false,
        title,
        filters: [
          {
            name: "代理配置文件",
            extensions: ["yaml", "yml", "json", "txt"],
          },
        ],
      },
    });
    return extractDialogSinglePath(raw);
  },

  async scanMigrationPath(path: string): Promise<MigrationPreviewDto[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MigrationPreviewDto[]>("scan_migration_path", { path });
    }
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

  async listDesktopAppCandidates(baselinePids?: number[]): Promise<DesktopAppCandidate[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<DesktopAppCandidate[]>("list_desktop_app_candidates", {
        baselinePids: baselinePids ?? null,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<LiveCaptureStartDto>("start_live_capture_session", {
        targetPid,
      });
    }
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
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("poll_live_capture_session", {
        sessionId,
      });
      return normalizeLiveCaptureStatus(raw, sessionId);
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<LiveCaptureOutcomeDto>("finish_live_capture_session", {
        sessionId,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("cancel_live_capture_session", { sessionId });
    }
    if (mockLiveCapture?.sessionId === sessionId) {
      mockLiveCapture = null;
    }
    return true;
  },

  async capsuleDragStart(): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("capsule_drag_start");
    }
    return true;
  },

  async capsuleDragStep(): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("capsule_drag_step");
    }
    return true;
  },

  async capsuleDragEnd(): Promise<boolean> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<boolean>("capsule_drag_end");
    }
    return true;
  },

  async exportShellEnv(shell: string): Promise<string> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("export_shell_env", { shell });
    }
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

  async buildAiOnboardingPrompt(
    lang?: UiLanguage,
    moduleId?: string | null
  ): Promise<string> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("build_ai_onboarding_prompt", {
        lang: normalizedLang,
        moduleId: moduleId ?? null,
      });
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SanitizedDiagnosticsDto>("export_sanitized_diagnostics");
    }
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AppUpdateCheckResult>("check_app_update");
    }
    const os = detectNavigatorOs();
    const platformKey =
      os === "macos"
        ? "darwin-aarch64"
        : os === "linux"
          ? "linux-x86_64"
          : "windows-x86_64-portable";
    const canAutoStage = os === "windows" && mockRuntime.portable_mode;
    return {
      has_update: false,
      current_version: mockRuntime.app_version,
      latest_version: mockRuntime.app_version,
      release_url: `https://github.com/${mockConfig.update.repo}/releases`,
      notes: "",
      checked_at: new Date().toISOString(),
      staged_version: null,
      platform_key: platformKey,
      can_auto_stage: canAutoStage,
      download_url: null,
    };
  },

  async downloadAndStageUpdate(): Promise<DownloadAndStageUpdateResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<DownloadAndStageUpdateResult>("download_and_stage_update");
    }
    const os = detectNavigatorOs();
    const canAutoStage = os === "windows" && mockRuntime.portable_mode;
    const releaseUrl = `https://github.com/${mockConfig.update.repo}/releases`;
    if (!canAutoStage) {
      return {
        staged: false,
        already_latest: false,
        can_auto_stage: false,
        target_version: mockRuntime.app_version,
        archive_sha256: null,
        release_url: releaseUrl,
        download_url: releaseUrl,
        message: "浏览器预览模式：当前平台为安装包形态，请前往官方下载页获取对应系统安装包",
      };
    }
    return {
      staged: true,
      already_latest: false,
      can_auto_stage: true,
      target_version: mockRuntime.app_version,
      archive_sha256: "preview-sha256-verified",
      release_url: releaseUrl,
      download_url: `${releaseUrl}/latest`,
      message: `浏览器预览模式：已模拟下载并校验 v${mockRuntime.app_version}（下次重启自动应用）`,
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

  async openExternalUrl(url: string): Promise<string> {
    const trimmed = url.trim();
    if (!trimmed) {
      throw new Error("外部链接不能为空");
    }
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("open_external_url", { url: trimmed });
    }
    if (typeof window !== "undefined") {
      window.open(trimmed, "_blank", "noopener,noreferrer");
    }
    return trimmed;
  },

  async getTrafficHistory(): Promise<TrafficSample[]> {
    if (!isTauriEnv()) {
      return [];
    }
    type RawTrafficPayload = Partial<TrafficSample> & {
      active_connections?: number;
      tunnel_connections?: number;
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
        tunnel_connections: safeNum(r.tunnel_connections),
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
          tunnel_connections: mockConfig.preaccel.enabled ? 4 : 0,
          memory_mb: Number((34.4 + wave * 4.5 + jitter * 0.6).toFixed(1)),
          timestamp_ms: Date.now(),
        });
      }, 2000);
    };

    if (isTauriEnv()) {
      type RawTrafficPayload = Partial<TrafficSample> & {
        active_connections?: number;
        tunnel_connections?: number;
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
          tunnel_connections: safeNum(payload.tunnel_connections),
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

  subscribeConfigUpdate(onUpdate: (cfg: AppConfig) => void): () => void {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    if (isTauriEnv()) {
      void tauriListen<AppConfig>("catcloud://config-updated", (payload) => {
        if (!disposed && payload) onUpdate(payload);
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
