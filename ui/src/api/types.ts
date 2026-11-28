/**
 * Pure TypeScript DTO and interface definitions for CatCloud IPC & UI layers.
 * Zero runtime emit.
 */

import type { UiLanguage } from "../i18n/types";

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
export type GlobalPreAccelMode = "off" | "windivert" | "local_socks5" | "suspended_for_tun";
export type PreAccelDispatchStrategy = "auto" | "load_balance" | "fallback";
export type PreAccelLbStrategy = "round_robin" | "consistent_hashing";
export type AgentPromptMode = "autopilot" | "readonly" | "troubleshoot_issue";

export interface DnsTlsDiagnostics {
  status: "healthy" | "degraded_recovered" | "cert_verification_failed" | string;
  category: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  failure_count: number;
  affected_paths: string[];
  affected_upstreams: string[];
  tls_verification_preserved: boolean;
  recovered: boolean;
  recovery_time: string | null;
  next_retry_at: string | null;
  next_retry_hint: string;
  scanned_window_desc?: string;
  network_timeout_only_count?: number;
}

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
  onboarding_completed?: boolean;
}

export interface PreAccelConfig {
  enabled: boolean;
  skip_443_native: boolean;
  probe_url: string;
  fallback_probe_url: string;
  active_relay_id?: string | null;
  campus_portal_guard?: boolean;
  global_bypass_enabled?: boolean;
  global_scope?: GlobalPreAccelScope;
  global_target_processes?: string[];
  windivert_dir?: string | null;
  dispatch_strategy?: PreAccelDispatchStrategy;
  lb_strategy?: PreAccelLbStrategy;
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

export interface UpdateConfig {
  repo: string;
  mode: "next_launch" | "manual" | "auto_restart";
  check_interval_min: number;
  include_prerelease: boolean;
  auto_download?: boolean;
  skipped_version?: string | null;
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
  override_mode?: string;
  override_merge_path?: string | null;
  override_script_path?: string | null;
  block_quic_udp_443?: boolean;
  domestic_direct_enabled?: boolean;
  custom_rules_only?: boolean;
  inline_override_yaml?: string | null;
}

export type GatewayExportProfile =
  | "relay_fragment"
  | "transparent_gateway"
  | "preferred_nodes";

export interface GatewayExportOptions {
  profile: GatewayExportProfile;
  tproxy_port: number;
  redir_port: number;
  dns_listen_port: number;
  redact_secrets: boolean;
}

export interface GatewayExportOutput {
  profile: GatewayExportProfile;
  yaml: string;
  redacted: boolean;
  relay_count: number;
  node_count: number;
  rule_count: number;
  warnings: string[];
  integration_hint: string;
}

export interface BulkRulesParseResult {
  valid_rules: string[];
  skipped_lines: string[];
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
  geodata_mode?: boolean;
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
  ip_clean?: boolean | null;
  ip_risk_level?: "clean" | "datacenter" | "proxy_risk" | "unknown" | string | null;
  ip_asn?: string | null;
  ip_risk_flags?: string | null;
  unlocked_sites: Record<string, boolean>;
  per_probe_ok?: Record<string, boolean>;
  per_probe_up_mbps: Record<string, number>;
  per_probe_down_mbps: Record<string, number>;
  per_probe_ping_ms: Record<string, number>;
  per_probe_detail?: Record<string, string>;
  per_probe_tested_at?: Record<string, string>;
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
  supports_ipv6?: boolean;
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
  reason?: string;
  stage?: string;
  probed_at_ms?: number | null;
}

export type NodeHealthHint = NodeHealthHintDto;

export interface CoreRuntimeInfo {
  running: boolean;
  status: CoreHealthStatus;
  last_error?: string | null;
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
  preaccel_effective_carrier?: string;
  effective_tun_mtu?: number | null;
  preaccel_transport?: Record<string, unknown> | null;
  standalone_tunnel_suspended_for_tun?: boolean;
  global_preaccel_active?: boolean;
  global_preaccel_mode?: GlobalPreAccelMode;
  global_preaccel_socks_port?: number | null;
  global_preaccel_connections?: number;
  global_windivert_active?: boolean;
  preaccel_install_state?: string;
  global_preaccel_verify_state?: PreAccelVerifyState;
  global_preaccel_verify_ms?: number | null;
  dns_tls_diagnostics?: DnsTlsDiagnostics | null;
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
  power_on_tun_degraded?: boolean;
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
  ip_clean?: boolean | null;
  ip_risk_level?: "clean" | "datacenter" | "proxy_risk" | "unknown" | string | null;
  ip_asn?: string | null;
  ip_risk_flags?: string | null;
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

export interface ProbeRunSummary {
  latency_ok_count: number;
  bandwidth_ok_count: number;
  keepalive_ok_count: number;
  failed_count: number;
  exec_error_count: number;
  untested_count: number;
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
  latency_ok_count?: number;
  bandwidth_ok_count?: number;
  keepalive_ok_count?: number;
  failed_count?: number;
  exec_error_count?: number;
  untested_count?: number;
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
  latency_ok_count?: number;
  bandwidth_ok_count?: number;
  keepalive_ok_count?: number;
  failed_count?: number;
  exec_error_count?: number;
  untested_count?: number;
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
  chain_latency_ms?: number | null;
  up_mbps: number | null;
  down_mbps: number | null;
  mode: "via_node" | "relay_direct";
  reference_node_name: string | null;
  error: string | null;
}

export type PreAccelRelaySpeedResult = PreAccelSpeedTestResult;

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

export interface SyncSendSessionDto {
  session_id: string;
  pin_code: string;
  lan_urls: string[];
  custom_endpoint: string | null;
  port: number;
  fingerprint: string;
  qr_uri: string;
  qr_svg: string;
  expires_at_unix: number;
  payload_bytes: number;
  allow_multiple: boolean;
}

export interface SyncReceiveSessionDto {
  session_id: string;
  pin_code: string;
  lan_urls: string[];
  custom_endpoint: string | null;
  port: number;
  qr_uri: string;
  qr_svg: string;
  expires_at_unix: number;
  allow_multiple: boolean;
}

export interface SyncEncryptedFileExportDto {
  cancelled: boolean;
  path: string | null;
  fingerprint: string;
  key_uri: string;
  qr_svg: string;
  payload_bytes: number;
  node_count: number;
  relay_count: number;
  group_count: number;
}

export interface SyncPreviewDto {
  pending_token: string;
  fingerprint: string;
  group_count: number;
  group_names: string[];
  preview: ShareBundlePreview;
}

export interface SyncReceivedEvent {
  session_id: string;
  pending_token: string;
  fingerprint: string;
  via_pin: boolean;
  node_count: number;
  relay_count: number;
  group_count: number;
  pack_name: string;
}

export interface SyncSessionUpdatedEvent {
  session_id: string;
  role: string;
  status: string;
  message: string;
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
  reloaded?: boolean;
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
  skipped?: boolean;
  skipped_version?: string | null;
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

export type StagedUpdateKind = "portable_zip" | "installer_package";
export type StagedUpdateApplyAction =
  | "portable_restart"
  | "installer_launch"
  | "reveal_archive";

export interface PendingUpdatePromptDto {
  current_version: string;
  target_version: string;
  kind: StagedUpdateKind;
  apply_action: StagedUpdateApplyAction;
  archive_sha256: string;
  package_size_bytes: number;
  staged_at: string;
  release_notes: string;
  release_url: string | null;
  platform_key: string | null;
  installer_filename: string | null;
  dismissed_in_session: boolean;
  is_elevated: boolean;
  silent_badge_only?: boolean;
}

export interface MigrationApplyOutcome {
  imported_count: number;
  sub_id: string;
  saved_rules_count?: number;
  dropped_dangling_rules_count?: number;
  rewritten_dangling_rules_count?: number;
  dropped_dangling_targets?: Array<[string, number]>;
}

export interface DanglingRuleGroupSummary {
  target: string;
  count: number;
  sample_rules: string[];
}

export interface DanglingRulesAudit {
  total_dangling: number;
  groups: DanglingRuleGroupSummary[];
  default_fallback_group: string;
}

export interface DanglingRuleRepairReport {
  removed_count: number;
  rewritten_count: number;
  target_group: string | null;
  affected_targets: string[];
}

export interface SkipUpdateResultDto {
  skipped_version: string;
  purged_staged: boolean;
  freed_bytes: number;
  message: string;
}

export interface ApplyUpdateRestartResultDto {
  started: boolean;
  exiting: boolean;
  cancelled: boolean;
  kind: StagedUpdateKind;
  apply_action: StagedUpdateApplyAction;
  target_version: string;
  message: string;
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
