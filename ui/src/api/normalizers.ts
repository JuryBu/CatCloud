/**
 * Default configuration objects and runtime DTO normalizers shared by desktop IPC
 * and browser preview fallback.
 */

import { DEFAULT_GLOBAL_TARGET_PROCESSES } from "../utils/platform";
import type {
  AcceleratedProcessStat,
  AppConfig,
  GlobalPreAccelMode,
  GlobalPreAccelStatus,
  LiveCaptureEventItem,
  LiveCaptureStatusDto,
  PreAccelInstallState,
  PreAccelVerifyState,
  TrafficSample,
} from "./types";

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
    dispatch_strategy: "auto",
    lb_strategy: "consistent_hashing",
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
    onboarding_completed: false,
  },
  update: {
    repo: "JuryBu/CatCloud",
    mode: "next_launch",
    check_interval_min: 360,
    include_prerelease: false,
    auto_download: true,
    skipped_version: null,
  },
};

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

export function normalizeAcceleratedProcessStats(raw: unknown): AcceleratedProcessStat[] {
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
    const detectedBy =
      typeof rec.detected_by === "string" ? rec.detected_by.trim() || "runtime" : "runtime";
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

export function normalizeGlobalPreAccelStatus(raw: unknown): GlobalPreAccelStatus {
  if (!raw || typeof raw !== "object") {
    return { ...DEFAULT_GLOBAL_PREACCEL_STATUS };
  }
  const r = raw as Partial<GlobalPreAccelStatus>;
  const mode: GlobalPreAccelMode =
    r.mode === "windivert" ||
    r.mode === "local_socks5" ||
    r.mode === "suspended_for_tun" ||
    r.mode === "off"
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

export function normalizeLiveCaptureStatus(
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
    typeof r.timed_out === "boolean" ? r.timed_out : !active && elapsedSec >= 180;
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

export type RawTrafficPayload = Partial<TrafficSample> & {
  active_connections?: number;
  tunnel_connections?: number;
  core_memory_mb?: number;
};

export function normalizeTrafficSample(
  payload: RawTrafficPayload,
  fallbackTimestampMs = 0
): TrafficSample {
  const safeNum = (v: unknown): number =>
    typeof v === "number" && Number.isFinite(v) ? v : 0;
  return {
    up_bps: safeNum(payload.up_bps),
    down_bps: safeNum(payload.down_bps),
    up_total_bytes: safeNum(payload.up_total_bytes),
    down_total_bytes: safeNum(payload.down_total_bytes),
    connections: safeNum(payload.connections ?? payload.active_connections),
    tunnel_connections: safeNum(payload.tunnel_connections),
    memory_mb: safeNum(payload.memory_mb ?? payload.core_memory_mb),
    timestamp_ms: safeNum(payload.timestamp_ms) || fallbackTimestampMs,
  };
}

const DEFAULT_SEED_UP_TOTAL = 186 * 1024 * 1024;
const DEFAULT_SEED_DOWN_TOTAL = 1.42 * 1024 * 1024 * 1024;

/**
 * Lightweight synchronous seed traffic generator preserved for backward compatibility
 * without pulling the full browser preview mock bundle into the desktop main chunk.
 */
export function generateSeedTrafficSamples(count = 75, intervalMs = 2000): TrafficSample[] {
  const now = Date.now();
  const samples: TrafficSample[] = [];
  let upAccum = DEFAULT_SEED_UP_TOTAL - count * 95_000;
  let downAccum = DEFAULT_SEED_DOWN_TOTAL - count * 520_000;

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
      tunnel_connections: DEFAULT_APP_CONFIG.preaccel.enabled ? 4 : 0,
      memory_mb: Number((34.2 + burst * 4.8).toFixed(1)),
      timestamp_ms: t,
    });
  }
  return samples;
}
