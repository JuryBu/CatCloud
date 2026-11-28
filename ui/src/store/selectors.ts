import type { AppState, BackgroundActivitySummary, ProxyMode } from "./types";

export function selectIsProbeEngineBusy(s: AppState): boolean {
  return Boolean(
    s.probeProgress.running ||
      s.bgTasks.probeLocalStarting ||
      s.bgTasks.preaccel.benchmark.running ||
      s.bgTasks.preaccel.relaysSpeedTestingAll ||
      s.bgTasks.preaccel.relaysSpeedTestingIds.length > 0
  );
}

let cachedBgActivity: BackgroundActivitySummary = {
  preaccel: false,
  nodes: false,
  groups: false,
  home: false,
  settings: false,
};

export function selectHasBackgroundActivity(s: AppState): BackgroundActivitySummary {
  const preaccel = Boolean(
    s.bgTasks.preaccel.benchmark.running ||
      s.bgTasks.preaccel.relaysTestingAll ||
      s.bgTasks.preaccel.relaysTestingIds.length > 0 ||
      s.bgTasks.preaccel.relaysSpeedTestingAll ||
      s.bgTasks.preaccel.relaysSpeedTestingIds.length > 0 ||
      s.bgTasks.preaccel.campusChecking ||
      s.bgTasks.preaccel.installingDriver ||
      s.bgTasks.preaccel.verifyingGlobal
  );
  const nodes = Boolean(
    s.probeProgress.running ||
      s.bgTasks.probeLocalStarting ||
      s.bgTasks.subs.refreshingAll ||
      s.bgTasks.subs.refreshingIds.length > 0 ||
      s.bgTasks.subs.importing ||
      s.bgTasks.capture.active ||
      s.bgTasks.capture.finishing
  );
  const groups = Boolean(
    s.bgTasks.groups.probingNodeIds.length > 0 ||
      s.bgTasks.groups.evaluatingGroupId !== null
  );
  const home = Boolean(
    s.bgTasks.home.checkingQuickSites || s.bgTasks.home.refreshingExitIp
  );
  const settings = Boolean(
    s.bgTasks.settings.geoBusy !== null ||
      s.bgTasks.settings.checkingUpdate ||
      s.bgTasks.settings.downloadingUpdate ||
      s.bgTasks.settings.coreOpBusy !== null ||
      s.bgTasks.settings.backupBusy !== null
  );
  if (
    cachedBgActivity.preaccel === preaccel &&
    cachedBgActivity.nodes === nodes &&
    cachedBgActivity.groups === groups &&
    cachedBgActivity.home === home &&
    cachedBgActivity.settings === settings
  ) {
    return cachedBgActivity;
  }
  cachedBgActivity = { preaccel, nodes, groups, home, settings };
  return cachedBgActivity;
}

/* ============================================================================
 * Atomic Runtime & PreAccel Selectors (prevent unnecessary component re-renders)
 * ============================================================================ */

export function selectRuntimeRunning(s: AppState): boolean {
  return s.runtime.running;
}

export function selectRuntimeStatus(s: AppState): string {
  return s.runtime.status;
}

export function selectRuntimeProxyMode(s: AppState): ProxyMode {
  return s.runtime.proxy_mode;
}

export function selectRuntimeSystemProxyEnabled(s: AppState): boolean {
  return s.runtime.system_proxy_enabled;
}

export function selectRuntimeTunEnabled(s: AppState): boolean {
  return s.runtime.tun_enabled;
}

export function selectRuntimeTunNeedsElevation(s: AppState): boolean {
  return Boolean(s.runtime.tun_needs_elevation);
}

export function selectRuntimePreAccelActive(s: AppState): boolean {
  return s.runtime.preaccel_active;
}

export function selectRuntimePreAccelEnabled(s: AppState): boolean {
  return Boolean(s.runtime.preaccel_enabled ?? s.config.preaccel.enabled);
}

export function selectRuntimePreAccelRelayName(s: AppState): string | null {
  return s.runtime.preaccel_relay_name ?? null;
}

export function selectRuntimeActiveNodeName(s: AppState): string {
  return s.runtime.active_node_name;
}

export function selectRuntimeActiveGroupName(s: AppState): string {
  return s.runtime.active_group_name;
}

export function selectRuntimeAppVersion(s: AppState): string {
  return s.runtime.app_version;
}

export function selectRuntimeOsLabel(s: AppState): string {
  return s.runtime.os_label;
}

export function selectRuntimeControllerAddr(s: AppState): string {
  return s.runtime.controller_addr;
}

export function selectRuntimeCoreName(s: AppState): string {
  return s.runtime.core_name;
}

export function selectRuntimeCoreVersion(s: AppState): string {
  return s.runtime.core_version;
}

export function selectRuntimeMixedPort(s: AppState): number {
  return s.runtime.mixed_port;
}

export function selectRuntimeCaptivePortalRequired(s: AppState): boolean {
  return s.runtime.captive_portal_required;
}

export function selectHasEnabledRelay(s: AppState): boolean {
  return s.preAccelRelays.some((r) => r.enabled);
}
