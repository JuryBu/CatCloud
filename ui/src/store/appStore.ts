import { useSyncExternalStore } from "react";
import { createCaptureActions } from "./actions/captureActions";
import { createDiagnosticsActions } from "./actions/diagnosticsActions";
import { createNavActions } from "./actions/navActions";
import { createPreAccelActions } from "./actions/preaccelActions";
import { createProbeSubActions } from "./actions/probeSubActions";
import { createProxyCoreActions } from "./actions/proxyCoreActions";
import { createUpdateGeoActions } from "./actions/updateGeoActions";
import { createStoreBootstrap } from "./bootstrap";
import { storeCore } from "./core";
import type { AppState, TrafficSample } from "./types";

export type {
  AgentPromptMode,
  AppConfig,
  AppState,
  BackgroundActivitySummary,
  BgTasksState,
  CoreRuntimeInfo,
  DnsTlsDiagnostics,
  GlobalPreAccelMode,
  GlobalPreAccelScope,
  GlobalPreAccelStatus,
  MascotState,
  NavRouteId,
  PreAccelDispatchStrategy,
  PreAccelLbStrategy,
  PreAccelVerifyState,
  ProbeRunProgressState,
  ProbeRunSummary,
  ProxyMode,
  ResolvedTheme,
  RouteTargetMode,
  SessionDraftsState,
  ThemeMode,
  ToastNotice,
  TrafficSample,
  UiLanguage,
  WindowMode,
} from "./types";

export { TRAFFIC_HISTORY_CAPACITY, TrafficRingBuffer } from "./trafficRingBuffer";

export {
  BUILTIN_WALLPAPER_PRESETS,
  getBeijingMinutes,
  getBeijingTimeLabel,
  resolveThemeBySchedule,
} from "./themeWallpaper";

export {
  selectHasBackgroundActivity,
  selectHasEnabledRelay,
  selectIsProbeEngineBusy,
  selectRuntimeActiveGroupName,
  selectRuntimeActiveNodeName,
  selectRuntimeAppVersion,
  selectRuntimeCaptivePortalRequired,
  selectRuntimeControllerAddr,
  selectRuntimeCoreName,
  selectRuntimeCoreVersion,
  selectRuntimeMixedPort,
  selectRuntimeOsLabel,
  selectRuntimePreAccelActive,
  selectRuntimePreAccelEnabled,
  selectRuntimePreAccelRelayName,
  selectRuntimeProxyMode,
  selectRuntimeRunning,
  selectRuntimeStatus,
  selectRuntimeSystemProxyEnabled,
  selectRuntimeTunEnabled,
  selectRuntimeTunNeedsElevation,
} from "./selectors";

/* ============================================================================
 * Modular Action Composition & Bootstrap Assembly (Strict Acyclic Facade)
 * ============================================================================ */

const navActions = createNavActions(storeCore);
const proxyCoreActions = createProxyCoreActions(storeCore);
const preAccelModule = createPreAccelActions(storeCore, {
  setNav: navActions.setNav,
});
const probeSubModule = createProbeSubActions(storeCore);
const updateGeoActions = createUpdateGeoActions(storeCore);
const captureModule = createCaptureActions(storeCore);

const bootstrap = createStoreBootstrap(storeCore, {
  setNav: navActions.setNav,
  refreshRuntime: proxyCoreActions.refreshRuntime,
  refreshGlobalPreAccelStatus: preAccelModule.actions.refreshGlobalPreAccelStatus,
  refreshPendingUpdate: updateGeoActions.refreshPendingUpdate,
  loadGeodataStatus: updateGeoActions.loadGeodataStatus,
  openTunAdminPrompt: proxyCoreActions.openTunAdminPrompt,
  pollLiveCaptureIfActive: captureModule.pollIfActive,
  disposeProbeRuntime: probeSubModule.dispose,
  disposeCaptureRuntime: captureModule.dispose,
  resetPreAccelRuntime: preAccelModule.resetRuntime,
});

const diagnosticsActions = createDiagnosticsActions(storeCore, {
  hydrateFromBackend: () => bootstrap.hydrateFromBackend(),
});

export const appStore = {
  getState: storeCore.getState,
  getTrafficBuffer: storeCore.getTrafficBuffer,
  getTrafficVersion: storeCore.getTrafficVersion,
  subscribe: storeCore.subscribe,
  subscribeTraffic: storeCore.subscribeTraffic,
  init: bootstrap.init,
  dispose: bootstrap.dispose,
};

export const appActions = {
  ...navActions,
  ...diagnosticsActions,
  ...preAccelModule.actions,
  ...proxyCoreActions,
  ...probeSubModule.actions,
  ...updateGeoActions,
  ...captureModule.actions,
};

export function useAppSelector<T>(selector: (s: AppState) => T): T {
  return useSyncExternalStore(
    appStore.subscribe,
    () => selector(appStore.getState()),
    () => selector(appStore.getState())
  );
}

export function useTrafficVersion(): number {
  return useSyncExternalStore(
    appStore.subscribeTraffic,
    appStore.getTrafficVersion,
    appStore.getTrafficVersion
  );
}

export function useLatestTraffic(): TrafficSample {
  return useSyncExternalStore(
    appStore.subscribeTraffic,
    storeCore.getLatestTraffic,
    storeCore.getLatestTraffic
  );
}
