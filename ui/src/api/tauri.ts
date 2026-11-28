/**
 * CatCloud Strongly-Typed Tauri v2 IPC Client with Lazy Browser Preview Fallback.
 *
 * - In Tauri runtime (`window.__TAURI_INTERNALS__`), delegates directly to `@tauri-apps/api/core`
 *   and `@tauri-apps/api/event`, surfacing backend IPC errors instead of silently returning null.
 * - In standalone browser preview (`pnpm dev` / `pnpm preview`), dynamically imports
 *   `./previewMock` on demand so desktop builds never pay for preview fixture weight.
 */

import { normalizeUiLanguage, type UiLanguage } from "../i18n/types";
import {
  extractDialogSinglePath,
  isTauriEnv,
  subscribeTauriEmptyEvent,
  subscribeTauriEvent,
  tauriInvokeOrThrow,
} from "./ipc";
import {
  DEFAULT_APP_CONFIG,
  normalizeGlobalPreAccelStatus,
  normalizeLiveCaptureStatus,
  normalizeTrafficSample,
  type RawTrafficPayload,
} from "./normalizers";
import type {
  ProxyMode,
  PreAccelOverrideMode,
  GlobalPreAccelScope,
  AgentPromptMode,
  GlobalPreAccelStatus,
  AppConfig,
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
  LiveCaptureStatusDto,
  LiveCaptureOutcomeDto,
  RefreshGeoDbResult,
  GeoDataStatusDto,
  AppUpdateCheckResult,
  DownloadAndStageUpdateResult,
  PendingUpdatePromptDto,
  MigrationApplyOutcome,
  DanglingRulesAudit,
  DanglingRuleRepairReport,
  SkipUpdateResultDto,
  ApplyUpdateRestartResultDto,
  ExportBackupResult,
  ImportBackupResult,
  UwpLoopbackResult,
  HotSwapCoreResult,
} from "./types";

export type * from "./types";
export * from "./errors";
export * from "./ipc";
export * from "./normalizers";

let previewMockPromise: Promise<typeof import("./previewMock")> | null = null;

/**
 * Dynamically load browser preview mock helpers and fixtures on demand.
 */
export async function loadPreviewMock(): Promise<typeof import("./previewMock")> {
  if (!previewMockPromise) {
    previewMockPromise = import("./previewMock");
  }
  return previewMockPromise;
}

function subscribePreviewMock(
  setup: (mod: typeof import("./previewMock")) => () => void
): () => void {
  let disposed = false;
  let unsub: (() => void) | null = null;
  void loadPreviewMock().then((mod) => {
    if (!disposed) {
      unsub = setup(mod);
    }
  });
  return () => {
    disposed = true;
    unsub?.();
  };
}

export const catcloudApi = {
  async getConfig(): Promise<AppConfig> {
    if (isTauriEnv()) return tauriInvokeOrThrow<AppConfig>("get_app_config");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getConfig();
  },

  async saveConfig(next: AppConfig): Promise<AppConfig> {
    if (isTauriEnv()) {
      const wireUpdate: AppConfig["update"] = {
        repo: next.update.repo,
        mode: next.update.mode,
        check_interval_min: next.update.check_interval_min,
        include_prerelease: next.update.include_prerelease,
        auto_download: next.update.auto_download ?? true,
      };
      const wireConfig: AppConfig = {
        ...next,
        update: wireUpdate,
      };
      delete wireConfig.behavior;
      return tauriInvokeOrThrow<AppConfig>("save_app_config", { config: wireConfig });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.saveConfig(next);
  },

  async markOnboardingCompleted(): Promise<void> {
    if (isTauriEnv()) {
      await tauriInvokeOrThrow<void>("mark_onboarding_completed");
      return;
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.markOnboardingCompleted();
  },

  async getFullConfig(): Promise<FullAppConfig> {
    if (isTauriEnv()) return tauriInvokeOrThrow<FullAppConfig>("get_full_config");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getFullConfig();
  },

  async saveFullConfig(next: FullAppConfig): Promise<FullAppConfig> {
    if (isTauriEnv()) return tauriInvokeOrThrow<FullAppConfig>("save_full_config", { next });
    const { previewApi } = await loadPreviewMock();
    return previewApi.saveFullConfig(next);
  },

  async saveExtendedSettings(patch: Record<string, unknown>): Promise<FullAppConfig> {
    if (isTauriEnv()) return tauriInvokeOrThrow<FullAppConfig>("save_extended_settings", { patch });
    const { previewApi } = await loadPreviewMock();
    return previewApi.saveExtendedSettings(patch);
  },

  async getRuntimeInfo(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("get_runtime_info");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getRuntimeInfo();
  },

  async startCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("start_core");
    const { previewApi } = await loadPreviewMock();
    return previewApi.startCore();
  },

  async stopCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("stop_core");
    const { previewApi } = await loadPreviewMock();
    return previewApi.stopCore();
  },

  async disableAllProxyAndStopCore(): Promise<RuntimeInfoDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<RuntimeInfoDto>("disable_all_proxy_and_stop_core");
    const { previewApi } = await loadPreviewMock();
    return previewApi.disableAllProxyAndStopCore();
  },

  async enableProxyPower(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("enable_proxy_power");
    const { previewApi } = await loadPreviewMock();
    return previewApi.enableProxyPower();
  },

  async consumePendingNav(): Promise<string | null> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<string | null>("consume_pending_nav");
      return typeof raw === "string" && raw.trim() ? raw.trim() : null;
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.consumePendingNav();
  },

  async restartCore(): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("restart_core");
    const { previewApi } = await loadPreviewMock();
    return previewApi.restartCore();
  },

  async reloadCoreConfig(forceDiskReload = false): Promise<ReloadOutcome> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ReloadOutcome>("reload_core_config", { forceDiskReload });
    const { previewApi } = await loadPreviewMock();
    return previewApi.reloadCoreConfig(forceDiskReload);
  },

  async setProxyMode(mode: ProxyMode): Promise<ProxyMode> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ProxyMode>("set_proxy_mode", { mode });
    const { previewApi } = await loadPreviewMock();
    return previewApi.setProxyMode(mode);
  },

  async toggleSystemProxy(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("set_system_proxy", { enabled });
    const { previewApi } = await loadPreviewMock();
    return previewApi.toggleSystemProxy(enabled);
  },

  async toggleTun(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("set_tun_enabled", { enabled });
    const { previewApi } = await loadPreviewMock();
    return previewApi.toggleTun(enabled);
  },

  async switchNextBestNode(groupId = "grp-ai"): Promise<SwitchResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<SwitchResult>("switch_next_best_node", { groupId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.switchNextBestNode(groupId);
  },

  async selectGroupNode(groupId: string, nodeId: string, closeOld = true, activateGroup?: boolean): Promise<SwitchResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SwitchResult>("select_group_node", {
        groupId,
        nodeId,
        closeOld,
        activateGroup: activateGroup ?? null,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.selectGroupNode(groupId, nodeId, closeOld, activateGroup);
  },

  async setActiveGroup(groupId: string): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("set_active_group", { groupId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.setActiveGroup(groupId);
  },

  async selectSingleNode(nodeId: string): Promise<CoreRuntimeInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreRuntimeInfo>("select_single_node", { nodeId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.selectSingleNode(nodeId);
  },

  async toggleCapsuleWindow(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("toggle_capsule_window");
    const { previewApi } = await loadPreviewMock();
    return previewApi.toggleCapsuleWindow();
  },

  async showMainWindow(): Promise<void> {
    if (isTauriEnv()) {
      await tauriInvokeOrThrow<void>("show_main_window");
      return;
    }
    const { previewApi } = await loadPreviewMock();
    await previewApi.showMainWindow();
  },

  async enterWindowlessMode(): Promise<void> {
    if (isTauriEnv()) {
      await tauriInvokeOrThrow<void>("enter_windowless_mode");
      return;
    }
    const { previewApi } = await loadPreviewMock();
    await previewApi.enterWindowlessMode();
  },

  async listGroups(): Promise<MultiGroup[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<MultiGroup[]>("list_multi_groups");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listGroups();
  },

  async upsertMultiGroup(group: MultiGroup): Promise<MultiGroup> {
    if (isTauriEnv()) return tauriInvokeOrThrow<MultiGroup>("upsert_multi_group", { group });
    const { previewApi } = await loadPreviewMock();
    return previewApi.upsertMultiGroup(group);
  },

  async deleteMultiGroup(groupId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("delete_multi_group", { groupId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.deleteMultiGroup(groupId);
  },

  async updateMultiGroupMembers(groupId: string, memberNodeIds: string[]): Promise<MultiGroup> {
    if (isTauriEnv()) return tauriInvokeOrThrow<MultiGroup>("update_multi_group_members", { groupId, memberNodeIds });
    const { previewApi } = await loadPreviewMock();
    return previewApi.updateMultiGroupMembers(groupId, memberNodeIds);
  },

  async listNodes(): Promise<ProxyNode[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ProxyNode[]>("list_nodes");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listNodes();
  },

  async setNodesPreAccelOverride(nodeIds: string[], overrideMode: PreAccelOverrideMode): Promise<number> {
    if (isTauriEnv()) return tauriInvokeOrThrow<number>("set_nodes_preaccel_override", { nodeIds, overrideMode });
    const { previewApi } = await loadPreviewMock();
    return previewApi.setNodesPreAccelOverride(nodeIds, overrideMode);
  },

  async listProbeDefinitions(): Promise<ProbeDefinition[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ProbeDefinition[]>("list_probe_definitions");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listProbeDefinitions();
  },

  async upsertProbeDefinition(probe: ProbeDefinition): Promise<ProbeDefinition> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ProbeDefinition>("upsert_probe_definition", { probe });
    const { previewApi } = await loadPreviewMock();
    return previewApi.upsertProbeDefinition(probe);
  },

  async deleteProbeDefinition(probeId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("delete_probe_definition", { probeId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.deleteProbeDefinition(probeId);
  },

  async listProbeSnapshots(): Promise<Record<string, ProbeSnapshot>> {
    if (isTauriEnv()) return tauriInvokeOrThrow<Record<string, ProbeSnapshot>>("list_probe_snapshots");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listProbeSnapshots();
  },

  async runIsolatedProbes(nodeIds: string[], probeIds: string[], maxTier: "latency" | "unlock" | "full" = "full", includeKeepalive = false, usePreaccel?: boolean): Promise<RunIsolatedProbesResult> {
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.runIsolatedProbes(nodeIds, probeIds, maxTier, includeKeepalive, usePreaccel);
  },

  async cancelIsolatedProbes(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("cancel_isolated_probes");
    const { previewApi } = await loadPreviewMock();
    return previewApi.cancelIsolatedProbes();
  },

  async pickWallpaperImage(): Promise<PickWallpaperResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PickWallpaperResult>("pick_wallpaper_image");
    const { previewApi } = await loadPreviewMock();
    return previewApi.pickWallpaperImage();
  },

  async resolveWallpaperDataUrl(path: string): Promise<string | null> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string | null>("resolve_wallpaper_data_url", { path });
    const { previewApi } = await loadPreviewMock();
    return previewApi.resolveWallpaperDataUrl(path);
  },

  async listSubscriptions(): Promise<SubscriptionRecord[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<SubscriptionRecord[]>("list_subscriptions");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listSubscriptions();
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.upsertSubscription(record);
  },

  async deleteSubscription(subId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("delete_subscription", { subId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.deleteSubscription(subId);
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.renameSubscription(subId, newName);
  },

  async applyNodesToExistingSubscription(targetSubId: string, nodes: ProxyNode[], mode: SubscriptionUpdateMode): Promise<SubscriptionNodesUpdateResult> {
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.applyNodesToExistingSubscription(targetSubId, nodes, mode);
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.mergeSubscriptions(params);
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportShareBundleDialog(params);
  },

  async pickAndPreviewShareBundle(): Promise<ShareBundlePreview | null> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ShareBundlePreview | null>("pick_and_preview_share_bundle");
    const { previewApi } = await loadPreviewMock();
    return previewApi.pickAndPreviewShareBundle();
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.importShareBundle(params);
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SyncSendSessionDto>("start_sync_send_session", {
        name: params.name?.trim() || "CatCloud Sync",
        description: params.description?.trim() || null,
        nodeIds: params.nodeIds,
        relayIds: params.relayIds,
        includeGroups: params.includeGroups ?? true,
        customEndpoint,
        ttlSec,
        allowMultiple,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.startSyncSendSession(params);
  },

  async cancelSyncSendSession(sessionId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("cancel_sync_send_session", { sessionId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.cancelSyncSendSession(sessionId);
  },

  async exportEncryptedSyncFile(params: {
    name?: string | null;
    description?: string | null;
    nodeIds: string[];
    relayIds: string[];
    includeGroups?: boolean;
  }): Promise<SyncEncryptedFileExportDto> {
    const name = params.name?.trim() || "CatCloud Sync";
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SyncEncryptedFileExportDto>("export_encrypted_sync_file", {
        name,
        description: params.description?.trim() || null,
        nodeIds: params.nodeIds,
        relayIds: params.relayIds,
        includeGroups: params.includeGroups ?? true,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportEncryptedSyncFile(params);
  },

  async startSyncReceiveListener(params?: {
    customEndpoint?: string | null;
    ttlSec?: number | null;
    allowMultiple?: boolean;
  }): Promise<SyncReceiveSessionDto> {
    const customEndpoint = params?.customEndpoint?.trim() || null;
    const ttlSec = params?.ttlSec ?? 180;
    const allowMultiple = params?.allowMultiple ?? false;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SyncReceiveSessionDto>("start_sync_receive_listener", {
        customEndpoint,
        ttlSec,
        allowMultiple,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.startSyncReceiveListener(params);
  },

  async cancelSyncReceiveSession(sessionId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("cancel_sync_receive_session", { sessionId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.cancelSyncReceiveSession(sessionId);
  },

  async previewSyncSource(params: {
    sourceInput?: string | null;
    pin?: string | null;
    pendingToken?: string | null;
    pickCcsyncFile?: boolean;
  }): Promise<SyncPreviewDto | null> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<SyncPreviewDto | null>("preview_sync_source", {
        sourceInput: params.sourceInput?.trim() || null,
        pin: params.pin?.trim() || null,
        pendingToken: params.pendingToken?.trim() || null,
        pickCcsyncFile: params.pickCcsyncFile ?? false,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.previewSyncSource(params);
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
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ShareBundleImportOutcome>("apply_sync_import", {
        pendingToken: params.pendingToken,
        selectedNodeIds: params.selectedNodeIds,
        selectedRelayIds: params.selectedRelayIds,
        importGroups: params.importGroups ?? true,
        targetSubId: params.targetSubId ?? null,
        newSubName: params.newSubName?.trim() || null,
        updateMode: params.updateMode ?? "merge_dedup",
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.applySyncImport(params);
  },

  async refreshSubscription(subId: string, options?: { bearerSecret?: string | null; endpointUrl?: string | null }): Promise<RefreshSubscriptionResult> {
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.refreshSubscription(subId, options);
  },

  async refreshAllSubscriptions(): Promise<RefreshAllSubscriptionsResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<RefreshAllSubscriptionsResult>("refresh_all_subscriptions");
    const { previewApi } = await loadPreviewMock();
    return previewApi.refreshAllSubscriptions();
  },

  async listPreAccelRelays(): Promise<PreAccelRelay[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PreAccelRelay[]>("list_preaccel_relays");
    const { previewApi } = await loadPreviewMock();
    return previewApi.listPreAccelRelays();
  },

  async upsertPreAccelRelay(relay: PreAccelRelay): Promise<PreAccelRelay> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PreAccelRelay>("upsert_preaccel_relay", { relay });
    const { previewApi } = await loadPreviewMock();
    return previewApi.upsertPreAccelRelay(relay);
  },

  async deletePreAccelRelay(relayId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("delete_preaccel_relay", { relayId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.deletePreAccelRelay(relayId);
  },

  async togglePreAccel(enabled: boolean): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("toggle_preaccel", { enabled });
    const { previewApi } = await loadPreviewMock();
    return previewApi.togglePreAccel(enabled);
  },

  async getGlobalPreAccelStatus(): Promise<GlobalPreAccelStatus> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("get_global_preaccel_status");
      return normalizeGlobalPreAccelStatus(raw);
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.getGlobalPreAccelStatus();
  },

  async toggleGlobalPreAccel(enabled: boolean): Promise<GlobalPreAccelStatus> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("toggle_global_preaccel", { enabled });
      if (raw && typeof raw === "object" && "running" in raw) {
        return normalizeGlobalPreAccelStatus(raw);
      }
      return catcloudApi.getGlobalPreAccelStatus();
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.toggleGlobalPreAccel(enabled);
  },

  async updateGlobalPreAccelSettings(scope: GlobalPreAccelScope, targetProcesses: string[], windivertDir: string | null = null): Promise<GlobalPreAccelStatus> {
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.updateGlobalPreAccelSettings(scope, targetProcesses, windivertDir);
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
    const { previewApi } = await loadPreviewMock();
    return previewApi.installWinDivertDriver();
  },

  async relaunchAsAdminForGlobalPreAccel(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("relaunch_as_admin_for_global_preaccel");
    const { previewApi } = await loadPreviewMock();
    return previewApi.relaunchAsAdminForGlobalPreAccel();
  },

  async verifyGlobalPreAccel(): Promise<GlobalPreAccelStatus> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("verify_global_preaccel");
      return normalizeGlobalPreAccelStatus(raw);
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.verifyGlobalPreAccel();
  },

  async failoverPreAccel(): Promise<string | null> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string | null>("failover_preaccel");
    const { previewApi } = await loadPreviewMock();
    return previewApi.failoverPreAccel();
  },

  async selectPreAccelRelay(relayId: string): Promise<string> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string>("select_preaccel_relay", { relayId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.selectPreAccelRelay(relayId);
  },

  async importMmRelayInput(raw: string): Promise<PreAccelRelay[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PreAccelRelay[]>("import_mmrelay_input", { raw });
    const { previewApi } = await loadPreviewMock();
    return previewApi.importMmRelayInput(raw);
  },

  async testPreAccelRelays(relayIds: string[] | null = null): Promise<PreAccelTestResult[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PreAccelTestResult[]>("test_preaccel_relays", { relayIds });
    const { previewApi } = await loadPreviewMock();
    return previewApi.testPreAccelRelays(relayIds);
  },

  async testPreAccelRelaySpeeds(relayIds: string[] | null = null, nodeId: string | null = null): Promise<PreAccelSpeedTestResult[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelSpeedTestResult[]>("test_preaccel_relay_speeds", {
        relayIds,
        nodeId,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.testPreAccelRelaySpeeds(relayIds, nodeId);
  },

  async benchmarkPreAccelComparison(relayId?: string | null, nodeId?: string | null): Promise<PreAccelComparisonResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<PreAccelComparisonResult>("benchmark_preaccel_comparison", {
        relayId: relayId ?? null,
        nodeId: nodeId ?? null,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.benchmarkPreAccelComparison(relayId, nodeId);
  },

  async checkCampusPortal(): Promise<CampusPortalStatus> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CampusPortalStatus>("check_campus_portal");
    const { previewApi } = await loadPreviewMock();
    return previewApi.checkCampusPortal();
  },

  async getExitIpInfo(): Promise<ExitIpInfo> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ExitIpInfo>("get_exit_ip_info");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getExitIpInfo();
  },

  async checkQuickSites(): Promise<SiteCheckItem[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<SiteCheckItem[]>("check_quick_sites");
    const { previewApi } = await loadPreviewMock();
    return previewApi.checkQuickSites();
  },

  async getActiveConnections(): Promise<ConnectionsSnapshotDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ConnectionsSnapshotDto>("get_active_connections");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getActiveConnections();
  },

  async closeConnection(id: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("close_connection", { id });
    const { previewApi } = await loadPreviewMock();
    return previewApi.closeConnection(id);
  },

  async closeGroupConnections(groupName: string): Promise<number> {
    if (isTauriEnv()) return tauriInvokeOrThrow<number>("close_group_connections", { groupName });
    const { previewApi } = await loadPreviewMock();
    return previewApi.closeGroupConnections(groupName);
  },

  async closeAllConnections(): Promise<number> {
    if (isTauriEnv()) return tauriInvokeOrThrow<number>("close_all_connections");
    const { previewApi } = await loadPreviewMock();
    return previewApi.closeAllConnections();
  },

  async getRecentLogs(limit: number | null = 300): Promise<CoreLogLineDto[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CoreLogLineDto[]>("get_recent_logs", { limit });
    const { previewApi } = await loadPreviewMock();
    return previewApi.getRecentLogs(limit);
  },

  async listAgentDocs(lang?: UiLanguage): Promise<AgentModuleDoc[]> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AgentModuleDoc[]>("list_agent_docs", {
        lang: normalizedLang,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.listAgentDocs(lang);
  },

  async exportAgentDocs(moduleId: string, asJson = false, lang?: UiLanguage): Promise<string> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("export_agent_docs", {
        moduleId,
        asJson,
        lang: normalizedLang,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportAgentDocs(moduleId, asJson, lang);
  },

  async buildAgentBootstrapPrompt(lang?: UiLanguage, currentPage?: string, mode: AgentPromptMode = "autopilot"): Promise<AgentBootstrapPromptDto> {
    const normalizedLang = normalizeUiLanguage(lang ?? DEFAULT_APP_CONFIG.personalization.ui_language);
    const resolvedMode: AgentPromptMode =
          mode === "readonly"
            ? "readonly"
            : mode === "troubleshoot_issue"
              ? "troubleshoot_issue"
              : "autopilot";
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<AgentBootstrapPromptDto>("build_agent_bootstrap_prompt", {
        lang: normalizedLang,
        currentPage: currentPage ?? null,
        mode: resolvedMode,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.buildAgentBootstrapPrompt(lang, currentPage, mode);
  },

  async exportAgentDocFileDialog(moduleId: string, lang?: UiLanguage): Promise<ExportAgentDocOutcome> {
    const normalizedLang = normalizeUiLanguage(lang ?? DEFAULT_APP_CONFIG.personalization.ui_language);
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ExportAgentDocOutcome>("export_agent_doc_file_dialog", {
        moduleId,
        lang: normalizedLang,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportAgentDocFileDialog(moduleId, lang);
  },

  async buildGithubIssueUrl(summary?: string | null, lang?: UiLanguage): Promise<GithubIssueDraftDto> {
    const normalizedLang = normalizeUiLanguage(lang ?? DEFAULT_APP_CONFIG.personalization.ui_language);
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<GithubIssueDraftDto>("build_github_issue_url", {
        summary: summary?.trim() || null,
        lang: normalizedLang,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.buildGithubIssueUrl(summary, lang);
  },

  async validateFormulaExpr(expr: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("validate_formula_expr", { expr });
    const { previewApi } = await loadPreviewMock();
    return previewApi.validateFormulaExpr(expr);
  },

  async evaluateMultiGroup(groupId: string): Promise<GroupEvaluationReport> {
    if (isTauriEnv()) return tauriInvokeOrThrow<GroupEvaluationReport>("evaluate_multi_group", { groupId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.evaluateMultiGroup(groupId);
  },

  async compilePreviewYaml(): Promise<CompiledYamlPreview> {
    if (isTauriEnv()) return tauriInvokeOrThrow<CompiledYamlPreview>("compile_preview_yaml");
    const { previewApi } = await loadPreviewMock();
    return previewApi.compilePreviewYaml();
  },

  async exportGatewayYaml(options: GatewayExportOptions): Promise<GatewayExportOutput> {
    if (isTauriEnv()) return tauriInvokeOrThrow<GatewayExportOutput>("export_gateway_yaml", { options });
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportGatewayYaml(options);
  },

  async saveGatewayYamlDialog(options: GatewayExportOptions): Promise<string | null> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string | null>("save_gateway_yaml_dialog", { options });
    const { previewApi } = await loadPreviewMock();
    return previewApi.saveGatewayYamlDialog(options);
  },

  async parseBulkRulesPreview(rawText: string): Promise<BulkRulesParseResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<BulkRulesParseResult>("parse_bulk_rules_preview", { rawText });
    const { previewApi } = await loadPreviewMock();
    return previewApi.parseBulkRulesPreview(rawText);
  },

  async scanLocalMigrations(): Promise<MigrationPreviewDto[]> {
    if (isTauriEnv()) return tauriInvokeOrThrow<MigrationPreviewDto[]>("scan_local_migrations");
    const { previewApi } = await loadPreviewMock();
    return previewApi.scanLocalMigrations();
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
    if (isTauriEnv()) return tauriInvokeOrThrow<MigrationPreviewDto[]>("scan_migration_path", { path });
    const { previewApi } = await loadPreviewMock();
    return previewApi.scanMigrationPath(path);
  },

  async previewMigrationFromText(name: string, rawYaml: string): Promise<MigrationTextPreviewResult> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MigrationTextPreviewResult>("preview_migration_from_text", {
        name,
        rawYaml,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.previewMigrationFromText(name, rawYaml);
  },

  async applyMigrationNodes(sourceName: string, nodes: ProxyNode[]): Promise<number> {
    if (isTauriEnv()) return tauriInvokeOrThrow<number>("apply_migration_nodes", { sourceName, nodes });
    const { previewApi } = await loadPreviewMock();
    return previewApi.applyMigrationNodes(sourceName, nodes);
  },

  async applyMigrationNodesWithMeta(sourceName: string, nodes: ProxyNode[], options?: {
      includeRules?: boolean;
      prependRules?: string[];
      appendRules?: string[];
      danglingRulePolicy?: "drop" | "rewrite";
    }): Promise<MigrationApplyOutcome> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<MigrationApplyOutcome>("apply_migration_nodes_with_meta", {
        sourceName,
        nodes,
        includeRules: options?.includeRules ?? false,
        prependRules: options?.prependRules ?? [],
        appendRules: options?.appendRules ?? [],
        danglingRulePolicy: options?.danglingRulePolicy ?? null,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.applyMigrationNodesWithMeta(sourceName, nodes, options);
  },

  async auditDanglingRules(): Promise<DanglingRulesAudit> {
    if (isTauriEnv()) return tauriInvokeOrThrow<DanglingRulesAudit>("audit_dangling_rules");
    const { previewApi } = await loadPreviewMock();
    return previewApi.auditDanglingRules();
  },

  async repairDanglingRules(mode: "remove" | "rewrite", targetGroup?: string | null, restartCoreIfNeeded = true): Promise<DanglingRuleRepairReport> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<DanglingRuleRepairReport>("repair_dangling_rules", {
        mode,
        targetGroup: targetGroup ?? null,
        restartCoreIfNeeded,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.repairDanglingRules(mode, targetGroup, restartCoreIfNeeded);
  },

  async listRunningProcesses(onlyLikelyProxy: boolean): Promise<ProcessCandidateDto[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<ProcessCandidateDto[]>("list_running_processes", {
        onlyLikelyProxy,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.listRunningProcesses(onlyLikelyProxy);
  },

  async inspectProcessSource(pid: number): Promise<ProcessInspectResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ProcessInspectResult>("inspect_process_source", { pid });
    const { previewApi } = await loadPreviewMock();
    return previewApi.inspectProcessSource(pid);
  },

  async listDesktopAppCandidates(baselinePids?: number[]): Promise<DesktopAppCandidate[]> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<DesktopAppCandidate[]>("list_desktop_app_candidates", {
        baselinePids: baselinePids ?? null,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.listDesktopAppCandidates(baselinePids);
  },

  async startLiveCaptureSession(targetPid: number): Promise<LiveCaptureStartDto> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<LiveCaptureStartDto>("start_live_capture_session", {
        targetPid,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.startLiveCaptureSession(targetPid);
  },

  async pollLiveCaptureSession(sessionId: string): Promise<LiveCaptureStatusDto> {
    if (isTauriEnv()) {
      const raw = await tauriInvokeOrThrow<unknown>("poll_live_capture_session", {
        sessionId,
      });
      return normalizeLiveCaptureStatus(raw, sessionId);
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.pollLiveCaptureSession(sessionId);
  },

  async finishLiveCaptureSession(sessionId: string): Promise<LiveCaptureOutcomeDto> {
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<LiveCaptureOutcomeDto>("finish_live_capture_session", {
        sessionId,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.finishLiveCaptureSession(sessionId);
  },

  async cancelLiveCaptureSession(sessionId: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("cancel_live_capture_session", { sessionId });
    const { previewApi } = await loadPreviewMock();
    return previewApi.cancelLiveCaptureSession(sessionId);
  },

  async capsuleDragStart(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("capsule_drag_start");
    const { previewApi } = await loadPreviewMock();
    return previewApi.capsuleDragStart();
  },

  async capsuleDragStep(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("capsule_drag_step");
    const { previewApi } = await loadPreviewMock();
    return previewApi.capsuleDragStep();
  },

  async capsuleDragEnd(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("capsule_drag_end");
    const { previewApi } = await loadPreviewMock();
    return previewApi.capsuleDragEnd();
  },

  async exportShellEnv(shell: string): Promise<string> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string>("export_shell_env", { shell });
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportShellEnv(shell);
  },

  async buildAiOnboardingPrompt(lang?: UiLanguage, moduleId?: string | null): Promise<string> {
    const normalizedLang = lang ? normalizeUiLanguage(lang) : null;
    if (isTauriEnv()) {
      return tauriInvokeOrThrow<string>("build_ai_onboarding_prompt", {
        lang: normalizedLang,
        moduleId: moduleId ?? null,
      });
    }
    const { previewApi } = await loadPreviewMock();
    return previewApi.buildAiOnboardingPrompt(lang, moduleId);
  },

  async exportSanitizedDiagnostics(): Promise<SanitizedDiagnosticsDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<SanitizedDiagnosticsDto>("export_sanitized_diagnostics");
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportSanitizedDiagnostics();
  },

  async refreshGeoDb(targets: string[] | null = null): Promise<RefreshGeoDbResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<RefreshGeoDbResult>("refresh_geo_db", { targets });
    const { previewApi } = await loadPreviewMock();
    return previewApi.refreshGeoDb(targets);
  },

  async getGeodataStatus(): Promise<GeoDataStatusDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<GeoDataStatusDto>("get_geodata_status");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getGeodataStatus();
  },

  async relaunchAsAdmin(enableTun = true): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("relaunch_as_admin", { enableTun });
    const { previewApi } = await loadPreviewMock();
    return previewApi.relaunchAsAdmin(enableTun);
  },

  async checkAppUpdate(): Promise<AppUpdateCheckResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<AppUpdateCheckResult>("check_app_update");
    const { previewApi } = await loadPreviewMock();
    return previewApi.checkAppUpdate();
  },

  async downloadAndStageUpdate(): Promise<DownloadAndStageUpdateResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<DownloadAndStageUpdateResult>("download_and_stage_update");
    const { previewApi } = await loadPreviewMock();
    return previewApi.downloadAndStageUpdate();
  },

  async getPendingStagedUpdate(): Promise<PendingUpdatePromptDto | null> {
    if (isTauriEnv()) return tauriInvokeOrThrow<PendingUpdatePromptDto | null>("get_pending_staged_update");
    const { previewApi } = await loadPreviewMock();
    return previewApi.getPendingStagedUpdate();
  },

  async dismissUpdatePromptForSession(version: string): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("dismiss_update_prompt_for_session", { version });
    const { previewApi } = await loadPreviewMock();
    return previewApi.dismissUpdatePromptForSession(version);
  },

  async skipUpdateVersion(version: string): Promise<SkipUpdateResultDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<SkipUpdateResultDto>("skip_update_version", { version });
    const { previewApi } = await loadPreviewMock();
    return previewApi.skipUpdateVersion(version);
  },

  async clearSkippedUpdateVersion(): Promise<boolean> {
    if (isTauriEnv()) return tauriInvokeOrThrow<boolean>("clear_skipped_update_version");
    const { previewApi } = await loadPreviewMock();
    return previewApi.clearSkippedUpdateVersion();
  },

  async applyStagedUpdateAndRestart(): Promise<ApplyUpdateRestartResultDto> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ApplyUpdateRestartResultDto>("apply_staged_update_and_restart");
    const { previewApi } = await loadPreviewMock();
    return previewApi.applyStagedUpdateAndRestart();
  },

  async exportBackupBundle(targetPath: string | null = null): Promise<ExportBackupResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ExportBackupResult>("export_backup_bundle", { targetPath });
    const { previewApi } = await loadPreviewMock();
    return previewApi.exportBackupBundle(targetPath);
  },

  async importBackupBundle(bundleJson: string): Promise<ImportBackupResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<ImportBackupResult>("import_backup_bundle", { bundleJson });
    const { previewApi } = await loadPreviewMock();
    return previewApi.importBackupBundle(bundleJson);
  },

  async launchUwpLoopback(): Promise<UwpLoopbackResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<UwpLoopbackResult>("launch_uwp_loopback");
    const { previewApi } = await loadPreviewMock();
    return previewApi.launchUwpLoopback();
  },

  async hotSwapCore(binaryPath: string): Promise<HotSwapCoreResult> {
    if (isTauriEnv()) return tauriInvokeOrThrow<HotSwapCoreResult>("hot_swap_core", { binaryPath });
    const { previewApi } = await loadPreviewMock();
    return previewApi.hotSwapCore(binaryPath);
  },

  async openAppDir(kind: string): Promise<string> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string>("open_app_dir", { kind });
    const { previewApi } = await loadPreviewMock();
    return previewApi.openAppDir(kind);
  },

  async openWebUi(url: string | null = null): Promise<string> {
    if (isTauriEnv()) return tauriInvokeOrThrow<string>("open_web_ui", { url });
    const { previewApi } = await loadPreviewMock();
    return previewApi.openWebUi(url);
  },

  async openExternalUrl(url: string): Promise<string> {
    const trimmed = url.trim();
    if (!trimmed) {
      throw new Error("外部链接不能为空");
    }
    if (isTauriEnv()) return tauriInvokeOrThrow<string>("open_external_url", { url: trimmed });
    const { previewApi } = await loadPreviewMock();
    return previewApi.openExternalUrl(url);
  },

  async getTrafficHistory(): Promise<TrafficSample[]> {
    if (!isTauriEnv()) {
      const { previewApi } = await loadPreviewMock();
      return previewApi.getTrafficHistory();
    }
    let rows: RawTrafficPayload[];
    try {
      rows = await tauriInvokeOrThrow<RawTrafficPayload[]>("get_traffic_history");
    } catch {
      return [];
    }
    if (!Array.isArray(rows)) return [];
    return rows
      .filter((r) => Boolean(r && typeof r === "object"))
      .map((r) => normalizeTrafficSample(r))
      .filter((s) => s.timestamp_ms > 0);
  },

  subscribeTraffic(onSample: (sample: TrafficSample) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent<RawTrafficPayload>("catcloud://traffic", (payload) => {
        onSample(normalizeTrafficSample(payload, Date.now()));
      });
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeTraffic(onSample));
  },

  subscribeRuntimeUpdate(onUpdate: (info: CoreRuntimeInfo) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://runtime", onUpdate);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeRuntimeUpdate(onUpdate));
  },

  subscribeProbeProgress(onProgress: (ev: ProbeProgressEvent) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://probe-progress", onProgress);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeProbeProgress(onProgress));
  },

  subscribeStrategySwitch(onSwitch: (ev: StrategySwitchEvent) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://strategy-switch", onSwitch);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeStrategySwitch(onSwitch));
  },

  subscribeConfigUpdate(onUpdate: (cfg: AppConfig) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://config-updated", onUpdate);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeConfigUpdate(onUpdate));
  },

  subscribeSyncReceived(onReceived: (ev: SyncReceivedEvent) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://sync-received", onReceived);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeSyncReceived(onReceived));
  },

  subscribeSyncSessionUpdated(onUpdate: (ev: SyncSessionUpdatedEvent) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent("catcloud://sync-session-updated", onUpdate);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeSyncSessionUpdated(onUpdate));
  },

  subscribeUpdateReady(cb: (payload: PendingUpdatePromptDto) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent<PendingUpdatePromptDto>("catcloud://update-ready", cb);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeUpdateReady(cb));
  },

  subscribeGroupsUpdated(onUpdate: () => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEmptyEvent("catcloud://groups-updated", onUpdate);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeGroupsUpdated(onUpdate));
  },

  subscribeRelaysUpdated(onUpdate: () => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEmptyEvent("catcloud://relays-updated", onUpdate);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeRelaysUpdated(onUpdate));
  },

  subscribeNodesUpdated(handler: () => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEmptyEvent("catcloud://nodes-updated", handler);
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeNodesUpdated(handler));
  },

  subscribeNavigate(handler: (nav: string) => void): () => void {
    if (isTauriEnv()) {
      return subscribeTauriEvent<unknown>("catcloud://navigate", (payload) => {
        if (typeof payload === "string") {
          const trimmed = payload.trim();
          if (trimmed) handler(trimmed);
          return;
        }
        if (payload && typeof payload === "object") {
          const rec = payload as { nav?: unknown; route?: unknown; target?: unknown };
          const raw =
            typeof rec.nav === "string"
              ? rec.nav
              : typeof rec.route === "string"
                ? rec.route
                : typeof rec.target === "string"
                  ? rec.target
                  : "";
          const trimmed = raw.trim();
          if (trimmed) handler(trimmed);
        }
      });
    }
    return subscribePreviewMock((mod) => mod.previewApi.subscribeNavigate(handler));
  },
};
