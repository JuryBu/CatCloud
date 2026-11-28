import type {
  AgentPromptMode,
  AppConfig,
  CampusPortalStatus,
  CoreRuntimeInfo,
  DanglingRulesAudit,
  DnsTlsDiagnostics,
  ExitIpInfo,
  GeoDataStatusDto,
  GlobalPreAccelMode,
  GlobalPreAccelScope,
  GlobalPreAccelStatus,
  GroupEvaluationReport,
  LiveCaptureOutcomeDto,
  LiveCaptureStatusDto,
  MultiGroup,
  PendingUpdatePromptDto,
  PreAccelComparisonResult,
  PreAccelDispatchStrategy,
  PreAccelLbStrategy,
  PreAccelRelay,
  PreAccelVerifyState,
  ProbeRunSummary,
  ProbeSnapshot,
  ProxyMode,
  ProxyNode,
  ResolvedTheme,
  RouteTargetMode,
  SiteCheckItem,
  SubscriptionRecord,
  ThemeMode,
  TrafficSample,
  AppUpdateCheckResult,
} from "../api/tauri";
import type { UiLanguage } from "../i18n";

export type { UiLanguage };

export type {
  AgentPromptMode,
  AppConfig,
  CoreRuntimeInfo,
  DnsTlsDiagnostics,
  GlobalPreAccelMode,
  GlobalPreAccelScope,
  GlobalPreAccelStatus,
  PreAccelDispatchStrategy,
  PreAccelLbStrategy,
  PreAccelVerifyState,
  ProbeRunSummary,
  ProxyMode,
  ResolvedTheme,
  RouteTargetMode,
  ThemeMode,
  TrafficSample,
};

export type MascotState =
  | "idle"
  | "searching"
  | "thinking"
  | "typing"
  | "approval"
  | "complete";

export type NavRouteId =
  | "overview"
  | "groups"
  | "speedtest"
  | "preaccel"
  | "nodes"
  | "rules"
  | "logs"
  | "ai"
  | "settings";

export type WindowMode = "main" | "capsule";

export interface ToastNotice {
  id: number;
  text: string;
  tone: "info" | "ok" | "warn";
}

export interface ProbeRunProgressState {
  running: boolean;
  completed: number;
  total: number;
  currentNodeName: string | null;
  cancelled: boolean;
}

export interface BgTasksState {
  preaccel: {
    benchmark: {
      running: boolean;
      nodeId: string | null;
      result: PreAccelComparisonResult | null;
      error: string | null;
      finishedAt: number | null;
    };
    relaysTestingAll: boolean;
    relaysTestingIds: string[];
    relaysSpeedTestingAll: boolean;
    relaysSpeedTestingIds: string[];
    campusChecking: boolean;
    campusResult: CampusPortalStatus | null;
    campusError: string | null;
    installingDriver: boolean;
    verifyingGlobal: boolean;
  };
  subs: {
    refreshingAll: boolean;
    refreshingIds: string[];
    importing: boolean;
  };
  home: {
    checkingQuickSites: boolean;
    refreshingExitIp: boolean;
  };
  groups: {
    probingNodeIds: string[];
    evaluatingGroupId: string | null;
    evalReports: Record<string, GroupEvaluationReport>;
  };
  settings: {
    geoStatus: GeoDataStatusDto | null;
    geoLoading: boolean;
    geoBusy: string | null;
    checkingUpdate: boolean;
    downloadingUpdate: boolean;
    updateInfo: AppUpdateCheckResult | null;
    updateMessage: string | null;
    coreOpBusy: "start" | "stop" | "restart" | "reload" | "hotswap" | null;
    backupBusy: "export" | "import" | null;
  };
  capture: {
    sessionId: string | null;
    active: boolean;
    timedOut: boolean;
    finishing: boolean;
    targetName: string | null;
    status: LiveCaptureStatusDto | null;
    outcome: LiveCaptureOutcomeDto | null;
  };
  probeActiveNodeIds: string[];
  probeLockedOrderIds: string[];
  probeIsPausing: boolean;
  probeLocalStarting: boolean;
}

export interface SessionDraftsState {
  scrollPositions: Record<string, number>;
  nodesWorkspace: {
    tab: "nodes" | "subs";
    filterSubId: string;
  };
  preAccel: {
    selectedCompareNodeId: string;
  };
  speedTest: {
    searchQuery: string;
    sourceFilter: string;
    groupFilter: string;
    filterContinent?: string;
    regionFilter: string;
    onlyGolden: boolean;
    onlyTested: boolean;
    onlyGoogleClean: boolean;
    onlyAiUnlocked: boolean;
    goldenManualSortOverride?: boolean;
    page: number;
    selectedIds: string[];
  };
  multiGroup: {
    selectedId: string;
    hasDirtyDrafts: boolean;
  };
  settings: {
    tab: string;
    hasDirtyDrafts: boolean;
  };
  rulesConns: {
    connPaused: boolean;
    connSearch: string;
    ruleSearch: string;
  };
  home: {
    ipMasked: boolean;
  };
}

export interface AppState {
  initialized: boolean;
  isTauri: boolean;
  windowMode: WindowMode;
  activeNav: NavRouteId;
  aiRouteHint: { moduleId?: string; tab?: "web" | "agent" } | null;
  settingsTabHint: "system" | "appearance" | "dns" | "core" | "updates" | null;
  settingsOpenAgentDocs: boolean;
  multiGroupCreateHint: "wsf" | "ai" | "manual" | "download" | null;
  geoRuleContext: {
    domesticDirectEnabled: boolean;
    customRulesOnly: boolean;
    geodataMode: boolean;
  };
  nodesTabHint: {
    tab: "nodes" | "subs";
    subId?: string | null;
    action?: "migration" | "share" | null;
  } | null;
  config: AppConfig;
  resolvedTheme: ResolvedTheme;
  wallpaperPreviewUrl: string | null;
  wallpaperError: string | null;
  mascotState: MascotState;
  runtime: CoreRuntimeInfo;
  groups: MultiGroup[];
  nodes: ProxyNode[];
  probes: Record<string, ProbeSnapshot>;
  probeProgress: ProbeRunProgressState;
  lastProbeSummary: ProbeRunSummary | null;
  subscriptions: SubscriptionRecord[];
  preAccelRelays: PreAccelRelay[];
  relayChainLatencies: Record<string, number | null>;
  globalPreAccel: GlobalPreAccelStatus;
  exitIp: ExitIpInfo;
  quickSites: SiteCheckItem[];
  latestTraffic: TrafficSample;
  trafficVersion: number;
  toast: ToastNotice | null;
  onboardingHydratedOk: boolean;
  onboardingModalOpen: boolean;
  onboardingAutoSkipped: boolean;
  tunAdminPromptOpen: boolean;
  tunAdminPromptBusy: boolean;
  tunAdminPromptReason: string | null;
  pendingUpdate: PendingUpdatePromptDto | null;
  updateModalVisible: boolean;
  danglingRulesAudit: DanglingRulesAudit | null;
  repairingDanglingRules: boolean;
  bgTasks: BgTasksState;
  sessionDrafts: SessionDraftsState;
}

export interface BackgroundActivitySummary {
  preaccel: boolean;
  nodes: boolean;
  groups: boolean;
  home: boolean;
  settings: boolean;
}

export function buildPendingExitIp(coreRunning: boolean): ExitIpInfo {
  return {
    ip_masked: "--.--.--.***",
    ip_raw: null,
    isp: coreRunning ? "已切换线路，点击「测一下」刷新" : "待核心启动探测",
    location: "待检测",
    timezone: "--",
    google_clean: null,
    core_running: coreRunning,
  };
}

export function createInitialBgTasks(): BgTasksState {
  return {
    preaccel: {
      benchmark: {
        running: false,
        nodeId: null,
        result: null,
        error: null,
        finishedAt: null,
      },
      relaysTestingAll: false,
      relaysTestingIds: [],
      relaysSpeedTestingAll: false,
      relaysSpeedTestingIds: [],
      campusChecking: false,
      campusResult: null,
      campusError: null,
      installingDriver: false,
      verifyingGlobal: false,
    },
    subs: {
      refreshingAll: false,
      refreshingIds: [],
      importing: false,
    },
    home: {
      checkingQuickSites: false,
      refreshingExitIp: false,
    },
    groups: {
      probingNodeIds: [],
      evaluatingGroupId: null,
      evalReports: {},
    },
    settings: {
      geoStatus: null,
      geoLoading: false,
      geoBusy: null,
      checkingUpdate: false,
      downloadingUpdate: false,
      updateInfo: null,
      updateMessage: null,
      coreOpBusy: null,
      backupBusy: null,
    },
    capture: {
      sessionId: null,
      active: false,
      timedOut: false,
      finishing: false,
      targetName: null,
      status: null,
      outcome: null,
    },
    probeActiveNodeIds: [],
    probeLockedOrderIds: [],
    probeIsPausing: false,
    probeLocalStarting: false,
  };
}

export function createInitialSessionDrafts(): SessionDraftsState {
  return {
    scrollPositions: {},
    nodesWorkspace: {
      tab: "nodes",
      filterSubId: "",
    },
    preAccel: {
      selectedCompareNodeId: "",
    },
    speedTest: {
      searchQuery: "",
      sourceFilter: "all",
      groupFilter: "all",
      filterContinent: "all",
      regionFilter: "all",
      onlyGolden: false,
      onlyTested: false,
      onlyGoogleClean: false,
      onlyAiUnlocked: false,
      goldenManualSortOverride: false,
      page: 1,
      selectedIds: [],
    },
    multiGroup: {
      selectedId: "",
      hasDirtyDrafts: false,
    },
    settings: {
      tab: "system",
      hasDirtyDrafts: false,
    },
    rulesConns: {
      connPaused: false,
      connSearch: "",
      ruleSearch: "",
    },
    home: {
      ipMasked: true,
    },
  };
}
