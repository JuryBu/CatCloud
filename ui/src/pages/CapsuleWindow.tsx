import {
  ArrowRightLeft,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Loader2,
  Maximize2,
  Moon,
  PinOff,
  Sun,
  Sunset,
  X,
  Zap,
} from "lucide-react";
import type {
  MouseEvent as ReactMouseEvent,
  PointerEvent as ReactPointerEvent,
} from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  catcloudApi,
  formatErrorMessage,
  type CoreRuntimeInfo,
  type ThemeMode,
} from "../api/tauri";
import { type MascotState, MascotSprite } from "../components/MascotSprite";
import { normalizeUiLanguage, useUiDict, type UiLanguage } from "../i18n";
import {
  appActions,
  appStore,
  useAppSelector,
  useLatestTraffic,
  type ResolvedTheme,
} from "../store/appStore";
import {
  type ResolvedNodeLatency,
  getLatencyTooltipKey,
  resolveNodeDisplayLatency,
} from "../utils/latencyDisplay";
import { resolvePlatformOs } from "../utils/platform";
import {
  type PreAccelSummary,
  resolvePreAccelSummary,
} from "../utils/preaccelStatus";

type ResizeDirection =
  | "East"
  | "West"
  | "North"
  | "South"
  | "NorthEast"
  | "NorthWest"
  | "SouthEast"
  | "SouthWest";

type DockEdge = "top" | "bottom" | "left" | "right";
type HoverHintPlacement = "full" | "row1" | "row2";

interface PhysicalRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface CapsuleHoverHint {
  title: string;
  desc: string;
  placement: HoverHintPlacement;
}

const CAPSULE_SIZE_STORAGE_KEY = "catcloud.capsule.size.v1";
const CAPSULE_DEFAULT_W = 364;
const CAPSULE_DEFAULT_H = 64;
const CAPSULE_MIN_W = 280;
const CAPSULE_MAX_W = 560;
const CAPSULE_MIN_H = 56;
const CAPSULE_MAX_H = 140;

// Require true overlap past screen edges (>= 10dp) before auto-docking on release
const DOCK_OVERLAP_THRESHOLD = 10;
const MULTI_MONITOR_SEAM_PROBE_DP = 24;
const DOCK_UNDOCK_THRESHOLD = 32;
const DOCK_UNDOCK_NUDGE = 42;
const DOCK_PILL_H_W = 116;
const DOCK_PILL_H_H = 18;
const DOCK_PILL_V_W = 18;
const DOCK_PILL_V_H = 96;
const DOCK_MOVE_SETTLE_DELAY_MS = 380;
const DOCK_HOVER_EXPAND_DELAY_MS = 120;
const DOCK_LEAVE_COLLAPSE_DELAY_MS = 500;
const DOCK_COLLAPSE_COOLDOWN_MS = 360;
const RESIZE_CLEAR_DEBOUNCE_MS = 140;
const RESIZE_IDLE_CLEAR_MS = 350;

const DOCK_EDGE_LABELS: Record<DockEdge, string> = {
  top: "顶部贴边",
  bottom: "底部贴边",
  left: "左侧贴边",
  right: "右侧贴边",
};

function clampRange(val: number, min: number, max: number): number {
  if (max < min) return min;
  return Math.max(min, Math.min(max, val));
}

function getDockPillSize(edge: DockEdge): { w: number; h: number } {
  return edge === "top" || edge === "bottom"
    ? { w: DOCK_PILL_H_W, h: DOCK_PILL_H_H }
    : { w: DOCK_PILL_V_W, h: DOCK_PILL_V_H };
}

function computeEdgeDistances(
  winRect: PhysicalRect,
  bounds: PhysicalRect
): Record<DockEdge, number> {
  return {
    top: winRect.y - bounds.y,
    bottom: bounds.y + bounds.height - (winRect.y + winRect.height),
    left: winRect.x - bounds.x,
    right: bounds.x + bounds.width - (winRect.x + winRect.width),
  };
}

function pointInsideRect(px: number, py: number, rect: PhysicalRect): boolean {
  return (
    px >= rect.x &&
    px < rect.x + rect.width &&
    py >= rect.y &&
    py < rect.y + rect.height
  );
}

function isMultiMonitorSeamEdge(
  edge: DockEdge,
  winRect: PhysicalRect,
  bounds: PhysicalRect,
  scale: number,
  otherMonitorRects: readonly PhysicalRect[]
): boolean {
  if (otherMonitorRects.length === 0) return false;
  const probeOffset = MULTI_MONITOR_SEAM_PROBE_DP * scale;
  const centerX = winRect.x + winRect.width / 2;
  const centerY = winRect.y + winRect.height / 2;

  let probeX = centerX;
  let probeY = centerY;
  switch (edge) {
    case "left":
      probeX = bounds.x - probeOffset;
      break;
    case "right":
      probeX = bounds.x + bounds.width + probeOffset;
      break;
    case "top":
      probeY = bounds.y - probeOffset;
      break;
    case "bottom":
      probeY = bounds.y + bounds.height + probeOffset;
      break;
  }

  return otherMonitorRects.some((rect) => pointInsideRect(probeX, probeY, rect));
}

function detectSnapEdge(
  winRect: PhysicalRect,
  bounds: PhysicalRect,
  scale: number,
  otherMonitorRects: readonly PhysicalRect[]
): DockEdge | null {
  const distances = computeEdgeDistances(winRect, bounds);
  const overlapThresholdPx = -(DOCK_OVERLAP_THRESHOLD * scale);
  const priorityOrder: readonly DockEdge[] = ["top", "bottom", "left", "right"];
  let bestEdge: DockEdge | null = null;
  let bestDist = Infinity;

  for (const edge of priorityOrder) {
    const d = distances[edge];
    if (d <= overlapThresholdPx && d < bestDist) {
      if (isMultiMonitorSeamEdge(edge, winRect, bounds, scale, otherMonitorRects)) {
        continue;
      }
      bestDist = d;
      bestEdge = edge;
    }
  }
  return bestEdge;
}

function computeAnchoredPosition(
  edge: DockEdge,
  targetPhysW: number,
  targetPhysH: number,
  anchorRect: PhysicalRect,
  bounds: PhysicalRect
): { x: number; y: number } {
  const centerX = anchorRect.x + anchorRect.width / 2;
  const centerY = anchorRect.y + anchorRect.height / 2;
  const minX = bounds.x;
  const maxX = bounds.x + bounds.width - targetPhysW;
  const minY = bounds.y;
  const maxY = bounds.y + bounds.height - targetPhysH;

  switch (edge) {
    case "top":
      return {
        x: Math.round(clampRange(centerX - targetPhysW / 2, minX, maxX)),
        y: Math.round(minY),
      };
    case "bottom":
      return {
        x: Math.round(clampRange(centerX - targetPhysW / 2, minX, maxX)),
        y: Math.round(maxY),
      };
    case "left":
      return {
        x: Math.round(minX),
        y: Math.round(clampRange(centerY - targetPhysH / 2, minY, maxY)),
      };
    case "right":
      return {
        x: Math.round(maxX),
        y: Math.round(clampRange(centerY - targetPhysH / 2, minY, maxY)),
      };
  }
}

function computeUndockedPosition(
  edge: DockEdge,
  targetPhysW: number,
  targetPhysH: number,
  anchorRect: PhysicalRect,
  bounds: PhysicalRect,
  scale: number
): { x: number; y: number } {
  const base = computeAnchoredPosition(edge, targetPhysW, targetPhysH, anchorRect, bounds);
  const nudgePx = Math.round(DOCK_UNDOCK_NUDGE * scale);
  const minX = bounds.x;
  const maxX = bounds.x + bounds.width - targetPhysW;
  const minY = bounds.y;
  const maxY = bounds.y + bounds.height - targetPhysH;
  switch (edge) {
    case "top":
      return { x: base.x, y: Math.round(clampRange(minY + nudgePx, minY, maxY)) };
    case "bottom":
      return { x: base.x, y: Math.round(clampRange(maxY - nudgePx, minY, maxY)) };
    case "left":
      return { x: Math.round(clampRange(minX + nudgePx, minX, maxX)), y: base.y };
    case "right":
      return { x: Math.round(clampRange(maxX - nudgePx, minX, maxX)), y: base.y };
  }
}

async function readWindowAndMonitorPhysicalRects(): Promise<{
  winRect: PhysicalRect;
  bounds: PhysicalRect;
  scale: number;
  otherMonitorRects: PhysicalRect[];
} | null> {
  const { availableMonitors, currentMonitor, getCurrentWindow } = await import(
    "@tauri-apps/api/window"
  );
  const win = getCurrentWindow();
  const [monitor, allMonitors, scaleFallback, outerPos, outerSize] = await Promise.all([
    currentMonitor(),
    availableMonitors().catch(() => []),
    win.scaleFactor(),
    win.outerPosition(),
    win.outerSize(),
  ]);
  if (!monitor) return null;
  const scale =
    Number.isFinite(monitor.scaleFactor) && monitor.scaleFactor > 0
      ? monitor.scaleFactor
      : Number.isFinite(scaleFallback) && scaleFallback > 0
        ? scaleFallback
        : 1;
  const areaPos = monitor.workArea?.position ?? monitor.position;
  const areaSize = monitor.workArea?.size ?? monitor.size;
  if (areaSize.width <= 0 || areaSize.height <= 0) return null;

  const otherMonitorRects: PhysicalRect[] = [];
  for (const m of allMonitors) {
    const isSameMonitor =
      m.position.x === monitor.position.x &&
      m.position.y === monitor.position.y &&
      m.size.width === monitor.size.width &&
      m.size.height === monitor.size.height;
    if (isSameMonitor) continue;
    const mWorkPos = m.workArea?.position ?? m.position;
    const mWorkSize = m.workArea?.size ?? m.size;
    if (mWorkSize.width > 0 && mWorkSize.height > 0) {
      otherMonitorRects.push({
        x: mWorkPos.x,
        y: mWorkPos.y,
        width: mWorkSize.width,
        height: mWorkSize.height,
      });
    }
    if (m.size.width > 0 && m.size.height > 0) {
      otherMonitorRects.push({
        x: m.position.x,
        y: m.position.y,
        width: m.size.width,
        height: m.size.height,
      });
    }
  }

  return {
    winRect: {
      x: outerPos.x,
      y: outerPos.y,
      width: outerSize.width,
      height: outerSize.height,
    },
    bounds: {
      x: areaPos.x,
      y: areaPos.y,
      width: areaSize.width,
      height: areaSize.height,
    },
    scale,
    otherMonitorRects,
  };
}

function clampCapsuleSize(w: number, h: number): { w: number; h: number } {
  return {
    w: Math.round(Math.max(CAPSULE_MIN_W, Math.min(CAPSULE_MAX_W, w))),
    h: Math.round(Math.max(CAPSULE_MIN_H, Math.min(CAPSULE_MAX_H, h))),
  };
}

function loadSavedCapsuleSize(): { w: number; h: number } | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(CAPSULE_SIZE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { w?: unknown; h?: unknown };
    if (typeof parsed.w !== "number" || typeof parsed.h !== "number") return null;
    if (!Number.isFinite(parsed.w) || !Number.isFinite(parsed.h)) return null;
    return clampCapsuleSize(parsed.w, parsed.h);
  } catch {
    return null;
  }
}

function saveCapsuleSize(w: number, h: number): void {
  if (typeof window === "undefined") return;
  try {
    const clamped = clampCapsuleSize(w, h);
    window.localStorage.setItem(CAPSULE_SIZE_STORAGE_KEY, JSON.stringify(clamped));
  } catch {
    /* ignore storage errors */
  }
}

type CapsulePulseMode = "none" | "work" | "alert";
type CapsuleBadgeTone = "red" | "amber" | "sky" | "green" | "accent";
type CapsuleHealthState = "idle" | "ok" | "preaccel" | "warn" | "error";

interface CapsuleStatusMeta {
  color: string;
  label: string;
  pulse: CapsulePulseMode;
  badge?: {
    label: string;
    tone: CapsuleBadgeTone;
  };
}

interface CapsuleDictSlice {
  common: { appName: string; on: string; off: string };
  nav: {
    preaccelActiveBadge: string;
    preaccelVerifiedBadge: string;
    preaccelProbingBadge: string;
    preaccelDegradedBadge: string;
  };
  titleBar: {
    modeRule: string;
    modeGlobal: string;
    modeDirect: string;
    standby: string;
  };
  capsule: {
    directMode: string;
    probingNow: string;
    circuitOpen: string;
    preaccelVerified: string;
    preaccelDegraded: string;
  };
}

function isActiveGroupCircuitOpen(runtime: CoreRuntimeInfo): boolean {
  if (runtime.active_group_circuit_open) return true;
  const st = runtime.active_group_state?.trim().toLowerCase() ?? "";
  return st.includes("circuit");
}

/**
 * Align strictly with `src-tauri/src/tray.rs::TrayIconMode::AutoAc` and `commands.rs::build_tray_visual_state`:
 * - Idle | Ok => Pack A (cream cloud cat)
 * - PreAccel | Warn | Error => Pack C (starry neko)
 */
function resolveCapsuleHealthState(
  runtime: CoreRuntimeInfo,
  preaccel: PreAccelSummary,
  hasEnabledRelay: boolean
): CapsuleHealthState {
  if (runtime.status === "error") {
    return "error";
  }
  const preaccelWithRelay = preaccel.enabled && hasEnabledRelay;
  const verifyDegraded =
    preaccelWithRelay &&
    (preaccel.verifyState === "degraded" || preaccel.verifyState === "failed");
  const verifyProbing = preaccelWithRelay && preaccel.verifyState === "probing";
  if (
    runtime.status === "warn" ||
    runtime.captive_portal_required ||
    isActiveGroupCircuitOpen(runtime) ||
    verifyDegraded
  ) {
    return "warn";
  }
  const isDirectMode = runtime.proxy_mode === "direct";
  if (isDirectMode) {
    if (!verifyProbing && hasEnabledRelay && preaccel.realWinDivertActive) {
      return "preaccel";
    }
    return "idle";
  }
  if (
    !verifyProbing &&
    hasEnabledRelay &&
    ((preaccel.proxyActive && runtime.preaccel_active && preaccel.tone === "green") ||
      preaccel.realWinDivertActive ||
      runtime.status === "preaccel")
  ) {
    return "preaccel";
  }
  if (preaccel.proxyActive || runtime.status === "ok") {
    return "ok";
  }
  return "idle";
}

function resolveStatusAccent(
  runtime: CoreRuntimeInfo,
  preaccel: PreAccelSummary,
  hasEnabledRelay: boolean,
  mascotState: MascotState,
  isLocalBusy: boolean,
  dict: CapsuleDictSlice,
  uiLang: UiLanguage
): CapsuleStatusMeta {
  const isZh = uiLang === "zh-CN";
  const circuitOpen = isActiveGroupCircuitOpen(runtime);
  const preaccelWithRelay = preaccel.enabled && hasEnabledRelay;
  const verifyDegraded =
    preaccelWithRelay &&
    (preaccel.verifyState === "degraded" || preaccel.verifyState === "failed");
  const verifyProbing = preaccelWithRelay && preaccel.verifyState === "probing";
  const isInstalling =
    preaccelWithRelay &&
    (preaccel.installState === "downloading" || preaccel.installState === "verifying");
  const isWorking =
    isLocalBusy ||
    Boolean(runtime.probing_active) ||
    Boolean(runtime.switching_active) ||
    verifyProbing ||
    mascotState === "searching" ||
    mascotState === "thinking" ||
    mascotState === "typing";

  if (runtime.status === "error") {
    return {
      color: "var(--red)",
      label: isZh ? "核心异常" : "Core Error",
      pulse: "alert",
      badge: { label: isZh ? "异常" : "Err", tone: "red" },
    };
  }
  if (circuitOpen) {
    return {
      color: "var(--red)",
      label: dict.capsule.circuitOpen,
      pulse: "alert",
      badge: { label: isZh ? "熔断" : "Open", tone: "red" },
    };
  }
  if (runtime.status === "warn" || runtime.captive_portal_required) {
    return {
      color: "var(--amber)",
      label: runtime.captive_portal_required
        ? isZh
          ? "校园网需认证"
          : "Portal Auth"
        : isZh
          ? "路线存在波动"
          : "Route Warning",
      pulse: "alert",
      badge: { label: isZh ? "告警" : "Warn", tone: "amber" },
    };
  }
  if (verifyDegraded) {
    return {
      color: "var(--amber)",
      label: dict.capsule.preaccelDegraded,
      pulse: "alert",
      badge: { label: dict.nav.preaccelDegradedBadge, tone: "amber" },
    };
  }
  if (isWorking) {
    return {
      color: "var(--amber)",
      label: verifyProbing
        ? preaccel.badgeText
        : dict.capsule.probingNow,
      pulse: "work",
      badge: {
        label: verifyProbing
          ? dict.nav.preaccelProbingBadge
          : isZh
            ? "处理中"
            : "Busy",
        tone: "amber",
      },
    };
  }
  if (isInstalling) {
    return {
      color: "var(--amber)",
      label: preaccel.badgeText,
      pulse: "work",
    };
  }
  if (runtime.proxy_mode === "direct") {
    if (hasEnabledRelay && preaccel.realWinDivertActive && preaccel.verifyState === "verified") {
      return {
        color: "var(--green)",
        label: preaccel.verifyLatencyMs
          ? `${dict.capsule.preaccelVerified} ${preaccel.verifyLatencyMs}ms · ${dict.capsule.directMode}`
          : `${dict.capsule.preaccelVerified} · ${dict.capsule.directMode}`,
        pulse: "none",
        badge: { label: dict.titleBar.modeDirect, tone: "sky" },
      };
    }
    return {
      color: "var(--sky)",
      label: dict.capsule.directMode,
      pulse: "none",
      badge: { label: dict.titleBar.modeDirect, tone: "sky" },
    };
  }
  if (preaccel.proxyActive) {
    if (preaccelWithRelay && preaccel.tone === "green") {
      if (preaccel.realWinDivertActive) {
        if (preaccel.verifyState === "verified") {
          return {
            color: "var(--green)",
            label: preaccel.verifyLatencyMs
              ? `${dict.capsule.preaccelVerified} (${preaccel.verifyLatencyMs}ms)`
              : dict.capsule.preaccelVerified,
            pulse: "none",
            badge: { label: dict.nav.preaccelVerifiedBadge, tone: "green" },
          };
        }
        return {
          color: "var(--accent)",
          label: preaccel.badgeText,
          pulse: "none",
        };
      }
      return {
        color: "var(--accent)",
        label: preaccel.badgeText,
        pulse: "none",
      };
    }
    return {
      color: "var(--green)",
      label: isZh ? "代理运行正常" : "Proxy Active",
      pulse: "none",
    };
  }
  if (hasEnabledRelay && preaccel.realWinDivertActive) {
    if (preaccel.verifyState === "verified") {
      return {
        color: "var(--green)",
        label: preaccel.verifyLatencyMs
          ? `${dict.capsule.preaccelVerified} ${preaccel.verifyLatencyMs}ms`
          : dict.capsule.preaccelVerified,
        pulse: "none",
        badge: { label: dict.nav.preaccelVerifiedBadge, tone: "green" },
      };
    }
    return {
      color: "var(--accent)",
      label: preaccel.badgeText,
      pulse: "none",
    };
  }
  if (preaccel.enabled) {
    if (!hasEnabledRelay) {
      return {
        color: "var(--amber)",
        label: preaccel.badgeText,
        pulse: "none",
      };
    }
    return {
      color: "var(--amber)",
      label: preaccel.badgeText,
      pulse: "none",
    };
  }
  return { color: "var(--muted)", label: dict.titleBar.standby, pulse: "none" };
}

function resolveThemeDisplay(
  resolvedTheme: ResolvedTheme,
  themeMode: ThemeMode,
  uiLang: UiLanguage
): { label: string; shortLabel: string; autoSuffix: string } {
  const isZh = uiLang === "zh-CN";
  const autoSuffix =
    themeMode === "auto_time" ? (isZh ? " · 按时间自动" : " · Auto") : "";
  switch (resolvedTheme) {
    case "light":
      return {
        label: isZh ? "晨曦浅色" : "Warm Light",
        shortLabel: isZh ? "晨曦" : "Light",
        autoSuffix,
      };
    case "warm-dark":
      return {
        label: isZh ? "深苔暖金" : "Warm Dark",
        shortLabel: isZh ? "暖金" : "Moss",
        autoSuffix,
      };
    default:
      return {
        label: isZh ? "午夜星蓝" : "Midnight Blue",
        shortLabel: isZh ? "星蓝" : "Night",
        autoSuffix,
      };
  }
}

function formatCompactRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "0B/s";
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)}B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb < 10 ? kb.toFixed(1) : Math.round(kb)}K/s`;
  const mb = kb / 1024;
  return `${mb < 100 ? mb.toFixed(1) : Math.round(mb)}M/s`;
}

function resolveLatencyToneClass(ms: number): string {
  if (ms < 180) return "text-[var(--green)]";
  if (ms <= 380) return "text-[var(--amber)]";
  return "text-[var(--coral)]";
}

export function CapsuleWindow() {
  const isTauri = useAppSelector((s) => s.isTauri);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const hasEnabledRelay = useAppSelector((s) =>
    s.preAccelRelays.some((r) => r.enabled)
  );
  const groups = useAppSelector((s) => s.groups);
  const probes = useAppSelector((s) => s.probes);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const trayIconMode = useAppSelector((s) => s.config.personalization.tray_icon_mode);
  const uiLang = useAppSelector((s) =>
    normalizeUiLanguage(s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const mascotState = useAppSelector((s) => s.mascotState);
  const traffic = useLatestTraffic();
  const isZh = uiLang === "zh-CN";

  const isWindows = resolvePlatformOs(runtime.os_label) === "windows";
  const isWindowsRef = useRef<boolean>(isWindows);
  isWindowsRef.current = isWindows;

  const [switching, setSwitching] = useState<boolean>(false);
  const [togglingPreAccel, setTogglingPreAccel] = useState<boolean>(false);
  const [justSwitched, setJustSwitched] = useState<boolean>(false);
  const [hoveredHint, setHoveredHint] = useState<CapsuleHoverHint | null>(null);
  const [dockEdge, setDockEdge] = useState<DockEdge | null>(null);
  const [dockCollapsed, setDockCollapsed] = useState<boolean>(false);
  const [previewSize, setPreviewSize] = useState<{ w: number; h: number }>({
    w: CAPSULE_DEFAULT_W,
    h: CAPSULE_DEFAULT_H,
  });
  const [boxSize, setBoxSize] = useState<{ w: number; h: number }>({
    w: CAPSULE_DEFAULT_W,
    h: CAPSULE_DEFAULT_H,
  });

  const shellRef = useRef<HTMLDivElement | null>(null);
  const switchFeedbackTimerRef = useRef<number | null>(null);
  const saveSizeTimerRef = useRef<number | null>(null);
  const moveSettleTimerRef = useRef<number | null>(null);
  const hoverExpandTimerRef = useRef<number | null>(null);
  const leaveCollapseTimerRef = useRef<number | null>(null);
  const resizeClearTimerRef = useRef<number | null>(null);
  const resizeIdleTimerRef = useRef<number | null>(null);
  const resizeCleanupRef = useRef<(() => void) | null>(null);
  const mountedRef = useRef<boolean>(true);
  const restoredSizeRef = useRef<boolean>(false);
  const resizingRef = useRef<boolean>(false);
  const pointerInsideRef = useRef<boolean>(false);
  const pointerDownRef = useRef<boolean>(false);
  const pendingMoveEvalRef = useRef<boolean>(false);
  const moveSeqRef = useRef<number>(0);
  const dockEdgeRef = useRef<DockEdge | null>(null);
  const dockCollapsedRef = useRef<boolean>(false);
  const dockOpBusyRef = useRef<boolean>(false);
  const switchingRef = useRef<boolean>(false);
  const togglingPreAccelRef = useRef<boolean>(false);
  const programmaticMoveUntilRef = useRef<number>(0);
  const expandCooldownUntilRef = useRef<number>(0);
  const expandedSizeRef = useRef<{ w: number; h: number }>(
    loadSavedCapsuleSize() ?? { w: CAPSULE_DEFAULT_W, h: CAPSULE_DEFAULT_H }
  );

  // Windows zero-HTCAPTION custom physical-coordinate drag state (eliminates Aero Snap)
  const customDragActiveRef = useRef<boolean>(false);
  const customDragPointerIdRef = useRef<number | null>(null);
  const customDragMovedRef = useRef<boolean>(false);
  const customDragStartRef = useRef<{
    clientX: number;
    clientY: number;
    screenX: number;
    screenY: number;
  }>({ clientX: 0, clientY: 0, screenX: 0, screenY: 0 });
  const dragStartPromiseRef = useRef<Promise<unknown> | null>(null);
  const dragStepInFlightRef = useRef<boolean>(false);
  const dragStepQueuedRef = useRef<boolean>(false);
  const dragRafIdRef = useRef<number | null>(null);

  dockEdgeRef.current = dockEdge;
  dockCollapsedRef.current = dockCollapsed;
  switchingRef.current = switching;
  togglingPreAccelRef.current = togglingPreAccel;

  const clearDockTimers = useCallback(() => {
    if (moveSettleTimerRef.current !== null) {
      window.clearTimeout(moveSettleTimerRef.current);
      moveSettleTimerRef.current = null;
    }
    if (hoverExpandTimerRef.current !== null) {
      window.clearTimeout(hoverExpandTimerRef.current);
      hoverExpandTimerRef.current = null;
    }
    if (leaveCollapseTimerRef.current !== null) {
      window.clearTimeout(leaveCollapseTimerRef.current);
      leaveCollapseTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearDockTimers();
      if (switchFeedbackTimerRef.current !== null) {
        window.clearTimeout(switchFeedbackTimerRef.current);
      }
      if (saveSizeTimerRef.current !== null) {
        window.clearTimeout(saveSizeTimerRef.current);
      }
      if (resizeClearTimerRef.current !== null) {
        window.clearTimeout(resizeClearTimerRef.current);
      }
      if (resizeIdleTimerRef.current !== null) {
        window.clearTimeout(resizeIdleTimerRef.current);
      }
      resizeCleanupRef.current?.();
      resizeCleanupRef.current = null;
      if (dragRafIdRef.current !== null) {
        window.cancelAnimationFrame(dragRafIdRef.current);
        dragRafIdRef.current = null;
      }
      if (customDragActiveRef.current) {
        customDragActiveRef.current = false;
        void catcloudApi.capsuleDragEnd().catch(() => {});
      }
    };
  }, [clearDockTimers]);

  const collapseToDock = useCallback(
    async (edge: DockEdge) => {
      if (dockOpBusyRef.current) return;
      if (hoverExpandTimerRef.current !== null) {
        window.clearTimeout(hoverExpandTimerRef.current);
        hoverExpandTimerRef.current = null;
      }
      if (leaveCollapseTimerRef.current !== null) {
        window.clearTimeout(leaveCollapseTimerRef.current);
        leaveCollapseTimerRef.current = null;
      }

      if (!isTauri) {
        dockEdgeRef.current = edge;
        dockCollapsedRef.current = true;
        setDockEdge(edge);
        setDockCollapsed(true);
        setHoveredHint(null);
        return;
      }

      try {
        dockOpBusyRef.current = true;
        programmaticMoveUntilRef.current = Date.now() + 600;
        const rects = await readWindowAndMonitorPhysicalRects();
        if (!rects || !mountedRef.current) return;
        const { winRect, bounds, scale } = rects;
        const logicalW = winRect.width / scale;
        const logicalH = winRect.height / scale;
        if (
          !dockCollapsedRef.current &&
          logicalW >= CAPSULE_MIN_W - 8 &&
          logicalH >= CAPSULE_MIN_H - 8
        ) {
          expandedSizeRef.current = clampCapsuleSize(logicalW, logicalH);
        }

        const pillSize = getDockPillSize(edge);
        const targetPhysW = Math.round(pillSize.w * scale);
        const targetPhysH = Math.round(pillSize.h * scale);
        const targetPos = computeAnchoredPosition(
          edge,
          targetPhysW,
          targetPhysH,
          winRect,
          bounds
        );
        const { getCurrentWindow, LogicalSize, PhysicalPosition } = await import(
          "@tauri-apps/api/window"
        );
        const win = getCurrentWindow();

        dockEdgeRef.current = edge;
        dockCollapsedRef.current = true;
        expandCooldownUntilRef.current = Date.now() + DOCK_COLLAPSE_COOLDOWN_MS;
        setDockEdge(edge);
        setDockCollapsed(true);
        setHoveredHint(null);

        await win.setMinSize(new LogicalSize(18, 18)).catch(() => {
          /* ignore if platform ignores minSize updates */
        });
        const targetPhysicalPos = new PhysicalPosition(
          Math.round(targetPos.x),
          Math.round(targetPos.y)
        );
        const targetPillSize = new LogicalSize(pillSize.w, pillSize.h);
        // Right/bottom dock anchors shift the top-left origin toward the edge when shrinking:
        // move first then shrink so the small pill never flashes detached mid-screen.
        if (edge === "right" || edge === "bottom") {
          await win.setPosition(targetPhysicalPos);
          await win.setSize(targetPillSize);
        } else {
          await win.setSize(targetPillSize);
          await win.setPosition(targetPhysicalPos);
        }
        programmaticMoveUntilRef.current = Date.now() + 340;
      } catch {
        try {
          const exp = clampCapsuleSize(expandedSizeRef.current.w, expandedSizeRef.current.h);
          const { getCurrentWindow, LogicalSize } = await import("@tauri-apps/api/window");
          const win = getCurrentWindow();
          await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {});
          await win.setSize(new LogicalSize(exp.w, exp.h)).catch(() => {});
          programmaticMoveUntilRef.current = Date.now() + 340;
        } catch {
          /* ignore fallback recovery failures */
        }
        if (mountedRef.current) {
          dockCollapsedRef.current = false;
          setDockCollapsed(false);
        }
      } finally {
        dockOpBusyRef.current = false;
      }
    },
    [isTauri]
  );

  const expandFromDock = useCallback(
    async (edgeOverride?: DockEdge) => {
      const edge = edgeOverride ?? dockEdgeRef.current;
      if (!edge || dockOpBusyRef.current) return;
      if (hoverExpandTimerRef.current !== null) {
        window.clearTimeout(hoverExpandTimerRef.current);
        hoverExpandTimerRef.current = null;
      }
      if (leaveCollapseTimerRef.current !== null) {
        window.clearTimeout(leaveCollapseTimerRef.current);
        leaveCollapseTimerRef.current = null;
      }

      if (!isTauri) {
        dockCollapsedRef.current = false;
        setDockCollapsed(false);
        return;
      }

      try {
        dockOpBusyRef.current = true;
        programmaticMoveUntilRef.current = Date.now() + 600;
        const rects = await readWindowAndMonitorPhysicalRects();
        const exp = clampCapsuleSize(expandedSizeRef.current.w, expandedSizeRef.current.h);
        const { getCurrentWindow, LogicalSize, PhysicalPosition } = await import(
          "@tauri-apps/api/window"
        );
        const win = getCurrentWindow();

        const targetExpSize = new LogicalSize(exp.w, exp.h);
        const targetPhysicalPos = rects
          ? (() => {
              const targetPhysW = Math.round(exp.w * rects.scale);
              const targetPhysH = Math.round(exp.h * rects.scale);
              const targetPos = computeAnchoredPosition(
                edge,
                targetPhysW,
                targetPhysH,
                rects.winRect,
                rects.bounds
              );
              return new PhysicalPosition(Math.round(targetPos.x), Math.round(targetPos.y));
            })()
          : null;

        // Right/bottom dock anchors shift the top-left origin away from the edge when expanding:
        // grow first then shift into place so the small pill never jumps away from the edge.
        if (edge === "right" || edge === "bottom") {
          await win.setSize(targetExpSize);
          if (targetPhysicalPos) {
            await win.setPosition(targetPhysicalPos);
          }
        } else {
          if (targetPhysicalPos) {
            await win.setPosition(targetPhysicalPos);
          }
          await win.setSize(targetExpSize);
        }
        await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {});

        if (mountedRef.current) {
          dockCollapsedRef.current = false;
          setDockCollapsed(false);
        }
        programmaticMoveUntilRef.current = Date.now() + 340;
      } catch {
        if (mountedRef.current) {
          dockCollapsedRef.current = false;
          setDockCollapsed(false);
        }
      } finally {
        dockOpBusyRef.current = false;
      }
    },
    [isTauri]
  );

  const undockCapsule = useCallback(
    async (nudgeIntoScreen = true) => {
      if (dockOpBusyRef.current) return;
      clearDockTimers();
      const prevEdge = dockEdgeRef.current;
      const wasCollapsed = dockCollapsedRef.current;

      if (!isTauri) {
        dockEdgeRef.current = null;
        dockCollapsedRef.current = false;
        setDockEdge(null);
        setDockCollapsed(false);
        setHoveredHint(null);
        if (prevEdge) {
          appActions.showToast("已取消贴边，恢复自由悬浮", "info");
        }
        return;
      }

      if (!prevEdge && !wasCollapsed) return;

      try {
        dockOpBusyRef.current = true;
        programmaticMoveUntilRef.current = Date.now() + 600;
        dockEdgeRef.current = null;
        dockCollapsedRef.current = false;
        setDockEdge(null);
        setDockCollapsed(false);
        setHoveredHint(null);

        const rects = await readWindowAndMonitorPhysicalRects();
        const exp = clampCapsuleSize(expandedSizeRef.current.w, expandedSizeRef.current.h);
        const { getCurrentWindow, LogicalSize, PhysicalPosition } = await import(
          "@tauri-apps/api/window"
        );
        const win = getCurrentWindow();

        if (wasCollapsed || nudgeIntoScreen) {
          if (rects && prevEdge) {
            const targetPhysW = Math.round(exp.w * rects.scale);
            const targetPhysH = Math.round(exp.h * rects.scale);
            const nextPos = computeUndockedPosition(
              prevEdge,
              targetPhysW,
              targetPhysH,
              rects.winRect,
              rects.bounds,
              rects.scale
            );
            await win.setPosition(
              new PhysicalPosition(Math.round(nextPos.x), Math.round(nextPos.y))
            );
          }
          if (wasCollapsed) {
            await win.setSize(new LogicalSize(exp.w, exp.h));
          }
        }
        await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {});
        programmaticMoveUntilRef.current = Date.now() + 340;
        if (prevEdge) {
          appActions.showToast("已取消贴边，恢复自由悬浮", "info");
        }
      } catch {
        /* ignore platform move restrictions */
      } finally {
        dockOpBusyRef.current = false;
      }
    },
    [clearDockTimers, isTauri]
  );

  // Unified post-drag dock/undock evaluation: invoked strictly after release
  const evaluateDockPosition = useCallback(
    async (expectedSeq?: number) => {
      if (
        !mountedRef.current ||
        dockOpBusyRef.current ||
        resizingRef.current ||
        dockCollapsedRef.current ||
        customDragActiveRef.current ||
        Date.now() < programmaticMoveUntilRef.current
      ) {
        return;
      }
      if (expectedSeq === undefined && pointerDownRef.current) {
        return;
      }
      try {
        const rects = await readWindowAndMonitorPhysicalRects();
        if (
          !rects ||
          !mountedRef.current ||
          (expectedSeq !== undefined && moveSeqRef.current !== expectedSeq) ||
          pointerDownRef.current ||
          customDragActiveRef.current ||
          dockOpBusyRef.current ||
          resizingRef.current ||
          dockCollapsedRef.current
        ) {
          return;
        }
        const { winRect, bounds, scale, otherMonitorRects } = rects;
        const logicalW = winRect.width / scale;
        const logicalH = winRect.height / scale;
        if (logicalW < CAPSULE_MIN_W - 20 || logicalH < CAPSULE_MIN_H - 12) {
          return;
        }
        const curEdge = dockEdgeRef.current;
        const distances = computeEdgeDistances(winRect, bounds);
        const undockThresholdPx = DOCK_UNDOCK_THRESHOLD * scale;

        if (curEdge) {
          if (distances[curEdge] > undockThresholdPx) {
            const nextSnap = detectSnapEdge(winRect, bounds, scale, otherMonitorRects);
            if (nextSnap && nextSnap !== curEdge) {
              expandedSizeRef.current = clampCapsuleSize(logicalW, logicalH);
              await collapseToDock(nextSnap);
            } else {
              dockEdgeRef.current = null;
              dockCollapsedRef.current = false;
              setDockEdge(null);
              setDockCollapsed(false);
              appActions.showToast("已取消贴边，恢复自由悬浮", "info");
            }
          }
          return;
        }

        const snapEdge = detectSnapEdge(winRect, bounds, scale, otherMonitorRects);
        if (snapEdge) {
          expandedSizeRef.current = clampCapsuleSize(logicalW, logicalH);
          await collapseToDock(snapEdge);
        }
      } catch {
        /* gracefully ignore monitor/position query failures on unsupported window managers */
      }
    },
    [collapseToDock]
  );

  // Restore last user-resized capsule dimensions cleanly on desktop startup
  useEffect(() => {
    if (!isTauri || restoredSizeRef.current) return;
    restoredSizeRef.current = true;
    const saved = loadSavedCapsuleSize();
    if (saved) {
      expandedSizeRef.current = saved;
    }
    if (!saved || (saved.w === CAPSULE_DEFAULT_W && saved.h === CAPSULE_DEFAULT_H)) return;
    programmaticMoveUntilRef.current = Date.now() + 500;
    void import("@tauri-apps/api/window")
      .then(async ({ getCurrentWindow, LogicalSize }) => {
        const win = getCurrentWindow();
        await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {});
        await win.setSize(new LogicalSize(saved.w, saved.h));
      })
      .catch(() => {
        /* ignore if window cannot resize yet */
      });
  }, [isTauri]);

  // Native window move/resize listeners:
  // - On Windows, custom drag handles pointerup settlement exclusively (no 380ms mid-drag collapse!).
  // - On macOS / Linux, native win.startDragging() relies on onMoved settle after pointer release.
  useEffect(() => {
    if (!isTauri) return;
    let disposed = false;
    let unlistenMoved: (() => void) | null = null;
    let unlistenResized: (() => void) | null = null;

    const scheduleMoveSettle = () => {
      if (isWindowsRef.current) return;
      const seq = moveSeqRef.current;
      if (moveSettleTimerRef.current !== null) {
        window.clearTimeout(moveSettleTimerRef.current);
      }
      moveSettleTimerRef.current = window.setTimeout(() => {
        moveSettleTimerRef.current = null;
        if (!disposed) {
          void evaluateDockPosition(seq);
        }
      }, DOCK_MOVE_SETTLE_DELAY_MS);
    };

    const handlePointerDown = (ev: MouseEvent | PointerEvent) => {
      if (ev.button !== 0 || isWindowsRef.current) return;
      pointerDownRef.current = true;
      if (moveSettleTimerRef.current !== null) {
        window.clearTimeout(moveSettleTimerRef.current);
        moveSettleTimerRef.current = null;
      }
      if (leaveCollapseTimerRef.current !== null) {
        window.clearTimeout(leaveCollapseTimerRef.current);
        leaveCollapseTimerRef.current = null;
      }
    };

    const handlePointerRelease = () => {
      if (isWindowsRef.current || !pointerDownRef.current) return;
      pointerDownRef.current = false;
      if (pendingMoveEvalRef.current && !dockCollapsedRef.current && !resizingRef.current) {
        pendingMoveEvalRef.current = false;
        scheduleMoveSettle();
      }
    };

    const handlePointerMoveButtonsCheck = (ev: MouseEvent | PointerEvent) => {
      if (!isWindowsRef.current && pointerDownRef.current && ev.buttons === 0) {
        handlePointerRelease();
      }
    };

    window.addEventListener("pointerdown", handlePointerDown, true);
    window.addEventListener("mousedown", handlePointerDown, true);
    window.addEventListener("pointerup", handlePointerRelease, true);
    window.addEventListener("mouseup", handlePointerRelease, true);
    window.addEventListener("pointercancel", handlePointerRelease, true);
    window.addEventListener("blur", handlePointerRelease);
    window.addEventListener("pointermove", handlePointerMoveButtonsCheck, true);
    window.addEventListener("mousemove", handlePointerMoveButtonsCheck, true);
    document.documentElement.addEventListener("mouseleave", handlePointerMoveButtonsCheck);

    void import("@tauri-apps/api/window")
      .then(async ({ getCurrentWindow }) => {
        const win = getCurrentWindow();
        const [movedRes, resizedRes] = await Promise.allSettled([
          win.onMoved(() => {
            if (
              disposed ||
              isWindowsRef.current ||
              dockOpBusyRef.current ||
              resizingRef.current ||
              dockCollapsedRef.current ||
              Date.now() < programmaticMoveUntilRef.current
            ) {
              return;
            }
            moveSeqRef.current += 1;
            if (leaveCollapseTimerRef.current !== null) {
              window.clearTimeout(leaveCollapseTimerRef.current);
              leaveCollapseTimerRef.current = null;
            }
            if (moveSettleTimerRef.current !== null) {
              window.clearTimeout(moveSettleTimerRef.current);
              moveSettleTimerRef.current = null;
            }
            if (pointerDownRef.current) {
              pendingMoveEvalRef.current = true;
              return;
            }
            scheduleMoveSettle();
          }),
          win.onResized(({ payload }) => {
            if (disposed || !mountedRef.current) {
              return;
            }
            if (resizingRef.current) {
              if (resizeIdleTimerRef.current !== null) {
                window.clearTimeout(resizeIdleTimerRef.current);
              }
              resizeIdleTimerRef.current = window.setTimeout(() => {
                resizeIdleTimerRef.current = null;
                if (resizingRef.current) {
                  resizeCleanupRef.current?.();
                  resizeCleanupRef.current = null;
                  resizingRef.current = false;
                }
              }, RESIZE_IDLE_CLEAR_MS);
            }
            if (dockOpBusyRef.current || !dockCollapsedRef.current) {
              return;
            }
            const physW = payload?.width ?? 0;
            const physH = payload?.height ?? 0;
            if (physW <= 0 || physH <= 0) return;
            void win
              .scaleFactor()
              .catch(() => window.devicePixelRatio || 1)
              .then((rawScale) => {
                const scale = Number.isFinite(rawScale) && rawScale > 0 ? rawScale : 1;
                if (
                  disposed ||
                  !mountedRef.current ||
                  dockOpBusyRef.current ||
                  !dockCollapsedRef.current
                ) {
                  return;
                }
                if (physW >= CAPSULE_MIN_W * scale && physH >= CAPSULE_MIN_H * scale) {
                  clearDockTimers();
                  dockCollapsedRef.current = false;
                  dockEdgeRef.current = null;
                  setDockCollapsed(false);
                  setDockEdge(null);
                  setHoveredHint(null);
                }
              });
          }),
        ]);
        if (movedRes.status === "fulfilled") {
          if (disposed) {
            movedRes.value();
          } else {
            unlistenMoved = movedRes.value;
          }
        }
        if (resizedRes.status === "fulfilled") {
          if (disposed) {
            resizedRes.value();
          } else {
            unlistenResized = resizedRes.value;
          }
        }
      })
      .catch(() => {
        /* ignore if onMoved/onResized listener is unavailable */
      });

    return () => {
      disposed = true;
      pointerDownRef.current = false;
      pendingMoveEvalRef.current = false;
      window.removeEventListener("pointerdown", handlePointerDown, true);
      window.removeEventListener("mousedown", handlePointerDown, true);
      window.removeEventListener("pointerup", handlePointerRelease, true);
      window.removeEventListener("mouseup", handlePointerRelease, true);
      window.removeEventListener("pointercancel", handlePointerRelease, true);
      window.removeEventListener("blur", handlePointerRelease);
      window.removeEventListener("pointermove", handlePointerMoveButtonsCheck, true);
      window.removeEventListener("mousemove", handlePointerMoveButtonsCheck, true);
      document.documentElement.removeEventListener("mouseleave", handlePointerMoveButtonsCheck);
      unlistenMoved?.();
      unlistenMoved = null;
      unlistenResized?.();
      unlistenResized = null;
      if (moveSettleTimerRef.current !== null) {
        window.clearTimeout(moveSettleTimerRef.current);
        moveSettleTimerRef.current = null;
      }
      if (resizeIdleTimerRef.current !== null) {
        window.clearTimeout(resizeIdleTimerRef.current);
        resizeIdleTimerRef.current = null;
      }
    };
  }, [clearDockTimers, evaluateDockPosition, isTauri]);

  // Observe live capsule width/height to adapt layout smoothly & persist resized size
  useEffect(() => {
    if (dockCollapsed) return;
    const el = shellRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const updateFromRect = (width: number, height: number) => {
      const nextW = Math.round(width);
      const nextH = Math.round(height);
      if (nextW <= 0 || nextH <= 0) return;
      setBoxSize((prev) =>
        prev.w === nextW && prev.h === nextH ? prev : { w: nextW, h: nextH }
      );
      if (
        isTauri &&
        !dockCollapsedRef.current &&
        Date.now() >= programmaticMoveUntilRef.current &&
        nextW + 4 >= CAPSULE_MIN_W - 8 &&
        nextH + 4 >= CAPSULE_MIN_H - 8
      ) {
        expandedSizeRef.current = clampCapsuleSize(nextW + 4, nextH + 4);
        if (saveSizeTimerRef.current !== null) {
          window.clearTimeout(saveSizeTimerRef.current);
        }
        saveSizeTimerRef.current = window.setTimeout(() => {
          saveSizeTimerRef.current = null;
          if (!dockCollapsedRef.current) {
            saveCapsuleSize(nextW + 4, nextH + 4);
          }
        }, 260);
      }
    };

    const rect = el.getBoundingClientRect();
    updateFromRect(rect.width, rect.height);

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      updateFromRect(entry.contentRect.width, entry.contentRect.height);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [dockCollapsed, isTauri]);

  // Windows rAF-throttled custom drag helpers (at most 1 IPC step in flight)
  const flushCustomDragStep = useCallback(async () => {
    if (!customDragActiveRef.current || dragStepInFlightRef.current) return;
    dragStepInFlightRef.current = true;
    dragStepQueuedRef.current = false;
    try {
      if (dragStartPromiseRef.current) {
        await dragStartPromiseRef.current;
      }
      if (!customDragActiveRef.current) return;
      const moved = await catcloudApi.capsuleDragStep();
      if (moved) {
        customDragMovedRef.current = true;
      }
    } catch {
      /* ignore transient Win32 move errors */
    } finally {
      dragStepInFlightRef.current = false;
      if (customDragActiveRef.current && dragStepQueuedRef.current) {
        dragStepQueuedRef.current = false;
        if (dragRafIdRef.current === null) {
          dragRafIdRef.current = window.requestAnimationFrame(() => {
            dragRafIdRef.current = null;
            void flushCustomDragStep();
          });
        }
      }
    }
  }, []);

  const scheduleCustomDragStep = useCallback(() => {
    if (!customDragActiveRef.current) return;
    if (dragStepInFlightRef.current) {
      dragStepQueuedRef.current = true;
      return;
    }
    if (dragRafIdRef.current !== null) return;
    dragRafIdRef.current = window.requestAnimationFrame(() => {
      dragRafIdRef.current = null;
      void flushCustomDragStep();
    });
  }, [flushCustomDragStep]);

  const finishCustomDrag = useCallback(
    async (target: HTMLDivElement | null, pointerId: number | null) => {
      if (!customDragActiveRef.current) return;
      const didMove = customDragMovedRef.current;
      customDragActiveRef.current = false;
      customDragPointerIdRef.current = null;
      customDragMovedRef.current = false;
      pointerDownRef.current = false;
      dragStepQueuedRef.current = false;

      if (dragRafIdRef.current !== null) {
        window.cancelAnimationFrame(dragRafIdRef.current);
        dragRafIdRef.current = null;
      }
      if (target && pointerId !== null) {
        try {
          if (target.hasPointerCapture(pointerId)) {
            target.releasePointerCapture(pointerId);
          }
        } catch {
          /* ignore pointer capture release errors */
        }
      }

      try {
        if (dragStartPromiseRef.current) {
          await dragStartPromiseRef.current;
        }
        if (didMove) {
          await catcloudApi.capsuleDragStep().catch(() => false);
        }
      } finally {
        dragStartPromiseRef.current = null;
        await catcloudApi.capsuleDragEnd().catch(() => false);
      }

      if (
        didMove &&
        mountedRef.current &&
        !resizingRef.current &&
        !dockCollapsedRef.current &&
        !dockOpBusyRef.current
      ) {
        await evaluateDockPosition();
      }
    },
    [evaluateDockPosition]
  );

  const handleShellPointerDown = (ev: ReactPointerEvent<HTMLDivElement>) => {
    if (!isTauri || ev.button !== 0 || dockCollapsedRef.current || dockOpBusyRef.current) {
      return;
    }
    // Reset any stale resizing state left over if Windows startResizeDragging ended outside the window
    if (resizingRef.current) {
      resizingRef.current = false;
      resizeCleanupRef.current?.();
      resizeCleanupRef.current = null;
      if (resizeClearTimerRef.current !== null) {
        window.clearTimeout(resizeClearTimerRef.current);
        resizeClearTimerRef.current = null;
      }
      if (resizeIdleTimerRef.current !== null) {
        window.clearTimeout(resizeIdleTimerRef.current);
        resizeIdleTimerRef.current = null;
      }
    }
    const targetEl = ev.target as HTMLElement | null;
    if (targetEl?.closest('button, [data-capsule-no-drag="true"]')) {
      return;
    }

    if (leaveCollapseTimerRef.current !== null) {
      window.clearTimeout(leaveCollapseTimerRef.current);
      leaveCollapseTimerRef.current = null;
    }
    if (moveSettleTimerRef.current !== null) {
      window.clearTimeout(moveSettleTimerRef.current);
      moveSettleTimerRef.current = null;
    }
    setHoveredHint(null);

    if (!isWindowsRef.current) {
      pointerDownRef.current = true;
      void import("@tauri-apps/api/window")
        .then(({ getCurrentWindow }) => getCurrentWindow().startDragging())
        .catch(() => {
          pointerDownRef.current = false;
        });
      return;
    }

    ev.preventDefault();
    customDragActiveRef.current = true;
    customDragPointerIdRef.current = ev.pointerId;
    customDragMovedRef.current = false;
    customDragStartRef.current = {
      clientX: ev.clientX,
      clientY: ev.clientY,
      screenX: ev.screenX,
      screenY: ev.screenY,
    };
    pointerDownRef.current = true;
    try {
      ev.currentTarget.setPointerCapture(ev.pointerId);
    } catch {
      /* continue drag even if pointer capture is unavailable */
    }
    dragStartPromiseRef.current = catcloudApi.capsuleDragStart().catch(() => false);
  };

  const handleShellPointerMove = (ev: ReactPointerEvent<HTMLDivElement>) => {
    if (
      !isWindowsRef.current ||
      !customDragActiveRef.current ||
      ev.pointerId !== customDragPointerIdRef.current
    ) {
      return;
    }
    if (ev.buttons === 0) {
      void finishCustomDrag(ev.currentTarget, ev.pointerId);
      return;
    }
    const start = customDragStartRef.current;
    const screenDelta = Math.hypot(ev.screenX - start.screenX, ev.screenY - start.screenY);
    const clientDelta = Math.hypot(ev.clientX - start.clientX, ev.clientY - start.clientY);
    if (
      screenDelta >= 2 ||
      clientDelta >= 2 ||
      Math.abs(ev.movementX) + Math.abs(ev.movementY) > 0
    ) {
      customDragMovedRef.current = true;
    }
    scheduleCustomDragStep();
  };

  const handleShellPointerUpOrCancel = (ev: ReactPointerEvent<HTMLDivElement>) => {
    if (
      !isWindowsRef.current ||
      !customDragActiveRef.current ||
      ev.pointerId !== customDragPointerIdRef.current
    ) {
      return;
    }
    void finishCustomDrag(ev.currentTarget, ev.pointerId);
  };

  const handleShellLostPointerCapture = (ev: ReactPointerEvent<HTMLDivElement>) => {
    if (
      !isWindowsRef.current ||
      !customDragActiveRef.current ||
      ev.pointerId !== customDragPointerIdRef.current
    ) {
      return;
    }
    void finishCustomDrag(null, null);
  };

  // Preserve 8-direction resize handles without the 1800ms forced timeout bug
  const handleStartResize = (
    direction: ResizeDirection,
    ev: ReactMouseEvent<HTMLDivElement>
  ) => {
    if (!isTauri || ev.button !== 0 || dockCollapsedRef.current) return;
    ev.preventDefault();
    ev.stopPropagation();
    setHoveredHint(null);
    resizingRef.current = true;

    if (leaveCollapseTimerRef.current !== null) {
      window.clearTimeout(leaveCollapseTimerRef.current);
      leaveCollapseTimerRef.current = null;
    }
    if (moveSettleTimerRef.current !== null) {
      window.clearTimeout(moveSettleTimerRef.current);
      moveSettleTimerRef.current = null;
    }
    if (resizeClearTimerRef.current !== null) {
      window.clearTimeout(resizeClearTimerRef.current);
      resizeClearTimerRef.current = null;
    }
    if (resizeIdleTimerRef.current !== null) {
      window.clearTimeout(resizeIdleTimerRef.current);
      resizeIdleTimerRef.current = null;
    }
    resizeCleanupRef.current?.();
    resizeCleanupRef.current = null;

    const detachListeners = () => {
      window.removeEventListener("mouseup", scheduleClearResize, true);
      window.removeEventListener("pointerup", scheduleClearResize, true);
      window.removeEventListener("pointercancel", scheduleClearResize, true);
      window.removeEventListener("blur", scheduleClearResize);
      window.removeEventListener("pointermove", handleButtonsReleased, true);
      window.removeEventListener("mousemove", handleButtonsReleased, true);
    };

    const scheduleClearResize = () => {
      detachListeners();
      resizeCleanupRef.current = null;
      if (resizeIdleTimerRef.current !== null) {
        window.clearTimeout(resizeIdleTimerRef.current);
        resizeIdleTimerRef.current = null;
      }
      if (resizeClearTimerRef.current !== null) {
        window.clearTimeout(resizeClearTimerRef.current);
      }
      resizeClearTimerRef.current = window.setTimeout(() => {
        resizeClearTimerRef.current = null;
        resizingRef.current = false;
      }, RESIZE_CLEAR_DEBOUNCE_MS);
    };

    const handleButtonsReleased = (moveEv: MouseEvent | PointerEvent) => {
      if (moveEv.buttons === 0) {
        scheduleClearResize();
      }
    };

    window.addEventListener("mouseup", scheduleClearResize, true);
    window.addEventListener("pointerup", scheduleClearResize, true);
    window.addEventListener("pointercancel", scheduleClearResize, true);
    window.addEventListener("blur", scheduleClearResize);
    window.addEventListener("pointermove", handleButtonsReleased, true);
    window.addEventListener("mousemove", handleButtonsReleased, true);
    resizeCleanupRef.current = detachListeners;

    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().startResizeDragging(direction))
      .catch(() => {
        scheduleClearResize();
      });
  };

  const handleExpandedPointerEnter = () => {
    pointerInsideRef.current = true;
    if (leaveCollapseTimerRef.current !== null) {
      window.clearTimeout(leaveCollapseTimerRef.current);
      leaveCollapseTimerRef.current = null;
    }
  };

  const handleExpandedPointerLeave = () => {
    pointerInsideRef.current = false;
    setHoveredHint(null);
    if (!dockEdgeRef.current || dockCollapsedRef.current) return;
    if (leaveCollapseTimerRef.current !== null) {
      window.clearTimeout(leaveCollapseTimerRef.current);
    }
    leaveCollapseTimerRef.current = window.setTimeout(() => {
      leaveCollapseTimerRef.current = null;
      const edge = dockEdgeRef.current;
      if (
        !mountedRef.current ||
        !edge ||
        dockCollapsedRef.current ||
        pointerInsideRef.current ||
        pointerDownRef.current ||
        customDragActiveRef.current ||
        resizingRef.current ||
        switchingRef.current ||
        togglingPreAccelRef.current
      ) {
        return;
      }
      void collapseToDock(edge);
    }, DOCK_LEAVE_COLLAPSE_DELAY_MS);
  };

  const handleDockHandleMouseEnter = () => {
    pointerInsideRef.current = true;
    if (!dockEdgeRef.current || !dockCollapsedRef.current) return;
    if (Date.now() < expandCooldownUntilRef.current) return;
    if (hoverExpandTimerRef.current !== null) {
      window.clearTimeout(hoverExpandTimerRef.current);
    }
    hoverExpandTimerRef.current = window.setTimeout(() => {
      hoverExpandTimerRef.current = null;
      if (mountedRef.current && dockCollapsedRef.current && pointerInsideRef.current) {
        void expandFromDock();
      }
    }, DOCK_HOVER_EXPAND_DELAY_MS);
  };

  const handleDockHandleMouseLeave = () => {
    pointerInsideRef.current = false;
    if (hoverExpandTimerRef.current !== null) {
      window.clearTimeout(hoverExpandTimerRef.current);
      hoverExpandTimerRef.current = null;
    }
  };

  const triggerSwitchedFeedback = () => {
    if (!mountedRef.current) return;
    setJustSwitched(true);
    if (switchFeedbackTimerRef.current !== null) {
      window.clearTimeout(switchFeedbackTimerRef.current);
    }
    switchFeedbackTimerRef.current = window.setTimeout(() => {
      switchFeedbackTimerRef.current = null;
      if (mountedRef.current) {
        setJustSwitched(false);
      }
    }, 1600);
  };

  const preaccelSummary = resolvePreAccelSummary(
    runtime,
    globalPreAccel,
    preAccelEnabledConfig,
    hasEnabledRelay,
    uiLang
  );
  const isLocalBusy = switching || togglingPreAccel;
  const statusMeta = resolveStatusAccent(
    runtime,
    preaccelSummary,
    hasEnabledRelay,
    mascotState,
    isLocalBusy,
    dict,
    uiLang
  );
  const capsuleHealthState = resolveCapsuleHealthState(
    runtime,
    preaccelSummary,
    hasEnabledRelay
  );
  const themeMeta = resolveThemeDisplay(resolvedTheme, themeMode, uiLang);
  const isSingleMode = runtime.route_mode === "single";
  const displayNodeName =
    runtime.active_node_name?.trim() ||
    runtime.active_group_name?.trim() ||
    (isZh ? "待选节点" : "No Node");
  const displayGroupName =
    runtime.active_group_name?.trim() || (isZh ? "默认分组" : "Default Group");

  const activeGroupForLatency =
    groups.find((g) => g.id === runtime.active_group_id) ?? null;
  const activeNodeIdForLatency = isSingleMode
    ? runtime.active_node_id || ""
    : runtime.active_node_id || activeGroupForLatency?.active_node_id || "";
  const activeNodeProbe = activeNodeIdForLatency
    ? probes[activeNodeIdForLatency]
    : undefined;
  const activeHealthHint = activeNodeIdForLatency
    ? runtime.node_health_hints?.[activeNodeIdForLatency]
    : undefined;
  const runtimeFallbackLatencyMs =
    typeof runtime.active_node_latency_ms === "number" &&
    Number.isFinite(runtime.active_node_latency_ms) &&
    runtime.active_node_latency_ms > 0
      ? runtime.active_node_latency_ms
      : null;
  const rawResolvedActiveLatency = resolveNodeDisplayLatency(
    activeNodeProbe,
    activeHealthHint
  );
  const resolvedActiveLatency: ResolvedNodeLatency =
    rawResolvedActiveLatency.state === "untested" &&
    rawResolvedActiveLatency.source === "none" &&
    runtimeFallbackLatencyMs !== null
      ? {
          latencyMs: runtimeFallbackLatencyMs,
          ok: true,
          source: "probe",
          state: "healthy",
          isProbation: false,
          isDegraded: false,
        }
      : rawResolvedActiveLatency;
  const liveLatencyMs = resolvedActiveLatency.latencyMs;
  const capsuleLatencyTooltip = (() => {
    const tipKey = getLatencyTooltipKey(resolvedActiveLatency);
    const base =
      tipKey === "probeHot"
        ? dict.latency.probeHotTooltip
        : tipKey === "healthCold"
          ? dict.latency.healthColdTooltip
          : tipKey === "failed"
            ? dict.latency.failedTooltip
            : dict.latency.untestedTooltip;
    const tags: string[] = [];
    if (resolvedActiveLatency.source === "probe") {
      tags.push(dict.latency.sourceProbeShort);
    } else if (resolvedActiveLatency.source === "health") {
      tags.push(dict.latency.sourceHealthShort);
    }
    if (resolvedActiveLatency.isProbation) tags.push(dict.latency.probationBadge);
    if (resolvedActiveLatency.isDegraded) tags.push(dict.latency.degradedBadge);
    return tags.length > 0 ? `${base} (${tags.join(" · ")})` : base;
  })();

  // Adaptive breakpoints compatible with 280..560 x 56..140.
  // Deduct the 5th PinOff button (~28px) when docked so the center slot never overflows into action buttons.
  const dockPenaltyPx = dockEdge ? 28 : 0;
  const effectiveWidth = Math.max(0, boxSize.w - dockPenaltyPx);
  const isCompactWidth = effectiveWidth < 328;
  const isUltraNarrowDocked = effectiveWidth < 270;
  const showLatencyChip = effectiveWidth >= 332;
  const isTallLayout = boxSize.h >= 82;

  // Strictly match `src-tauri/src/tray.rs::TrayIconMode::AutoAc`:
  // - idle | ok => Pack A (cream cloud cat)
  // - preaccel | warn | error => Pack C (starry neko)
  // Never force Pack C based on theme (`midnight-blue`).
  const useStarryIcon =
    trayIconMode === "always_c" ||
    (trayIconMode === "auto_ac" &&
      (capsuleHealthState === "preaccel" ||
        capsuleHealthState === "warn" ||
        capsuleHealthState === "error"));

  const usePixelIcon = trayIconMode === "always_pixel";
  const iconSrc = useStarryIcon
    ? "./icons/icon_c_starry_neko.png"
    : "./icons/icon_a_cream_cat.png";

  const capsuleMascotState: MascotState = (() => {
    if (capsuleHealthState === "error" || capsuleHealthState === "warn") {
      return "approval";
    }
    if (
      runtime.probing_active ||
      (hasEnabledRelay && preaccelSummary.verifyState === "probing") ||
      mascotState === "searching"
    ) {
      return "searching";
    }
    if (
      switching ||
      togglingPreAccel ||
      runtime.switching_active ||
      mascotState === "thinking"
    ) {
      return "thinking";
    }
    if (
      mascotState === "typing" ||
      (runtime.running && traffic.up_bps + traffic.down_bps > 512 * 1024)
    ) {
      return "typing";
    }
    if (justSwitched || mascotState === "complete") {
      return "complete";
    }
    return "idle";
  })();

  const dotPulseClass =
    statusMeta.pulse === "alert"
      ? "cc-capsule-dot-alert"
      : statusMeta.pulse === "work"
        ? "cc-capsule-dot-work"
        : "";

  const statusBadgeClass = (tone: CapsuleBadgeTone): string => {
    switch (tone) {
      case "red":
        return "border-[var(--red)]/55 bg-[var(--red-soft)] text-[var(--red)]";
      case "amber":
        return "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)]";
      case "sky":
        return "border-[var(--sky)]/50 bg-[var(--sky-soft)] text-[var(--sky)]";
      case "green":
        return "border-[var(--green)]/50 bg-[var(--green-soft)] text-[var(--green)]";
      default:
        return "border-[var(--accent)]/50 bg-[var(--accent-soft)] text-[var(--accent)]";
    }
  };

  const handleSwitchNextBest = async () => {
    if (switching) return;
    setSwitching(true);
    try {
      if (isSingleMode) {
        const res = await catcloudApi.switchNextBestNode("single");
        const latestRt = await catcloudApi.getRuntimeInfo().catch(() => null);
        if (latestRt) {
          appActions.syncRuntime(latestRt);
        } else {
          const curRt = appStore.getState().runtime;
          appActions.syncRuntime({
            ...curRt,
            route_mode: "single",
            active_node_id: res.active_node_id,
            active_node_name: res.active_node_name,
            active_node_region: res.active_node_region,
            active_node_latency_ms: res.latency_ms,
            active_node_up_mbps: res.up_mbps,
          });
        }
        appActions.showToast(`已切至 ${res.active_node_name}`, "ok");
        triggerSwitchedFeedback();
        return;
      }

      const groupId = runtime.active_group_id || groups[0]?.id || "";
      if (!groupId) {
        appActions.showToast("暂无可用分组，请先在主窗口创建", "warn");
        return;
      }
      const res = await catcloudApi.switchNextBestNode(groupId);
      const curState = appStore.getState();
      appActions.syncRuntime({
        ...curState.runtime,
        active_group_id: res.group_id,
        active_node_id: res.active_node_id,
        active_node_name: res.active_node_name,
        active_node_region: res.active_node_region,
        active_node_latency_ms: res.latency_ms,
        active_node_up_mbps: res.up_mbps,
      });
      appActions.syncGroups(
        curState.groups.map((g) =>
          g.id === res.group_id ? { ...g, active_node_id: res.active_node_id } : g
        )
      );
      appActions.showToast(
        `已切至 ${res.active_node_name}${res.closed_connections > 0 ? `（断 ${res.closed_connections} 旧连）` : ""}`,
        "ok"
      );
      triggerSwitchedFeedback();
    } catch (err) {
      appActions.showToast(`切下一优失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      if (mountedRef.current) {
        setSwitching(false);
      }
    }
  };

  const handleTogglePreAccel = async () => {
    if (togglingPreAccel) return;
    setTogglingPreAccel(true);
    try {
      await appActions.togglePreAccel();
    } finally {
      if (mountedRef.current) {
        setTogglingPreAccel(false);
      }
    }
  };

  const handleCloseCapsule = async () => {
    if (isTauri) {
      try {
        await catcloudApi.toggleCapsuleWindow();
      } catch (err) {
        appActions.showToast(`关闭悬浮小窗失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }
    appActions.showToast("已关闭悬浮小窗（预览已返回主窗）", "info");
    await appActions.showMainFromCapsule();
  };

  const stopBtnDragProp = (e: ReactMouseEvent | ReactPointerEvent) => {
    e.stopPropagation();
  };

  // Source-aware hover hints (never overlap the hovered element itself)
  const avatarHint: CapsuleHoverHint = {
    title: `${dict.common.appName} · ${statusMeta.label}`,
    desc: dockEdge
      ? isZh
        ? `${DOCK_EDGE_LABELS[dockEdge]}中 · 拖离边缘或点解除钮取消贴边`
        : `Docked (${dockEdge}) · Drag away or click undock`
      : preaccelSummary.enabled
        ? `${preaccelSummary.detailText}${themeMeta.autoSuffix}`
        : isZh
          ? `拖动可移动，拖出屏幕边缘松手自动收起 · ${themeMeta.label}${themeMeta.autoSuffix}`
          : `Drag to move; drop past edge to dock · ${themeMeta.label}${themeMeta.autoSuffix}`,
    placement: "full",
  };

  const modeHint: CapsuleHoverHint = {
    title: isSingleMode
      ? isZh
        ? "单节点直选"
        : "Single Node"
      : dict.nav.groups,
    desc: isSingleMode ? displayNodeName : displayGroupName,
    placement: "row2",
  };

  const proxyHint: CapsuleHoverHint = {
    title: `${dict.home.systemProxy}: ${runtime.system_proxy_enabled ? dict.common.on : dict.common.off}`,
    desc: isZh ? "接管浏览器等常用软件" : "Routes browser & desktop apps",
    placement: "row1",
  };

  const tunHint: CapsuleHoverHint = runtime.tun_needs_elevation
    ? {
        title: dict.home.tunNeedsAdminHover,
        desc: isZh ? "请打开主窗口一键提权生效" : "Open main window to elevate & enable",
        placement: "row1",
      }
    : {
        title: `${dict.home.tunMode}: ${runtime.tun_enabled ? dict.common.on : dict.common.off}`,
        desc: isZh ? "接管桌面与终端全部流量" : "Routes all system & CLI traffic",
        placement: "row1",
      };

  const preAccelHint: CapsuleHoverHint = togglingPreAccel
    ? {
        title: isZh ? "正在切换国内提速…" : `Switching ${dict.home.preaccel}…`,
        desc: isZh ? "正在同步中转与全机加速状态" : "Syncing relay & global tunnel state",
        placement: "full",
      }
    : preaccelSummary.enabled
      ? {
          title: `${dict.home.preaccel} (${hasEnabledRelay ? statusMeta.label : preaccelSummary.badgeText})`,
          desc: preaccelSummary.detailText,
          placement: "full",
        }
      : {
          title: `${dict.home.preaccel}: ${dict.common.off}`,
          desc: isZh
            ? "点击开启：猫云与其它代理软件一起走国内 443 提速"
            : "Click to enable domestic 443 boost",
          placement: "full",
        };

  const switchHint: CapsuleHoverHint = {
    title: switching
      ? isZh
        ? "正在切换更优节点…"
        : dict.capsule.probingNow
      : dict.home.switchNextNode,
    desc: isZh ? "自动切优并断开旧卡死连接" : "Switch to next best node & close stale conns",
    placement: "full",
  };

  const expandHint: CapsuleHoverHint = {
    title: isZh ? "展开主窗口" : dict.titleBar.restore,
    desc: isZh ? `回到${dict.common.appName}完整控制台` : `Return to ${dict.common.appName}`,
    placement: "full",
  };

  const closeHint: CapsuleHoverHint = {
    title: isZh ? "隐藏悬浮小窗" : `Hide ${dict.home.openCapsule}`,
    desc: isZh ? "代理继续在后台稳定运行" : "Proxy continues running in background",
    placement: "full",
  };

  const undockHint: CapsuleHoverHint = {
    title: isZh
      ? `取消${dockEdge ? DOCK_EDGE_LABELS[dockEdge] : "贴边"}`
      : "Undock Capsule",
    desc: isZh ? "点击恢复自由悬浮，也可拖离边缘解除" : "Restore floating position",
    placement: "full",
  };

  const clearHint = () => setHoveredHint(null);

  const ThemeGlyph =
    resolvedTheme === "light" ? Sun : resolvedTheme === "warm-dark" ? Sunset : Moon;

  const avatarDimClass = isTallLayout ? "h-11 w-11" : "h-9 w-9";
  const btnDimClass = isTallLayout
    ? "h-7 w-7"
    : isCompactWidth
      ? "h-[22px] w-[22px]"
      : "h-[25px] w-[25px]";
  const shellRadiusClass = isTallLayout ? "rounded-[24px]" : "rounded-full";

  const isPreAccelVisuallyOn = preaccelSummary.enabled && hasEnabledRelay;
  const isPreAccelSolidGold =
    isPreAccelVisuallyOn &&
    preaccelSummary.tone !== "amber" &&
    (preaccelSummary.proxyActive || preaccelSummary.realWinDivertActive);
  const isFullHintActive = hoveredHint?.placement === "full";
  const isRow1HintActive = hoveredHint?.placement === "row1";
  const isRow2HintActive = hoveredHint?.placement === "row2";
  const showPriorityStatusBadge = Boolean(
    statusMeta.badge &&
      (statusMeta.pulse !== "none" ||
        runtime.proxy_mode === "direct" ||
        effectiveWidth >= 344)
  );
  const showLatencyAlongside =
    showLatencyChip &&
    !isUltraNarrowDocked &&
    (liveLatencyMs !== null || resolvedActiveLatency.state === "failed") &&
    (!showPriorityStatusBadge || effectiveWidth >= 400);

  const capsulePill = (
    <div
      ref={shellRef}
      onPointerDown={handleShellPointerDown}
      onPointerMove={handleShellPointerMove}
      onPointerUp={handleShellPointerUpOrCancel}
      onPointerCancel={handleShellPointerUpOrCancel}
      onLostPointerCapture={handleShellLostPointerCapture}
      onMouseEnter={handleExpandedPointerEnter}
      onMouseLeave={handleExpandedPointerLeave}
      className={`cc-capsule-shell relative flex h-full w-full select-none items-center border text-[var(--text)] transition-[border-radius,border-color,background-image] duration-150 ${shellRadiusClass} ${
        isTallLayout ? "gap-2.5 px-2.5 py-2" : "gap-1.5 px-2"
      }`}
    >
      {/* 8-direction invisible resize handles (never trigger drag or Aero Snap) */}
      {isTauri && (
        <>
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("North", e)}
            className="absolute inset-x-3 top-0 z-20 h-[4px] cursor-ns-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("South", e)}
            className="absolute inset-x-3 bottom-0 z-20 h-[4px] cursor-ns-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("West", e)}
            className="absolute inset-y-2.5 left-0 z-20 w-[4px] cursor-ew-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("East", e)}
            className="absolute inset-y-2.5 right-0 z-20 w-[4px] cursor-ew-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("NorthWest", e)}
            className="absolute left-0 top-0 z-30 h-[8px] w-[8px] cursor-nwse-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("NorthEast", e)}
            className="absolute right-0 top-0 z-30 h-[8px] w-[8px] cursor-nesw-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("SouthWest", e)}
            className="absolute bottom-0 left-0 z-30 h-[8px] w-[8px] cursor-nesw-resize"
            aria-hidden="true"
          />
          <div
            data-capsule-no-drag="true"
            onPointerDown={stopBtnDragProp}
            onMouseDown={(e) => handleStartResize("SouthEast", e)}
            className="absolute bottom-0 right-0 z-30 h-[8px] w-[8px] cursor-nwse-resize"
            aria-hidden="true"
          />
        </>
      )}

      {/* A / C / Live Pixel Mascot avatar with controlled working/alert pulse dot */}
      <div
        className={`relative flex shrink-0 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] ${avatarDimClass}`}
        onMouseEnter={() => setHoveredHint(avatarHint)}
        onMouseLeave={clearHint}
        aria-label={`${avatarHint.title}：${avatarHint.desc}`}
      >
        {usePixelIcon ? (
          <MascotSprite
            state={capsuleMascotState}
            scale={1}
            maxSize={isTallLayout ? 34 : 26}
            className="pointer-events-none"
            title={statusMeta.label}
          />
        ) : (
          <img
            src={iconSrc}
            alt={`${dict.common.appName} · ${statusMeta.label}`}
            className={`pointer-events-none rounded-full object-cover ${avatarDimClass}`}
            draggable={false}
          />
        )}
        <span
          className={`pointer-events-none absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)] ${dotPulseClass}`}
          style={{ backgroundColor: statusMeta.color, color: statusMeta.color }}
        />
      </div>

      {/* Center info column with clean non-overlapping 100% opaque hover hint replacement */}
      <div className="relative flex min-w-0 flex-1 flex-col justify-center overflow-hidden">
        {/* Row 1: Mode badge + Active Node Name + Concise Status Badge / Live Latency */}
        <div className="relative flex min-w-0 items-center gap-1 overflow-hidden">
          <div
            className={`flex min-w-0 flex-1 items-center gap-1 overflow-hidden ${
              isFullHintActive || isRow1HintActive ? "invisible" : ""
            }`}
          >
            <span
              data-capsule-no-drag="true"
              onMouseDown={stopBtnDragProp}
              onPointerDown={stopBtnDragProp}
              onMouseEnter={() => setHoveredHint(modeHint)}
              onMouseLeave={clearHint}
              className={`shrink-0 rounded border px-1 py-[1px] text-[9px] font-medium leading-none ${
                isSingleMode
                  ? "border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--sky)]/40 bg-[var(--sky-soft)] text-[var(--sky)]"
              }`}
              aria-label={`${modeHint.title}：${modeHint.desc}`}
            >
              {isSingleMode ? (isZh ? "单节点" : "1x") : isZh ? "组" : "Grp"}
            </span>
            <span
              className={`min-w-0 flex-1 truncate font-semibold leading-tight text-[var(--text)] ${
                isTallLayout ? "text-[12px]" : "text-[11px]"
              }`}
            >
              {displayNodeName}
            </span>
            {showPriorityStatusBadge && statusMeta.badge && (
              <span
                className={`pointer-events-none shrink-0 rounded border px-1 py-[1px] text-[8.5px] font-semibold leading-none ${statusBadgeClass(
                  statusMeta.badge.tone
                )}`}
              >
                {statusMeta.badge.label}
              </span>
            )}
            {showLatencyAlongside &&
              (liveLatencyMs !== null || resolvedActiveLatency.state === "failed") && (
                <span
                  title={capsuleLatencyTooltip}
                  className={`cc-mono cc-tabular shrink-0 rounded bg-[var(--card)] px-1 py-[1px] text-[9px] font-semibold ${
                    resolvedActiveLatency.state === "failed"
                      ? "text-[var(--red)]"
                      : resolvedActiveLatency.isDegraded
                        ? "text-[var(--amber)]"
                        : resolveLatencyToneClass(liveLatencyMs ?? 0)
                  }`}
                >
                  {liveLatencyMs !== null
                    ? `${Math.round(liveLatencyMs)}ms`
                    : dict.latency.timeoutShort}
                </span>
              )}
          </div>

          {isRow1HintActive && hoveredHint && (
            <div
              aria-live="polite"
              className="pointer-events-none absolute inset-0 z-10 flex items-center gap-1 overflow-hidden rounded bg-[var(--surface)] px-1"
            >
              <span className="max-w-[55%] shrink-0 truncate text-[10px] font-semibold leading-none text-[var(--text)]">
                {hoveredHint.title}
              </span>
              <span className="min-w-0 flex-1 truncate text-[9.5px] leading-none text-[var(--text-secondary)]">
                · {hoveredHint.desc}
              </span>
            </div>
          )}
        </div>

        {/* Row 2: Live Up/Down Rates + Concise Proxy / TUN Status Badges */}
        <div
          className={`relative flex min-w-0 items-center justify-between gap-1 overflow-hidden leading-none ${
            isTallLayout ? "mt-1.5" : "mt-1"
          }`}
        >
          <div
            className={`flex min-w-0 flex-1 items-center justify-between gap-1 overflow-hidden ${
              isFullHintActive || isRow2HintActive ? "invisible" : ""
            }`}
          >
            <div
              className={`cc-mono cc-tabular flex min-w-0 shrink items-center gap-1 overflow-hidden whitespace-nowrap tracking-tight ${
                isTallLayout
                  ? "text-[11px]"
                  : isUltraNarrowDocked
                    ? "text-[8px]"
                    : isCompactWidth
                      ? "text-[8.5px]"
                      : "text-[9px]"
              }`}
            >
              <span className="pointer-events-none truncate text-[var(--coral)]">
                ↑{formatCompactRate(traffic.up_bps)}
              </span>
              <span className="pointer-events-none truncate text-[var(--sky)]">
                ↓{formatCompactRate(traffic.down_bps)}
              </span>
            </div>

            <div className="flex shrink-0 items-center gap-[3px]">
              <span
                data-capsule-no-drag="true"
                onMouseDown={stopBtnDragProp}
                onPointerDown={stopBtnDragProp}
                onMouseEnter={() => setHoveredHint(proxyHint)}
                onMouseLeave={clearHint}
                className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                  isCompactWidth
                    ? "px-[3px] py-[1px] text-[8px]"
                    : "px-[3.5px] py-[1.5px] text-[8px]"
                } ${
                  runtime.system_proxy_enabled
                    ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)]"
                }`}
                aria-label={`${proxyHint.title}：${proxyHint.desc}`}
              >
                {isZh ? (isCompactWidth ? "代" : "代理") : isCompactWidth ? "P" : "Proxy"}
              </span>
              <span
                data-capsule-no-drag="true"
                onMouseDown={stopBtnDragProp}
                onPointerDown={stopBtnDragProp}
                onMouseEnter={() => setHoveredHint(tunHint)}
                onMouseLeave={clearHint}
                className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                  isCompactWidth
                    ? "px-[3px] py-[1px] text-[8px]"
                    : "px-[3.5px] py-[1.5px] text-[8px]"
                } ${
                  runtime.tun_enabled
                    ? "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]"
                    : runtime.tun_needs_elevation
                      ? "border-[var(--amber)]/65 bg-[var(--amber-soft)] text-[var(--amber)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)]"
                }`}
                aria-label={`${tunHint.title}：${tunHint.desc}`}
              >
                {isZh ? (isCompactWidth ? "卡" : "网卡") : "TUN"}
              </span>
            </div>
          </div>

          {isRow2HintActive && hoveredHint && (
            <div
              aria-live="polite"
              className="pointer-events-none absolute inset-0 z-10 flex items-center gap-1 overflow-hidden rounded bg-[var(--surface)] px-1"
            >
              <span className="max-w-[55%] shrink-0 truncate text-[9.5px] font-semibold leading-none text-[var(--text)]">
                {hoveredHint.title}
              </span>
              <span className="min-w-0 flex-1 truncate text-[9px] leading-none text-[var(--text-secondary)]">
                · {hoveredHint.desc}
              </span>
            </div>
          )}
        </div>

        {/* Row 3 (auto-revealed when dragged taller >= 82px) */}
        {isTallLayout && (
          <div
            className={`mt-1.5 flex min-w-0 items-center justify-between gap-2 overflow-hidden text-[10px] leading-none text-[var(--muted)] ${
              isFullHintActive ? "invisible" : ""
            }`}
          >
            <span className="pointer-events-none min-w-0 flex-1 truncate">
              {isSingleMode ? (isZh ? "单节点模式" : "Single Node") : displayGroupName} ·{" "}
              {traffic.connections} {isZh ? "连接" : "conns"}
            </span>
            <span className="pointer-events-none inline-flex shrink-0 items-center gap-0.5 text-[9.5px] text-[var(--accent)]">
              <ThemeGlyph className="h-2.5 w-2.5" />
              {themeMeta.shortLabel}
            </span>
          </div>
        )}

        {/* Full center-slot solid opaque replacement for avatar & right action button hovers */}
        {isFullHintActive && hoveredHint && (
          <div
            aria-live="polite"
            className="pointer-events-none absolute inset-0 z-10 flex flex-col justify-center overflow-hidden rounded-lg border border-[var(--line)]/85 bg-[var(--surface)] px-1.5"
          >
            <div className="truncate text-[10.5px] font-semibold leading-tight text-[var(--text)]">
              {hoveredHint.title}
            </div>
            <div className="mt-0.5 truncate text-[9.5px] leading-tight text-[var(--text-secondary)]">
              {hoveredHint.desc}
            </div>
          </div>
        )}
      </div>

      {/* Right circular action cluster: [PinOff?] -> [Zap PreAccel] -> [ArrowRightLeft Switch] -> [Maximize2] -> [X] */}
      <div className="relative z-20 flex shrink-0 items-center gap-[2.5px]">
        {dockEdge && (
          <button
            type="button"
            data-capsule-no-drag="true"
            onMouseDown={stopBtnDragProp}
            onPointerDown={stopBtnDragProp}
            onClick={() => void undockCapsule(true)}
            onMouseEnter={() => setHoveredHint(undockHint)}
            onMouseLeave={clearHint}
            onFocus={() => setHoveredHint(undockHint)}
            onBlur={clearHint}
            className={`inline-flex cursor-pointer items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)]/90 text-[var(--muted)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)] hover:text-[var(--accent)] ${btnDimClass}`}
            aria-label={undockHint.title}
          >
            <PinOff className="h-3 w-3" />
          </button>
        )}

        {/* Dedicated circular Domestic Pre-Accel toggle (bright gold solid when active, crisp gray when off) */}
        <button
          type="button"
          data-capsule-no-drag="true"
          disabled={togglingPreAccel}
          onMouseDown={stopBtnDragProp}
          onPointerDown={stopBtnDragProp}
          onClick={() => void handleTogglePreAccel()}
          onMouseEnter={() => setHoveredHint(preAccelHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(preAccelHint)}
          onBlur={clearHint}
          aria-pressed={preaccelSummary.enabled}
          aria-label={`${preAccelHint.title}：${preAccelHint.desc}`}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border transition-colors disabled:opacity-60 ${btnDimClass} ${
            isPreAccelSolidGold
              ? "border-[var(--amber)] bg-[var(--amber-soft)] text-[var(--amber)] shadow-[0_0_0_1px_rgba(231,184,110,0.28)]"
              : isPreAccelVisuallyOn
                ? "border-[var(--accent)]/75 bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
          }`}
        >
          {togglingPreAccel ||
          (isPreAccelVisuallyOn &&
            (preaccelSummary.installState === "downloading" ||
              preaccelSummary.installState === "verifying" ||
              preaccelSummary.verifyState === "probing")) ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Zap
              className="h-3 w-3"
              fill={isPreAccelSolidGold ? "currentColor" : "none"}
              strokeWidth={isPreAccelVisuallyOn ? 2.2 : 1.9}
            />
          )}
        </button>

        {/* Dedicated circular Switch Next Best Node button (ArrowRightLeft — zero icon collision with Zap) */}
        <button
          type="button"
          data-capsule-no-drag="true"
          disabled={switching}
          onMouseDown={stopBtnDragProp}
          onPointerDown={stopBtnDragProp}
          onClick={() => void handleSwitchNextBest()}
          onMouseEnter={() => setHoveredHint(switchHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(switchHint)}
          onBlur={clearHint}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border transition-colors disabled:opacity-60 ${btnDimClass} ${
            justSwitched
              ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)]"
              : "border-[var(--line)] bg-[var(--card)] text-[var(--accent)] hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
          }`}
          aria-label={switchHint.title}
        >
          {switching ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : justSwitched ? (
            <Check className="h-3 w-3" />
          ) : (
            <ArrowRightLeft className="h-3 w-3" />
          )}
        </button>

        <button
          type="button"
          data-capsule-no-drag="true"
          onMouseDown={stopBtnDragProp}
          onPointerDown={stopBtnDragProp}
          onClick={() => void appActions.showMainFromCapsule()}
          onMouseEnter={() => setHoveredHint(expandHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(expandHint)}
          onBlur={clearHint}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] ${btnDimClass}`}
          aria-label={expandHint.title}
        >
          <Maximize2 className="h-3 w-3" />
        </button>

        <button
          type="button"
          data-capsule-no-drag="true"
          onMouseDown={stopBtnDragProp}
          onPointerDown={stopBtnDragProp}
          onClick={() => void handleCloseCapsule()}
          onMouseEnter={() => setHoveredHint(closeHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(closeHint)}
          onBlur={clearHint}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] transition-colors hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)] ${btnDimClass}`}
          aria-label={closeHint.title}
        >
          <X className="h-3 w-3" />
        </button>
      </div>
    </div>
  );

  const dockRateLabel = (() => {
    const peakDown = traffic.down_bps;
    const peakUp = traffic.up_bps;
    if (peakDown >= 1024 || peakUp >= 1024) {
      return peakDown >= peakUp
        ? `↓${formatCompactRate(peakDown).replace("/s", "")}`
        : `↑${formatCompactRate(peakUp).replace("/s", "")}`;
    }
    if (statusMeta.badge) return statusMeta.badge.label;
    if (
      preaccelSummary.proxyActive &&
      isPreAccelVisuallyOn &&
      preaccelSummary.tone === "green"
    ) {
      return dict.nav.preaccelActiveBadge;
    }
    if (!preaccelSummary.proxyActive && isPreAccelVisuallyOn && preaccelSummary.realWinDivertActive) {
      return preaccelSummary.verifyState === "probing"
        ? dict.nav.preaccelProbingBadge
        : dict.nav.preaccelActiveBadge;
    }
    if (!preaccelSummary.proxyActive && preaccelSummary.enabled) {
      if (!hasEnabledRelay) {
        return dict.common.off;
      }
      if (
        preaccelSummary.installState === "downloading" ||
        preaccelSummary.installState === "verifying"
      ) {
        return isZh ? "准备中" : "Setup";
      }
      if (preaccelSummary.installState === "need_elevation") return isZh ? "需提权" : "Admin";
      if (preaccelSummary.verifyState === "probing") return dict.nav.preaccelProbingBadge;
      if (preaccelSummary.verifyState === "degraded") return dict.nav.preaccelDegradedBadge;
      return dict.titleBar.standby;
    }
    if (runtime.running) return isZh ? "运行中" : "Active";
    return dict.common.appName;
  })();

  const collapsedDockBar = dockEdge ? (
    (() => {
      const isHorizontalDock = dockEdge === "top" || dockEdge === "bottom";
      const DockArrow =
        dockEdge === "top"
          ? ChevronDown
          : dockEdge === "bottom"
            ? ChevronUp
            : dockEdge === "left"
              ? ChevronRight
              : ChevronLeft;
      const edgeRadiusClass =
        dockEdge === "top"
          ? "rounded-b-[10px] rounded-t-[2px] border-t-0"
          : dockEdge === "bottom"
            ? "rounded-t-[10px] rounded-b-[2px] border-b-0"
            : dockEdge === "left"
              ? "rounded-r-[10px] rounded-l-[2px] border-l-0"
              : "rounded-l-[10px] rounded-r-[2px] border-r-0";

      return (
        <button
          type="button"
          onMouseEnter={handleDockHandleMouseEnter}
          onMouseLeave={handleDockHandleMouseLeave}
          onClick={(ev) => {
            if (ev.detail >= 2) {
              void undockCapsule(true);
            } else {
              void expandFromDock(dockEdge);
            }
          }}
          onContextMenu={(ev) => {
            ev.preventDefault();
            void undockCapsule(true);
          }}
          title={
            isZh
              ? `悬停或点击展开悬浮小窗 · 双击/右键或拖离边缘取消贴边（${statusMeta.label}）`
              : `Hover or click to expand ${dict.home.openCapsule} · Double-click/Right-click to undock (${statusMeta.label})`
          }
          aria-label={`${dict.home.openCapsule} (${statusMeta.label})`}
          className={`cc-capsule-shell flex h-full w-full cursor-pointer select-none items-center justify-center border text-[var(--text)] transition-colors hover:border-[var(--accent)] ${edgeRadiusClass} ${
            isHorizontalDock ? "flex-row gap-1.5 px-2.5" : "flex-col gap-1.5 py-2.5"
          }`}
        >
          <span
            className={`relative h-2 w-2 shrink-0 rounded-full ${dotPulseClass}`}
            style={{ backgroundColor: statusMeta.color, color: statusMeta.color }}
            aria-hidden="true"
          />
          {isHorizontalDock ? (
            <>
              <span className="cc-mono cc-tabular truncate text-[9.5px] font-medium leading-none text-[var(--text-secondary)]">
                {dockRateLabel}
              </span>
              <DockArrow className="h-3 w-3 shrink-0 text-[var(--muted)]" aria-hidden="true" />
            </>
          ) : (
            <>
              <DockArrow className="h-3 w-3 shrink-0 text-[var(--muted)]" aria-hidden="true" />
              <span
                className="h-4 w-[2px] rounded-full bg-[var(--muted)]/45"
                aria-hidden="true"
              />
            </>
          )}
        </button>
      );
    })()
  ) : null;

  if (isTauri) {
    return (
      <div
        className={`flex h-screen w-screen items-center justify-center overflow-hidden bg-transparent ${
          dockCollapsed ? "p-0" : "p-[2px]"
        }`}
      >
        {dockCollapsed && collapsedDockBar ? collapsedDockBar : capsulePill}
      </div>
    );
  }

  const previewDockBox =
    dockCollapsed && dockEdge ? getDockPillSize(dockEdge) : previewSize;

  return (
    <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[var(--bg)] p-6">
      <div className="text-center">
        <div className="text-xs font-semibold text-[var(--text)]">
          {dict.home.openCapsule} ({previewDockBox.w} × {previewDockBox.h} · {themeMeta.label}
          {themeMeta.autoSuffix}
          {dockEdge
            ? ` · ${DOCK_EDGE_LABELS[dockEdge]}${dockCollapsed ? "已收起" : "展开中"}`
            : ""}
          )
        </div>
        <div className="mt-1 text-[11px] text-[var(--muted)]">
          {statusMeta.label} · {isSingleMode ? (isZh ? "单节点" : "Single") : displayGroupName} ·{" "}
          {dict.home.systemProxy}: {runtime.system_proxy_enabled ? dict.common.on : dict.common.off}{" "}
          · {dict.home.tunMode}:{" "}
          {runtime.tun_enabled
            ? dict.common.on
            : runtime.tun_needs_elevation
              ? isZh
                ? "未生效（需管理员）"
                : "Needs admin"
              : dict.common.off}{" "}
          ·{" "}
          {dict.home.preaccel}:{" "}
          {preaccelSummary.enabled
            ? hasEnabledRelay
              ? dict.common.on
              : preaccelSummary.badgeText
            : dict.common.off}
        </div>
      </div>

      <div
        style={{ width: `${previewDockBox.w}px`, height: `${previewDockBox.h}px` }}
        className={`flex items-center justify-center bg-transparent transition-[width,height] duration-150 ${
          dockCollapsed ? "p-0" : "p-[2px]"
        }`}
      >
        {dockCollapsed && collapsedDockBar ? collapsedDockBar : capsulePill}
      </div>

      <div className="flex flex-wrap items-center justify-center gap-2">
        {(
          [
            { label: "紧凑 288×58", w: 288, h: 58 },
            { label: "默认 364×64", w: 364, h: 64 },
            { label: "舒展 430×96", w: 430, h: 96 },
          ] as const
        ).map((preset) => (
          <button
            key={preset.label}
            type="button"
            onClick={() => {
              clearDockTimers();
              dockEdgeRef.current = null;
              dockCollapsedRef.current = false;
              setDockEdge(null);
              setDockCollapsed(false);
              setPreviewSize({ w: preset.w, h: preset.h });
            }}
            className={`rounded-lg border px-2.5 py-1 text-[11px] transition-colors ${
              !dockCollapsed && previewSize.w === preset.w && previewSize.h === preset.h
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            {preset.label}
          </button>
        ))}

        {(
          [
            { edge: "top", label: "贴顶收起" },
            { edge: "bottom", label: "贴底收起" },
            { edge: "left", label: "贴左收起" },
            { edge: "right", label: "贴右收起" },
          ] as const
        ).map((item) => (
          <button
            key={item.edge}
            type="button"
            onClick={() => void collapseToDock(item.edge)}
            className={`rounded-lg border px-2.5 py-1 text-[11px] transition-colors ${
              dockEdge === item.edge
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            {item.label}
          </button>
        ))}

        {dockEdge && (
          <button
            type="button"
            onClick={() => void undockCapsule(false)}
            className="rounded-lg border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--amber)]"
          >
            取消贴边
          </button>
        )}

        <button
          type="button"
          onClick={() => void appActions.showMainFromCapsule()}
          className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1 text-[11px] font-medium text-[var(--text)] hover:border-[var(--accent)]"
        >
          返回主窗口视图
        </button>
      </div>
    </div>
  );
}
