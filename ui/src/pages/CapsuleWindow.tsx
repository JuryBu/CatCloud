import {
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
import type { MouseEvent as ReactMouseEvent } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  catcloudApi,
  formatErrorMessage,
  type ThemeMode,
} from "../api/tauri";
import { MascotSprite } from "../components/MascotSprite";
import {
  appActions,
  appStore,
  useAppSelector,
  useLatestTraffic,
  type ResolvedTheme,
} from "../store/appStore";

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

interface PhysicalRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

const CAPSULE_SIZE_STORAGE_KEY = "catcloud.capsule.size.v1";
const CAPSULE_DEFAULT_W = 344;
const CAPSULE_DEFAULT_H = 64;
const CAPSULE_MIN_W = 280;
const CAPSULE_MAX_W = 560;
const CAPSULE_MIN_H = 56;
const CAPSULE_MAX_H = 140;

const DOCK_SNAP_THRESHOLD = 14;
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

function computeEdgeDistances(winRect: PhysicalRect, bounds: PhysicalRect): Record<DockEdge, number> {
  return {
    top: winRect.y - bounds.y,
    bottom: bounds.y + bounds.height - (winRect.y + winRect.height),
    left: winRect.x - bounds.x,
    right: bounds.x + bounds.width - (winRect.x + winRect.width),
  };
}

function detectSnapEdge(
  winRect: PhysicalRect,
  bounds: PhysicalRect,
  scale: number
): DockEdge | null {
  const distances = computeEdgeDistances(winRect, bounds);
  const snapThresholdPx = DOCK_SNAP_THRESHOLD * scale;
  const priorityOrder: readonly DockEdge[] = ["top", "bottom", "left", "right"];
  let bestEdge: DockEdge | null = null;
  let bestDist = Infinity;
  for (const edge of priorityOrder) {
    const d = distances[edge];
    if (d <= snapThresholdPx && d < bestDist) {
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
} | null> {
  const { currentMonitor, getCurrentWindow } = await import("@tauri-apps/api/window");
  const win = getCurrentWindow();
  const [monitor, scaleFallback, outerPos, outerSize] = await Promise.all([
    currentMonitor(),
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

function resolveStatusAccent(
  status: string,
  standaloneGlobalPreAccel = false
): { color: string; label: string } {
  if (standaloneGlobalPreAccel) {
    return { color: "var(--accent)", label: "底层提速运行中" };
  }
  switch (status) {
    case "error":
      return { color: "var(--red)", label: "核心异常" };
    case "warn":
      return { color: "var(--amber)", label: "路线存在波动" };
    case "preaccel":
      return { color: "var(--accent)", label: "国内提速运行中" };
    case "ok":
      return { color: "var(--green)", label: "代理运行正常" };
    default:
      return { color: "var(--muted)", label: "待机中" };
  }
}

function resolveThemeDisplay(
  resolvedTheme: ResolvedTheme,
  themeMode: ThemeMode
): { label: string; shortLabel: string; autoSuffix: string } {
  const autoSuffix = themeMode === "auto_time" ? " · 按时间自动" : "";
  switch (resolvedTheme) {
    case "light":
      return { label: "晨曦浅色", shortLabel: "晨曦", autoSuffix };
    case "warm-dark":
      return { label: "深苔暖金", shortLabel: "暖金", autoSuffix };
    default:
      return { label: "午夜星蓝", shortLabel: "星蓝", autoSuffix };
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

interface CapsuleHoverHint {
  title: string;
  desc: string;
}

export function CapsuleWindow() {
  const isTauri = useAppSelector((s) => s.isTauri);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const groups = useAppSelector((s) => s.groups);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const trayIconMode = useAppSelector((s) => s.config.personalization.tray_icon_mode);
  const traffic = useLatestTraffic();

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
  const resizeGuardTimerRef = useRef<number | null>(null);
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
      if (resizeGuardTimerRef.current !== null) {
        window.clearTimeout(resizeGuardTimerRef.current);
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
        await win.setSize(new LogicalSize(pillSize.w, pillSize.h));
        await win.setPosition(
          new PhysicalPosition(Math.round(targetPos.x), Math.round(targetPos.y))
        );
        programmaticMoveUntilRef.current = Date.now() + 340;
      } catch {
        /* gracefully recover expanded size & minSize if OS window move/resize is rejected (e.g. restricted Wayland) */
        try {
          const exp = clampCapsuleSize(expandedSizeRef.current.w, expandedSizeRef.current.h);
          const { getCurrentWindow, LogicalSize } = await import("@tauri-apps/api/window");
          const win = getCurrentWindow();
          await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {
            /* ignore minSize restore failure */
          });
          await win.setSize(new LogicalSize(exp.w, exp.h)).catch(() => {
            /* ignore size restore failure */
          });
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

        if (rects) {
          const targetPhysW = Math.round(exp.w * rects.scale);
          const targetPhysH = Math.round(exp.h * rects.scale);
          const targetPos = computeAnchoredPosition(
            edge,
            targetPhysW,
            targetPhysH,
            rects.winRect,
            rects.bounds
          );
          await win.setPosition(
            new PhysicalPosition(Math.round(targetPos.x), Math.round(targetPos.y))
          );
        }
        await win.setSize(new LogicalSize(exp.w, exp.h));
        await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {
          /* ignore if platform ignores minSize restore */
        });

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
        await win.setMinSize(new LogicalSize(CAPSULE_MIN_W, CAPSULE_MIN_H)).catch(() => {
          /* ignore */
        });
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

  // Listen to native window move/resize events for 4-edge auto-dock, drag-out undock & external restore
  useEffect(() => {
    if (!isTauri) return;
    let disposed = false;
    let unlistenMoved: (() => void) | null = null;
    let unlistenResized: (() => void) | null = null;

    const evaluateDockAfterMoveSettle = async (seq: number) => {
      if (
        disposed ||
        !mountedRef.current ||
        dockOpBusyRef.current ||
        resizingRef.current ||
        dockCollapsedRef.current ||
        Date.now() < programmaticMoveUntilRef.current
      ) {
        return;
      }
      if (pointerDownRef.current) {
        pendingMoveEvalRef.current = true;
        return;
      }
      pendingMoveEvalRef.current = false;
      try {
        const rects = await readWindowAndMonitorPhysicalRects();
        if (
          !rects ||
          disposed ||
          !mountedRef.current ||
          moveSeqRef.current !== seq ||
          pointerDownRef.current ||
          dockOpBusyRef.current ||
          resizingRef.current ||
          dockCollapsedRef.current
        ) {
          return;
        }
        const { winRect, bounds, scale } = rects;
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
            const nextSnap = detectSnapEdge(winRect, bounds, scale);
            if (nextSnap && nextSnap !== curEdge) {
              expandedSizeRef.current = clampCapsuleSize(logicalW, logicalH);
              await collapseToDock(nextSnap);
            } else {
              dockEdgeRef.current = null;
              dockCollapsedRef.current = false;
              setDockEdge(null);
              setDockCollapsed(false);
            }
          }
          return;
        }

        const snapEdge = detectSnapEdge(winRect, bounds, scale);
        if (snapEdge) {
          expandedSizeRef.current = clampCapsuleSize(logicalW, logicalH);
          await collapseToDock(snapEdge);
        }
      } catch {
        /* gracefully ignore monitor/position query failures on unsupported window managers */
      }
    };

    const scheduleMoveSettle = () => {
      const seq = moveSeqRef.current;
      if (moveSettleTimerRef.current !== null) {
        window.clearTimeout(moveSettleTimerRef.current);
      }
      moveSettleTimerRef.current = window.setTimeout(() => {
        moveSettleTimerRef.current = null;
        void evaluateDockAfterMoveSettle(seq);
      }, DOCK_MOVE_SETTLE_DELAY_MS);
    };

    const handlePointerDown = (ev: MouseEvent | PointerEvent) => {
      if (ev.button !== 0) return;
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
      if (!pointerDownRef.current) return;
      pointerDownRef.current = false;
      if (pendingMoveEvalRef.current && !dockCollapsedRef.current && !resizingRef.current) {
        pendingMoveEvalRef.current = false;
        scheduleMoveSettle();
      }
    };

    const handlePointerMoveButtonsCheck = (ev: MouseEvent | PointerEvent) => {
      if (pointerDownRef.current && ev.buttons === 0) {
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
            if (
              disposed ||
              !mountedRef.current ||
              dockOpBusyRef.current ||
              !dockCollapsedRef.current
            ) {
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
    };
  }, [clearDockTimers, collapseToDock, isTauri]);

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
    const clearResizeFlag = () => {
      resizingRef.current = false;
      window.removeEventListener("mouseup", clearResizeFlag);
      window.removeEventListener("blur", clearResizeFlag);
      if (resizeGuardTimerRef.current !== null) {
        window.clearTimeout(resizeGuardTimerRef.current);
        resizeGuardTimerRef.current = null;
      }
    };
    window.addEventListener("mouseup", clearResizeFlag, { once: true });
    window.addEventListener("blur", clearResizeFlag, { once: true });
    if (resizeGuardTimerRef.current !== null) {
      window.clearTimeout(resizeGuardTimerRef.current);
    }
    resizeGuardTimerRef.current = window.setTimeout(clearResizeFlag, 1800);
    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().startResizeDragging(direction))
      .catch(() => {
        clearResizeFlag();
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

  const isProxyEnabled =
    runtime.running && (runtime.system_proxy_enabled || runtime.tun_enabled);
  const isGlobalPreAccelRunning = Boolean(
    runtime.global_preaccel_active || globalPreAccel.running
  );
  const effectiveGlobalMode = runtime.global_preaccel_mode ?? globalPreAccel.mode ?? "off";
  const effectiveGlobalPort =
    runtime.global_preaccel_socks_port ?? globalPreAccel.socks_port ?? null;
  const isPreAccelConfigOn = Boolean(runtime.preaccel_enabled ?? preAccelEnabledConfig);
  const isProxyPreAccelRunning = Boolean(
    isProxyEnabled && (runtime.preaccel_active || isPreAccelConfigOn)
  );
  const isStandaloneGlobalOnly = !isProxyEnabled && isGlobalPreAccelRunning;
  const isPreAccelOn =
    isProxyPreAccelRunning || isGlobalPreAccelRunning || isPreAccelConfigOn;

  const statusMeta = resolveStatusAccent(runtime.status, isStandaloneGlobalOnly);
  const themeMeta = resolveThemeDisplay(resolvedTheme, themeMode);
  const isSingleMode = runtime.route_mode === "single";
  const displayNodeName =
    runtime.active_node_name?.trim() || runtime.active_group_name?.trim() || "待选节点";
  const displayGroupName = runtime.active_group_name?.trim() || "默认分组";

  // Adaptive breakpoints based on live dragged capsule dimensions
  const isCompactWidth = boxSize.w < 308;
  const isCompactPreAccel =
    boxSize.w < 320 || (dockEdge !== null && boxSize.w < 368);
  const isWideWidth = boxSize.w >= 404;
  const isTallLayout = boxSize.h >= 82;

  // In auto_ac mode, follow both network status and day/night atmosphere so the capsule
  // visibly reflects daytime cream-cat vs nighttime/preaccel starry-neko changes.
  const useStarryIcon =
    trayIconMode === "always_c" ||
    (trayIconMode === "auto_ac" &&
      (isStandaloneGlobalOnly ||
        runtime.status === "preaccel" ||
        runtime.status === "warn" ||
        runtime.status === "error" ||
        resolvedTheme === "midnight-blue"));

  const usePixelIcon = trayIconMode === "always_pixel";
  const iconSrc = useStarryIcon
    ? "./icons/icon_c_starry_neko.png"
    : "./icons/icon_a_cream_cat.png";

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

  const avatarHint: CapsuleHoverHint = {
    title: `${statusMeta.label} · ${themeMeta.label}`,
    desc: dockEdge
      ? `${DOCK_EDGE_LABELS[dockEdge]}中 · 拖离边缘或点解除钮可取消贴边`
      : isStandaloneGlobalOnly
        ? `${
            effectiveGlobalMode === "windivert"
              ? "底层透明加速其它软件中"
              : effectiveGlobalPort
                ? `本地 443 通道 127.0.0.1:${effectiveGlobalPort}`
                : "底层提速运行中"
          }${themeMeta.autoSuffix}`
        : runtime.preaccel_active && runtime.preaccel_relay_name
          ? `国内提速 · ${runtime.preaccel_relay_name}${themeMeta.autoSuffix}`
          : `拖动可移动，贴屏幕边缘自动收起${themeMeta.autoSuffix}`,
  };

  const modeHint: CapsuleHoverHint = {
    title: isSingleMode ? "单节点直选" : "智能多选组",
    desc: isSingleMode ? displayNodeName : displayGroupName,
  };

  const proxyHint: CapsuleHoverHint = {
    title: runtime.system_proxy_enabled ? "系统代理已开启" : "系统代理未开启",
    desc: "接管浏览器等应用流量",
  };

  const tunHint: CapsuleHoverHint = {
    title: runtime.tun_enabled ? "虚拟网卡已接管" : "虚拟网卡未开启",
    desc: "接管桌面与终端全部流量",
  };

  const preAccelHint: CapsuleHoverHint = togglingPreAccel
    ? {
        title: "正在切换国内提速…",
        desc: "正在同步中转与底层加速状态",
      }
    : isStandaloneGlobalOnly
      ? {
          title: "底层全局提速运行中（加速其它软件中）· 点击关闭",
          desc:
            effectiveGlobalMode === "windivert"
              ? "WinDivert 最底层透明接管中"
              : effectiveGlobalPort
                ? `本地独立 443 通道 127.0.0.1:${effectiveGlobalPort}`
                : "本地独立 443 通道运行中",
        }
      : isProxyPreAccelRunning
        ? {
            title: "国内提速运行中 · 点击关闭",
            desc: runtime.preaccel_relay_name
              ? `主力中转 · ${runtime.preaccel_relay_name}`
              : "正在通过国内 443 中转加速上传",
          }
        : isPreAccelConfigOn
          ? {
              title: "国内提速已开启 · 点击关闭",
              desc: "开启代理或底层全局提速后即刻生效",
            }
          : {
              title: "国内提速未开启 · 点击一键开启",
              desc: "突破上传限速，关代理也能给其它软件加速",
            };

  const switchHint: CapsuleHoverHint = {
    title: switching ? "正在切换更优节点…" : "切换下一个更优节点",
    desc: "自动切优并断开旧卡死连接",
  };

  const expandHint: CapsuleHoverHint = {
    title: "展开主窗口",
    desc: "回到猫猫云梯完整控制台",
  };

  const closeHint: CapsuleHoverHint = {
    title: "隐藏悬浮小窗",
    desc: "代理继续在后台稳定运行",
  };

  const undockHint: CapsuleHoverHint = {
    title: `取消${dockEdge ? DOCK_EDGE_LABELS[dockEdge] : "贴边"}`,
    desc: "点击恢复自由悬浮，也可直接拖离边缘解除",
  };

  const clearHint = () => setHoveredHint(null);

  const ThemeGlyph =
    resolvedTheme === "light" ? Sun : resolvedTheme === "warm-dark" ? Sunset : Moon;

  const avatarDimClass = isTallLayout ? "h-11 w-11" : "h-9 w-9";
  const btnDimClass = isTallLayout ? "h-7 w-7" : "h-[25px] w-[25px]";
  const shellRadiusClass = isTallLayout ? "rounded-[24px]" : "rounded-full";

  const capsulePill = (
    <div
      ref={shellRef}
      data-tauri-drag-region
      onMouseEnter={handleExpandedPointerEnter}
      onMouseLeave={handleExpandedPointerLeave}
      className={`cc-capsule-shell relative flex h-full w-full select-none items-center border text-[var(--text)] transition-[border-radius,border-color,background-image] duration-150 ${shellRadiusClass} ${
        isTallLayout ? "gap-2.5 px-2.5 py-2" : "gap-1.5 px-2"
      }`}
    >
      {/* 8-direction invisible resize handles for frameless transparent Tauri window */}
      {isTauri && (
        <>
          <div
            onMouseDown={(e) => handleStartResize("North", e)}
            className="absolute inset-x-3 top-0 z-20 h-[4px] cursor-ns-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("South", e)}
            className="absolute inset-x-3 bottom-0 z-20 h-[4px] cursor-ns-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("West", e)}
            className="absolute inset-y-2.5 left-0 z-20 w-[4px] cursor-ew-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("East", e)}
            className="absolute inset-y-2.5 right-0 z-20 w-[4px] cursor-ew-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("NorthWest", e)}
            className="absolute left-0 top-0 z-30 h-[8px] w-[8px] cursor-nwse-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("NorthEast", e)}
            className="absolute right-0 top-0 z-30 h-[8px] w-[8px] cursor-nesw-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("SouthWest", e)}
            className="absolute bottom-0 left-0 z-30 h-[8px] w-[8px] cursor-nesw-resize"
            aria-hidden="true"
          />
          <div
            onMouseDown={(e) => handleStartResize("SouthEast", e)}
            className="absolute bottom-0 right-0 z-30 h-[8px] w-[8px] cursor-nwse-resize"
            aria-hidden="true"
          />
        </>
      )}

      {/* A / C / Pixel status badge with semantic status dot */}
      <div
        className={`relative flex shrink-0 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] ${avatarDimClass}`}
        data-tauri-drag-region
        onMouseEnter={() => setHoveredHint(avatarHint)}
        onMouseLeave={clearHint}
        aria-label={`${avatarHint.title}：${avatarHint.desc}`}
      >
        {usePixelIcon ? (
          <MascotSprite
            state="idle"
            scale={1}
            animationsEnabled={false}
            className="pointer-events-none"
            title={statusMeta.label}
          />
        ) : (
          <img
            src={iconSrc}
            alt={useStarryIcon ? "CatCloud 午夜星云状态" : "CatCloud 奶油云朵状态"}
            className={`pointer-events-none rounded-full object-cover ${avatarDimClass}`}
            draggable={false}
          />
        )}
        <span
          className="pointer-events-none absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)]"
          style={{ backgroundColor: statusMeta.color }}
        />
      </div>

      {/* Route mode badge, active node/group, live up/down rates & in-place hover hint overlay */}
      <div className="relative flex min-w-0 flex-1 flex-col justify-center" data-tauri-drag-region>
        {/* Row 1: Mode badge + Active Node Name + Optional Latency/Theme on wide capsules */}
        <div className="flex min-w-0 items-center gap-1" data-tauri-drag-region>
          <span
            onMouseEnter={() => setHoveredHint(modeHint)}
            onMouseLeave={clearHint}
            className={`shrink-0 rounded border px-1 py-[1px] text-[9px] font-medium leading-none ${
              isSingleMode
                ? "border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--sky)]/40 bg-[var(--sky-soft)] text-[var(--sky)]"
            }`}
            aria-label={`${modeHint.title}：${modeHint.desc}`}
          >
            {isSingleMode ? "单节点" : "组"}
          </span>
          <span
            data-tauri-drag-region
            className={`truncate font-semibold leading-tight text-[var(--text)] ${
              isTallLayout ? "text-[12px]" : "text-[11px]"
            }`}
          >
            {displayNodeName}
          </span>
          {isWideWidth &&
            typeof runtime.active_node_latency_ms === "number" &&
            runtime.active_node_latency_ms > 0 && (
              <span className="cc-mono pointer-events-none shrink-0 rounded bg-[var(--card)]/90 px-1 py-[1px] text-[9px] text-[var(--green)]">
                {Math.round(runtime.active_node_latency_ms)}ms
              </span>
            )}
        </div>

        {/* Row 2: Unclipped Up/Down Live Rates + Proxy / TUN / PreAccel badges */}
        <div
          data-tauri-drag-region
          className={`flex items-center justify-between gap-1 leading-none ${
            isTallLayout ? "mt-1.5" : "mt-1"
          }`}
        >
          <div
            data-tauri-drag-region
            className={`cc-mono cc-tabular flex min-w-0 shrink-0 items-center gap-1 whitespace-nowrap tracking-tight ${
              isTallLayout
                ? "text-[11px]"
                : isCompactPreAccel
                  ? "text-[8.5px]"
                  : "text-[9px]"
            }`}
          >
            <span className="pointer-events-none text-[var(--coral)]">
              ↑{formatCompactRate(traffic.up_bps)}
            </span>
            <span className="pointer-events-none text-[var(--sky)]">
              ↓{formatCompactRate(traffic.down_bps)}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-[3px]">
            <span
              onMouseDown={(e) => e.stopPropagation()}
              onMouseEnter={() => setHoveredHint(proxyHint)}
              onMouseLeave={clearHint}
              className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                isCompactWidth
                  ? "px-[3px] py-[1px] text-[8px]"
                  : "px-[3.5px] py-[1.5px] text-[8px]"
              } ${
                runtime.system_proxy_enabled
                  ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[var(--muted)]/55"
              }`}
              aria-label={`${proxyHint.title}：${proxyHint.desc}`}
            >
              {isCompactWidth ? "代" : "代理"}
            </span>
            <span
              onMouseDown={(e) => e.stopPropagation()}
              onMouseEnter={() => setHoveredHint(tunHint)}
              onMouseLeave={clearHint}
              className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                isCompactWidth
                  ? "px-[3px] py-[1px] text-[8px]"
                  : "px-[3.5px] py-[1.5px] text-[8px]"
              } ${
                runtime.tun_enabled
                  ? "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[var(--muted)]/55"
              }`}
              aria-label={`${tunHint.title}：${tunHint.desc}`}
            >
              {isCompactWidth ? "卡" : "网卡"}
            </span>
            <button
              type="button"
              disabled={togglingPreAccel}
              onMouseDown={(e) => e.stopPropagation()}
              onClick={() => void handleTogglePreAccel()}
              onMouseEnter={() => setHoveredHint(preAccelHint)}
              onMouseLeave={clearHint}
              onFocus={() => setHoveredHint(preAccelHint)}
              onBlur={clearHint}
              aria-pressed={isPreAccelOn}
              aria-label={`${preAccelHint.title}：${preAccelHint.desc}`}
              className={`inline-flex cursor-pointer items-center justify-center whitespace-nowrap rounded border font-medium leading-none transition-colors disabled:opacity-60 ${
                isCompactPreAccel
                  ? "px-[3.5px] py-[1.5px]"
                  : "gap-[1.5px] px-[4px] py-[1.5px] text-[8px]"
              } ${
                isStandaloneGlobalOnly
                  ? "border-[var(--amber)]/65 bg-[var(--amber-soft)] text-[var(--amber)]"
                  : isProxyPreAccelRunning
                    ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                    : isPreAccelConfigOn
                      ? "border-[var(--accent)]/40 bg-[var(--accent-soft)]/50 text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)]/75 text-[var(--muted)]/75 hover:border-[var(--accent)]/50 hover:text-[var(--text)]"
              }`}
            >
              {togglingPreAccel ? (
                <Loader2 className="h-2.5 w-2.5 shrink-0 animate-spin" />
              ) : (
                <Zap className="h-2.5 w-2.5 shrink-0" />
              )}
              {!isCompactPreAccel && <span>提速</span>}
            </button>
          </div>
        </div>

        {/* Row 3 (auto-revealed when user drags capsule taller >= 82px): group, connections & day/night theme */}
        {isTallLayout && (
          <div
            data-tauri-drag-region
            className="mt-1.5 flex items-center justify-between gap-2 text-[10px] leading-none text-[var(--muted)]"
          >
            <span className="pointer-events-none truncate">
              {isSingleMode ? "单节点模式" : displayGroupName} · {traffic.connections} 连接
            </span>
            <span className="pointer-events-none inline-flex shrink-0 items-center gap-0.5 text-[9.5px] text-[var(--accent)]">
              <ThemeGlyph className="h-2.5 w-2.5" />
              {themeMeta.shortLabel}
            </span>
          </div>
        )}

        {/* Instant in-place Chinese description overlay (adapts to capsule theme, zero clipping) */}
        {hoveredHint && (
          <div
            aria-live="polite"
            style={{ backgroundImage: "var(--capsule-bg)" }}
            className="pointer-events-none absolute -inset-y-1 inset-x-0 z-10 flex flex-col justify-center rounded-lg px-1"
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

      {/* Compact single-click action cluster (never marked as drag region) */}
      <div className="flex shrink-0 items-center gap-[2.5px]">
        {dockEdge && (
          <button
            type="button"
            onMouseDown={(e) => e.stopPropagation()}
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

        <button
          type="button"
          disabled={switching}
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
          aria-label="切换下一个更优节点"
        >
          {switching ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : justSwitched ? (
            <Check className="h-3 w-3" />
          ) : (
            <Zap className="h-3 w-3" />
          )}
        </button>

        <button
          type="button"
          onClick={() => void appActions.showMainFromCapsule()}
          onMouseEnter={() => setHoveredHint(expandHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(expandHint)}
          onBlur={clearHint}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] ${btnDimClass}`}
          aria-label="展开主窗口"
        >
          <Maximize2 className="h-3 w-3" />
        </button>

        <button
          type="button"
          onClick={() => void handleCloseCapsule()}
          onMouseEnter={() => setHoveredHint(closeHint)}
          onMouseLeave={clearHint}
          onFocus={() => setHoveredHint(closeHint)}
          onBlur={clearHint}
          className={`inline-flex cursor-pointer items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] transition-colors hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)] ${btnDimClass}`}
          aria-label="隐藏悬浮小窗"
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
    if (isStandaloneGlobalOnly) return "底层提速";
    if (isProxyPreAccelRunning) return "提速中";
    if (runtime.running) return "运行中";
    return "猫猫";
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
          title={`悬停或点击展开悬浮小窗 · 双击/右键或拖离边缘取消贴边（${statusMeta.label}）`}
          aria-label={`展开悬浮小窗（${DOCK_EDGE_LABELS[dockEdge]} · ${statusMeta.label}）`}
          className={`cc-capsule-shell flex h-full w-full cursor-pointer select-none items-center justify-center border text-[var(--text)] transition-colors hover:border-[var(--accent)] ${edgeRadiusClass} ${
            isHorizontalDock ? "flex-row gap-1.5 px-2.5" : "flex-col gap-1.5 py-2.5"
          }`}
        >
          <span
            className="h-2 w-2 shrink-0 rounded-full"
            style={{ backgroundColor: statusMeta.color }}
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
          悬浮小窗预览（{previewDockBox.w} × {previewDockBox.h} · {themeMeta.label}
          {themeMeta.autoSuffix}
          {dockEdge ? ` · ${DOCK_EDGE_LABELS[dockEdge]}${dockCollapsed ? "已收起" : "展开中"}` : ""}）
        </div>
        <div className="mt-1 text-[11px] text-[var(--muted)]">
          状态：{statusMeta.label} · 模式：{isSingleMode ? "单节点" : `多选组（${displayGroupName}）`} · 系统代理：
          {runtime.system_proxy_enabled ? "开" : "关"} · 虚拟网卡：{runtime.tun_enabled ? "开" : "关"} · 国内提速：
          {isStandaloneGlobalOnly ? "底层提速中" : isProxyPreAccelRunning ? "开" : isPreAccelConfigOn ? "就绪" : "关"}
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
            { label: "默认 344×64", w: 344, h: 64 },
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
