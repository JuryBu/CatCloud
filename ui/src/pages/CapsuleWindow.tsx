import { Check, Loader2, Maximize2, Moon, Sun, Sunset, X, Zap } from "lucide-react";
import type { MouseEvent as ReactMouseEvent } from "react";
import { useEffect, useRef, useState } from "react";
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

const CAPSULE_SIZE_STORAGE_KEY = "catcloud.capsule.size.v1";
const CAPSULE_DEFAULT_W = 344;
const CAPSULE_DEFAULT_H = 64;
const CAPSULE_MIN_W = 280;
const CAPSULE_MAX_W = 560;
const CAPSULE_MIN_H = 56;
const CAPSULE_MAX_H = 140;

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

function resolveStatusAccent(status: string): { color: string; label: string } {
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
  const groups = useAppSelector((s) => s.groups);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const themeMode = useAppSelector((s) => s.config.personalization.theme_mode);
  const trayIconMode = useAppSelector((s) => s.config.personalization.tray_icon_mode);
  const traffic = useLatestTraffic();

  const [switching, setSwitching] = useState<boolean>(false);
  const [justSwitched, setJustSwitched] = useState<boolean>(false);
  const [hoveredHint, setHoveredHint] = useState<CapsuleHoverHint | null>(null);
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
  const mountedRef = useRef<boolean>(true);
  const restoredSizeRef = useRef<boolean>(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (switchFeedbackTimerRef.current !== null) {
        window.clearTimeout(switchFeedbackTimerRef.current);
      }
      if (saveSizeTimerRef.current !== null) {
        window.clearTimeout(saveSizeTimerRef.current);
      }
    };
  }, []);

  // Restore last user-resized capsule dimensions cleanly on desktop startup
  useEffect(() => {
    if (!isTauri || restoredSizeRef.current) return;
    restoredSizeRef.current = true;
    const saved = loadSavedCapsuleSize();
    if (!saved) return;
    if (saved.w === CAPSULE_DEFAULT_W && saved.h === CAPSULE_DEFAULT_H) return;
    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow, LogicalSize }) =>
        getCurrentWindow().setSize(new LogicalSize(saved.w, saved.h))
      )
      .catch(() => {
        /* ignore if window cannot resize yet */
      });
  }, [isTauri]);

  // Observe live capsule width/height to adapt layout smoothly & persist resized size
  useEffect(() => {
    const el = shellRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const updateFromRect = (width: number, height: number) => {
      const nextW = Math.round(width);
      const nextH = Math.round(height);
      if (nextW <= 0 || nextH <= 0) return;
      setBoxSize((prev) =>
        prev.w === nextW && prev.h === nextH ? prev : { w: nextW, h: nextH }
      );
      if (isTauri) {
        if (saveSizeTimerRef.current !== null) {
          window.clearTimeout(saveSizeTimerRef.current);
        }
        saveSizeTimerRef.current = window.setTimeout(() => {
          saveSizeTimerRef.current = null;
          saveCapsuleSize(nextW + 4, nextH + 4);
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
  }, [isTauri]);

  const handleStartResize = (
    direction: ResizeDirection,
    ev: ReactMouseEvent<HTMLDivElement>
  ) => {
    if (!isTauri || ev.button !== 0) return;
    ev.preventDefault();
    ev.stopPropagation();
    setHoveredHint(null);
    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().startResizeDragging(direction))
      .catch(() => {
        /* ignore unsupported platform */
      });
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

  const statusMeta = resolveStatusAccent(runtime.status);
  const themeMeta = resolveThemeDisplay(resolvedTheme, themeMode);
  const isSingleMode = runtime.route_mode === "single";
  const displayNodeName =
    runtime.active_node_name?.trim() || runtime.active_group_name?.trim() || "待选节点";
  const displayGroupName = runtime.active_group_name?.trim() || "默认分组";

  // Adaptive breakpoints based on live dragged capsule dimensions
  const isCompactWidth = boxSize.w < 308;
  const isWideWidth = boxSize.w >= 404;
  const isTallLayout = boxSize.h >= 82;

  // In auto_ac mode, follow both network status and day/night atmosphere so the capsule
  // visibly reflects daytime cream-cat vs nighttime/preaccel starry-neko changes.
  const useStarryIcon =
    trayIconMode === "always_c" ||
    (trayIconMode === "auto_ac" &&
      (runtime.status === "preaccel" ||
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
    desc:
      runtime.preaccel_active && runtime.preaccel_relay_name
        ? `国内提速 · ${runtime.preaccel_relay_name}${themeMeta.autoSuffix}`
        : `拖动可移动，拖边缘可拉伸尺寸${themeMeta.autoSuffix}`,
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

  const clearHint = () => setHoveredHint(null);

  const ThemeGlyph =
    resolvedTheme === "light" ? Sun : resolvedTheme === "warm-dark" ? Sunset : Moon;

  const avatarDimClass = isTallLayout ? "h-11 w-11" : "h-9 w-9";
  const btnDimClass = isTallLayout ? "h-7 w-7" : "h-[26px] w-[26px]";
  const shellRadiusClass = isTallLayout ? "rounded-[24px]" : "rounded-full";

  const capsulePill = (
    <div
      ref={shellRef}
      data-tauri-drag-region
      onMouseLeave={clearHint}
      className={`cc-capsule-shell relative flex h-full w-full select-none items-center border px-2.5 text-[var(--text)] transition-[border-radius,border-color,background-image] duration-150 ${shellRadiusClass} ${
        isTallLayout ? "gap-2.5 py-2" : "gap-1.5"
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

        {/* Row 2: Unclipped Up/Down Live Rates + Proxy / TUN badges */}
        <div
          data-tauri-drag-region
          className={`flex items-center justify-between gap-1.5 leading-none ${
            isTallLayout ? "mt-1.5" : "mt-1"
          }`}
        >
          <div
            data-tauri-drag-region
            className={`cc-mono flex min-w-0 items-center gap-1.5 whitespace-nowrap tracking-tight ${
              isTallLayout
                ? "text-[11px]"
                : isCompactWidth
                  ? "text-[9px]"
                  : "text-[9.5px]"
            }`}
          >
            <span className="pointer-events-none text-[var(--coral)]">
              ↑{formatCompactRate(traffic.up_bps)}
            </span>
            <span className="pointer-events-none text-[var(--sky)]">
              ↓{formatCompactRate(traffic.down_bps)}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-1">
            <span
              onMouseEnter={() => setHoveredHint(proxyHint)}
              onMouseLeave={clearHint}
              className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                isCompactWidth ? "px-[3px] py-[1px] text-[8px]" : "px-1 py-[1.5px] text-[8.5px]"
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
              onMouseEnter={() => setHoveredHint(tunHint)}
              onMouseLeave={clearHint}
              className={`whitespace-nowrap rounded border font-medium leading-none transition-colors ${
                isCompactWidth ? "px-[3px] py-[1px] text-[8px]" : "px-1 py-[1.5px] text-[8.5px]"
              } ${
                runtime.tun_enabled
                  ? "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[var(--muted)]/55"
              }`}
              aria-label={`${tunHint.title}：${tunHint.desc}`}
            >
              {isCompactWidth ? "卡" : "网卡"}
            </span>
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
      <div className="flex shrink-0 items-center gap-[3px]">
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

  if (isTauri) {
    return (
      <div className="flex h-screen w-screen items-center justify-center overflow-hidden bg-transparent p-[2px]">
        {capsulePill}
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[var(--bg)] p-6">
      <div className="text-center">
        <div className="text-xs font-semibold text-[var(--text)]">
          悬浮小窗预览（{previewSize.w} × {previewSize.h} · {themeMeta.label}
          {themeMeta.autoSuffix}）
        </div>
        <div className="mt-1 text-[11px] text-[var(--muted)]">
          状态：{statusMeta.label} · 模式：{isSingleMode ? "单节点" : `多选组（${displayGroupName}）`} · 系统代理：
          {runtime.system_proxy_enabled ? "开" : "关"} · 虚拟网卡：{runtime.tun_enabled ? "开" : "关"}
        </div>
      </div>

      <div
        style={{ width: `${previewSize.w}px`, height: `${previewSize.h}px` }}
        className="flex items-center justify-center bg-transparent p-[2px] transition-[width,height] duration-150"
      >
        {capsulePill}
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
            onClick={() => setPreviewSize({ w: preset.w, h: preset.h })}
            className={`rounded-lg border px-2.5 py-1 text-[11px] transition-colors ${
              previewSize.w === preset.w && previewSize.h === preset.h
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            {preset.label}
          </button>
        ))}

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
