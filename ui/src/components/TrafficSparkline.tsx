import { Cpu, Pause } from "lucide-react";
import { type MouseEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  TrafficRingBuffer,
  appStore,
  useAppSelector,
  useLatestTraffic,
  useTrafficVersion,
} from "../store/appStore";

export { TrafficRingBuffer };

type TimeWindowSec = 120 | 600;
type ScaleMode = "linear" | "sqrt";

/** Gap threshold (ms) above which consecutive samples split into separate visual segments. */
const SEGMENT_GAP_MS = 5_000;
/** Maximum SVG X distance (out of vbWidth=600) to snap hover crosshair to an existing sample. */
const MAX_HOVER_SNAP_DX = 26;

export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "0 B/s";
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb < 100 ? kb.toFixed(1) : Math.round(kb)} KB/s`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb < 10 ? mb.toFixed(2) : mb < 100 ? mb.toFixed(1) : Math.round(mb)} MB/s`;
  return `${(mb / 1024).toFixed(2)} GB/s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value >= 100 || idx === 0 ? value.toFixed(0) : value.toFixed(2)} ${units[idx]}`;
}

export function formatClock(timestampMs: number): string {
  if (!Number.isFinite(timestampMs) || timestampMs <= 0) return "--:--:--";
  const d = new Date(timestampMs);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function formatAxisTime(timestampMs: number, includeSeconds: boolean): string {
  if (!Number.isFinite(timestampMs) || timestampMs <= 0) return "--:--";
  const d = new Date(timestampMs);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  if (!includeSeconds) return `${hh}:${mm}`;
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

/** Round peak throughput up to clean human-readable axis ticks (64 KB/s, 128 KB/s, ..., 1 MB/s, 2 MB/s, 5 MB/s...). */
function niceCeilRate(rawPeakBps: number): number {
  const floorBps = 64 * 1024;
  const target = Math.max(floorBps, rawPeakBps * 1.12);
  const steps: number[] = [
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    5 * 1024 * 1024,
    10 * 1024 * 1024,
    20 * 1024 * 1024,
    40 * 1024 * 1024,
    50 * 1024 * 1024,
    100 * 1024 * 1024,
    200 * 1024 * 1024,
    500 * 1024 * 1024,
    1024 * 1024 * 1024,
  ];
  for (const s of steps) {
    if (target <= s) return s;
  }
  const gb = 1024 * 1024 * 1024;
  return Math.ceil(target / gb) * gb;
}

function mapValueToRatio(value: number, scaleMax: number, scaleMode: ScaleMode): number {
  if (!Number.isFinite(value) || value <= 0 || scaleMax <= 0) return 0;
  const linear = Math.min(1, Math.max(0, value / scaleMax));
  return scaleMode === "sqrt" ? Math.sqrt(linear) : linear;
}

interface SmoothPathResult {
  linePath: string;
  areaPath: string;
  xs: Float64Array;
  ys: Float64Array;
}

/**
 * Fritsch-Carlson Monotone Cubic Hermite Spline builder over timestamp-aligned coordinates.
 * Guarantees:
 * 1) Curve passes EXACTLY through every (xs[i], ys[i]) — zero peak shrinkage, hover dots sit right on the stroke.
 * 2) Strictly monotone between samples — never overshoots below baseline or above ceiling.
 * 3) Automatically splits across time gaps (> SEGMENT_GAP_MS) so restarts/pauses never draw fake diagonal bridges.
 */
function buildTimeAlignedPath(
  xs: Float64Array,
  values: Float64Array,
  ts: Float64Array,
  count: number,
  scaleMax: number,
  scaleMode: ScaleMode,
  height: number,
  padTop: number,
  padBottom: number
): SmoothPathResult {
  const ys = new Float64Array(count);
  if (count === 0) {
    return { linePath: "", areaPath: "", xs, ys };
  }

  const innerH = Math.max(1, height - padTop - padBottom);
  const baseY = height - padBottom;

  for (let i = 0; i < count; i++) {
    const ratio = mapValueToRatio(values[i], scaleMax, scaleMode);
    ys[i] = baseY - ratio * innerH;
  }

  const lineSegs: string[] = [];
  const areaSegs: string[] = [];

  let segStart = 0;
  while (segStart < count) {
    let segEnd = segStart;
    while (
      segEnd + 1 < count &&
      ts[segEnd + 1] - ts[segEnd] <= SEGMENT_GAP_MS &&
      xs[segEnd + 1] >= xs[segEnd]
    ) {
      segEnd += 1;
    }

    const len = segEnd - segStart + 1;
    if (len === 1) {
      const x = xs[segStart];
      const y = ys[segStart];
      const x0 = Math.max(0, x - 1.5).toFixed(1);
      const x1 = x.toFixed(1);
      const yf = y.toFixed(1);
      lineSegs.push(`M${x0},${yf} L${x1},${yf}`);
      areaSegs.push(`M${x0},${yf} L${x1},${yf} L${x1},${baseY.toFixed(1)} L${x0},${baseY.toFixed(1)} Z`);
    } else if (len === 2) {
      const x0 = xs[segStart].toFixed(1);
      const y0 = ys[segStart].toFixed(1);
      const x1 = xs[segEnd].toFixed(1);
      const y1 = ys[segEnd].toFixed(1);
      const segLine = `M${x0},${y0} L${x1},${y1}`;
      lineSegs.push(segLine);
      areaSegs.push(`${segLine} L${x1},${baseY.toFixed(1)} L${x0},${baseY.toFixed(1)} Z`);
    } else {
      // Fritsch-Carlson monotone tangents
      const dx = new Float64Array(len - 1);
      const slope = new Float64Array(len - 1);
      for (let k = 0; k < len - 1; k++) {
        const i0 = segStart + k;
        const d = Math.max(0.001, xs[i0 + 1] - xs[i0]);
        dx[k] = d;
        slope[k] = (ys[i0 + 1] - ys[i0]) / d;
      }

      const m = new Float64Array(len);
      m[0] = slope[0];
      m[len - 1] = slope[len - 2];
      for (let k = 1; k < len - 1; k++) {
        if (slope[k - 1] * slope[k] <= 0) {
          m[k] = 0;
        } else {
          const w1 = 2 * dx[k] + dx[k - 1];
          const w2 = dx[k] + 2 * dx[k - 1];
          m[k] = (w1 + w2) / (w1 / slope[k - 1] + w2 / slope[k]);
        }
      }

      // Clamp tangents to preserve monotonicity
      for (let k = 0; k < len - 1; k++) {
        if (Math.abs(slope[k]) < 1e-9) {
          m[k] = 0;
          m[k + 1] = 0;
        } else {
          const a = m[k] / slope[k];
          const b = m[k + 1] / slope[k];
          const sumSq = a * a + b * b;
          if (sumSq > 9) {
            const tau = 3 / Math.sqrt(sumSq);
            m[k] = tau * a * slope[k];
            m[k + 1] = tau * b * slope[k];
          }
        }
      }

      const parts: string[] = [`M${xs[segStart].toFixed(1)},${ys[segStart].toFixed(1)}`];
      for (let k = 0; k < len - 1; k++) {
        const i0 = segStart + k;
        const i1 = i0 + 1;
        const h = dx[k];
        const cp1x = xs[i0] + h / 3;
        const cp1y = Math.min(baseY, Math.max(padTop, ys[i0] + (m[k] * h) / 3));
        const cp2x = xs[i1] - h / 3;
        const cp2y = Math.min(baseY, Math.max(padTop, ys[i1] - (m[k + 1] * h) / 3));
        parts.push(
          `C${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${xs[i1].toFixed(1)},${ys[i1].toFixed(1)}`
        );
      }

      const segLine = parts.join(" ");
      lineSegs.push(segLine);
      areaSegs.push(
        `${segLine} L${xs[segEnd].toFixed(1)},${baseY.toFixed(1)} L${xs[segStart].toFixed(1)},${baseY.toFixed(1)} Z`
      );
    }

    segStart = segEnd + 1;
  }

  return {
    linePath: lineSegs.join(" "),
    areaPath: areaSegs.join(" "),
    xs,
    ys,
  };
}

export interface TrafficSparklineProps {
  variant: "full" | "mini";
  /** Optional custom ring buffer; defaults to shared 600-point store buffer. */
  buffer?: TrafficRingBuffer;
  /** Optional local override to pause SVG redraws. */
  paused?: boolean;
  className?: string;
}

export function TrafficSparkline({
  variant,
  buffer,
  paused,
  className = "",
}: TrafficSparklineProps) {
  const uid = useId().replace(/:/g, "");
  const liveVersion = useTrafficVersion();
  const latest = useLatestTraffic();
  const coreRunning = useAppSelector((s) => s.runtime.running);
  const sparklineEnabled = useAppSelector((s) => s.config.personalization.sparkline_enabled);

  const [isVisible, setIsVisible] = useState<boolean>(() =>
    typeof document === "undefined" ? true : document.visibilityState === "visible"
  );
  const [windowSec, setWindowSec] = useState<TimeWindowSec>(600);
  const [scaleMode, setScaleMode] = useState<ScaleMode>("linear");
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const lastRenderedVersionRef = useRef<number>(liveVersion);

  useEffect(() => {
    const onVisibility = () => {
      setIsVisible(document.visibilityState === "visible");
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  const redrawPaused = Boolean(paused) || !isVisible || !sparklineEnabled;
  if (!redrawPaused) {
    lastRenderedVersionRef.current = liveVersion;
  }
  const effectiveVersion = lastRenderedVersionRef.current;

  const ring = buffer ?? appStore.getTrafficBuffer();
  const isFull = variant === "full";
  const activeWindowSec = isFull ? windowSec : 120;
  const activeScaleMode: ScaleMode = isFull ? scaleMode : "linear";
  const windowMs = activeWindowSec * 1000;

  const vbWidth = isFull ? 600 : 196;
  const vbHeight = isFull ? 156 : 42;
  const padX = isFull ? 6 : 2;
  const padTop = isFull ? 14 : 4;
  const padBottom = isFull ? 10 : 3;
  const innerW = Math.max(1, vbWidth - padX * 2);

  // Extract timestamp-aligned slice within [endTs - windowMs, endTs]
  const computed = useMemo(() => {
    const total = ring.length;
    if (total === 0) {
      const now = Date.now();
      return {
        count: 0,
        startTs: now - windowMs,
        endTs: now,
        spanSec: 0,
        rawPeak: 0,
        scaleMax: 64 * 1024,
        xs: new Float64Array(0),
        upSlice: new Float64Array(0),
        downSlice: new Float64Array(0),
        tsSlice: new Float64Array(0),
        upGeom: { linePath: "", areaPath: "", xs: new Float64Array(0), ys: new Float64Array(0) },
        downGeom: { linePath: "", areaPath: "", xs: new Float64Array(0), ys: new Float64Array(0) },
        version: effectiveVersion,
      };
    }

    const latestTs = ring.tsAt(total - 1);
    const endTs = latestTs > 0 ? latestTs : Date.now();
    const startTs = endTs - windowMs;

    // Collect valid points inside [startTs, endTs] in chronological order
    let firstValid = total;
    for (let i = total - 1; i >= 0; i--) {
      const t = ring.tsAt(i);
      if (t <= 0) continue;
      if (t < startTs) break;
      firstValid = i;
    }

    const count = firstValid < total ? total - firstValid : 0;
    const xs = new Float64Array(count);
    const upSlice = new Float64Array(count);
    const downSlice = new Float64Array(count);
    const tsSlice = new Float64Array(count);

    let rawPeak = 0;
    for (let i = 0; i < count; i++) {
      const idx = firstValid + i;
      const u = ring.upAt(idx);
      const d = ring.downAt(idx);
      const t = ring.tsAt(idx);
      upSlice[i] = u;
      downSlice[i] = d;
      tsSlice[i] = t;
      const frac = Math.min(1, Math.max(0, (t - startTs) / windowMs));
      xs[i] = padX + frac * innerW;
      if (u > rawPeak) rawPeak = u;
      if (d > rawPeak) rawPeak = d;
    }

    const scaleMax = niceCeilRate(rawPeak);
    const spanSec = count >= 2 ? Math.max(1, Math.round((tsSlice[count - 1] - tsSlice[0]) / 1000)) : count;

    const downGeom = buildTimeAlignedPath(
      xs,
      downSlice,
      tsSlice,
      count,
      scaleMax,
      activeScaleMode,
      vbHeight,
      padTop,
      padBottom
    );
    const upGeom = buildTimeAlignedPath(
      xs,
      upSlice,
      tsSlice,
      count,
      scaleMax,
      activeScaleMode,
      vbHeight,
      padTop,
      padBottom
    );

    return {
      count,
      startTs,
      endTs,
      spanSec,
      rawPeak,
      scaleMax,
      xs,
      upSlice,
      downSlice,
      tsSlice,
      upGeom,
      downGeom,
      version: effectiveVersion,
    };
  }, [
    activeScaleMode,
    effectiveVersion,
    innerW,
    padBottom,
    padTop,
    padX,
    ring,
    vbHeight,
    windowMs,
  ]);

  // Reset stale hover index if sample count drops
  useEffect(() => {
    if (hoverIdx !== null && hoverIdx >= computed.count) {
      setHoverIdx(null);
    }
  }, [computed.count, hoverIdx]);

  const handleMouseMove = (ev: MouseEvent<SVGSVGElement>) => {
    if (!isFull || computed.count === 0) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return;
    const svgX = ((ev.clientX - rect.left) / rect.width) * vbWidth;

    // Binary search nearest point by timestamp-aligned X coordinate
    const xs = computed.xs;
    let lo = 0;
    let hi = computed.count - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (xs[mid] < svgX) lo = mid + 1;
      else hi = mid;
    }
    let best = lo;
    if (best > 0 && Math.abs(xs[best - 1] - svgX) < Math.abs(xs[best] - svgX)) {
      best -= 1;
    }
    if (Math.abs(xs[best] - svgX) > MAX_HOVER_SNAP_DX) {
      if (hoverIdx !== null) setHoverIdx(null);
      return;
    }
    setHoverIdx(best);
  };

  const handleMouseLeave = () => {
    if (hoverIdx !== null) setHoverIdx(null);
  };

  const gradDownId = `cc-down-${uid}`;
  const gradUpId = `cc-up-${uid}`;

  if (!isFull) {
    return (
      <div
        className={`cc-card cc-glass rounded-xl px-3 py-2.5 ${className}`}
        title={
          redrawPaused
            ? "流量动画已暂停（省电模式）"
            : `近 2 分钟实时流量 · 内核内存 ${latest.memory_mb.toFixed(1)} MB`
        }
      >
        <div className="mb-1.5 flex items-center justify-between text-[11px] text-[var(--muted)]">
          <span className="font-medium">实时流量</span>
          {!sparklineEnabled ? (
            <span className="inline-flex items-center gap-1 text-[10px] text-[var(--amber)]">
              <Pause className="h-2.5 w-2.5" />
              已暂停
            </span>
          ) : (
            <span className="cc-tabular text-[10px] text-[var(--muted)]">
              {latest.connections} 个连接
            </span>
          )}
        </div>

        <svg
          viewBox={`0 0 ${vbWidth} ${vbHeight}`}
          preserveAspectRatio="none"
          className="block h-[40px] w-full overflow-visible"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id={gradDownId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--sky)" stopOpacity="0.34" />
              <stop offset="100%" stopColor="var(--sky)" stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id={gradUpId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--coral)" stopOpacity="0.32" />
              <stop offset="100%" stopColor="var(--coral)" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <line
            x1={padX}
            y1={vbHeight - padBottom}
            x2={vbWidth - padX}
            y2={vbHeight - padBottom}
            stroke="var(--line)"
            strokeOpacity="0.55"
            vectorEffect="non-scaling-stroke"
          />
          {computed.downGeom.areaPath && (
            <path d={computed.downGeom.areaPath} fill={`url(#${gradDownId})`} />
          )}
          {computed.upGeom.areaPath && (
            <path d={computed.upGeom.areaPath} fill={`url(#${gradUpId})`} />
          )}
          {computed.downGeom.linePath && (
            <path
              d={computed.downGeom.linePath}
              fill="none"
              stroke="var(--sky)"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
          )}
          {computed.upGeom.linePath && (
            <path
              d={computed.upGeom.linePath}
              fill="none"
              stroke="var(--coral)"
              strokeWidth="1.4"
              strokeLinecap="round"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </svg>

        <div className="mt-2 grid grid-cols-2 gap-x-2 gap-y-1 text-[11px]">
          <div className="flex items-center justify-between gap-1">
            <span className="text-[var(--coral)]">↑</span>
            <span className="cc-mono truncate font-medium text-[var(--text)]">
              {formatRate(latest.up_bps)}
            </span>
          </div>
          <div className="flex items-center justify-between gap-1">
            <span className="text-[var(--sky)]">↓</span>
            <span className="cc-mono truncate font-medium text-[var(--text)]">
              {formatRate(latest.down_bps)}
            </span>
          </div>
        </div>

        <div className="mt-1.5 flex items-center justify-between border-t border-[var(--line)] pt-1.5 text-[11px]">
          <span className="inline-flex items-center gap-1 text-[var(--muted)]">
            <Cpu className="h-3 w-3 text-[var(--green)]" />
            内核内存
          </span>
          <span className="cc-mono font-medium text-[var(--green)]">
            {latest.memory_mb.toFixed(1)} MB
          </span>
        </div>
      </div>
    );
  }

  // Exact Y-axis coordinates matching SVG horizontal gridlines
  const topY = padTop;
  const midY = (padTop + (vbHeight - padBottom)) * 0.5;
  const baseY = vbHeight - padBottom;
  const midAxisRate = activeScaleMode === "sqrt" ? computed.scaleMax * 0.25 : computed.scaleMax * 0.5;

  // 5 evenly spaced X-axis time ticks matching [startTs, endTs]
  const includeSecOnAxis = activeWindowSec <= 120;
  const hasSamples = computed.count > 0;
  const xTicks = hasSamples
    ? [
        formatAxisTime(computed.startTs, includeSecOnAxis),
        formatAxisTime(computed.startTs + windowMs * 0.25, includeSecOnAxis),
        formatAxisTime(computed.startTs + windowMs * 0.5, includeSecOnAxis),
        formatAxisTime(computed.startTs + windowMs * 0.75, includeSecOnAxis),
        "现在",
      ]
    : activeWindowSec === 600
      ? ["-10分", "-7.5分", "-5分", "-2.5分", "现在"]
      : ["-2分", "-90秒", "-1分", "-30秒", "现在"];

  const validHover =
    hoverIdx !== null && hoverIdx >= 0 && hoverIdx < computed.count ? hoverIdx : null;
  const hoverX = validHover !== null ? computed.xs[validHover] : 0;
  const hoverDownY = validHover !== null ? computed.downGeom.ys[validHover] : 0;
  const hoverUpY = validHover !== null ? computed.upGeom.ys[validHover] : 0;
  const hoverLeftPct = validHover !== null ? (hoverX / vbWidth) * 100 : 0;
  const alignRight = hoverLeftPct > 68;

  const titleLabel = activeWindowSec === 600 ? "近 10 分钟流量走势" : "近 2 分钟流量走势";

  return (
    <div className={`cc-card cc-glass rounded-2xl p-4 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold tracking-tight text-[var(--text)]">{titleLabel}</h2>

          {/* Time window selector: 2 min (zoomed) vs 10 min (full) */}
          <div
            className="inline-flex items-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[10.5px]"
            role="group"
            aria-label="切换流量时间跨度"
          >
            <button
              type="button"
              onClick={() => setWindowSec(120)}
              className={`rounded-md px-2 py-0.5 font-medium transition-colors ${
                windowSec === 120
                  ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              2 分钟
            </button>
            <button
              type="button"
              onClick={() => setWindowSec(600)}
              className={`rounded-md px-2 py-0.5 font-medium transition-colors ${
                windowSec === 600
                  ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              10 分钟
            </button>
          </div>

          {/* Linear vs Sqrt-soft scale toggle so burst spikes don't flatten everyday traffic */}
          <button
            type="button"
            onClick={() => setScaleMode((m) => (m === "linear" ? "sqrt" : "linear"))}
            className={`rounded-lg border px-2 py-0.5 text-[10.5px] font-medium transition-colors ${
              scaleMode === "sqrt"
                ? "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
            title={
              scaleMode === "sqrt"
                ? "柔和刻度：同时看清小流量与突发高峰（中线已如实标注为峰值的 1/4）"
                : "标准线性刻度：点击切为柔和刻度，避免偶发高峰压扁日常流量"
            }
          >
            {scaleMode === "sqrt" ? "柔和刻度" : "标准刻度"}
          </button>

          <span className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[10.5px] cc-mono text-[var(--text-secondary)]">
            {computed.rawPeak > 0
              ? `实测峰值 ${formatRate(computed.rawPeak)}`
              : `量程 ${formatRate(computed.scaleMax)}`}
          </span>

          {!sparklineEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--amber)]">
              <Pause className="h-3 w-3" />
              曲线已暂停
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-[var(--coral)]" />
            <span className="text-[var(--muted)]">上传</span>
            <span className="cc-mono font-semibold text-[var(--text)]">
              {formatRate(latest.up_bps)}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-[var(--sky)]" />
            <span className="text-[var(--muted)]">下载</span>
            <span className="cc-mono font-semibold text-[var(--text)]">
              {formatRate(latest.down_bps)}
            </span>
          </div>
        </div>
      </div>

      <div className="flex h-[156px] w-full items-stretch gap-2">
        {/* Left Y-axis column precisely aligned to topY, midY, and baseY gridlines */}
        <div
          className="relative w-[68px] shrink-0 select-none text-right text-[10.5px] font-medium leading-none cc-mono text-[var(--text-secondary)]"
          aria-hidden="true"
        >
          <span
            className="absolute right-0 -translate-y-1/2 whitespace-nowrap"
            style={{ top: `${(topY / vbHeight) * 100}%` }}
          >
            {formatRate(computed.scaleMax)}
          </span>
          <span
            className="absolute right-0 -translate-y-1/2 whitespace-nowrap"
            style={{ top: `${(midY / vbHeight) * 100}%` }}
          >
            {formatRate(midAxisRate)}
          </span>
          <span
            className="absolute right-0 -translate-y-1/2 whitespace-nowrap"
            style={{ top: `${(baseY / vbHeight) * 100}%` }}
          >
            0
          </span>
        </div>

        <div className="relative min-w-0 flex-1">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${vbWidth} ${vbHeight}`}
            preserveAspectRatio="none"
            onMouseMove={handleMouseMove}
            onMouseLeave={handleMouseLeave}
            className="block h-full w-full cursor-crosshair select-none"
            role="img"
            aria-label={`${titleLabel}，上传与下载速率`}
          >
            <defs>
              <linearGradient id={gradDownId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--sky)" stopOpacity="0.28" />
                <stop offset="100%" stopColor="var(--sky)" stopOpacity="0.01" />
              </linearGradient>
              <linearGradient id={gradUpId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--coral)" stopOpacity="0.26" />
                <stop offset="100%" stopColor="var(--coral)" stopOpacity="0.01" />
              </linearGradient>
            </defs>

            {/* 3 horizontal gridlines */}
            <line
              x1={padX}
              y1={topY}
              x2={vbWidth - padX}
              y2={topY}
              stroke="var(--line)"
              strokeOpacity="0.45"
              strokeDasharray="3 4"
              vectorEffect="non-scaling-stroke"
            />
            <line
              x1={padX}
              y1={midY}
              x2={vbWidth - padX}
              y2={midY}
              stroke="var(--line)"
              strokeOpacity="0.45"
              strokeDasharray="3 4"
              vectorEffect="non-scaling-stroke"
            />
            <line
              x1={padX}
              y1={baseY}
              x2={vbWidth - padX}
              y2={baseY}
              stroke="var(--line)"
              strokeOpacity="0.7"
              vectorEffect="non-scaling-stroke"
            />

            {/* Subtle vertical time-quarter reference lines */}
            {[0.25, 0.5, 0.75].map((q) => {
              const gx = padX + q * innerW;
              return (
                <line
                  key={q}
                  x1={gx}
                  y1={topY}
                  x2={gx}
                  y2={baseY}
                  stroke="var(--line)"
                  strokeOpacity="0.24"
                  strokeDasharray="2 4"
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}

            {/* Area fills */}
            {computed.downGeom.areaPath && (
              <path d={computed.downGeom.areaPath} fill={`url(#${gradDownId})`} />
            )}
            {computed.upGeom.areaPath && (
              <path d={computed.upGeom.areaPath} fill={`url(#${gradUpId})`} />
            )}

            {/* Exact-interpolating monotone spline strokes */}
            {computed.downGeom.linePath && (
              <path
                d={computed.downGeom.linePath}
                fill="none"
                stroke="var(--sky)"
                strokeWidth="1.9"
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              />
            )}
            {computed.upGeom.linePath && (
              <path
                d={computed.upGeom.linePath}
                fill="none"
                stroke="var(--coral)"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              />
            )}

            {/* Hover vertical guide line */}
            {validHover !== null && (
              <line
                x1={hoverX}
                y1={topY}
                x2={hoverX}
                y2={baseY}
                stroke="var(--accent)"
                strokeOpacity="0.65"
                strokeWidth="1"
                strokeDasharray="3 3"
                vectorEffect="non-scaling-stroke"
              />
            )}
          </svg>

          {/* Clean empty-state hint before traffic starts */}
          {!hasSamples && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <span className="rounded-lg bg-[var(--card)]/80 px-3 py-1 text-xs text-[var(--muted)]">
                {coreRunning ? "正在采集实时流量走势…" : "开启代理后将按秒绘制实时流量走势"}
              </span>
            </div>
          )}

          {/* Crisp hover dots sitting strictly on the spline & floating tooltip */}
          {validHover !== null && (
            <>
              <span
                className="pointer-events-none absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-[var(--card)] bg-[var(--sky)]"
                style={{
                  left: `${hoverLeftPct}%`,
                  top: `${(hoverDownY / vbHeight) * 100}%`,
                }}
              />
              <span
                className="pointer-events-none absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-[var(--card)] bg-[var(--coral)]"
                style={{
                  left: `${hoverLeftPct}%`,
                  top: `${(hoverUpY / vbHeight) * 100}%`,
                }}
              />
              <div
                className="pointer-events-none absolute top-2 z-20 min-w-[152px] rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-2 text-xs"
                style={{
                  boxShadow: "var(--shadow-popover)",
                  left: alignRight ? undefined : `calc(${Math.min(hoverLeftPct, 82)}% + 10px)`,
                  right: alignRight ? `calc(${100 - hoverLeftPct}% + 10px)` : undefined,
                }}
              >
                <div className="mb-1.5 flex items-center justify-between border-b border-[var(--line)] pb-1 text-[11px]">
                  <span className="text-[var(--muted)]">时间</span>
                  <span className="cc-mono font-semibold text-[var(--accent)]">
                    {formatClock(computed.tsSlice[validHover])}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="inline-flex items-center gap-1 text-[var(--coral)]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[var(--coral)]" />
                    上传
                  </span>
                  <span className="cc-mono font-medium text-[var(--text)]">
                    {formatRate(computed.upSlice[validHover])}
                  </span>
                </div>
                <div className="mt-1 flex items-center justify-between gap-3">
                  <span className="inline-flex items-center gap-1 text-[var(--sky)]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[var(--sky)]" />
                    下载
                  </span>
                  <span className="cc-mono font-medium text-[var(--text)]">
                    {formatRate(computed.downSlice[validHover])}
                  </span>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Bottom X-axis time labels aligned with plot area */}
      <div className="mt-1 flex items-center gap-2">
        <div className="w-[68px] shrink-0" aria-hidden="true" />
        <div className="flex min-w-0 flex-1 items-center justify-between text-[10px] cc-mono text-[var(--muted)]">
          {xTicks.map((label, idx) => (
            <span key={`${idx}-${label}`}>{label}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
