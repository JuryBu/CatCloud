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

export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "0 B/s";
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb < 100 ? kb.toFixed(1) : Math.round(kb)} KB/s`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(2)} MB/s`;
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

interface SmoothPathResult {
  linePath: string;
  areaPath: string;
  xs: Float64Array;
  ys: Float64Array;
}

/**
 * Single-<path> monotonic-friendly midpoint quadratic Bezier builder.
 * Never overshoots below the baseline and emits only 1 stroke <path> + 1 area <path>.
 */
function buildSingleSvgPath(
  values: Float64Array,
  count: number,
  maxValue: number,
  width: number,
  height: number,
  padX: number,
  padTop: number,
  padBottom: number
): SmoothPathResult {
  const xs = new Float64Array(count);
  const ys = new Float64Array(count);
  if (count === 0) {
    return { linePath: "", areaPath: "", xs, ys };
  }

  const innerW = Math.max(1, width - padX * 2);
  const innerH = Math.max(1, height - padTop - padBottom);
  const baseY = height - padBottom;
  const safeMax = Math.max(maxValue, 1024);

  for (let i = 0; i < count; i++) {
    const x = count === 1 ? padX + innerW : padX + (i / (count - 1)) * innerW;
    const ratio = Math.min(1, Math.max(0, values[i] / safeMax));
    const y = baseY - ratio * innerH;
    xs[i] = x;
    ys[i] = y;
  }

  if (count === 1) {
    const linePath = `M${padX.toFixed(1)},${ys[0].toFixed(1)} L${xs[0].toFixed(1)},${ys[0].toFixed(1)}`;
    const areaPath = `${linePath} L${xs[0].toFixed(1)},${baseY.toFixed(1)} L${padX.toFixed(1)},${baseY.toFixed(1)} Z`;
    return { linePath, areaPath, xs, ys };
  }

  const parts: string[] = [`M${xs[0].toFixed(1)},${ys[0].toFixed(1)}`];
  if (count === 2) {
    parts.push(`L${xs[1].toFixed(1)},${ys[1].toFixed(1)}`);
  } else {
    for (let i = 1; i < count - 1; i++) {
      const mx = (xs[i] + xs[i + 1]) * 0.5;
      const my = (ys[i] + ys[i + 1]) * 0.5;
      parts.push(`Q${xs[i].toFixed(1)},${ys[i].toFixed(1)} ${mx.toFixed(1)},${my.toFixed(1)}`);
    }
    const last = count - 1;
    parts.push(`L${xs[last].toFixed(1)},${ys[last].toFixed(1)}`);
  }

  const linePath = parts.join(" ");
  const lastX = xs[count - 1].toFixed(1);
  const firstX = xs[0].toFixed(1);
  const areaPath = `${linePath} L${lastX},${baseY.toFixed(1)} L${firstX},${baseY.toFixed(1)} Z`;
  return { linePath, areaPath, xs, ys };
}

export interface TrafficSparklineProps {
  variant: "full" | "mini";
  /** Optional custom ring buffer; defaults to shared 300-point store buffer. */
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
  const sparklineEnabled = useAppSelector(
    (s) => s.config.personalization.animations_enabled && s.config.personalization.sparkline_enabled
  );

  const [isVisible, setIsVisible] = useState<boolean>(() =>
    typeof document === "undefined" ? true : document.visibilityState === "visible"
  );
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
  const vbWidth = isFull ? 600 : 196;
  const vbHeight = isFull ? 168 : 42;
  const padX = isFull ? 6 : 2;
  const padTop = isFull ? 14 : 4;
  const padBottom = isFull ? 10 : 3;
  const windowPoints = isFull ? 300 : 60;

  // Snapshot slice from the Float64Array ring buffer only when effectiveVersion advances
  const computed = useMemo(() => {
    const total = ring.length;
    const count = Math.min(total, windowPoints);
    const startOffset = total - count;
    const upSlice = new Float64Array(count);
    const downSlice = new Float64Array(count);
    const tsSlice = new Float64Array(count);

    let peak = 64 * 1024; // minimum 64 KB/s scale floor so idle noise doesn't look huge
    for (let i = 0; i < count; i++) {
      const idx = startOffset + i;
      const u = ring.upAt(idx);
      const d = ring.downAt(idx);
      upSlice[i] = u;
      downSlice[i] = d;
      tsSlice[i] = ring.tsAt(idx);
      if (u > peak) peak = u;
      if (d > peak) peak = d;
    }

    const scaleMax = peak * 1.15;
    const downGeom = buildSingleSvgPath(
      downSlice,
      count,
      scaleMax,
      vbWidth,
      vbHeight,
      padX,
      padTop,
      padBottom
    );
    const upGeom = buildSingleSvgPath(
      upSlice,
      count,
      scaleMax,
      vbWidth,
      vbHeight,
      padX,
      padTop,
      padBottom
    );

    return {
      count,
      scaleMax,
      upSlice,
      downSlice,
      tsSlice,
      upGeom,
      downGeom,
      version: effectiveVersion,
    };
  }, [effectiveVersion, padBottom, padTop, padX, ring, vbHeight, vbWidth, windowPoints]);

  const handleMouseMove = (ev: MouseEvent<SVGSVGElement>) => {
    if (!isFull || computed.count === 0) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return;
    const ratio = Math.min(1, Math.max(0, (ev.clientX - rect.left) / rect.width));
    const idx = Math.round(ratio * (computed.count - 1));
    setHoverIdx(idx);
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
            ? "曲线动效已暂停（低功耗模式）"
            : `近 2 分钟实时波形 · 内核内存 ${latest.memory_mb.toFixed(1)} MB`
        }
      >
        <div className="mb-1.5 flex items-center justify-between text-[11px] text-[var(--muted)]">
          <span className="font-medium tracking-wide">实时流量</span>
          {!sparklineEnabled ? (
            <span className="inline-flex items-center gap-1 text-[10px] text-[var(--amber)]">
              <Pause className="h-2.5 w-2.5" />
              静止
            </span>
          ) : (
            <span className="cc-mono text-[10px] text-[var(--muted)]">
              {latest.connections} 连接
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

  // Full 10-minute homepage sparkline with hover tooltip (HH:MM:SS + up/down)
  const validHover =
    hoverIdx !== null && hoverIdx >= 0 && hoverIdx < computed.count ? hoverIdx : null;
  const hoverX = validHover !== null ? computed.downGeom.xs[validHover] : 0;
  const hoverDownY = validHover !== null ? computed.downGeom.ys[validHover] : 0;
  const hoverUpY = validHover !== null ? computed.upGeom.ys[validHover] : 0;
  const hoverLeftPct = validHover !== null ? (hoverX / vbWidth) * 100 : 0;
  const alignRight = hoverLeftPct > 68;

  return (
    <div className={`cc-card cc-glass rounded-2xl p-4 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <h2 className="text-sm font-semibold tracking-tight text-[var(--text)]">
            10 分钟实时流量曲线
          </h2>
          <span className="rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--muted)] cc-mono">
            {computed.count}/300 pts
          </span>
          {!sparklineEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--amber)]">
              <Pause className="h-3 w-3" />
              曲线重绘已暂停
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
          <div className="hidden items-center gap-1 text-[11px] text-[var(--muted)] sm:flex">
            <span>量程</span>
            <span className="cc-mono">{formatRate(computed.scaleMax)}</span>
          </div>
        </div>
      </div>

      <div className="relative h-[168px] w-full">
        {/* Subtle horizontal reference labels */}
        <div className="pointer-events-none absolute inset-y-2 left-1 z-10 flex flex-col justify-between text-[10px] cc-mono text-[var(--muted)]/80">
          <span>{formatRate(computed.scaleMax)}</span>
          <span>{formatRate(computed.scaleMax * 0.5)}</span>
          <span>0</span>
        </div>

        <svg
          ref={svgRef}
          viewBox={`0 0 ${vbWidth} ${vbHeight}`}
          preserveAspectRatio="none"
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          className="block h-full w-full cursor-crosshair select-none"
          role="img"
          aria-label="10 分钟实时上传与下载流量曲线"
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

          {/* 3 lightweight horizontal gridlines */}
          <line
            x1={padX}
            y1={padTop}
            x2={vbWidth - padX}
            y2={padTop}
            stroke="var(--line)"
            strokeOpacity="0.45"
            strokeDasharray="3 4"
            vectorEffect="non-scaling-stroke"
          />
          <line
            x1={padX}
            y1={(padTop + (vbHeight - padBottom)) * 0.5}
            x2={vbWidth - padX}
            y2={(padTop + (vbHeight - padBottom)) * 0.5}
            stroke="var(--line)"
            strokeOpacity="0.45"
            strokeDasharray="3 4"
            vectorEffect="non-scaling-stroke"
          />
          <line
            x1={padX}
            y1={vbHeight - padBottom}
            x2={vbWidth - padX}
            y2={vbHeight - padBottom}
            stroke="var(--line)"
            strokeOpacity="0.7"
            vectorEffect="non-scaling-stroke"
          />

          {/* Area fills (1 path each) */}
          {computed.downGeom.areaPath && (
            <path d={computed.downGeom.areaPath} fill={`url(#${gradDownId})`} />
          )}
          {computed.upGeom.areaPath && (
            <path d={computed.upGeom.areaPath} fill={`url(#${gradUpId})`} />
          )}

          {/* Smooth single-path strokes */}
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
              y1={padTop}
              x2={hoverX}
              y2={vbHeight - padBottom}
              stroke="var(--accent)"
              strokeOpacity="0.65"
              strokeWidth="1"
              strokeDasharray="3 3"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </svg>

        {/* Crisp non-distorted hover dots & floating tooltip */}
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
              className="pointer-events-none absolute top-2 z-20 min-w-[144px] rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-2 text-xs"
              style={{
                boxShadow: "var(--shadow-popover)",
                left: alignRight ? undefined : `calc(${Math.min(hoverLeftPct, 82)}% + 10px)`,
                right: alignRight ? `calc(${100 - hoverLeftPct}% + 10px)` : undefined,
              }}
            >
              <div className="mb-1 border-b border-[var(--line)] pb-1 cc-mono text-[11px] font-semibold text-[var(--accent)]">
                {formatClock(computed.tsSlice[validHover])}
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-[var(--coral)]">↑ 上传</span>
                <span className="cc-mono font-medium text-[var(--text)]">
                  {formatRate(computed.upSlice[validHover])}
                </span>
              </div>
              <div className="mt-0.5 flex items-center justify-between gap-3">
                <span className="text-[var(--sky)]">↓ 下载</span>
                <span className="cc-mono font-medium text-[var(--text)]">
                  {formatRate(computed.downSlice[validHover])}
                </span>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
