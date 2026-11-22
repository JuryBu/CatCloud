import { useEffect, useRef, useState } from "react";
import rawSpriteSheet from "../assets/mascotSprites.json";
import { type MascotState, useAppSelector } from "../store/appStore";

export type { MascotState };

interface SpriteStateRaw {
  w: number;
  h: number;
  frames: string[][];
}

interface SpriteSheetSchema {
  format: string;
  palette: Record<string, string | null>;
  timings: {
    idle: number[];
    idleOrder?: number[];
    searching: number[];
    thinking: number[];
    typing: number[];
    approval: number[];
    complete: number[];
  };
  states: Record<MascotState, SpriteStateRaw>;
}

interface HorizontalSpan {
  color: string;
  x: number;
  y: number;
  len: number;
}

interface CompiledState {
  w: number;
  h: number;
  frameSpans: HorizontalSpan[][];
  stepFrames: number[];
  stepDurations: number[];
}

export const MASCOT_STATES: readonly MascotState[] = [
  "idle",
  "searching",
  "thinking",
  "typing",
  "approval",
  "complete",
] as const;

export const MASCOT_STATE_LABELS: Record<MascotState, string> = {
  idle: "奶油猫饼待机",
  searching: "放大镜测速中",
  thinking: "策略思考中",
  typing: "写入配置中",
  approval: "等待确认",
  complete: "执行完成",
};

const sheet = rawSpriteSheet as unknown as SpriteSheetSchema;
const compiledCache = new Map<MascotState, CompiledState>();

function compileState(state: MascotState): CompiledState {
  const hit = compiledCache.get(state);
  if (hit) return hit;

  const raw = sheet.states[state];
  const palette = sheet.palette;
  const frameSpans: HorizontalSpan[][] = raw.frames.map((grid) => {
    const spans: HorizontalSpan[] = [];
    for (let y = 0; y < grid.length; y++) {
      const row = grid[y];
      let x = 0;
      while (x < row.length) {
        const key = row[x];
        const color = palette[key] ?? null;
        if (!color) {
          x += 1;
          continue;
        }
        let end = x + 1;
        while (end < row.length && row[end] === key) {
          end += 1;
        }
        spans.push({ color, x, y, len: end - x });
        x = end;
      }
    }
    return spans;
  });

  const rawTimings = sheet.timings[state];
  const frameCount = Math.max(1, frameSpans.length);
  let stepFrames: number[];
  let stepDurations: number[];

  if (state === "idle" && Array.isArray(sheet.timings.idleOrder) && sheet.timings.idleOrder.length > 0) {
    stepFrames = sheet.timings.idleOrder.map((idx) => Math.max(0, Math.min(frameCount - 1, idx)));
    stepDurations = stepFrames.map((_, i) => rawTimings[i] ?? rawTimings[rawTimings.length - 1] ?? 400);
  } else {
    stepFrames = Array.from({ length: frameCount }, (_, i) => i);
    stepDurations = stepFrames.map((_, i) => rawTimings[i] ?? rawTimings[0] ?? 400);
  }

  const compiled: CompiledState = {
    w: raw.w,
    h: raw.h,
    frameSpans,
    stepFrames,
    stepDurations,
  };
  compiledCache.set(state, compiled);
  return compiled;
}

export function getMascotDimensions(state: MascotState, scale = 2): { width: number; height: number } {
  const intScale = Math.max(1, Math.round(scale));
  const spec = sheet.states[state];
  return {
    width: spec.w * intScale,
    height: spec.h * intScale,
  };
}

export interface MascotSpriteProps {
  state: MascotState;
  /** Integer pixel scale factor (e.g. 2 = 2x crisp pixels). Non-integers are rounded to nearest >= 1. */
  scale?: number;
  /** Optional local override for animation playback; defaults to global store animationsEnabled && mascotEnabled. */
  animationsEnabled?: boolean;
  className?: string;
  title?: string;
}

export function MascotSprite({
  state,
  scale = 2,
  animationsEnabled,
  className = "",
  title,
}: MascotSpriteProps) {
  const globalAnimations = useAppSelector(
    (s) => s.config.personalization.animations_enabled && s.config.personalization.mascot_enabled
  );
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const timerRef = useRef<number | null>(null);
  const stepRef = useRef<number>(0);

  const [isVisible, setIsVisible] = useState<boolean>(() =>
    typeof document === "undefined" ? true : document.visibilityState === "visible"
  );
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(() =>
    typeof window === "undefined" || !window.matchMedia
      ? false
      : window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );

  const intScale = Math.max(1, Math.round(scale));
  const compiled = compileState(state);
  const width = compiled.w * intScale;
  const height = compiled.h * intScale;
  const effectiveAnimated =
    (animationsEnabled ?? globalAnimations) &&
    !prefersReducedMotion &&
    isVisible &&
    compiled.stepFrames.length > 1;

  // Listen to document.visibilityState and prefers-reduced-motion
  useEffect(() => {
    const onVisibility = () => {
      setIsVisible(document.visibilityState === "visible");
    };
    document.addEventListener("visibilitychange", onVisibility);

    let mediaQuery: MediaQueryList | null = null;
    const onMotionChange = (ev: MediaQueryListEvent) => {
      setPrefersReducedMotion(ev.matches);
    };
    if (typeof window !== "undefined" && window.matchMedia) {
      mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      setPrefersReducedMotion(mediaQuery.matches);
      mediaQuery.addEventListener("change", onMotionChange);
    }

    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      mediaQuery?.removeEventListener("change", onMotionChange);
    };
  }, []);

  // Draw crisp integer-scaled frame & strictly clear timer when hidden/disabled/static
  useEffect(() => {
    const clearScheduledTimer = () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };

    clearScheduledTimer();
    stepRef.current = 0;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    const drawStep = (stepIdx: number) => {
      const frameIndex = compiled.stepFrames[stepIdx % compiled.stepFrames.length] ?? 0;
      const spans = compiled.frameSpans[frameIndex] ?? compiled.frameSpans[0];
      ctx.imageSmoothingEnabled = false;
      ctx.clearRect(0, 0, width, height);
      for (let i = 0; i < spans.length; i++) {
        const sp = spans[i];
        ctx.fillStyle = sp.color;
        ctx.fillRect(sp.x * intScale, sp.y * intScale, sp.len * intScale, intScale);
      }
    };

    // Always paint initial frame once
    drawStep(0);

    // 100% zero timer / zero CPU & GPU overhead when hidden, disabled, or single-frame
    if (!effectiveAnimated) {
      return clearScheduledTimer;
    }

    let cancelled = false;
    const scheduleNext = () => {
      if (cancelled || document.visibilityState !== "visible") {
        clearScheduledTimer();
        return;
      }
      const delay = compiled.stepDurations[stepRef.current] ?? 400;
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        if (cancelled || document.visibilityState !== "visible") return;
        stepRef.current = (stepRef.current + 1) % compiled.stepFrames.length;
        drawStep(stepRef.current);
        scheduleNext();
      }, delay);
    };

    scheduleNext();

    return () => {
      cancelled = true;
      clearScheduledTimer();
    };
  }, [compiled, effectiveAnimated, height, intScale, width]);

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      style={{ width: `${width}px`, height: `${height}px` }}
      className={`cc-pixelated block shrink-0 ${className}`}
      role="img"
      aria-label={title ?? MASCOT_STATE_LABELS[state]}
      title={title ?? MASCOT_STATE_LABELS[state]}
    />
  );
}
