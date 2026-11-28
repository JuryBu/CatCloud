import {
  type AppConfig,
  DEFAULT_APP_CONFIG,
  type ResolvedTheme,
  type ThemeMode,
  type ThemeSchedule,
  catcloudApi,
  formatErrorMessage,
} from "../api/tauri";
import { ensureUiLocaleLoaded, normalizeUiLanguage } from "../i18n";
import type { NavRouteId, WindowMode } from "./types";

export const UI_PREFS_STORAGE_KEY = "catcloud.ui.prefs.v1";
export const ONBOARDING_PENDING_SYNC_KEY = "catcloud.onboarding.pending_sync.v1";

/* ============================================================================
 * Beijing-Time (UTC+8) 3-Segment Theme Scheduler
 * 07:00 - 18:30 -> light
 * 18:30 - 22:30 -> warm-dark
 * 22:30 - 07:00 -> midnight-blue
 * ============================================================================ */

function parseClockMinutes(hhmm: string, fallback: number): number {
  const m = /^(\d{1,2}):(\d{2})$/.exec(hhmm.trim());
  if (!m) return fallback;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h < 0 || h > 23 || min < 0 || min > 59) return fallback;
  return h * 60 + min;
}

export function getBeijingMinutes(now: Date = new Date()): number {
  const utcMinutes = now.getUTCHours() * 60 + now.getUTCMinutes();
  return (utcMinutes + 8 * 60) % 1440;
}

export function resolveThemeBySchedule(
  mode: ThemeMode,
  schedule: ThemeSchedule = DEFAULT_APP_CONFIG.personalization.theme_schedule,
  now: Date = new Date()
): ResolvedTheme {
  if (mode === "light") return "light";
  if (mode === "warm_dark") return "warm-dark";
  if (mode === "midnight_blue") return "midnight-blue";

  const bjt = getBeijingMinutes(now);
  const points: Array<{ min: number; theme: ResolvedTheme }> = [
    { min: parseClockMinutes(schedule.light_start, 7 * 60), theme: "light" },
    { min: parseClockMinutes(schedule.warm_dark_start, 18 * 60 + 30), theme: "warm-dark" },
    { min: parseClockMinutes(schedule.midnight_start, 22 * 60 + 30), theme: "midnight-blue" },
  ];
  points.sort((a, b) => a.min - b.min);

  let active = points[points.length - 1].theme;
  for (const pt of points) {
    if (bjt >= pt.min) {
      active = pt.theme;
    }
  }
  return active;
}

export function getBeijingTimeLabel(now: Date = new Date()): string {
  const bjt = getBeijingMinutes(now);
  const h = String(Math.floor(bjt / 60)).padStart(2, "0");
  const m = String(bjt % 60).padStart(2, "0");
  return `${h}:${m} BJT`;
}

/* ============================================================================
 * Location Hash & Local UI Preferences Helpers
 * ============================================================================ */

export function detectWindowModeFromLocation(): WindowMode {
  if (typeof window === "undefined") return "main";
  const hash = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  if (hash === "capsule") return "capsule";
  return "main";
}

export const VALID_ROUTES = new Set<NavRouteId>([
  "overview",
  "groups",
  "speedtest",
  "preaccel",
  "nodes",
  "rules",
  "logs",
  "ai",
  "settings",
]);

export const NAVIGATE_EVENT_ALLOWLIST = new Set<NavRouteId>([
  "overview",
  "nodes",
  "groups",
  "preaccel",
  "ai",
  "rules",
  "logs",
  "settings",
]);

export function normalizeAllowedNavRoute(rawNav: string | null | undefined): NavRouteId | null {
  if (typeof rawNav !== "string") return null;
  const candidate = rawNav.trim().toLowerCase();
  if (!candidate) return null;
  const normalized =
    candidate === "speedtest"
      ? "nodes"
      : candidate === "home"
        ? "overview"
        : candidate;
  return NAVIGATE_EVENT_ALLOWLIST.has(normalized as NavRouteId)
    ? (normalized as NavRouteId)
    : null;
}

export function detectNavFromHash(): NavRouteId {
  if (typeof window === "undefined") return "overview";
  const raw = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  if (raw === "speedtest") return "nodes";
  if (raw === "home") return "overview";
  return VALID_ROUTES.has(raw as NavRouteId) ? (raw as NavRouteId) : "overview";
}

export function hasExplicitRouteHash(): boolean {
  if (typeof window === "undefined") return false;
  const raw = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  return raw.length > 0 && (raw === "capsule" || VALID_ROUTES.has(raw as NavRouteId));
}

export function loadCachedUiPrefs(): Partial<AppConfig["personalization"]> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(UI_PREFS_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<AppConfig["personalization"]>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function saveCachedUiPrefs(p: AppConfig["personalization"]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      UI_PREFS_STORAGE_KEY,
      JSON.stringify({
        ui_language: normalizeUiLanguage(p.ui_language),
        theme_mode: p.theme_mode,
        theme_schedule: p.theme_schedule,
        tray_icon_mode: p.tray_icon_mode,
        animations_enabled: p.animations_enabled,
        mascot_enabled: p.mascot_enabled,
        sparkline_enabled: p.sparkline_enabled,
        wallpaper_opacity: p.wallpaper_opacity,
        glass_blur_px: p.glass_blur_px,
        onboarding_completed: p.onboarding_completed,
      })
    );
  } catch {
    /* ignore storage quota errors */
  }
}

export function hasPendingOnboardingSync(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(ONBOARDING_PENDING_SYNC_KEY) === "1";
  } catch {
    return false;
  }
}

export function setPendingOnboardingSync(pending: boolean): void {
  if (typeof window === "undefined") return;
  try {
    if (pending) {
      window.localStorage.setItem(ONBOARDING_PENDING_SYNC_KEY, "1");
    } else {
      window.localStorage.removeItem(ONBOARDING_PENDING_SYNC_KEY);
    }
  } catch {
    /* ignore storage quota errors */
  }
}

/* ============================================================================
 * Built-in Wallpaper Presets & Zero-Copy ObjectURL Wallpaper Lifecycle
 * ============================================================================ */

export function sanitizeCssUrl(raw: string): string {
  return raw.replace(/["\\\n\r]/g, "");
}

export const BUILTIN_WALLPAPER_PRESETS: ReadonlyArray<{
  id: string;
  label: string;
  cssBackground: string;
  previewStyle: string;
}> = [
  {
    id: "preset:sunset-cloud",
    label: "晚霞猫云",
    cssBackground:
      "radial-gradient(circle at 18% 20%, rgba(242, 165, 114, 0.55), transparent 52%), radial-gradient(circle at 82% 28%, rgba(132, 179, 232, 0.5), transparent 56%), linear-gradient(135deg, #2b2338 0%, #5c3e4f 45%, #c77d5c 100%)",
    previewStyle:
      "linear-gradient(135deg, #2b2338 0%, #5c3e4f 45%, #c77d5c 100%)",
  },
  {
    id: "preset:warm-paper",
    label: "晨光暖雾",
    cssBackground:
      "radial-gradient(circle at 22% 18%, rgba(236, 189, 128, 0.55), transparent 55%), radial-gradient(circle at 80% 78%, rgba(164, 191, 159, 0.45), transparent 55%), linear-gradient(135deg, #f8f1e4 0%, #eadac2 55%, #dfcbb0 100%)",
    previewStyle:
      "linear-gradient(135deg, #f8f1e4 0%, #eadac2 55%, #dfcbb0 100%)",
  },
  {
    id: "preset:moss-gold",
    label: "深苔流金",
    cssBackground:
      "radial-gradient(circle at 20% 25%, rgba(223, 183, 130, 0.35), transparent 50%), radial-gradient(circle at 78% 72%, rgba(130, 175, 145, 0.3), transparent 55%), linear-gradient(135deg, #121716 0%, #1d2624 52%, #2c251c 100%)",
    previewStyle:
      "linear-gradient(135deg, #121716 0%, #1d2624 52%, #2c251c 100%)",
  },
  {
    id: "preset:midnight-star",
    label: "午夜星海",
    cssBackground:
      "radial-gradient(circle at 24% 22%, rgba(96, 165, 250, 0.4), transparent 48%), radial-gradient(circle at 80% 76%, rgba(223, 183, 130, 0.28), transparent 52%), linear-gradient(135deg, #0b1224 0%, #162447 55%, #1e315c 100%)",
    previewStyle:
      "linear-gradient(135deg, #0b1224 0%, #162447 55%, #1e315c 100%)",
  },
];

export const SAFE_BITMAP_DATA_URL_RE = /^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i;
const BITMAP_DATA_URL_PARTS_RE = /^data:(image\/(?:png|jpe?g|webp|gif|bmp));base64,([\s\S]+)$/i;

interface ResolvedWallpaperEntry {
  rawPath: string;
  dataFingerprint: string;
  objectUrl: string | null;
  cssValue: string;
  previewUrl: string;
}

function computeDataUrlFingerprint(dataUrl: string): string {
  const len = dataUrl.length;
  if (len <= 128) return `${len}:${dataUrl}`;
  return `${len}:${dataUrl.slice(0, 64)}:${dataUrl.slice(len - 64)}`;
}

let resolvedWallpaperCache: ResolvedWallpaperEntry | null = null;
let wallpaperLoadSeq = 0;

export function isBuiltinWallpaperPreset(rawPath: string | null | undefined): boolean {
  const trimmed = rawPath?.trim() ?? "";
  if (!trimmed) return false;
  return BUILTIN_WALLPAPER_PRESETS.some((item) => item.id === trimmed);
}

export function bumpWallpaperLoadSeq(): number {
  wallpaperLoadSeq += 1;
  return wallpaperLoadSeq;
}

export function revokeObjectUrlSafe(url: string | null | undefined): void {
  if (!url || !url.startsWith("blob:")) return;
  if (typeof URL !== "undefined" && typeof URL.revokeObjectURL === "function") {
    try {
      URL.revokeObjectURL(url);
    } catch {
      /* ignore revoke failures in restricted runtimes */
    }
  }
}

/**
 * Decode a validated bitmap data URL into a single Blob-backed ObjectURL so
 * `--wallpaper-image` and `state.wallpaperPreviewUrl` share one reference
 * without duplicating megabyte-scale Base64 strings across DOM and React state.
 */
export function dataUrlToObjectUrl(dataUrl: string): string {
  if (
    typeof URL === "undefined" ||
    typeof URL.createObjectURL !== "function" ||
    typeof Blob === "undefined" ||
    typeof atob !== "function"
  ) {
    return dataUrl;
  }
  const match = BITMAP_DATA_URL_PARTS_RE.exec(dataUrl.trim());
  if (!match) return dataUrl;
  try {
    const mime = match[1].toLowerCase();
    const b64 = match[2].replace(/\s+/g, "");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: mime });
    return URL.createObjectURL(blob);
  } catch {
    return dataUrl;
  }
}

/**
 * Detach and return the previous cached ObjectURL without immediately revoking it.
 * Callers must first apply the replacement DOM/state URL, then call `revokeObjectUrlSafe`.
 */
export function detachCachedWallpaperObjectUrl(): string | null {
  const oldObjectUrl = resolvedWallpaperCache?.objectUrl ?? null;
  resolvedWallpaperCache = null;
  return oldObjectUrl;
}

export function disposeWallpaperCache(): void {
  wallpaperLoadSeq += 1;
  const oldObjectUrl = detachCachedWallpaperObjectUrl();
  revokeObjectUrlSafe(oldObjectUrl);
}

export function resolveImmediateWallpaperCss(rawPath: string | null | undefined): string | null {
  const trimmed = rawPath?.trim() ?? "";
  if (!trimmed) return null;
  const preset = BUILTIN_WALLPAPER_PRESETS.find((item) => item.id === trimmed);
  if (preset) return preset.cssBackground;
  if (resolvedWallpaperCache && resolvedWallpaperCache.rawPath === trimmed) {
    return resolvedWallpaperCache.cssValue;
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return `url("${sanitizeCssUrl(trimmed)}")`;
  }
  if (SAFE_BITMAP_DATA_URL_RE.test(trimmed)) {
    // Preview mode may store a bitmap data URL directly in wallpaper_path;
    // return it immediately if not yet converted, and ensureLocalWallpaperLoaded
    // upgrades it to a shared Blob ObjectURL.
    return `url("${sanitizeCssUrl(trimmed)}")`;
  }
  return null;
}

/**
 * Apply theme, animation flags, and wallpaper CSS variables to `document.documentElement`.
 * Note: wallpaper CSS variables are intentionally kept intact while `document.hidden === true`
 * to prevent solid-color flashes when restoring from minimize/tray.
 */
export function applyPersonalizationToDom(
  resolvedTheme: ResolvedTheme,
  p: AppConfig["personalization"],
  windowMode: WindowMode,
  explicitCssValue?: string | null
): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  const lang = normalizeUiLanguage(p.ui_language);
  root.setAttribute("lang", lang);
  if (lang !== "zh-CN") {
    void ensureUiLocaleLoaded(lang);
  }
  root.setAttribute("data-theme", resolvedTheme);
  root.setAttribute("data-animations", p.animations_enabled ? "on" : "off");
  if (windowMode === "capsule") {
    root.setAttribute("data-window", "capsule");
    root.setAttribute("data-wallpaper", "off");
    root.setAttribute("data-glass", "off");
    root.style.setProperty("--wallpaper-image", "none");
    root.style.setProperty("--wallpaper-opacity", "0");
    root.style.setProperty("--surface-alpha", "1");
    root.style.setProperty("--card-alpha", "1");
    root.style.setProperty("--glass-blur", "0px");
    return;
  }
  root.removeAttribute("data-window");

  const rawPath = p.wallpaper_path?.trim() ?? "";
  const cssBg = explicitCssValue ?? resolveImmediateWallpaperCss(rawPath);
  if (rawPath && cssBg) {
    const opacity = Math.max(0.05, Math.min(0.65, p.wallpaper_opacity));
    const blurPx = Math.max(0, Math.min(24, Math.round(p.glass_blur_px)));
    root.setAttribute("data-wallpaper", "on");
    root.setAttribute("data-glass", blurPx > 0 ? "on" : "off");
    root.style.setProperty("--wallpaper-image", cssBg);
    root.style.setProperty("--wallpaper-opacity", String(opacity));
    root.style.setProperty("--surface-alpha", blurPx > 0 ? "0.82" : "0.90");
    root.style.setProperty("--card-alpha", blurPx > 0 ? "0.78" : "0.88");
    root.style.setProperty("--glass-blur", `${blurPx}px`);
  } else {
    root.setAttribute("data-wallpaper", "off");
    root.setAttribute("data-glass", "off");
    root.style.setProperty("--wallpaper-image", "none");
    root.style.setProperty("--wallpaper-opacity", "0");
    root.style.setProperty("--surface-alpha", "1");
    root.style.setProperty("--card-alpha", "1");
    root.style.setProperty("--glass-blur", "0px");
  }
}

export interface WallpaperStoreHooks {
  getCurrentWallpaperPath: () => string | null | undefined;
  setWallpaperState: (patch: {
    wallpaperPreviewUrl?: string | null;
    wallpaperError?: string | null;
  }) => void;
}

/**
 * Promote a bitmap data URL into the shared Blob ObjectURL cache, attach it to
 * DOM and React state FIRST, and only then revoke the previous ObjectURL so
 * rapid image swaps never flash a broken frame.
 */
export function commitDataUrlWallpaper(params: {
  rawPath: string;
  dataUrl: string;
  resolvedTheme: ResolvedTheme;
  personalization: AppConfig["personalization"];
  windowMode: WindowMode;
  onCommitState: (previewUrl: string) => void;
}): string {
  const { rawPath, dataUrl, resolvedTheme, personalization, windowMode, onCommitState } = params;
  const dataFingerprint = computeDataUrlFingerprint(dataUrl);
  if (
    resolvedWallpaperCache &&
    resolvedWallpaperCache.rawPath === rawPath &&
    resolvedWallpaperCache.dataFingerprint === dataFingerprint
  ) {
    applyPersonalizationToDom(
      resolvedTheme,
      personalization,
      windowMode,
      resolvedWallpaperCache.cssValue
    );
    onCommitState(resolvedWallpaperCache.previewUrl);
    return resolvedWallpaperCache.previewUrl;
  }

  const nextUrl = dataUrlToObjectUrl(dataUrl);
  const nextCssValue = `url("${sanitizeCssUrl(nextUrl)}")`;
  const oldObjectUrl = resolvedWallpaperCache?.objectUrl ?? null;

  resolvedWallpaperCache = {
    rawPath,
    dataFingerprint,
    objectUrl: nextUrl.startsWith("blob:") ? nextUrl : null,
    cssValue: nextCssValue,
    previewUrl: nextUrl,
  };

  // Write the new ObjectURL into DOM and state BEFORE revoking the previous URL.
  applyPersonalizationToDom(resolvedTheme, personalization, windowMode, nextCssValue);
  onCommitState(nextUrl);

  if (oldObjectUrl && oldObjectUrl !== nextUrl) {
    revokeObjectUrlSafe(oldObjectUrl);
  }
  return nextUrl;
}

export async function ensureLocalWallpaperLoaded(
  rawPath: string | null | undefined,
  resolvedTheme: ResolvedTheme,
  p: AppConfig["personalization"],
  windowMode: WindowMode,
  hooks: WallpaperStoreHooks
): Promise<void> {
  if (windowMode === "capsule") {
    applyPersonalizationToDom(
      resolvedTheme,
      { ...p, wallpaper_path: null, glass_blur_px: 0 },
      windowMode,
      null
    );
    return;
  }

  const trimmed = rawPath?.trim() ?? "";

  // Empty wallpaper path: clear DOM/state first, then revoke any cached ObjectURL.
  if (!trimmed) {
    bumpWallpaperLoadSeq();
    const oldObjectUrl = detachCachedWallpaperObjectUrl();
    applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
    hooks.setWallpaperState({ wallpaperPreviewUrl: null, wallpaperError: null });
    revokeObjectUrlSafe(oldObjectUrl);
    return;
  }

  // Reject unsupported data URL formats (e.g. SVG) and release stale cache.
  if (/^data:/i.test(trimmed) && !SAFE_BITMAP_DATA_URL_RE.test(trimmed)) {
    bumpWallpaperLoadSeq();
    const oldObjectUrl = detachCachedWallpaperObjectUrl();
    applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
    hooks.setWallpaperState({
      wallpaperPreviewUrl: null,
      wallpaperError: "不支持此图片格式，请选择 PNG、JPG、WebP、GIF 或 BMP 图片",
    });
    revokeObjectUrlSafe(oldObjectUrl);
    return;
  }

  // Built-in presets or remote HTTP(S) URLs: clear local ObjectURL cache and preview URL.
  if (isBuiltinWallpaperPreset(trimmed) || /^https?:\/\//i.test(trimmed)) {
    bumpWallpaperLoadSeq();
    const oldObjectUrl = detachCachedWallpaperObjectUrl();
    applyPersonalizationToDom(resolvedTheme, p, windowMode);
    hooks.setWallpaperState({ wallpaperPreviewUrl: null, wallpaperError: null });
    revokeObjectUrlSafe(oldObjectUrl);
    return;
  }

  // Inline bitmap data URL (preview mode): convert once into a shared Blob ObjectURL.
  if (SAFE_BITMAP_DATA_URL_RE.test(trimmed)) {
    bumpWallpaperLoadSeq();
    commitDataUrlWallpaper({
      rawPath: trimmed,
      dataUrl: trimmed,
      resolvedTheme,
      personalization: p,
      windowMode,
      onCommitState: (previewUrl) => {
        hooks.setWallpaperState({ wallpaperPreviewUrl: previewUrl, wallpaperError: null });
      },
    });
    return;
  }

  // Already resolved in cache for the exact same local file path.
  if (resolvedWallpaperCache && resolvedWallpaperCache.rawPath === trimmed) {
    applyPersonalizationToDom(resolvedTheme, p, windowMode, resolvedWallpaperCache.cssValue);
    hooks.setWallpaperState({
      wallpaperPreviewUrl: resolvedWallpaperCache.previewUrl,
      wallpaperError: null,
    });
    return;
  }

  hooks.setWallpaperState({ wallpaperError: null });
  const mySeq = bumpWallpaperLoadSeq();
  try {
    const dataUrl = await catcloudApi.resolveWallpaperDataUrl(trimmed);
    if (
      mySeq !== wallpaperLoadSeq ||
      (hooks.getCurrentWallpaperPath()?.trim() ?? "") !== trimmed
    ) {
      return;
    }
    if (!dataUrl || !SAFE_BITMAP_DATA_URL_RE.test(dataUrl)) {
      const oldObjectUrl = detachCachedWallpaperObjectUrl();
      applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
      hooks.setWallpaperState({
        wallpaperPreviewUrl: null,
        wallpaperError:
          "本地壁纸加载失败：原图片可能已移动、删除或格式不受支持，可重新选择或恢复纯色背景",
      });
      revokeObjectUrlSafe(oldObjectUrl);
      return;
    }
    commitDataUrlWallpaper({
      rawPath: trimmed,
      dataUrl,
      resolvedTheme,
      personalization: p,
      windowMode,
      onCommitState: (previewUrl) => {
        hooks.setWallpaperState({ wallpaperPreviewUrl: previewUrl, wallpaperError: null });
      },
    });
  } catch (err) {
    if (
      mySeq !== wallpaperLoadSeq ||
      (hooks.getCurrentWallpaperPath()?.trim() ?? "") !== trimmed
    ) {
      return;
    }
    const detail = formatErrorMessage(err);
    const oldObjectUrl = detachCachedWallpaperObjectUrl();
    applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
    hooks.setWallpaperState({
      wallpaperPreviewUrl: null,
      wallpaperError: detail
        ? `本地壁纸加载失败（${detail}），可重新选择图片或恢复纯色背景`
        : "本地壁纸加载失败：无法读取图片文件，可重新选择或恢复纯色背景",
    });
    revokeObjectUrlSafe(oldObjectUrl);
  }
}
