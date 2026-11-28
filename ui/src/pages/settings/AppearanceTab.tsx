import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Image,
  Languages,
  RotateCcw,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { AppConfig, ResolvedTheme, TrayIconMode } from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import { UI_LANGUAGE_OPTIONS, type UiLanguage, type useUiDict } from "../../i18n";

type UiDict = ReturnType<typeof useUiDict>;
import {
  BUILTIN_WALLPAPER_PRESETS,
  appActions,
  getBeijingTimeLabel,
} from "../../store/appStore";
import { BTN_CLS, Card, INPUT_CLS, SegButtons, SwitchRow } from "./SettingsPrimitives";
import {
  RESOLVED_THEME_LABELS,
  THEME_CARDS,
  extractWallpaperLabel,
} from "./settingsPatch";

export interface AppearanceTabProps {
  uiLang: UiLanguage;
  dict: UiDict;
  personalization: AppConfig["personalization"];
  resolvedTheme: ResolvedTheme;
  wallpaperPreviewUrl: string | null;
  wallpaperError: string | null;
}

export function AppearanceTab({
  uiLang,
  dict,
  personalization: p,
  resolvedTheme,
  wallpaperPreviewUrl,
  wallpaperError,
}: AppearanceTabProps) {
  const [pickingWallpaper, setPickingWallpaper] = useState(false);
  const [showUrlInput, setShowUrlInput] = useState(false);
  const [wallpaperUrlInput, setWallpaperUrlInput] = useState(() => {
    const raw = p.wallpaper_path?.trim() ?? "";
    return /^https?:\/\//i.test(raw) ? raw : "";
  });
  const [imgLoadFailed, setImgLoadFailed] = useState(false);

  const sliderCommitTimerRef = useRef<number | null>(null);
  const pendingSliderPatchRef = useRef<Partial<AppConfig["personalization"]>>({});

  useEffect(() => {
    return () => {
      if (sliderCommitTimerRef.current !== null) {
        window.clearTimeout(sliderCommitTimerRef.current);
        sliderCommitTimerRef.current = null;
      }
      const pending = pendingSliderPatchRef.current;
      if (Object.keys(pending).length > 0) {
        pendingSliderPatchRef.current = {};
        void appActions.updatePersonalization(pending);
      }
    };
  }, []);

  useEffect(() => {
    const raw = p.wallpaper_path?.trim() ?? "";
    setImgLoadFailed(false);
    if (/^https?:\/\//i.test(raw)) {
      setWallpaperUrlInput(raw);
    } else if (!raw) {
      setWallpaperUrlInput("");
    }
  }, [p.wallpaper_path]);

  const commitSliderPersonalization = () => {
    if (sliderCommitTimerRef.current !== null) {
      window.clearTimeout(sliderCommitTimerRef.current);
      sliderCommitTimerRef.current = null;
    }
    const pending = pendingSliderPatchRef.current;
    if (Object.keys(pending).length === 0) return;
    pendingSliderPatchRef.current = {};
    void appActions.updatePersonalization(pending);
  };

  const handleSliderPreview = (patch: Partial<AppConfig["personalization"]>) => {
    pendingSliderPatchRef.current = {
      ...pendingSliderPatchRef.current,
      ...patch,
    };
    appActions.previewPersonalization(patch);
    if (sliderCommitTimerRef.current !== null) {
      window.clearTimeout(sliderCommitTimerRef.current);
    }
    sliderCommitTimerRef.current = window.setTimeout(() => {
      commitSliderPersonalization();
    }, 250);
  };

  const handlePickWallpaper = async () => {
    if (pickingWallpaper) return;
    setPickingWallpaper(true);
    try {
      await appActions.pickWallpaperImage();
    } finally {
      setPickingWallpaper(false);
    }
  };

  const handleApplyWallpaperUrl = async () => {
    const trimmed = wallpaperUrlInput.trim();
    if (!trimmed) {
      await appActions.setWallpaperPath(null, "已恢复纯色背景");
      return;
    }
    if (!/^(https?:\/\/|data:image\/(?:png|jpe?g|webp|gif|bmp);base64,)/i.test(trimmed)) {
      appActions.showToast("请输入以 http:// 或 https:// 开头的图片链接", "warn");
      return;
    }
    setImgLoadFailed(false);
    await appActions.setWallpaperPath(trimmed, "已更换为网络图片壁纸");
  };

  const uiLanguageSelectOptions = useMemo(
    () =>
      UI_LANGUAGE_OPTIONS.map((item) => ({
        value: item.value,
        label: item.optionLabel,
      })),
    []
  );

  const rawWallpaper = p.wallpaper_path?.trim() ?? "";
  const hasWallpaper = rawWallpaper.length > 0;
  const activePreset =
    BUILTIN_WALLPAPER_PRESETS.find((preset) => preset.id === rawWallpaper) ?? null;
  const isDirectHttpImageUrl = /^https?:\/\//i.test(rawWallpaper);
  const isDirectDataImageUrl = /^data:image\/(?:png|jpe?g|webp|gif|bmp);base64,/i.test(rawWallpaper);
  const wallpaperThumbSrc =
    !hasWallpaper || activePreset
      ? null
      : isDirectHttpImageUrl
        ? rawWallpaper
        : isDirectDataImageUrl
          ? wallpaperPreviewUrl ?? rawWallpaper
          : wallpaperPreviewUrl;
  const effectiveWallpaperError =
    wallpaperError || (imgLoadFailed ? "背景图片加载失败，请检查链接或重新选择图片" : null);
  const currentThemeName = RESOLVED_THEME_LABELS[resolvedTheme];
  const beijingClock = getBeijingTimeLabel().replace(" BJT", "");

  return (
    <div className="space-y-4">
      {/* Interface Language Selector Row */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <Languages className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-[var(--text)]">
              {dict.settings.languageLabel}
              {uiLang !== "en" && (
                <span className="ml-1.5 font-normal text-[var(--muted)]">/ Language</span>
              )}
            </div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">{dict.settings.languageDesc}</p>
          </div>
        </div>
        <AppSelect
          aria-label={`${dict.settings.languageLabel} / Language`}
          size="sm"
          value={uiLang}
          onChange={(v) => void appActions.setUiLanguage(v as UiLanguage)}
          options={uiLanguageSelectOptions}
          className="min-w-[220px]"
        />
      </section>

      <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-2">
        {/* Theme Palette 4 Visual Cards */}
        <Card title="主题配色" sub={`当前生效：${currentThemeName} · 点选即刻换肤`}>
          <div className="grid grid-cols-2 gap-2.5">
            {THEME_CARDS.map((item) => {
              const selected = p.theme_mode === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => void appActions.setThemeMode(item.id)}
                  aria-pressed={selected}
                  className="group relative flex flex-col overflow-hidden rounded-2xl border p-2.5 text-left transition-all"
                  style={{
                    borderColor: selected ? "var(--accent)" : "var(--line)",
                    backgroundColor: selected ? "var(--accent-soft)" : "var(--surface)",
                    boxShadow: selected ? "0 0 0 1px var(--accent)" : "none",
                  }}
                >
                  {/* Visual mini-window swatch */}
                  <div
                    className="relative mb-2 h-14 w-full overflow-hidden rounded-xl border border-black/15"
                    style={{ background: item.bg }}
                  >
                    {item.isAuto ? (
                      <div className="flex h-full w-full items-end justify-between p-2">
                        <span className="rounded-md bg-black/35 px-1.5 py-0.5 text-[10px] font-medium text-white backdrop-blur-xs">
                          日 / 暮 / 夜
                        </span>
                        <div className="flex items-center gap-1">
                          <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#f6f3ec]" />
                          <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#191c1c]" />
                          <span className="h-2.5 w-2.5 rounded-full border border-white/50 bg-[#16213e]" />
                        </div>
                      </div>
                    ) : (
                      <div className="flex h-full w-full">
                        <div
                          className="flex w-7 shrink-0 flex-col gap-1 p-1.5"
                          style={{ backgroundColor: item.sidebar }}
                        >
                          <span
                            className="h-1.5 w-full rounded-full"
                            style={{ backgroundColor: item.accent }}
                          />
                          <span
                            className="h-1 w-3/4 rounded-full opacity-35"
                            style={{ backgroundColor: item.text }}
                          />
                          <span
                            className="h-1 w-2/3 rounded-full opacity-25"
                            style={{ backgroundColor: item.text }}
                          />
                        </div>
                        <div className="flex flex-1 flex-col justify-between p-2">
                          <div className="flex items-center justify-between gap-1">
                            <span
                              className="h-1.5 w-10 rounded-full opacity-70"
                              style={{ backgroundColor: item.text }}
                            />
                            <span
                              className="h-2 w-4 rounded-full"
                              style={{ backgroundColor: item.accent }}
                            />
                          </div>
                          <div
                            className="h-5 w-full rounded-md border border-black/10 p-1"
                            style={{ backgroundColor: item.card }}
                          >
                            <span
                              className="block h-1 w-1/2 rounded-full opacity-40"
                              style={{ backgroundColor: item.text }}
                            />
                          </div>
                        </div>
                      </div>
                    )}
                    {selected && (
                      <span
                        className="absolute right-1.5 top-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full shadow-sm"
                        style={{
                          backgroundColor: "var(--accent)",
                          color: "var(--accent-ink)",
                        }}
                      >
                        <Check className="h-3 w-3 stroke-[2.5]" />
                      </span>
                    )}
                  </div>

                  <div className="text-xs font-semibold text-[var(--text)]">{item.title}</div>
                  <div className="mt-0.5 text-[11px] text-[var(--muted)]">{item.desc}</div>
                </button>
              );
            })}
          </div>

          {/* Show 3 clock inputs ONLY when auto_time is selected */}
          {p.theme_mode === "auto_time" && (
            <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/75 p-3">
              <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-[var(--muted)]">
                <span>定时切换时刻（北京时间 {beijingClock}）</span>
                <span className="font-medium text-[var(--accent)]">当前：{currentThemeName}</span>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {(
                  [
                    ["light_start", "浅色开始"],
                    ["warm_dark_start", "深苔暖金开始"],
                    ["midnight_start", "午夜蓝开始"],
                  ] as const
                ).map(([field, label]) => (
                  <label key={field} className="min-w-0 text-[11px] text-[var(--muted)]">
                    <span className="block truncate">{label}</span>
                    <input
                      type="time"
                      value={p.theme_schedule[field]}
                      onChange={(e) =>
                        void appActions.updatePersonalization({
                          theme_schedule: {
                            ...p.theme_schedule,
                            [field]: e.target.value,
                          },
                        })
                      }
                      className={`${INPUT_CLS} mt-1 min-w-0 cc-mono`}
                    />
                  </label>
                ))}
              </div>
            </div>
          )}
        </Card>

        {/* Wallpaper Picker + Preview + 4 Presets + Sliders + Collapsible URL */}
        <Card
          title="背景壁纸"
          sub="支持本地图片与内置氛围渐变，纯色模式零额外开销"
          action={
            hasWallpaper ? (
              <button
                type="button"
                onClick={() => {
                  setWallpaperUrlInput("");
                  void appActions.setWallpaperPath(null, "已恢复纯色背景");
                }}
                className={BTN_CLS}
              >
                <RotateCcw className="h-3.5 w-3.5" />
                <span>恢复纯色</span>
              </button>
            ) : undefined
          }
        >
          {/* Primary action: Pick local image from computer */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={pickingWallpaper}
              onClick={() => void handlePickWallpaper()}
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-xs font-semibold transition-opacity hover:opacity-90 disabled:opacity-60"
              style={{
                backgroundColor: "var(--accent)",
                color: "var(--accent-ink)",
              }}
            >
              <Image className="h-4 w-4 shrink-0" />
              <span>{pickingWallpaper ? "正在打开文件选择…" : "从电脑选择图片"}</span>
            </button>
          </div>

          {/* Current wallpaper thumbnail preview */}
          {hasWallpaper ? (
            <div className="relative h-24 w-full overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)]">
              {activePreset ? (
                <div
                  className="h-full w-full"
                  style={{ background: activePreset.cssBackground }}
                />
              ) : effectiveWallpaperError ? (
                <div className="flex h-full w-full flex-col items-center justify-center gap-1.5 bg-[var(--amber-soft)]/50 px-3 text-center">
                  <div className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--amber)]">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    <span className="line-clamp-1">{effectiveWallpaperError}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setImgLoadFailed(false);
                      setWallpaperUrlInput("");
                      void appActions.setWallpaperPath(null, "已恢复纯色背景");
                    }}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>恢复纯色背景</span>
                  </button>
                </div>
              ) : wallpaperThumbSrc ? (
                <img
                  src={wallpaperThumbSrc}
                  alt="当前背景壁纸预览"
                  onError={() => setImgLoadFailed(true)}
                  className="h-full w-full object-cover"
                />
              ) : (
                <div className="flex h-full w-full items-center justify-center text-xs text-[var(--muted)]">
                  正在加载壁纸预览…
                </div>
              )}
              {!effectiveWallpaperError && (
                <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-between gap-2 bg-gradient-to-t from-black/65 via-black/30 to-transparent px-3 py-1.5 text-[11px] text-white">
                  <span className="truncate font-medium" title={rawWallpaper}>
                    {activePreset
                      ? `内置壁纸 · ${activePreset.label}`
                      : extractWallpaperLabel(rawWallpaper)}
                  </span>
                  <span className="shrink-0 opacity-85">
                    透明 {Math.round(p.wallpaper_opacity * 100)}% · 柔和度 {p.glass_blur_px}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-[var(--line-strong)] bg-[var(--surface)]/50 px-3 py-2.5 text-center text-[11px] text-[var(--muted)]">
              当前使用纯色背景；选择本地图片或点下方内置氛围即可上墙
            </div>
          )}

          {/* 4 Built-in Gradient Wallpapers */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-medium text-[var(--muted)]">内置氛围壁纸</div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {BUILTIN_WALLPAPER_PRESETS.map((preset) => {
                const active = rawWallpaper === preset.id;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() =>
                      void appActions.setWallpaperPath(preset.id, `已更换壁纸：${preset.label}`)
                    }
                    aria-pressed={active}
                    className="group relative overflow-hidden rounded-xl border p-1 text-left transition-all"
                    style={{
                      borderColor: active ? "var(--accent)" : "var(--line)",
                      backgroundColor: active ? "var(--accent-soft)" : "var(--surface)",
                    }}
                  >
                    <div
                      className="h-11 w-full rounded-lg border border-black/10"
                      style={{ background: preset.cssBackground }}
                    />
                    <div className="mt-1 truncate px-0.5 text-center text-[11px] font-medium text-[var(--text)]">
                      {preset.label}
                    </div>
                    {active && (
                      <span
                        className="absolute right-2 top-2 inline-flex h-4 w-4 items-center justify-center rounded-full shadow-sm"
                        style={{
                          backgroundColor: "var(--accent)",
                          color: "var(--accent-ink)",
                        }}
                      >
                        <Check className="h-2.5 w-2.5 stroke-[2.5]" />
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Opacity & Glass Blur Sliders (Live Preview on drag, persist on release/debounce) */}
          <div className="space-y-1.5 pt-0.5">
            <div
              className={`grid grid-cols-2 gap-3 text-[11px] text-[var(--muted)] transition-opacity ${
                !hasWallpaper ? "opacity-50" : ""
              }`}
            >
              <label className={!hasWallpaper ? "cursor-not-allowed" : ""}>
                壁纸透明度：{Math.round(p.wallpaper_opacity * 100)}%
                <input
                  type="range"
                  min={0.05}
                  max={0.65}
                  step={0.01}
                  disabled={!hasWallpaper}
                  value={p.wallpaper_opacity}
                  onChange={(e) =>
                    handleSliderPreview({
                      wallpaper_opacity: Number(e.target.value),
                    })
                  }
                  onPointerUp={commitSliderPersonalization}
                  onTouchEnd={commitSliderPersonalization}
                  onKeyUp={commitSliderPersonalization}
                  className="mt-1 w-full accent-[var(--accent)] disabled:cursor-not-allowed"
                />
              </label>
              <label className={!hasWallpaper ? "cursor-not-allowed" : ""}>
                毛玻璃柔和度：{p.glass_blur_px === 0 ? "关闭（0）" : `${p.glass_blur_px} / 24`}
                <input
                  type="range"
                  min={0}
                  max={24}
                  step={1}
                  disabled={!hasWallpaper}
                  value={p.glass_blur_px}
                  onChange={(e) =>
                    handleSliderPreview({
                      glass_blur_px: Number(e.target.value),
                    })
                  }
                  onPointerUp={commitSliderPersonalization}
                  onTouchEnd={commitSliderPersonalization}
                  onKeyUp={commitSliderPersonalization}
                  className="mt-1 w-full accent-[var(--accent)] disabled:cursor-not-allowed"
                />
              </label>
            </div>
            {!hasWallpaper && (
              <p className="text-[10.5px] text-[var(--muted)]">先选择一张背景壁纸后可调节</p>
            )}
          </div>

          {/* Collapsible network image URL input */}
          <div className="border-t border-[var(--line)] pt-2">
            <button
              type="button"
              onClick={() => setShowUrlInput((open) => !open)}
              className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)] transition-colors hover:text-[var(--accent)]"
            >
              {showUrlInput ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5" />
              )}
              <span>或输入网络图片地址</span>
            </button>
            {showUrlInput && (
              <div className="mt-2 flex gap-2">
                <input
                  value={wallpaperUrlInput}
                  placeholder="https://example.com/wallpaper.jpg"
                  onChange={(e) => setWallpaperUrlInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      void handleApplyWallpaperUrl();
                    }
                  }}
                  className={`${INPUT_CLS} cc-mono`}
                />
                <button
                  type="button"
                  onClick={() => void handleApplyWallpaperUrl()}
                  className={`${BTN_CLS} shrink-0`}
                >
                  应用
                </button>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Interface animations & tray icon style */}
      <Card title="界面动效与托盘图标" sub="按喜好开关过渡动画，自定义右下角托盘图标样式">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <SwitchRow
            title="界面过渡动效"
            desc="切换页面与按钮的平滑过渡"
            checked={p.animations_enabled}
            onChange={(v) => void appActions.updatePersonalization({ animations_enabled: v })}
          />
          <SwitchRow
            title="看板猫猫动效"
            desc="界面与首页小猫的眨眼和状态动画"
            checked={p.mascot_enabled}
            onChange={(v) => void appActions.updatePersonalization({ mascot_enabled: v })}
          />
          <SwitchRow
            title="流量曲线动效"
            desc="左下角实时网速波形动画"
            checked={p.sparkline_enabled}
            onChange={(v) => void appActions.updatePersonalization({ sparkline_enabled: v })}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
          <span className="text-xs font-medium text-[var(--text)]">托盘图标样式</span>
          <SegButtons<TrayIconMode>
            value={p.tray_icon_mode}
            onChange={(m) =>
              void appActions.updatePersonalization({ tray_icon_mode: m }, "托盘图标样式已更新")
            }
            options={[
              ["auto_ac", "随状态自动"],
              ["always_a", "简约猫标"],
              ["always_c", "高亮猫标"],
              ["always_pixel", "像素猫饼"],
            ]}
          />
        </div>
      </Card>
    </div>
  );
}
