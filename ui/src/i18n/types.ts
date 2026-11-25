export const SUPPORTED_UI_LANGUAGES = ["zh-CN", "en", "ja", "ru"] as const;

export type UiLanguage = (typeof SUPPORTED_UI_LANGUAGES)[number];

export interface UiLanguageOption {
  value: UiLanguage;
  nativeLabel: string;
  helperLabel: string;
  optionLabel: string;
}

export const UI_LANGUAGE_OPTIONS: readonly UiLanguageOption[] = [
  {
    value: "zh-CN",
    nativeLabel: "简体中文",
    helperLabel: "Chinese (Simplified)",
    optionLabel: "简体中文 · Chinese (Simplified)",
  },
  {
    value: "en",
    nativeLabel: "English",
    helperLabel: "英语",
    optionLabel: "English · 英语",
  },
  {
    value: "ja",
    nativeLabel: "日本語",
    helperLabel: "Japanese / 日语",
    optionLabel: "日本語 · Japanese",
  },
  {
    value: "ru",
    nativeLabel: "Русский",
    helperLabel: "Russian / 俄语",
    optionLabel: "Русский · Russian",
  },
] as const;

export function normalizeUiLanguage(raw: unknown): UiLanguage {
  if (typeof raw !== "string") return "zh-CN";
  const lower = raw.trim().toLowerCase().replace("_", "-");
  if (lower === "en" || lower.startsWith("en-")) return "en";
  if (lower === "ja" || lower.startsWith("ja-") || lower === "jp") return "ja";
  if (lower === "ru" || lower.startsWith("ru-")) return "ru";
  return "zh-CN";
}

export type DeepStringDict<T> = {
  [K in keyof T]: T[K] extends string ? string : DeepStringDict<T[K]>;
};

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends string ? string : DeepPartial<T[K]>;
};
