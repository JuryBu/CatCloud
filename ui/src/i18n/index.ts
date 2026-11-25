import { useEffect, useState } from "react";
import { zhCN, type TranslationDict } from "./locales/zh-CN";
import {
  SUPPORTED_UI_LANGUAGES,
  UI_LANGUAGE_OPTIONS,
  normalizeUiLanguage,
  type DeepPartial,
  type DeepStringDict,
  type UiLanguage,
} from "./types";

export {
  SUPPORTED_UI_LANGUAGES,
  UI_LANGUAGE_OPTIONS,
  normalizeUiLanguage,
  type UiLanguage,
  type TranslationDict,
};

type Dict = DeepStringDict<TranslationDict>;

const loadedLocales = new Map<UiLanguage, Dict>([["zh-CN", zhCN]]);
const inflightLoads = new Map<UiLanguage, Promise<Dict>>();
const listeners = new Set<() => void>();

function notifyListeners() {
  for (const fn of listeners) {
    try {
      fn();
    } catch {
      /* ignore */
    }
  }
}

function mergeLocale(base: Dict, patch: DeepPartial<TranslationDict>): Dict {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(base) as Array<keyof Dict>) {
    const baseVal = base[key];
    const patchVal = (patch as Record<string, unknown>)[key as string];
    if (typeof baseVal === "string") {
      out[key as string] = typeof patchVal === "string" && patchVal.trim() ? patchVal : baseVal;
    } else if (baseVal && typeof baseVal === "object") {
      const subOut: Record<string, string> = {};
      const baseRec = baseVal as Record<string, string>;
      const patchRec =
        patchVal && typeof patchVal === "object"
          ? (patchVal as Record<string, unknown>)
          : {};
      for (const subKey of Object.keys(baseRec)) {
        const pv = patchRec[subKey];
        subOut[subKey] = typeof pv === "string" && pv.trim() ? pv : baseRec[subKey];
      }
      out[key as string] = subOut;
    }
  }
  return out as Dict;
}

export async function ensureUiLocaleLoaded(lang: UiLanguage): Promise<Dict> {
  const cached = loadedLocales.get(lang);
  if (cached) return cached;
  const pending = inflightLoads.get(lang);
  if (pending) return pending;

  const task = (async () => {
    try {
      if (lang === "en") {
        const mod = await import("./locales/en");
        const merged = mergeLocale(zhCN, mod.en);
        loadedLocales.set("en", merged);
        notifyListeners();
        return merged;
      }
      const enBase = await ensureUiLocaleLoaded("en");
      if (lang === "ja") {
        const mod = await import("./locales/ja");
        const merged = mergeLocale(enBase, mod.ja);
        loadedLocales.set("ja", merged);
        notifyListeners();
        return merged;
      }
      if (lang === "ru") {
        const mod = await import("./locales/ru");
        const merged = mergeLocale(enBase, mod.ru);
        loadedLocales.set("ru", merged);
        notifyListeners();
        return merged;
      }
      return zhCN;
    } catch {
      return zhCN;
    } finally {
      inflightLoads.delete(lang);
    }
  })();

  inflightLoads.set(lang, task);
  return task;
}

export function getUiDictSync(lang: UiLanguage): Dict {
  const hit = loadedLocales.get(lang);
  if (hit) return hit;
  if (lang !== "zh-CN") {
    void ensureUiLocaleLoaded(lang);
  }
  return loadedLocales.get("en") && lang !== "zh-CN"
    ? (loadedLocales.get("en") as Dict)
    : zhCN;
}

export function formatI18nTemplate(
  template: string,
  params?: Record<string, string | number>
): string {
  if (!params) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key: string) =>
    params[key] !== undefined ? String(params[key]) : `{${key}}`
  );
}

export function useUiDict(lang: UiLanguage): Dict {
  const [, setTick] = useState(0);
  useEffect(() => {
    const onUpdate = () => setTick((n) => n + 1);
    listeners.add(onUpdate);
    if (!loadedLocales.has(lang)) {
      void ensureUiLocaleLoaded(lang);
    }
    return () => {
      listeners.delete(onUpdate);
    };
  }, [lang]);

  return getUiDictSync(lang);
}
