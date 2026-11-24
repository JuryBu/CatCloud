import { useCallback, useState } from "react";

const STORAGE_PREFIX = "catcloud:ui-pref:v1:";

export type PrefValidator<T> = (raw: unknown) => T | undefined;

export function readUiPref<T>(key: string, fallback: T, validate?: PrefValidator<T>): T {
  try {
    if (typeof window === "undefined" || !window.localStorage) {
      return fallback;
    }
    const raw = window.localStorage.getItem(`${STORAGE_PREFIX}${key}`);
    if (raw === null) {
      return fallback;
    }
    const parsed: unknown = JSON.parse(raw);
    if (validate) {
      const checked = validate(parsed);
      return checked !== undefined ? checked : fallback;
    }
    return parsed as T;
  } catch {
    return fallback;
  }
}

export function writeUiPref<T>(key: string, value: T): void {
  try {
    if (typeof window === "undefined" || !window.localStorage) {
      return;
    }
    window.localStorage.setItem(`${STORAGE_PREFIX}${key}`, JSON.stringify(value));
  } catch {
    // Ignore storage quota or restricted-mode errors so UI interactions never break.
  }
}

export function isBoolPref(raw: unknown): boolean | undefined {
  return typeof raw === "boolean" ? raw : undefined;
}

export function oneOfPref<const T extends readonly (string | number)[]>(
  allowed: T,
): PrefValidator<T[number]> {
  return (raw: unknown) => {
    for (const item of allowed) {
      if (raw === item) {
        return item;
      }
    }
    return undefined;
  };
}

export function isStringArrayPref(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  if (raw.every((item) => typeof item === "string")) {
    return raw;
  }
  return undefined;
}

/**
 * Lightweight persisted React state backed by localStorage.
 * Survives windowless tray close (WebView teardown) and full app restarts.
 */
export function usePersistedState<T>(
  key: string,
  fallback: T,
  validate?: PrefValidator<T>,
): [T, (next: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => readUiPref(key, fallback, validate));

  const setPersisted = useCallback(
    (next: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const resolved = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        writeUiPref(key, resolved);
        return resolved;
      });
    },
    [key],
  );

  return [value, setPersisted];
}
