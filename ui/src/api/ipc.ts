/**
 * Low-level Tauri v2 IPC invoke/event wrappers and lightweight preview query flags.
 */

import { formatErrorMessage } from "./errors";

export function isTauriEnv(): boolean {
  return (
    typeof window !== "undefined" &&
    ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)
  );
}

export async function tauriInvokeOrThrow<T>(
  cmd: string,
  args?: Record<string, unknown>
): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    throw new Error(formatErrorMessage(err));
  }
}

export function extractDialogSinglePath(raw: unknown): string | null {
  if (typeof raw === "string") {
    return raw.trim() || null;
  }
  if (Array.isArray(raw)) {
    const first = raw[0];
    if (typeof first === "string") return first.trim() || null;
    if (first && typeof first === "object" && "path" in first && typeof first.path === "string") {
      return first.path.trim() || null;
    }
    return null;
  }
  if (raw && typeof raw === "object" && "path" in raw && typeof raw.path === "string") {
    return raw.path.trim() || null;
  }
  return null;
}

export async function tauriListen<T>(
  event: string,
  handler: (payload: T) => void
): Promise<(() => void) | null> {
  if (!isTauriEnv()) return null;
  try {
    const { listen } = await import("@tauri-apps/api/event");
    const unlisten = await listen<T>(event, (ev) => handler(ev.payload));
    return unlisten;
  } catch {
    return null;
  }
}

export function subscribeTauriEvent<T>(
  event: string,
  onEvent: (payload: T) => void
): () => void {
  let disposed = false;
  let unlisten: (() => void) | null = null;
  if (isTauriEnv()) {
    void tauriListen<T>(event, (payload) => {
      if (!disposed && payload) onEvent(payload);
    }).then((fn) => {
      if (disposed) fn?.();
      else unlisten = fn;
    });
  }
  return () => {
    disposed = true;
    unlisten?.();
  };
}

export function subscribeTauriEmptyEvent(event: string, onEvent: () => void): () => void {
  let disposed = false;
  let unlisten: (() => void) | null = null;
  if (isTauriEnv()) {
    void tauriListen<unknown>(event, () => {
      if (!disposed) onEvent();
    }).then((fn) => {
      if (disposed) fn?.();
      else unlisten = fn;
    });
  }
  return () => {
    disposed = true;
    unlisten?.();
  };
}

export function getPreviewQueryParam(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    const v = new URLSearchParams(window.location.search).get(key);
    if (v !== null) return v;
    const h = window.location.hash || "";
    const i = h.indexOf("?");
    return i >= 0 ? new URLSearchParams(h.slice(i + 1)).get(key) : null;
  } catch {
    return null;
  }
}

export function hasPreviewTunNeedsAdminFlag(): boolean {
  return (
    getPreviewQueryParam("preview_tun_needs_admin") === "1" ||
    (typeof window !== "undefined" &&
      /(?:^|[?&#])preview_tun_needs_admin=1(?:$|&|#)/.test(window.location.hash || ""))
  );
}

export function hasPreviewUpdateModalFlag(): boolean {
  return getPreviewQueryParam("update_modal") === "1";
}
