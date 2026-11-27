import { Loader2, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";

export function TunAdminPromptModal() {
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const runtime = useAppSelector((s) => s.runtime);
  const tunAdminPromptOpen = useAppSelector((s) => s.tunAdminPromptOpen);
  const tunAdminPromptBusy = useAppSelector((s) => s.tunAdminPromptBusy);
  const tunAdminPromptReason = useAppSelector((s) => s.tunAdminPromptReason);
  const [disablingTunIntent, setDisablingTunIntent] = useState(false);

  const platformOs = resolvePlatformOs(runtime.os_label);

  useEffect(() => {
    if (!tunAdminPromptOpen) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !tunAdminPromptBusy) {
        appActions.closeTunAdminPrompt();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [tunAdminPromptOpen, tunAdminPromptBusy]);

  if (!tunAdminPromptOpen || typeof document === "undefined") {
    return null;
  }

  const tunElevationCopy =
    platformOs === "linux"
      ? {
          ariaLabel: dict.tunPrompt.linuxAria,
          title: dict.tunPrompt.linuxTitle,
          desc: dict.tunPrompt.linuxDesc,
          actionLabel: dict.tunPrompt.linuxAction,
          busyLabel: dict.tunPrompt.linuxBusy,
        }
      : platformOs === "macos"
        ? {
            ariaLabel: dict.tunPrompt.macosAria,
            title: dict.tunPrompt.macosTitle,
            desc: dict.tunPrompt.macosDesc,
            actionLabel: dict.tunPrompt.macosAction,
            busyLabel: dict.tunPrompt.macosBusy,
          }
        : {
            ariaLabel: dict.tunPrompt.winAria,
            title: dict.tunPrompt.winTitle,
            desc: dict.tunPrompt.winDesc,
            actionLabel: dict.tunPrompt.winAction,
            busyLabel: dict.tunPrompt.winBusy,
          };

  const handleDisableTunIntent = async () => {
    if (tunAdminPromptBusy || disablingTunIntent) return;
    setDisablingTunIntent(true);
    try {
      const ok = await appActions.toggleTun(false);
      if (ok) {
        appActions.closeTunAdminPrompt();
      }
    } finally {
      setDisablingTunIntent(false);
    }
  };

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={() => {
        if (!tunAdminPromptBusy) appActions.closeTunAdminPrompt();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={tunElevationCopy.ariaLabel}
        onClick={(e) => e.stopPropagation()}
        className="cc-surface flex max-h-[calc(100vh-2rem)] w-full max-w-[468px] flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] shadow-2xl"
      >
        <div className="min-h-0 flex-1 overflow-y-auto p-5 pb-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                <ShieldCheck className="h-5 w-5" />
              </span>
              <div className="min-w-0 flex-1">
                <h3 className="break-words text-sm font-semibold text-[var(--text)]">
                  {tunElevationCopy.title}
                </h3>
                <p className="mt-1 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                  {tunElevationCopy.desc}
                </p>
              </div>
            </div>
            <button
              type="button"
              disabled={tunAdminPromptBusy || disablingTunIntent}
              onClick={() => appActions.closeTunAdminPrompt()}
              className="shrink-0 rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
              aria-label={dict.tunPrompt.closeModalAria}
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {tunAdminPromptReason && (
            <div className="mt-3 whitespace-pre-wrap break-words rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] leading-relaxed text-[var(--muted)]">
              {tunAdminPromptReason}
            </div>
          )}
        </div>

        <div
          className={`flex shrink-0 flex-wrap items-center gap-2 border-t border-[var(--line)]/75 bg-[var(--bg-elevated)]/45 px-5 py-3.5 ${
            runtime.tun_needs_elevation ? "justify-between" : "justify-end"
          }`}
        >
          {runtime.tun_needs_elevation && (
            <button
              type="button"
              disabled={tunAdminPromptBusy || disablingTunIntent}
              onClick={() => void handleDisableTunIntent()}
              className="rounded-xl border border-[var(--line)] bg-transparent px-3 py-2 text-xs font-medium text-[var(--muted)] transition-colors hover:border-[var(--amber)]/55 hover:bg-[var(--amber-soft)]/45 hover:text-[var(--text)] disabled:opacity-50"
            >
              {disablingTunIntent
                ? dict.tunPrompt.disablingTunIntentBtn
                : dict.tunPrompt.disableTunIntentBtn}
            </button>
          )}
          <div className="flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              disabled={tunAdminPromptBusy || disablingTunIntent}
              onClick={() => appActions.closeTunAdminPrompt()}
              className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] disabled:opacity-50"
            >
              {runtime.tun_needs_elevation ? dict.common.cancel : dict.tunPrompt.skipForNowBtn}
            </button>
            <button
              type="button"
              disabled={tunAdminPromptBusy || disablingTunIntent}
              onClick={() => void appActions.relaunchAsAdminForTun()}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-65"
            >
              {tunAdminPromptBusy ? (
                <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
              )}
              <span>
                {tunAdminPromptBusy
                  ? tunElevationCopy.busyLabel
                  : tunElevationCopy.actionLabel}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
