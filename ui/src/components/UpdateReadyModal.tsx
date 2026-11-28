import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Download,
  ExternalLink,
  FolderOpen,
  Info,
  Loader2,
  Package,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { catcloudApi, formatErrorMessage } from "../api/tauri";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";
import { buildReleasesFallbackUrl } from "../utils/releaseUrl";

function formatPackageSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${Math.round(bytes)} B`;
}

export function UpdateReadyModal() {
  const pendingUpdate = useAppSelector((s) => s.pendingUpdate);
  const updateModalVisible = useAppSelector((s) => s.updateModalVisible);
  const runtimeOsLabel = useAppSelector((s) => s.runtime.os_label);
  const updateRepo = useAppSelector((s) => s.config.update.repo);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);

  const [busyAction, setBusyAction] = useState<"apply" | "skip" | null>(null);
  const [inlineNotice, setInlineNotice] = useState<{
    tone: "error" | "info" | "ok";
    text: string;
    showReleaseFallback?: boolean;
  } | null>(null);
  const exitFallbackTimerRef = useRef<number | null>(null);

  const clearExitFallbackTimer = () => {
    if (exitFallbackTimerRef.current !== null) {
      window.clearTimeout(exitFallbackTimerRef.current);
      exitFallbackTimerRef.current = null;
    }
  };

  const targetVersion = pendingUpdate?.target_version ?? "";
  const isBusy = busyAction !== null;

  useEffect(() => {
    clearExitFallbackTimer();
    setBusyAction(null);
    setInlineNotice(null);
    return () => {
      clearExitFallbackTimer();
    };
  }, [targetVersion, updateModalVisible]);

  useEffect(() => {
    if (!updateModalVisible || !pendingUpdate) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !isBusy) {
        void appActions.dismissUpdatePrompt();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [updateModalVisible, pendingUpdate, isBusy]);

  if (!updateModalVisible || !pendingUpdate || typeof document === "undefined") {
    return null;
  }

  const platformOs = resolvePlatformOs(
    pendingUpdate.platform_key || runtimeOsLabel
  );
  const sizeLabel = formatPackageSize(pendingUpdate.package_size_bytes);
  const shaShort = pendingUpdate.archive_sha256
    ? pendingUpdate.archive_sha256.trim().slice(0, 10)
    : "";
  const notesText = pendingUpdate.release_notes?.trim() ?? "";
  const releaseUrl =
    pendingUpdate.release_url?.trim() || buildReleasesFallbackUrl(updateRepo);
  const isPortable = pendingUpdate.kind === "portable_zip";

  const applyButtonConfig = (() => {
    switch (pendingUpdate.apply_action) {
      case "installer_launch":
        return {
          label: dict.updateModal.applyInstallerBtn,
          busyLabel: dict.updateModal.applyingInstallerBtn,
          icon: Download,
          hint:
            platformOs === "macos"
              ? dict.updateModal.installerMacHint
              : dict.updateModal.installerWinHint,
        };
      case "reveal_archive":
        return {
          label: dict.updateModal.applyRevealBtn,
          busyLabel: dict.updateModal.applyingRevealBtn,
          icon: FolderOpen,
          hint: dict.updateModal.revealHint,
        };
      default:
        return {
          label: dict.updateModal.applyPortableBtn,
          busyLabel: dict.updateModal.applyingPortableBtn,
          icon: RotateCw,
          hint: "",
        };
    }
  })();

  const ApplyIcon = applyButtonConfig.icon;

  const handleDismiss = () => {
    if (isBusy) return;
    void appActions.dismissUpdatePrompt();
  };

  const handleOpenReleaseFallback = async () => {
    try {
      await catcloudApi.openExternalUrl(releaseUrl);
    } catch (err) {
      setInlineNotice({
        tone: "error",
        text: `${dict.updateModal.applyErrorPrefix}${formatErrorMessage(err)}`,
        showReleaseFallback: false,
      });
    }
  };

  const handleSkipVersion = async () => {
    if (isBusy) return;
    setBusyAction("skip");
    setInlineNotice(null);
    try {
      await appActions.skipPendingUpdateVersion(pendingUpdate.target_version, {
        silentError: true,
      });
    } catch (err) {
      setInlineNotice({
        tone: "error",
        text: `${dict.updateModal.applyErrorPrefix}${formatErrorMessage(err)}`,
        showReleaseFallback: false,
      });
    } finally {
      setBusyAction(null);
    }
  };

  const handleApplyUpdate = async () => {
    if (isBusy) return;
    clearExitFallbackTimer();
    setBusyAction("apply");
    setInlineNotice(null);
    let exitingNow = false;
    try {
      const res = await appActions.applyPendingUpdateAndRestart();
      if (res.cancelled) {
        setInlineNotice({
          tone: "info",
          text: dict.updateModal.cancelledHint,
        });
      } else if (res.exiting) {
        exitingNow = true;
        // Safety unlock fallback: if graceful exit stalls unexpectedly, unlock buttons so user is never stuck.
        exitFallbackTimerRef.current = window.setTimeout(() => {
          exitFallbackTimerRef.current = null;
          setBusyAction(null);
          setInlineNotice({
            tone: "error",
            text: `${dict.updateModal.applyErrorPrefix}${res.message?.trim() || dict.updateModal.exitTimeoutFallback}`,
            showReleaseFallback: true,
          });
        }, 12_000);
      } else if (res.started) {
        const localizedStartedHint =
          res.apply_action === "reveal_archive"
            ? dict.updateModal.revealOpenedHint
            : dict.updateModal.installerMacHint;
        setInlineNotice({
          tone: "ok",
          text:
            uiLang !== "zh-CN"
              ? localizedStartedHint
              : res.message?.trim() || localizedStartedHint,
        });
      } else {
        setInlineNotice({
          tone: "error",
          text: `${dict.updateModal.applyErrorPrefix}${res.message || dict.updateModal.unknownErrorFallback}`,
          showReleaseFallback: true,
        });
      }
    } catch (err) {
      setInlineNotice({
        tone: "error",
        text: `${dict.updateModal.applyErrorPrefix}${formatErrorMessage(err)}`,
        showReleaseFallback: true,
      });
    } finally {
      if (!exitingNow) {
        clearExitFallbackTimer();
        setBusyAction(null);
      }
    }
  };

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/62 p-4 backdrop-blur-[3px]"
      onClick={handleDismiss}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="cc-update-ready-title"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface relative flex max-h-[calc(100vh-2rem)] w-full max-w-[540px] flex-col overflow-hidden rounded-3xl border border-[var(--line-strong)] text-[var(--text)] shadow-2xl"
      >
        {/* Top warm-gold accent rail */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-[var(--accent)]/40 via-[var(--accent)] to-[var(--green)]/65"
        />

        {/* Header */}
        <div className="shrink-0 px-5 pt-5 pb-3.5 sm:px-6">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--accent)]/45 bg-[var(--accent-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
                <Sparkles className="h-3 w-3 shrink-0" />
                <span>{dict.updateModal.badge}</span>
              </span>
              <h2
                id="cc-update-ready-title"
                className="mt-2 break-words text-base font-bold tracking-tight text-[var(--text)] sm:text-[17px]"
              >
                {dict.updateModal.title}
              </h2>
              <p className="mt-1 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                {dict.updateModal.subtitle}
              </p>
            </div>
            <button
              type="button"
              disabled={isBusy}
              onClick={handleDismiss}
              aria-label={dict.updateModal.closeAria}
              title={dict.updateModal.laterBtnTitle}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Body */}
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-5 pb-4 sm:px-6">
          {/* Version & Verified Package Metadata Strip */}
          <div className="rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)]/85 px-3.5 py-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="inline-flex items-center gap-2">
                <span className="cc-mono rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2 py-0.5 text-xs font-medium text-[var(--text-secondary)]">
                  v{pendingUpdate.current_version}
                </span>
                <ArrowRight className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                <span className="cc-mono rounded-lg border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-2.5 py-0.5 text-xs font-bold text-[var(--accent)]">
                  v{pendingUpdate.target_version}
                </span>
              </div>

              {sizeLabel && (
                <span className="cc-mono rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
                  {sizeLabel}
                </span>
              )}
            </div>

            <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px]">
              <span
                title={pendingUpdate.installer_filename ?? undefined}
                className="inline-flex items-center gap-1 rounded-full border border-[var(--line)] bg-[var(--surface)] px-2.5 py-0.5 font-medium text-[var(--text-secondary)]"
              >
                {isPortable ? (
                  <Zap className="h-3 w-3 shrink-0 text-[var(--accent)]" />
                ) : (
                  <Package className="h-3 w-3 shrink-0 text-[var(--sky)]" />
                )}
                <span>
                  {isPortable
                    ? dict.updateModal.kindPortable
                    : dict.updateModal.kindInstaller}
                </span>
              </span>

              {shaShort && (
                <span
                  title={`SHA-256: ${pendingUpdate.archive_sha256}`}
                  className="inline-flex items-center gap-1 rounded-full border border-[var(--green)]/40 bg-[var(--green-soft)] px-2.5 py-0.5 font-medium text-[var(--green)]"
                >
                  <ShieldCheck className="h-3 w-3 shrink-0" />
                  <span className="cc-mono">
                    {dict.updateModal.shaVerified} {shaShort}
                  </span>
                </span>
              )}
            </div>

            {applyButtonConfig.hint && (
              <p className="mt-2 text-[11px] leading-relaxed text-[var(--muted)]">
                {applyButtonConfig.hint}
              </p>
            )}
          </div>

          {/* Gentle Elevated Installer Notice */}
          {pendingUpdate.kind === "installer_package" && pendingUpdate.is_elevated && (
            <div className="flex items-start gap-2 rounded-2xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/55 px-3.5 py-2.5 text-[11.5px] leading-relaxed text-[var(--text)]">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[var(--amber)]" />
              <span className="min-w-0 flex-1 break-words">{dict.updateModal.elevatedInstallerHint}</span>
            </div>
          )}

          {/* Release Notes Card (hidden cleanly when empty) */}
          {notesText && (
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface)]/80 px-3.5 py-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-[var(--text-secondary)]">
                  {dict.updateModal.notesTitle}
                </span>
                {pendingUpdate.release_url && (
                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={() => void handleOpenReleaseFallback()}
                    className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--accent)] transition-opacity hover:underline disabled:opacity-50"
                  >
                    <ExternalLink className="h-3 w-3" />
                    <span>{dict.settings.updateViewReleaseNotes}</span>
                  </button>
                )}
              </div>
              <div className="cc-selectable max-h-48 overflow-y-auto whitespace-pre-wrap break-words pr-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                {notesText}
              </div>
            </div>
          )}

          {/* Inline Feedback / Error Area (inside modal so it is never hidden behind z-50 toast) */}
          {inlineNotice && (
            <div
              role={inlineNotice.tone === "error" ? "alert" : "status"}
              className={`rounded-2xl border px-3.5 py-2.5 text-xs leading-relaxed ${
                inlineNotice.tone === "error"
                  ? "border-[var(--red)]/45 bg-[var(--red)]/10 text-[var(--text)]"
                  : inlineNotice.tone === "ok"
                    ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--text)]"
                    : "border-[var(--amber)]/45 bg-[var(--amber-soft)]/60 text-[var(--text)]"
              }`}
            >
              <div className="flex items-start gap-2">
                {inlineNotice.tone === "error" ? (
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--red)]" />
                ) : inlineNotice.tone === "ok" ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[var(--green)]" />
                ) : (
                  <Info className="mt-0.5 h-4 w-4 shrink-0 text-[var(--amber)]" />
                )}
                <div className="min-w-0 flex-1 space-y-2">
                  <p className="break-words">{inlineNotice.text}</p>
                  {inlineNotice.showReleaseFallback && (
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void handleOpenReleaseFallback()}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line-strong)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                    >
                      <ExternalLink className="h-3 w-3" />
                      <span>{dict.updateModal.openReleaseFallbackBtn}</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer 3-Action Bar (flex-wrap for long RU/DE/EN labels) */}
        <div className="shrink-0 border-t border-[var(--line)] bg-[var(--bg-elevated)]/65 px-5 py-3.5 sm:px-6">
          <div className="flex flex-wrap items-center justify-between gap-2.5">
            {/* Left subtle Skip + Delete Package Action */}
            <div className="min-w-0">
              <button
                type="button"
                disabled={isBusy}
                onClick={() => void handleSkipVersion()}
                title={dict.updateModal.skipBtnHint}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-transparent px-3 py-2 text-xs font-medium text-[var(--muted)] transition-colors hover:border-[var(--amber)]/55 hover:bg-[var(--amber-soft)]/45 hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busyAction === "skip" ? (
                  <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5 shrink-0" />
                )}
                <span>
                  {busyAction === "skip"
                    ? dict.updateModal.skippingBtn
                    : dict.updateModal.skipBtn}
                </span>
              </button>
              <p className="mt-1 pl-0.5 text-[10.5px] leading-snug text-[var(--muted)]">
                {dict.updateModal.skipBtnHint}
              </p>
            </div>

            {/* Right Later + Primary Apply Actions */}
            <div className="flex flex-wrap items-center justify-end gap-2">
              <button
                type="button"
                disabled={isBusy}
                onClick={handleDismiss}
                title={dict.updateModal.laterBtnTitle}
                className="rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)]/60 hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {dict.updateModal.laterBtn}
              </button>

              <button
                type="button"
                disabled={isBusy}
                onClick={() => void handleApplyUpdate()}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-bold text-[var(--accent-ink)] shadow-sm transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-65"
              >
                {busyAction === "apply" ? (
                  <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                ) : (
                  <ApplyIcon className="h-3.5 w-3.5 shrink-0" />
                )}
                <span>
                  {busyAction === "apply"
                    ? applyButtonConfig.busyLabel
                    : applyButtonConfig.label}
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
