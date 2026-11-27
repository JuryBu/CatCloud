import {
  ArrowRight,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Globe,
  Loader2,
  Package,
  Sparkles,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";

export function OnboardingModal() {
  const windowMode = useAppSelector((s) => s.windowMode);
  const initialized = useAppSelector((s) => s.initialized);
  const onboardingCompleted = useAppSelector(
    (s) => s.config.personalization.onboarding_completed === true
  );
  const onboardingHydratedOk = useAppSelector((s) => s.onboardingHydratedOk);
  const onboardingModalOpen = useAppSelector((s) => s.onboardingModalOpen);
  const onboardingAutoSkipped = useAppSelector((s) => s.onboardingAutoSkipped);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);

  const [busyAction, setBusyAction] = useState<"local" | "web" | null>(null);
  const [copiedMode, setCopiedMode] = useState<"local" | "web" | null>(null);

  const shouldRender =
    windowMode === "main" &&
    initialized &&
    (onboardingModalOpen ||
      (onboardingHydratedOk && !onboardingCompleted && !onboardingAutoSkipped));

  useEffect(() => {
    if (!shouldRender) {
      setCopiedMode(null);
      return;
    }
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        void appActions.closeOnboardingModal(true);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [shouldRender]);

  if (!shouldRender || typeof document === "undefined") {
    return null;
  }

  const handleCopyAutopilot = async () => {
    if (busyAction) return;
    setBusyAction("local");
    try {
      const ok = await appActions.copyAgentBootstrapPrompt("onboarding", "autopilot", uiLang);
      if (ok) {
        setCopiedMode("local");
        await appActions.markOnboardingCompleted();
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopyWebGuide = async () => {
    if (busyAction) return;
    setBusyAction("web");
    try {
      const ok = await appActions.copyAiOnboardingForUser(uiLang, "onboarding");
      if (ok) {
        setCopiedMode("web");
        await appActions.markOnboardingCompleted();
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handleCompleteAndClose = () => {
    void appActions.closeOnboardingModal(true);
  };

  const handleGoBoostOnly = () => {
    void appActions.closeOnboardingModal(true);
    appActions.setNav("preaccel");
  };

  const handleGoMainImport = () => {
    void appActions.closeOnboardingModal(true);
    appActions.openNodesWorkspace("subs", null, "migration");
  };

  const handleGoMainShare = () => {
    void appActions.closeOnboardingModal(true);
    appActions.openNodesWorkspace("subs", null, "share");
  };

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/62 p-4 backdrop-blur-[3px]"
      onClick={handleCompleteAndClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="cc-onboarding-title"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface relative flex max-h-[calc(100vh-2rem)] w-full max-w-[820px] flex-col overflow-hidden rounded-3xl border border-[var(--line-strong)] text-[var(--text)] shadow-2xl"
      >
        {/* Top subtle warm glow accent bar */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-[var(--accent)]/45 via-[var(--accent)] to-[var(--green)]/65"
        />

        {/* Minimal Header (always visible & clickable in short viewports) */}
        <div className="shrink-0 px-5 pt-4 pb-3 sm:px-6 sm:pt-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
                <Sparkles className="h-3 w-3 shrink-0" />
                <span>{dict.onboarding.welcomeBadge}</span>
              </span>
              <h2
                id="cc-onboarding-title"
                className="mt-2 break-words text-lg font-bold tracking-tight text-[var(--text)]"
              >
                {dict.onboarding.title}
              </h2>
              <p className="mt-0.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                {dict.onboarding.subtitle}
              </p>
            </div>
            <button
              type="button"
              onClick={handleCompleteAndClose}
              aria-label={dict.common.close}
              title={dict.common.close}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Scrollable 2+1 Body (zero overflow & airy at both 1200x780 and 920x620) */}
        <div className="min-h-0 flex-1 overflow-y-auto px-5 pb-4 sm:px-6">
          {/* Top Row: 2 Equal Primary Path Cards */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {/* Card 1: Keep Current Proxy, Enable Domestic Boost Only (Warm-Gold Soft Border) */}
            <section
              className="flex flex-col justify-between rounded-2xl border border-[var(--accent)]/55 p-4 transition-colors hover:border-[var(--accent)]/80"
              style={{
                background:
                  "linear-gradient(145deg, color-mix(in srgb, var(--accent-soft) 88%, var(--card)) 0%, var(--card) 100%)",
              }}
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent)] text-[var(--accent-ink)] shadow-xs">
                    <Zap className="h-[18px] w-[18px]" />
                  </span>
                  <span className="rounded-full border border-[var(--accent)]/45 bg-[var(--surface)]/90 px-2.5 py-0.5 text-[10.5px] font-semibold text-[var(--accent)]">
                    {dict.onboarding.pathBoostBadge}
                  </span>
                </div>
                <h3 className="mt-3 break-words text-[14.5px] font-bold leading-snug tracking-tight text-[var(--text)]">
                  {dict.onboarding.pathBoostTitle}
                </h3>
                <p className="mt-1.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                  {dict.onboarding.pathBoostDesc}
                </p>
              </div>

              <div className="mt-4 pt-1">
                <button
                  type="button"
                  onClick={handleGoBoostOnly}
                  className="inline-flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2.5 text-xs font-bold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                >
                  <Zap className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate">{dict.onboarding.pathBoostBtn}</span>
                  <ArrowRight className="h-3.5 w-3.5 shrink-0" />
                </button>
              </div>
            </section>

            {/* Card 2: Use CatCloud as Main Proxy (Mint-Green Soft Border) */}
            <section
              className="flex flex-col justify-between rounded-2xl border border-[var(--green)]/50 p-4 transition-colors hover:border-[var(--green)]/75"
              style={{
                background:
                  "linear-gradient(145deg, color-mix(in srgb, var(--green-soft) 82%, var(--card)) 0%, var(--card) 100%)",
              }}
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--green)] text-[var(--accent-ink)] shadow-xs">
                    <Globe className="h-[18px] w-[18px]" />
                  </span>
                  <span className="rounded-full border border-[var(--green)]/45 bg-[var(--surface)]/90 px-2.5 py-0.5 text-[10.5px] font-semibold text-[var(--green)]">
                    {dict.onboarding.pathMainBadge}
                  </span>
                </div>
                <h3 className="mt-3 break-words text-[14.5px] font-bold leading-snug tracking-tight text-[var(--text)]">
                  {dict.onboarding.pathMainTitle}
                </h3>
                <p className="mt-1.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                  {dict.onboarding.pathMainDesc}
                </p>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={handleGoMainImport}
                  className="inline-flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-xl bg-[var(--green)] px-3 py-2.5 text-xs font-bold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                >
                  <Download className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate">{dict.onboarding.pathMainImportBtn}</span>
                </button>
                <button
                  type="button"
                  onClick={handleGoMainShare}
                  className="inline-flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-[var(--green)]/45 bg-[var(--surface)]/95 px-3 py-2.5 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--green)] hover:text-[var(--green)]"
                >
                  <Package className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                  <span className="truncate">{dict.onboarding.pathMainShareBtn}</span>
                </button>
              </div>
            </section>
          </div>

          {/* Bottom Row: Compact Horizontal Light AI Card */}
          <section className="mt-3 rounded-2xl border border-[var(--line-strong)] bg-[var(--bg-elevated)]/85 px-4 py-3.5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-start gap-2.5">
                <span className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--accent)]/35 bg-[var(--accent-soft)] text-[var(--accent)]">
                  <Bot className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="break-words text-[13.5px] font-bold tracking-tight text-[var(--text)]">
                      {dict.onboarding.pathAiTitle}
                    </h3>
                    <span className="rounded-full border border-[var(--line-strong)] bg-[var(--surface)] px-2 py-0.5 text-[10px] font-semibold text-[var(--text-secondary)]">
                      {dict.onboarding.pathAiBadge}
                    </span>
                  </div>
                  <p className="mt-0.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                    {dict.onboarding.pathAiDesc}
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void handleCopyAutopilot()}
                className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-[var(--accent)]/55 bg-[var(--accent-soft)] px-3.5 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:opacity-60"
              >
                {copiedMode === "local" ? (
                  <Check className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                ) : busyAction === "local" ? (
                  <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                ) : (
                  <Copy className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                )}
                <span>
                  {copiedMode === "local"
                    ? dict.common.copied
                    : dict.onboarding.copyAutopilotBtn}
                </span>
              </button>

              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void handleCopyWebGuide()}
                className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] px-3.5 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--sky)] hover:text-[var(--sky)] disabled:opacity-60"
              >
                {copiedMode === "web" ? (
                  <Check className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                ) : busyAction === "web" ? (
                  <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                ) : (
                  <Copy className="h-3.5 w-3.5 shrink-0 text-[var(--sky)]" />
                )}
                <span>
                  {copiedMode === "web"
                    ? dict.common.copied
                    : dict.onboarding.copyWebGuideBtn}
                </span>
              </button>
            </div>

            {/* Gentle Post-Copy Feedback & Quick Enter */}
            {copiedMode && (
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--green)]/45 bg-[var(--green-soft)] px-3.5 py-2 text-xs">
                <div className="flex min-w-0 flex-1 items-center gap-2 text-[var(--text)]">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--green)]" />
                  <span className="break-words leading-snug">
                    {copiedMode === "local"
                      ? dict.onboarding.copiedHintLocal
                      : dict.onboarding.copiedHintWeb}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleCompleteAndClose}
                  className="inline-flex shrink-0 cursor-pointer items-center gap-1 rounded-lg bg-[var(--green)] px-3 py-1.5 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  <span>{dict.onboarding.enterMainAfterCopy}</span>
                  <ArrowRight className="h-3 w-3" />
                </button>
              </div>
            )}
          </section>
        </div>

        {/* Fixed Footer (never pushed out of view on 620px short viewports) */}
        <div className="flex shrink-0 items-center justify-end border-t border-[var(--line)]/80 bg-[var(--surface)]/90 px-5 py-3 sm:px-6">
          <button
            type="button"
            onClick={handleCompleteAndClose}
            className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-4 py-1.5 text-xs font-semibold text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
          >
            <span>{dict.onboarding.skipToHomeBtn}</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
