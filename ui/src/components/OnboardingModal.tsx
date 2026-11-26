import {
  ArrowRight,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Globe,
  Layers,
  Loader2,
  SlidersHorizontal,
  Sparkles,
  Terminal,
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
    (onboardingModalOpen || (!onboardingCompleted && !onboardingAutoSkipped));

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
        void appActions.markOnboardingCompleted();
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
        void appActions.markOnboardingCompleted();
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handleCompleteAndClose = () => {
    void appActions.closeOnboardingModal(true);
  };

  const taskItems = [
    { icon: Globe, text: dict.onboarding.aiTask1 },
    { icon: Sparkles, text: dict.onboarding.aiTask2 },
    { icon: Layers, text: dict.onboarding.aiTask3 },
    { icon: Zap, text: dict.onboarding.aiTask4 },
  ] as const;

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
        className="cc-surface relative w-full max-w-[760px] overflow-hidden rounded-3xl border border-[var(--line-strong)] p-5 text-[var(--text)] shadow-2xl sm:p-6"
      >
        {/* Top subtle warm glow accent bar */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-[var(--accent)]/40 via-[var(--accent)] to-[var(--sky)]/60"
        />

        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              <span>{dict.onboarding.welcomeBadge}</span>
            </span>
            <h2
              id="cc-onboarding-title"
              className="mt-2 text-lg font-bold tracking-tight text-[var(--text)]"
            >
              {dict.onboarding.title}
            </h2>
            <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
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

        {/* Centerpiece Hero Card: Hand Everything Over to AI Autopilot */}
        <section
          className="mt-4 rounded-2xl border border-[var(--accent)]/65 p-4 sm:p-5"
          style={{
            background:
              "linear-gradient(135deg, var(--accent-soft) 0%, color-mix(in srgb, var(--card) 92%, var(--sky-soft)) 100%)",
          }}
        >
          <div className="flex flex-wrap items-start justify-between gap-2.5">
            <div className="flex items-center gap-2.5">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-[var(--accent)] text-[var(--accent-ink)] shadow-sm">
                <Bot className="h-5 w-5" />
              </span>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-[15px] font-bold tracking-tight text-[var(--text)]">
                    {dict.onboarding.aiCardTitle}
                  </h3>
                  <span className="rounded-full bg-[var(--accent)] px-2 py-0.5 text-[10px] font-bold text-[var(--accent-ink)]">
                    {dict.onboarding.aiCardBadge}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
                  {dict.onboarding.aiCardLead}
                </p>
              </div>
            </div>
          </div>

          {/* Supported AI Channels Strip */}
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--accent)]/35 bg-[var(--surface)]/90 px-3 py-2">
              <div className="min-w-0">
                <div className="text-[10.5px] font-semibold text-[var(--accent)]">
                  {dict.onboarding.aiSupportLocalLabel}
                </div>
                <div className="mt-0.5 truncate text-xs font-semibold text-[var(--text)]">
                  {dict.onboarding.aiSupportLocalNames}
                </div>
              </div>
              <Terminal className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            </div>
            <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/90 px-3 py-2">
              <div className="min-w-0">
                <div className="text-[10.5px] font-semibold text-[var(--sky)]">
                  {dict.onboarding.aiSupportWebLabel}
                </div>
                <div className="mt-0.5 truncate text-xs font-semibold text-[var(--text)]">
                  {dict.onboarding.aiSupportWebNames}
                </div>
              </div>
              <Sparkles className="h-4 w-4 shrink-0 text-[var(--sky)]" />
            </div>
          </div>

          {/* 4 Things AI Can Handle Completely */}
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {taskItems.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.text}
                  className="flex items-start gap-2 rounded-xl border border-[var(--line)]/80 bg-[var(--card)]/85 px-3 py-2 text-xs text-[var(--text-secondary)]"
                >
                  <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                  <span className="leading-snug">{item.text}</span>
                </div>
              );
            })}
          </div>

          {/* Action Buttons */}
          <div className="mt-4 flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleCopyAutopilot()}
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl bg-[var(--accent)] px-4 py-2.5 text-xs font-bold text-[var(--accent-ink)] shadow-sm transition-opacity hover:opacity-90 disabled:opacity-60 sm:flex-none"
            >
              {copiedMode === "local" ? (
                <Check className="h-4 w-4 shrink-0" />
              ) : busyAction === "local" ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
              ) : (
                <Copy className="h-4 w-4 shrink-0" />
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
              className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] px-3.5 py-2.5 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
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
                <span className="leading-snug">
                  {copiedMode === "local"
                    ? dict.onboarding.copiedHintLocal
                    : dict.onboarding.copiedHintWeb}
                </span>
              </div>
              <button
                type="button"
                onClick={handleCompleteAndClose}
                className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--green)] px-3 py-1.5 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <span>{dict.onboarding.enterMainAfterCopy}</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          )}
        </section>

        {/* Bottom Clean Self-Setup Card */}
        <section className="mt-3 flex flex-col justify-between gap-3 rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3.5 sm:flex-row sm:items-center">
          <div className="flex min-w-0 items-start gap-2.5">
            <span className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)]">
              <SlidersHorizontal className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[var(--text)]">
                {dict.onboarding.selfTitle}
              </div>
              <p className="mt-0.5 text-[11px] leading-relaxed text-pretty text-[var(--muted)]">
                {dict.onboarding.selfDesc}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleCompleteAndClose}
            className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-4 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <span>{dict.onboarding.selfBtn}</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </section>
      </div>
    </div>,
    document.body
  );
}
