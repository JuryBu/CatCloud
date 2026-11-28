import {
  Bot,
  CloudDownload,
  Copy,
  Download,
  ExternalLink,
  FolderOpen,
  MessageSquareWarning,
  RefreshCw,
  RotateCcw,
  RotateCw,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  type AppConfig,
  type AppUpdateCheckResult,
  type PendingUpdatePromptDto,
  type RuntimeInfoDto,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import { type UiLanguage, formatI18nTemplate, type useUiDict } from "../../i18n";

type UiDict = ReturnType<typeof useUiDict>;
import { appActions } from "../../store/appStore";
import { buildReleasesFallbackUrl } from "../../utils/releaseUrl";
import { BTN_CLS, Card, INPUT_CLS, NumericDraftInput, SwitchRow } from "./SettingsPrimitives";
import { copySettingText, formatGeoFileSize } from "./settingsPatch";

export interface UpdatesTabProps {
  uiLang: UiLanguage;
  isZh: boolean;
  dict: UiDict;
  inTauri: boolean;
  draft: AppConfig;
  storeSkippedVersion: string | null | undefined;
  runtime: RuntimeInfoDto;
  checkingUpdate: boolean;
  downloadingUpdate: boolean;
  updateInfo: AppUpdateCheckResult | null;
  updateMsg: string | null;
  pendingUpdate: PendingUpdatePromptDto | null;
  patchDraft: (patch: Partial<AppConfig>) => void;
}

export function UpdatesTab({
  uiLang,
  isZh,
  dict,
  inTauri,
  draft,
  storeSkippedVersion,
  runtime,
  checkingUpdate,
  downloadingUpdate,
  updateInfo,
  updateMsg,
  pendingUpdate,
  patchDraft,
}: UpdatesTabProps) {
  const [openingIssue, setOpeningIssue] = useState(false);
  const [updateActionBusy, setUpdateActionBusy] = useState<
    "apply" | "skip" | "clear_skip" | null
  >(null);

  const updateExitFallbackTimerRef = useRef<number | null>(null);
  const clearUpdateExitFallbackTimer = () => {
    if (updateExitFallbackTimerRef.current !== null) {
      window.clearTimeout(updateExitFallbackTimerRef.current);
      updateExitFallbackTimerRef.current = null;
    }
  };
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearUpdateExitFallbackTimer();
    };
  }, []);

  const handleCheckUpdate = async () => {
    if (checkingUpdate) return;
    await appActions.runCheckAppUpdate();
  };

  const handleDownloadAndStageUpdate = async () => {
    if (downloadingUpdate) return;
    await appActions.runDownloadAppUpdate();
  };

  const handleApplyPendingUpdate = async () => {
    if (updateActionBusy !== null) return;
    clearUpdateExitFallbackTimer();
    setUpdateActionBusy("apply");
    let exitingNow = false;
    try {
      const res = await appActions.applyPendingUpdateAndRestart();
      if (res.cancelled) {
        appActions.showToast(dict.updateModal.cancelledHint, "info");
      } else if (res.exiting) {
        exitingNow = true;
        // Safety unlock fallback matching UpdateReadyModal: never leave buttons permanently locked if graceful exit stalls.
        updateExitFallbackTimerRef.current = window.setTimeout(() => {
          updateExitFallbackTimerRef.current = null;
          if (!mountedRef.current) return;
          setUpdateActionBusy(null);
          appActions.showToast(
            `${dict.updateModal.applyErrorPrefix}${res.message?.trim() || dict.updateModal.exitTimeoutFallback}`,
            "warn",
            5000
          );
        }, 12_000);
      } else if (res.started) {
        const localizedStartedHint =
          res.apply_action === "reveal_archive"
            ? dict.updateModal.revealOpenedHint
            : dict.updateModal.installerMacHint;
        appActions.showToast(
          uiLang !== "zh-CN"
            ? localizedStartedHint
            : res.message?.trim() || localizedStartedHint,
          "ok"
        );
      } else {
        appActions.showToast(
          `${dict.updateModal.applyErrorPrefix}${res.message || dict.updateModal.unknownErrorFallback}`,
          "warn"
        );
      }
    } catch (err) {
      appActions.showToast(
        `${dict.updateModal.applyErrorPrefix}${formatErrorMessage(err)}`,
        "warn"
      );
    } finally {
      if (!exitingNow) {
        clearUpdateExitFallbackTimer();
        if (mountedRef.current) {
          setUpdateActionBusy(null);
        }
      }
    }
  };

  const handleSkipPendingUpdate = async () => {
    if (updateActionBusy !== null || !pendingUpdate) return;
    setUpdateActionBusy("skip");
    try {
      await appActions.skipPendingUpdateVersion(pendingUpdate.target_version);
    } catch {
      /* toast already shown by appActions.skipPendingUpdateVersion */
    } finally {
      setUpdateActionBusy(null);
    }
  };

  const handleClearSkippedUpdate = async () => {
    if (updateActionBusy !== null) return;
    setUpdateActionBusy("clear_skip");
    try {
      await appActions.clearSkippedUpdateVersion();
    } finally {
      setUpdateActionBusy(null);
    }
  };

  const handleOpenReleasePage = async () => {
    const fallbackUrl = buildReleasesFallbackUrl(draft.update.repo);
    const targetUrl =
      updateInfo?.release_url?.trim() || pendingUpdate?.release_url?.trim() || fallbackUrl;
    try {
      await catcloudApi.openExternalUrl(targetUrl);
      if (inTauri) {
        try {
          await navigator.clipboard.writeText(targetUrl);
        } catch {
          /* clipboard optional when browser opens directly */
        }
        appActions.showToast(
          formatI18nTemplate(dict.settings.updateOpenedReleaseToast, {
            url: targetUrl,
          }),
          "ok"
        );
        return;
      }
    } catch {
      /* fall back to copying link below */
    }
    await copySettingText(targetUrl, dict.settings.updateReleaseLinkLabel);
  };

  return (
    <div className="space-y-4">
      <Card
        title={dict.settings.updateCardTitle}
        sub={formatI18nTemplate(dict.settings.updateCardSub, {
          version: runtime.app_version,
          os: runtime.os_label,
          repo: draft.update.repo,
        })}
        action={
          <button
            type="button"
            onClick={() => void handleCheckUpdate()}
            disabled={checkingUpdate}
            className={BTN_CLS}
          >
            {checkingUpdate ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <CloudDownload className="h-3.5 w-3.5" />
            )}
            <span>
              {checkingUpdate ? dict.settings.updateCheckingBtn : dict.settings.updateCheckBtn}
            </span>
          </button>
        }
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="text-[11px] text-[var(--muted)]">
            {dict.settings.updateRepoLabel}
            <input
              value={draft.update.repo}
              onChange={(e) => patchDraft({ update: { ...draft.update, repo: e.target.value } })}
              className={`${INPUT_CLS} mt-1 cc-mono`}
            />
          </label>
          <div className="text-[11px] text-[var(--muted)]">
            <span className="block">{dict.settings.updateModeLabel}</span>
            <AppSelect
              aria-label={dict.settings.updateModeLabel}
              size="sm"
              value={draft.update.mode}
              onChange={(v) =>
                patchDraft({
                  update: {
                    ...draft.update,
                    mode: v as AppConfig["update"]["mode"],
                  },
                })
              }
              options={[
                { value: "next_launch", label: dict.settings.updateModePrompt },
                { value: "manual", label: dict.settings.updateModeManual },
                ...(draft.update.mode === "auto_restart"
                  ? [
                      {
                        value: "auto_restart",
                        label: dict.settings.updateModeAutoRestartLegacy,
                      },
                    ]
                  : []),
              ]}
              className="mt-1 w-full"
            />
          </div>
          <label className="text-[11px] text-[var(--muted)]">
            {dict.settings.updateIntervalLabel}
            <NumericDraftInput
              min={30}
              max={43200}
              fallback={360}
              value={draft.update.check_interval_min}
              onCommit={(nextVal) =>
                patchDraft({
                  update: {
                    ...draft.update,
                    check_interval_min: nextVal,
                  },
                })
              }
              className={`${INPUT_CLS} mt-1 cc-mono`}
            />
          </label>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <SwitchRow
            title={dict.settings.updateAutoDownloadTitle}
            desc={dict.settings.updateAutoDownloadDesc}
            checked={draft.update.auto_download ?? true}
            onChange={(v) => patchDraft({ update: { ...draft.update, auto_download: v } })}
          />
          <SwitchRow
            title={dict.settings.updatePrereleaseTitle}
            desc={dict.settings.updatePrereleaseDesc}
            checked={draft.update.include_prerelease}
            onChange={(v) => patchDraft({ update: { ...draft.update, include_prerelease: v } })}
          />
        </div>

        {pendingUpdate && (
          <div className="space-y-2.5 rounded-xl border border-[var(--green)]/45 bg-[var(--green-soft)] px-3.5 py-3">
            <div className="flex flex-wrap items-start justify-between gap-2.5">
              <div className="flex min-w-0 items-start gap-2.5">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--green)]" />
                <div className="min-w-0 space-y-0.5">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    {formatI18nTemplate(dict.settings.updateReadyTitle, {
                      version: pendingUpdate.target_version,
                    })}
                  </div>
                  <p className="text-[11px] leading-relaxed text-[var(--text-secondary)]">
                    {formatI18nTemplate(dict.settings.updateReadyDesc, {
                      size: formatGeoFileSize(pendingUpdate.package_size_bytes),
                      kind:
                        pendingUpdate.kind === "portable_zip"
                          ? dict.updateModal.kindPortable
                          : dict.updateModal.kindInstaller,
                      sha: pendingUpdate.archive_sha256.slice(0, 10),
                    })}
                  </p>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 pl-6">
              <button
                type="button"
                disabled={updateActionBusy !== null}
                onClick={() => void handleApplyPendingUpdate()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {updateActionBusy === "apply" ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : pendingUpdate.apply_action === "reveal_archive" ? (
                  <FolderOpen className="h-3.5 w-3.5" />
                ) : pendingUpdate.apply_action === "installer_launch" ? (
                  <Download className="h-3.5 w-3.5" />
                ) : (
                  <RotateCw className="h-3.5 w-3.5" />
                )}
                <span>
                  {pendingUpdate.apply_action === "installer_launch"
                    ? dict.settings.updateApplyInstallerBtn
                    : pendingUpdate.apply_action === "reveal_archive"
                      ? dict.settings.updateApplyRevealBtn
                      : dict.settings.updateApplyPortableBtn}
                </span>
              </button>

              <button
                type="button"
                disabled={updateActionBusy !== null}
                onClick={() => appActions.openUpdateModal()}
                className={BTN_CLS}
              >
                <Sparkles className="h-3.5 w-3.5 text-[var(--accent)]" />
                <span>{dict.settings.updatePreviewModalBtn}</span>
              </button>

              <button
                type="button"
                disabled={updateActionBusy !== null}
                onClick={() => void handleSkipPendingUpdate()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/80 px-3 py-1.5 text-xs font-medium text-[var(--muted)] transition-colors hover:border-[var(--amber)]/55 hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {updateActionBusy === "skip" ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
                <span>{dict.settings.updateSkipPurgeBtn}</span>
              </button>
            </div>
          </div>
        )}

        {storeSkippedVersion && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/40 px-3.5 py-2 text-xs text-[var(--text-secondary)]">
            <span className="min-w-0 leading-relaxed">
              {formatI18nTemplate(dict.settings.updateSkippedBanner, {
                version: storeSkippedVersion.trim().replace(/^[vV]/, ""),
              })}
            </span>
            <button
              type="button"
              disabled={updateActionBusy !== null || checkingUpdate}
              onClick={() => void handleClearSkippedUpdate()}
              className={BTN_CLS}
            >
              {updateActionBusy === "clear_skip" ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RotateCcw className="h-3.5 w-3.5" />
              )}
              <span>{dict.settings.updateClearSkipBtn}</span>
            </button>
          </div>
        )}

        {updateInfo?.has_update && !pendingUpdate && (
          <div className="space-y-2.5 rounded-xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/45 px-3.5 py-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0 space-y-0.5">
                <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-[var(--text)]">
                  <span>
                    {formatI18nTemplate(dict.settings.updateFoundTitle, {
                      version: updateInfo.latest_version,
                    })}
                  </span>
                  <span className="rounded-md bg-[var(--surface)] px-1.5 py-0.5 cc-mono text-[10px] font-normal text-[var(--muted)]">
                    {formatI18nTemplate(dict.settings.updateCurrentBadge, {
                      version: updateInfo.current_version,
                    })}
                  </span>
                  {updateInfo.skipped && (
                    <span className="rounded-md border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                      {dict.settings.updateFoundSkippedBadge}
                    </span>
                  )}
                </div>
                <p className="text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  {updateInfo.can_auto_stage
                    ? dict.settings.updateFoundDescAuto
                    : dict.settings.updateFoundDescManual}
                </p>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                {updateInfo.can_auto_stage ? (
                  <button
                    type="button"
                    disabled={downloadingUpdate}
                    onClick={() => void handleDownloadAndStageUpdate()}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {downloadingUpdate ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Download className="h-3.5 w-3.5" />
                    )}
                    <span>
                      {downloadingUpdate
                        ? dict.settings.updateDownloadingBtn
                        : dict.settings.updateDownloadBtn}
                    </span>
                  </button>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={() => void handleOpenReleasePage()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      <span>{dict.settings.updateOpenReleaseBtn}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        void copySettingText(
                          updateInfo.release_url || buildReleasesFallbackUrl(draft.update.repo),
                          dict.settings.updateReleaseLinkLabel
                        )
                      }
                      className={BTN_CLS}
                    >
                      <Copy className="h-3.5 w-3.5" />
                      <span>{dict.settings.updateCopyReleaseBtn}</span>
                    </button>
                    {updateInfo.download_url &&
                      updateInfo.download_url !== updateInfo.release_url && (
                        <button
                          type="button"
                          onClick={() =>
                            void copySettingText(
                              updateInfo.download_url ?? "",
                              dict.settings.updateDirectLinkLabel
                            )
                          }
                          className={BTN_CLS}
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>{dict.settings.updateCopyDirectBtn}</span>
                        </button>
                      )}
                  </>
                )}
              </div>
            </div>

            {updateInfo.notes?.trim() && (
              <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)]/80 px-3 py-2">
                <div className="mb-1 text-[10px] font-medium text-[var(--muted)]">
                  {dict.settings.updateNotesTitle}
                </div>
                <div className="cc-selectable max-h-24 overflow-y-auto whitespace-pre-wrap text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  {updateInfo.notes.trim()}
                </div>
              </div>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-[var(--muted)]">
          <span>
            {updateMsg ??
              formatI18nTemplate(dict.settings.updateLastChecked, {
                time: runtime.last_update_check ?? dict.settings.updateNeverChecked,
              })}
          </span>
          {(updateInfo?.release_url || pendingUpdate?.release_url) && (
            <button
              type="button"
              onClick={() => void handleOpenReleasePage()}
              className="inline-flex items-center gap-1 text-[var(--accent)] hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              <span>{dict.settings.updateViewReleaseNotes}</span>
            </button>
          )}
        </div>
      </Card>

      {/* Compact AI Assistant & GitHub Issue Entry Card */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3.5">
        <div className="flex min-w-0 items-center gap-3">
          <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <Bot className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-[var(--text)]">{dict.aiHub.title}</div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              {isZh
                ? "新手上手指南、脱敏排障诊断包、8 篇本地详尽手册与本机 Agent 只读命令已统一迁移至侧边栏「AI 全权代管」。"
                : dict.aiHub.subtitle}
            </p>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => appActions.openOnboardingModal()}
            className={BTN_CLS}
          >
            <Sparkles className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{dict.settings.reopenOnboardingBtn}</span>
          </button>

          <button
            type="button"
            onClick={() => appActions.openAiAssistant()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
          >
            <Bot className="h-3.5 w-3.5" />
            <span>{dict.settings.goToAiHub}</span>
          </button>

          <button
            type="button"
            disabled={openingIssue}
            onClick={() => {
              if (openingIssue) return;
              setOpeningIssue(true);
              void appActions.openGithubIssueFeedback().finally(() => {
                setOpeningIssue(false);
              });
            }}
            className={BTN_CLS}
          >
            <MessageSquareWarning className="h-3.5 w-3.5 text-[var(--amber)]" />
            <span>{dict.common.openIssue}</span>
          </button>
        </div>
      </section>
    </div>
  );
}
