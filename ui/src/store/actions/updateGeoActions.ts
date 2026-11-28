import {
  type AppUpdateCheckResult,
  type ApplyUpdateRestartResultDto,
  type PendingUpdatePromptDto,
  type SkipUpdateResultDto,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import {
  ensureUiLocaleLoaded,
  formatI18nTemplate,
  getUiDictSync,
  normalizeUiLanguage,
  type UiLanguage,
} from "../../i18n";
import { buildReleasesFallbackUrl } from "../../utils/releaseUrl";
import type { StoreCore } from "../core";

const stripVer = (v: string) => v.trim().replace(/^[vV]/, "");

const pickUpdateMsg = (lang: UiLanguage, localized: string, raw?: string | null) =>
  lang !== "zh-CN" ? localized : raw?.trim() || localized;

const fmtUpdateErr = (tpl: string, err: unknown) =>
  formatI18nTemplate(tpl, { error: formatErrorMessage(err) });

export function createUpdateGeoActions(core: StoreCore) {
  let pendingUpdateRefreshSeq = 0;

  async function loadUpdateI18n() {
    const lang = normalizeUiLanguage(core.getState().config.personalization.ui_language);
    const d = await ensureUiLocaleLoaded(lang).catch(() => getUiDictSync(lang));
    return [lang, d.updateModal] as const;
  }

  async function runCheckAppUpdate(): Promise<void> {
    return core.runInFlight(
      "settings:checkUpdate",
      async () => {
        core.patchSettingsBg({ checkingUpdate: true });
        try {
          const res = await catcloudApi.checkAppUpdate();
          const cur = core.getState();
          const pending =
            cur.windowMode === "main"
              ? await catcloudApi.getPendingStagedUpdate().catch(() => cur.pendingUpdate)
              : cur.pendingUpdate;
          const [, u] = await loadUpdateI18n();
          let message: string;
          if (res.error) {
            message = formatI18nTemplate(u.checkFailedMsg, { error: res.error });
            core.pushToast(message, "warn");
          } else if (pending || res.staged_version) {
            message = formatI18nTemplate(u.checkReadyMsg, {
              version: stripVer(pending?.target_version ?? res.staged_version ?? res.latest_version),
            });
            core.pushToast(message, "ok");
          } else if (res.has_update) {
            const latestVer = stripVer(res.latest_version);
            message = res.skipped
              ? formatI18nTemplate(u.checkFoundSkippedMsg, { version: latestVer })
              : formatI18nTemplate(u.checkFoundMsg, {
                  version: latestVer,
                  current: stripVer(res.current_version),
                });
            core.pushToast(message, res.skipped ? "info" : "ok");
          } else {
            message = formatI18nTemplate(u.alreadyLatestMsg, {
              version: stripVer(res.current_version),
            });
            core.pushToast(u.alreadyLatestToast, "info");
          }
          core.patchUpdateSlice({
            pendingUpdate: pending,
            updateModalVisible: pending ? core.getState().updateModalVisible : false,
            skippedVersion: res.skipped_version,
            settingsPatch: { updateInfo: res, updateMessage: message },
          });
        } catch (err) {
          const [, u] = await loadUpdateI18n();
          const msg = fmtUpdateErr(u.checkFailedMsg, err);
          core.patchSettingsBg({ updateMessage: msg });
          core.pushToast(msg, "warn");
        } finally {
          core.patchSettingsBg({ checkingUpdate: false });
        }
      },
      { mascot: true }
    );
  }

  return {
    async loadGeodataStatus(force = false): Promise<void> {
      if (!force && core.getState().bgTasks.settings.geoStatus !== null) {
        return;
      }
      return core.runInFlight("settings:geoStatus", async () => {
        core.patchSettingsBg({ geoLoading: true });
        try {
          core.patchSettingsBg({ geoStatus: await catcloudApi.getGeodataStatus() });
        } catch {
          /* preserve previous geodata status on transient failure */
        } finally {
          core.patchSettingsBg({ geoLoading: false });
        }
      });
    },

    async runRefreshGeoDb(target: string | string[]): Promise<void> {
      const busyKey = Array.isArray(target) ? target.join(",") : target;
      const targetsPayload = Array.isArray(target)
        ? target
        : target === "all"
          ? null
          : [target];
      const existing = core.inFlightTasks.get("settings:geoRefresh");
      if (existing) {
        if (core.getState().bgTasks.settings.geoBusy !== busyKey) {
          core.pushToast("地理数据库正在更新中，请稍候完成后再试", "info");
        }
        return existing as Promise<void>;
      }
      return core.runInFlight(
        "settings:geoRefresh",
        async () => {
          core.patchSettingsBg({ geoBusy: busyKey });
          try {
            const res = await catcloudApi.refreshGeoDb(targetsPayload);
            const [geoRes, rtRes] = await Promise.allSettled([
              catcloudApi.getGeodataStatus(),
              catcloudApi.getRuntimeInfo(),
            ]);
            if (geoRes.status === "fulfilled") {
              core.patchSettingsBg({ geoStatus: geoRes.value });
            }
            if (rtRes.status === "fulfilled") {
              core.setState((prev) => ({ ...prev, runtime: rtRes.value }));
            }
            const baseMsg = res.message?.trim() || "地理数据库已更新";
            let finalMsg = baseMsg;
            if (res.ok) {
              if (res.reloaded === true && !/热载|生效|reload/i.test(baseMsg)) {
                finalMsg = `${baseMsg}（已自动热载生效）`;
              } else if (res.reloaded === false && !/下次|启动|reload/i.test(baseMsg)) {
                finalMsg = core.getState().runtime.running
                  ? `${baseMsg}（已写入本地，如未立即生效可点重载核心）`
                  : `${baseMsg}（已写入本地，下次启动代理生效）`;
              }
            }
            core.pushToast(finalMsg, res.ok ? "ok" : "warn");
          } catch (err) {
            core.pushToast(`更新地理数据库失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.patchSettingsBg({ geoBusy: null });
          }
        },
        { mascot: true }
      );
    },

    openUpdateModal(): void {
      const state = core.getState();
      if (state.pendingUpdate && !state.updateModalVisible) {
        core.patchUpdateSlice({ updateModalVisible: true });
      }
    },

    async refreshPendingUpdate(): Promise<PendingUpdatePromptDto | null> {
      if (core.getState().windowMode !== "main") return core.getState().pendingUpdate;
      const seq = ++pendingUpdateRefreshSeq;
      try {
        const pending = await catcloudApi.getPendingStagedUpdate();
        const cur = core.getState();
        if (seq !== pendingUpdateRefreshSeq) return cur.pendingUpdate;
        const prevInfo = cur.bgTasks.settings.updateInfo;
        core.patchUpdateSlice({
          pendingUpdate: pending,
          updateModalVisible: pending ? cur.updateModalVisible : false,
          settingsPatch:
            !pending && prevInfo?.staged_version
              ? { updateInfo: { ...prevInfo, staged_version: null } }
              : undefined,
        });
        return pending;
      } catch {
        return core.getState().pendingUpdate;
      }
    },

    async dismissUpdatePrompt(): Promise<void> {
      const cur = core.getState();
      const version = cur.pendingUpdate?.target_version ?? "";
      core.patchUpdateSlice({
        updateModalVisible: false,
        pendingUpdate: cur.pendingUpdate
          ? { ...cur.pendingUpdate, dismissed_in_session: true }
          : null,
      });
      if (version) {
        await catcloudApi.dismissUpdatePromptForSession(version).catch(() => false);
      }
    },

    async skipPendingUpdateVersion(
      version?: string,
      opts?: { silentError?: boolean }
    ): Promise<SkipUpdateResultDto | null> {
      const targetVersion = (version ?? core.getState().pendingUpdate?.target_version ?? "").trim();
      if (!targetVersion) return null;
      try {
        const res = await catcloudApi.skipUpdateVersion(targetVersion);
        const [, u] = await loadUpdateI18n();
        const skippedVer = stripVer(res.skipped_version || targetVersion);
        const toastText = formatI18nTemplate(
          res.purged_staged ? u.skippedToast : u.skippedToastNoPurge,
          { version: skippedVer }
        );
        const prevInfo = core.getState().bgTasks.settings.updateInfo;
        core.patchUpdateSlice({
          pendingUpdate: null,
          updateModalVisible: false,
          skippedVersion: skippedVer,
          settingsPatch: {
            updateInfo: prevInfo
              ? {
                  ...prevInfo,
                  staged_version: null,
                  skipped: prevInfo.latest_version === skippedVer || Boolean(prevInfo.skipped),
                  skipped_version: skippedVer,
                }
              : prevInfo,
            updateMessage: toastText,
          },
        });
        core.pushToast(toastText, "ok", 4500);
        return res;
      } catch (err) {
        if (!opts?.silentError) {
          const [, u] = await loadUpdateI18n();
          core.pushToast(fmtUpdateErr(u.skipFailedToast, err), "warn");
        }
        throw err;
      }
    },

    async clearSkippedUpdateVersion(): Promise<boolean> {
      try {
        const ok = await catcloudApi.clearSkippedUpdateVersion();
        const [, u] = await loadUpdateI18n();
        const prevInfo = core.getState().bgTasks.settings.updateInfo;
        core.patchUpdateSlice({
          skippedVersion: null,
          settingsPatch: {
            updateInfo: prevInfo ? { ...prevInfo, skipped: false, skipped_version: null } : prevInfo,
          },
        });
        core.pushToast(u.clearSkippedToast, "info", 3200);
        await runCheckAppUpdate();
        return ok;
      } catch (err) {
        const [, u] = await loadUpdateI18n();
        core.pushToast(fmtUpdateErr(u.clearSkipFailedToast, err), "warn");
        return false;
      }
    },

    async applyPendingUpdateAndRestart(): Promise<ApplyUpdateRestartResultDto> {
      return catcloudApi.applyStagedUpdateAndRestart();
    },

    runCheckAppUpdate,

    async runDownloadAppUpdate(): Promise<void> {
      return core.runInFlight(
        "settings:downloadUpdate",
        async () => {
          core.patchSettingsBg({ downloadingUpdate: true });
          try {
            const res = await catcloudApi.downloadAndStageUpdate();
            const state = core.getState();
            const prevInfo = state.bgTasks.settings.updateInfo;
            const [uiLang, u] = await loadUpdateI18n();
            if (res.staged) {
              const pendingDto =
                state.windowMode === "main"
                  ? await catcloudApi.getPendingStagedUpdate().catch(() => null)
                  : null;
              const targetVersion = stripVer(
                pendingDto?.target_version ||
                  res.target_version ||
                  prevInfo?.latest_version ||
                  state.runtime.app_version
              );
              const readyMsg = formatI18nTemplate(u.downloadReadyMsg, { version: targetVersion });
              const nextInfo: AppUpdateCheckResult = {
                has_update: true,
                current_version: prevInfo?.current_version ?? state.runtime.app_version,
                latest_version: targetVersion,
                release_url:
                  pendingDto?.release_url ||
                  res.release_url ||
                  prevInfo?.release_url ||
                  buildReleasesFallbackUrl(state.config.update.repo),
                download_url: res.download_url ?? prevInfo?.download_url ?? null,
                notes: pendingDto?.release_notes || prevInfo?.notes || "",
                checked_at: prevInfo?.checked_at ?? new Date().toISOString(),
                platform_key: pendingDto?.platform_key ?? prevInfo?.platform_key,
                can_auto_stage: true,
                staged_version: targetVersion,
                skipped: false,
                skipped_version: null,
                error: null,
              };
              core.patchUpdateSlice({
                pendingUpdate: pendingDto ?? core.getState().pendingUpdate,
                skippedVersion: null,
                settingsPatch: { updateInfo: nextInfo, updateMessage: readyMsg },
              });
              core.pushToast(pickUpdateMsg(uiLang, readyMsg, res.message), "ok", 4500);
            } else if (res.already_latest) {
              const msg = pickUpdateMsg(
                uiLang,
                formatI18nTemplate(u.alreadyLatestMsg, {
                  version: stripVer(state.runtime.app_version),
                }),
                res.message
              );
              core.patchSettingsBg({
                updateInfo: prevInfo ? { ...prevInfo, has_update: false } : prevInfo,
                updateMessage: msg,
              });
              core.pushToast(msg, "info");
            } else {
              const releaseUrl =
                res.release_url ||
                prevInfo?.release_url ||
                buildReleasesFallbackUrl(state.config.update.repo);
              const hint = pickUpdateMsg(uiLang, u.downloadManualHint, res.message);
              core.patchSettingsBg({
                updateInfo: prevInfo
                  ? {
                      ...prevInfo,
                      can_auto_stage: res.can_auto_stage ?? prevInfo.can_auto_stage,
                      release_url: releaseUrl,
                      download_url: res.download_url ?? prevInfo.download_url,
                    }
                  : prevInfo,
                updateMessage: hint,
              });
              core.pushToast(hint, "info");
            }
          } catch (err) {
            const [, u] = await loadUpdateI18n();
            const msg = fmtUpdateErr(u.downloadFailedMsg, err);
            core.patchSettingsBg({ updateMessage: msg });
            core.pushToast(msg, "warn");
          } finally {
            core.patchSettingsBg({ downloadingUpdate: false });
          }
        },
        { mascot: true }
      );
    },
  };
}
