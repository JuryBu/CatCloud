import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  CloudDownload,
  Cpu,
  Globe,
  Palette,
  RefreshCw,
  RotateCcw,
  Save,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";
import {
  type AppConfig,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";
import { normalizeUpdateRepo } from "../utils/releaseUrl";
import { usePersistedState } from "../utils/uiPrefs";
import { AppearanceTab } from "./settings/AppearanceTab";
import { BackupImportConfirmModal } from "./settings/BackupModals";
import { CoreTab } from "./settings/CoreTab";
import { DnsTab } from "./settings/DnsTab";
import { SystemTab } from "./settings/SystemTab";
import { UpdatesTab } from "./settings/UpdatesTab";
import {
  DEFAULT_EXTENDED,
  type ExtendedSettings,
  SETTINGS_TAB_VALIDATOR,
  type SettingsTabId,
  TAB_LABELS_BY_LANG,
  buildExtendedPatch,
  buildMergedSettingsPatch,
  formatDnsListenAddr,
  hydrateExtendedFromFullConfig,
  isValidSettingsTab,
  splitHostPort,
  tierFromMb,
} from "./settings/settingsPatch";

const ShareBundleModal = lazy(() =>
  import("../components/ShareBundleModal").then((m) => ({ default: m.ShareBundleModal }))
);

interface SettingsSessionDraftCache {
  draft: AppConfig | null;
  ext: ExtendedSettings | null;
  extLoaded: boolean;
  draftDirty: boolean;
  extDirty: boolean;
  appendRulesDirty: boolean;
  coreBinaryPath: string;
  yamlPreview: string | null;
  yamlSha: string | null;
}

let settingsDraftCache: SettingsSessionDraftCache = {
  draft: null,
  ext: null,
  extLoaded: false,
  draftDirty: false,
  extDirty: false,
  appendRulesDirty: false,
  coreBinaryPath: "",
  yamlPreview: null,
  yamlSha: null,
};

function clearSettingsDirtyDraftCache(): void {
  settingsDraftCache = {
    ...settingsDraftCache,
    draft: null,
    ext: null,
    draftDirty: false,
    extDirty: false,
    appendRulesDirty: false,
  };
}

export function SettingsPage() {
  const storeConfig = useAppSelector((s) => s.config);
  const uiLang = normalizeUiLanguage(storeConfig.personalization.ui_language);
  const dict = useUiDict(uiLang);
  const isZh = uiLang === "zh-CN";
  const runtime = useAppSelector((s) => s.runtime);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const wallpaperPreviewUrl = useAppSelector((s) => s.wallpaperPreviewUrl);
  const wallpaperError = useAppSelector((s) => s.wallpaperError);
  const settingsTabHint = useAppSelector((s) => s.settingsTabHint);
  const savedSettingsTab = useAppSelector((s) => s.sessionDrafts.settings.tab);
  const geoStatus = useAppSelector((s) => s.bgTasks.settings.geoStatus);
  const geoStatusLoading = useAppSelector((s) => s.bgTasks.settings.geoLoading);
  const geoBusy = useAppSelector((s) => s.bgTasks.settings.geoBusy);
  const checkingUpdate = useAppSelector((s) => s.bgTasks.settings.checkingUpdate);
  const downloadingUpdate = useAppSelector((s) => s.bgTasks.settings.downloadingUpdate);
  const updateInfo = useAppSelector((s) => s.bgTasks.settings.updateInfo);
  const updateMsg = useAppSelector((s) => s.bgTasks.settings.updateMessage);
  const pendingUpdate = useAppSelector((s) => s.pendingUpdate);
  const coreOpBusy = useAppSelector((s) => s.bgTasks.settings.coreOpBusy);
  const backupBusy = useAppSelector((s) => s.bgTasks.settings.backupBusy);
  const inTauri = isTauriEnv();
  const platformOs = resolvePlatformOs(runtime.os_label);
  const isWindows = platformOs === "windows";

  const [tab, setTab] = usePersistedState<SettingsTabId>(
    "settings.activeTab",
    isValidSettingsTab(savedSettingsTab) ? savedSettingsTab : "system",
    SETTINGS_TAB_VALIDATOR
  );

  useEffect(() => {
    if (settingsTabHint) {
      setTab(settingsTabHint);
      appActions.consumeSettingsTabHint();
    }
  }, [settingsTabHint, setTab]);

  useEffect(() => {
    if (tab !== appStore.getState().sessionDrafts.settings.tab) {
      appActions.patchSessionDraft("settings", { tab });
    }
  }, [tab]);

  const [draft, setDraft] = useState<AppConfig>(() => {
    if (settingsDraftCache.draftDirty && settingsDraftCache.draft) {
      return {
        ...structuredClone(settingsDraftCache.draft),
        personalization: structuredClone(storeConfig.personalization),
        preaccel: structuredClone(storeConfig.preaccel),
        system_proxy_enabled: storeConfig.system_proxy_enabled,
        tun_enabled: storeConfig.tun_enabled,
        proxy_mode: storeConfig.proxy_mode,
        update: {
          ...settingsDraftCache.draft.update,
          skipped_version: storeConfig.update.skipped_version ?? null,
        },
      };
    }
    return structuredClone(storeConfig);
  });
  const [ext, setExt] = useState<ExtendedSettings>(() =>
    settingsDraftCache.extDirty && settingsDraftCache.ext
      ? structuredClone(settingsDraftCache.ext)
      : DEFAULT_EXTENDED
  );
  const [extLoaded, setExtLoaded] = useState<boolean>(
    () => settingsDraftCache.extDirty && settingsDraftCache.extLoaded
  );
  const [extLoadError, setExtLoadError] = useState<string | null>(null);
  const [coreBinaryPath, setCoreBinaryPath] = useState<string>(
    () => settingsDraftCache.coreBinaryPath
  );
  const [draftDirty, setDraftDirty] = useState<boolean>(() => settingsDraftCache.draftDirty);
  const [extDirty, setExtDirty] = useState<boolean>(() => settingsDraftCache.extDirty);
  const [appendRulesDirty, setAppendRulesDirty] = useState<boolean>(
    () => settingsDraftCache.appendRulesDirty
  );
  const [saving, setSaving] = useState(false);
  const [yamlPreview, setYamlPreview] = useState<string | null>(
    () => settingsDraftCache.yamlPreview
  );
  const [yamlSha, setYamlSha] = useState<string | null>(() => settingsDraftCache.yamlSha);
  const [confirmImportBackupOpen, setConfirmImportBackupOpen] = useState(false);
  const [syncModalOpen, setSyncModalOpen] = useState(false);

  const dirty = draftDirty || extDirty;
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const extDirtyRef = useRef(extDirty);
  extDirtyRef.current = extDirty;
  const appendRulesDirtyRef = useRef(appendRulesDirty);
  appendRulesDirtyRef.current = appendRulesDirty;
  const savedExtRef = useRef<ExtendedSettings | null>(null);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    settingsDraftCache = {
      draft: draftDirty ? draft : null,
      ext: extDirty ? ext : null,
      extLoaded,
      draftDirty,
      extDirty,
      appendRulesDirty,
      coreBinaryPath,
      yamlPreview,
      yamlSha,
    };
    if (dirty !== appStore.getState().sessionDrafts.settings.hasDirtyDrafts) {
      appActions.patchSessionDraft("settings", { hasDirtyDrafts: dirty });
    }
  }, [
    draft,
    ext,
    extLoaded,
    draftDirty,
    extDirty,
    appendRulesDirty,
    dirty,
    coreBinaryPath,
    yamlPreview,
    yamlSha,
  ]);

  // Preserve unsaved network/core edits when theme, wallpaper, or live toggles update storeConfig
  useEffect(() => {
    if (dirtyRef.current) {
      setDraft((prev) => ({
        ...prev,
        personalization: structuredClone(storeConfig.personalization),
        preaccel: structuredClone(storeConfig.preaccel),
        system_proxy_enabled: storeConfig.system_proxy_enabled,
        tun_enabled: storeConfig.tun_enabled,
        proxy_mode: storeConfig.proxy_mode,
        update: {
          ...prev.update,
          skipped_version: storeConfig.update.skipped_version ?? null,
        },
      }));
      return;
    }
    setDraft((prev) => {
      const next = structuredClone(storeConfig);
      if (next.update.auto_download === undefined && prev.update.auto_download !== undefined) {
        next.update.auto_download = prev.update.auto_download;
      }
      return next;
    });
  }, [storeConfig]);

  const loadExtendedConfig = async (isActive?: () => boolean) => {
    try {
      const full = await catcloudApi.getFullConfig();
      if (isActive && !isActive()) return;
      const hydrated = hydrateExtendedFromFullConfig(full);
      savedExtRef.current = structuredClone(hydrated);
      if (!extDirtyRef.current) {
        setExt(hydrated);
      } else if (!appendRulesDirtyRef.current) {
        // Keep appendRules synced with latest backend state when user edited other extended fields
        // so cross-page edits from RulesConnsPage are never overwritten by stale drafts.
        setExt((prev) =>
          prev.appendRules === hydrated.appendRules
            ? prev
            : { ...prev, appendRules: hydrated.appendRules }
        );
      }
      setExtLoaded(true);
      setExtLoadError(null);
      if (full.core_runtime?.custom_binary_path) {
        setCoreBinaryPath((prev) => prev || full.core_runtime?.custom_binary_path || "");
      }
      if (typeof full.update?.auto_download === "boolean" && !dirtyRef.current) {
        setDraft((prev) => ({
          ...prev,
          update: {
            ...prev.update,
            auto_download: full.update?.auto_download,
          },
        }));
      }
    } catch (err) {
      if (isActive && !isActive()) return;
      if (!extDirtyRef.current) {
        setExtLoaded(false);
        setExtLoadError(formatErrorMessage(err) || "读取高级配置失败");
      }
    }
  };

  useEffect(() => {
    let active = true;
    void loadExtendedConfig(() => active);
    void appActions.loadGeodataStatus();

    return () => {
      active = false;
    };
  }, []);

  const patchDraft = (patch: Partial<AppConfig>) => {
    setDraft((prev) => ({ ...prev, ...patch }));
    setDraftDirty(true);
  };

  const patchExt = <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => {
    if (!extLoaded) {
      appActions.showToast(
        extLoadError
          ? `高级配置加载失败（${extLoadError}），请先重新加载后再修改`
          : "高级配置正在加载，请稍候片刻再修改",
        "warn"
      );
      return;
    }
    setExt((prev) => ({ ...prev, [k]: v }));
    setExtDirty(true);
    if (k === "appendRules") {
      appendRulesDirtyRef.current = true;
      setAppendRulesDirty(true);
    }
  };

  const handleDnsPortChange = (nextPort: number) => {
    patchDraft({ dns_listen_port: nextPort });
    if (extLoaded) {
      setExt((prev) => {
        const { host } = splitHostPort(prev.dnsListen);
        return { ...prev, dnsListen: formatDnsListenAddr(host, nextPort) };
      });
    }
  };

  const handleDnsListenChange = (nextAddr: string) => {
    if (!extLoaded) {
      appActions.showToast("高级配置正在加载，请稍候片刻再修改", "warn");
      return;
    }
    patchExt("dnsListen", nextAddr);
    const { port: portPart } = splitHostPort(nextAddr);
    if (portPart !== null) {
      setDraft((prev) => ({ ...prev, dns_listen_port: portPart }));
    }
  };

  const handleSave = async () => {
    if (!draftDirty && !extDirty) {
      appActions.showToast("当前没有待保存的更改", "info");
      return;
    }
    if (extDirty && !extLoaded) {
      appActions.showToast(
        extLoadError
          ? `高级配置加载失败（${extLoadError}），已阻止保存以防止覆写原配置`
          : "高级配置尚未加载完成，已阻止保存以防止覆写原配置",
        "warn"
      );
      return;
    }
    setSaving(true);
    try {
      const normalizedRepo = normalizeUpdateRepo(draft.update.repo);
      const latestStoreConfig = appStore.getState().config;
      const prevIncludePrerelease = Boolean(latestStoreConfig.update.include_prerelease);
      const payload: AppConfig = {
        ...draft,
        proxy_mode: latestStoreConfig.proxy_mode,
        system_proxy_enabled: latestStoreConfig.system_proxy_enabled,
        tun_enabled: latestStoreConfig.tun_enabled,
        memory_tier: tierFromMb(draft.gomemlimit_mb),
        personalization: latestStoreConfig.personalization,
        preaccel: structuredClone(latestStoreConfig.preaccel),
        update: {
          repo: normalizedRepo,
          mode: draft.update.mode,
          check_interval_min: draft.update.check_interval_min,
          include_prerelease: draft.update.include_prerelease,
          auto_download: draft.update.auto_download ?? true,
        },
      };
      const shouldSubmitAppendRules =
        savedExtRef.current !== null &&
        appendRulesDirtyRef.current &&
        ext.appendRules !== savedExtRef.current.appendRules;
      let savedBasic: AppConfig;
      if (draftDirty && !extDirty) {
        savedBasic = await catcloudApi.saveConfig(payload);
      } else if (!draftDirty && extDirty) {
        await catcloudApi.saveExtendedSettings(
          buildExtendedPatch(ext, shouldSubmitAppendRules)
        );
        savedBasic = inTauri ? await catcloudApi.getConfig() : payload;
      } else if (inTauri) {
        // Single merged submission avoids back-to-back saveConfig + saveExtendedSettings double core reloads
        await catcloudApi.saveExtendedSettings(
          buildMergedSettingsPatch(payload, ext, shouldSubmitAppendRules)
        );
        savedBasic = await catcloudApi.getConfig();
      } else {
        savedBasic = await catcloudApi.saveConfig(payload);
        await catcloudApi.saveExtendedSettings(
          buildExtendedPatch(ext, shouldSubmitAppendRules)
        );
      }
      const syncedUpdate = {
        ...savedBasic.update,
        auto_download:
          savedBasic.update.auto_download ?? payload.update.auto_download ?? true,
        skipped_version:
          savedBasic.update.skipped_version !== undefined
            ? savedBasic.update.skipped_version
            : (latestStoreConfig.update.skipped_version ?? null),
      };
      const syncedConfig: AppConfig = extDirty
        ? {
            ...savedBasic,
            update: syncedUpdate,
            behavior: {
              ...savedBasic.behavior,
              minimize_to_tray_on_close: ext.closeToWindowless,
            },
          }
        : {
            ...savedBasic,
            update: syncedUpdate,
          };
      const nextIncludePrerelease = Boolean(syncedConfig.update.include_prerelease);
      dirtyRef.current = false;
      extDirtyRef.current = false;
      appendRulesDirtyRef.current = false;
      clearSettingsDirtyDraftCache();
      setDraftDirty(false);
      setExtDirty(false);
      setAppendRulesDirty(false);
      if (extLoaded) {
        savedExtRef.current = structuredClone(ext);
      }
      appActions.patchSessionDraft("settings", { hasDirtyDrafts: false });
      appActions.syncConfig(syncedConfig);
      if (prevIncludePrerelease !== nextIncludePrerelease) {
        void appActions.refreshPendingUpdate();
      }
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      appActions.showToast("设置已保存并生效", "ok");
    } catch (err) {
      appActions.showToast(`保存设置失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSaving(false);
    }
  };

  const handleDiscardUnsaved = () => {
    if (saving) return;
    const latestStoreConfig = appStore.getState().config;
    dirtyRef.current = false;
    extDirtyRef.current = false;
    appendRulesDirtyRef.current = false;
    clearSettingsDirtyDraftCache();
    setDraftDirty(false);
    setExtDirty(false);
    setAppendRulesDirty(false);
    appActions.patchSessionDraft("settings", { hasDirtyDrafts: false });
    setDraft(structuredClone(latestStoreConfig));
    if (savedExtRef.current) {
      setExt(structuredClone(savedExtRef.current));
    } else {
      void loadExtendedConfig(() => mountedRef.current);
    }
    appActions.showToast(dict.settings.discardUnsavedToast, "info");
  };

  const handleExportBackup = async () => {
    if (backupBusy !== null) return;
    await appActions.runBackupOperation("export", async () => {
      if (inTauri) {
        try {
          const saved = await catcloudApi.exportBackupBundle(null);
          appActions.showToast(`已导出脱敏备份：${saved.path} (${saved.bytes} B)`, "ok");
        } catch (err) {
          appActions.showToast(`导出备份失败：${formatErrorMessage(err)}`, "warn");
        }
        return;
      }

      const json = JSON.stringify(
        {
          exported_at: new Date().toISOString(),
          app_version: runtime.app_version,
          config: draft,
          extended: ext,
        },
        null,
        2
      );
      const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const a = Object.assign(document.createElement("a"), {
        href: url,
        download: "catcloud-settings-backup.json",
      });
      a.click();
      URL.revokeObjectURL(url);
      appActions.showToast("已下载配置备份文件", "ok");
    });
  };

  const openImportBackupPicker = () => {
    if (backupBusy !== null) return;
    const input = Object.assign(document.createElement("input"), {
      type: "file",
      accept: "application/json,.json",
    });
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      void appActions.runBackupOperation("import", async () => {
        const raw = await file.text();
        if (inTauri) {
          try {
            const res = await catcloudApi.importBackupBundle(raw);
            clearSettingsDirtyDraftCache();
            appActions.patchSessionDraft("settings", { hasDirtyDrafts: false });
            dirtyRef.current = false;
            extDirtyRef.current = false;
            appendRulesDirtyRef.current = false;
            if (mountedRef.current) {
              setDraftDirty(false);
              setExtDirty(false);
              setAppendRulesDirty(false);
            }
            await appActions.refreshAllData();
            const full = await catcloudApi.getFullConfig();
            if (mountedRef.current) {
              const hydrated = hydrateExtendedFromFullConfig(full);
              savedExtRef.current = structuredClone(hydrated);
              setExt(hydrated);
              setExtLoaded(true);
              setExtLoadError(null);
            }
            appActions.showToast(
              res.message ||
                `已恢复备份（分组 ${res.restored_groups} / 中转 ${res.restored_relays}）`,
              "ok"
            );
          } catch (err) {
            appActions.showToast(`导入备份失败：${formatErrorMessage(err)}`, "warn");
          }
          return;
        }
        try {
          const parsed = JSON.parse(raw) as {
            config?: AppConfig;
            extended?: Partial<ExtendedSettings>;
          };
          if (parsed.config && mountedRef.current) {
            setDraft(parsed.config);
            setDraftDirty(true);
          }
          if (parsed.extended && mountedRef.current) {
            setExt((prev) => ({ ...prev, ...parsed.extended }));
            setExtDirty(true);
            if (typeof parsed.extended.appendRules === "string") {
              appendRulesDirtyRef.current = true;
              setAppendRulesDirty(true);
            }
          }
          appActions.showToast("已导入备份配置，点击右上角保存后生效", "ok");
        } catch {
          appActions.showToast("备份文件格式无效", "warn");
        }
      });
    };
    input.click();
  };

  const tabs: ReadonlyArray<{ id: SettingsTabId; label: string; icon: LucideIcon }> = [
    { id: "system", label: TAB_LABELS_BY_LANG[uiLang].system, icon: SlidersHorizontal },
    { id: "appearance", label: TAB_LABELS_BY_LANG[uiLang].appearance, icon: Palette },
    { id: "dns", label: TAB_LABELS_BY_LANG[uiLang].dns, icon: Globe },
    { id: "core", label: TAB_LABELS_BY_LANG[uiLang].core, icon: Cpu },
    { id: "updates", label: TAB_LABELS_BY_LANG[uiLang].updates, icon: CloudDownload },
  ];

  const startupPageOptions = useMemo(
    () => [
      { value: "overview", label: dict.nav.overview },
      { value: "groups", label: dict.nav.groups },
      { value: "nodes", label: dict.nav.nodes },
      { value: "preaccel", label: dict.nav.preaccel },
      { value: "rules", label: dict.nav.rules },
      { value: "logs", label: dict.nav.logs },
      { value: "ai", label: dict.nav.ai },
      { value: "settings", label: dict.nav.settings },
    ],
    [dict.nav]
  );

  return (
    <div className="space-y-4">
      {/* Top Title + 5-Tab Bar + Save Button */}
      <div className="cc-card cc-glass flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-2xl px-4 py-2.5">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1.5">
          <h1 className="mr-1 shrink-0 whitespace-nowrap text-sm font-semibold text-[var(--text)]">
            {dict.settings.title}
          </h1>
          <div className="flex flex-wrap items-center gap-1">
            {tabs.map(({ id, label, icon: Icon }) => {
              const on = tab === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setTab(id)}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-2.5 py-1.5 text-xs font-medium transition-colors"
                  style={{
                    backgroundColor: on ? "var(--accent-soft)" : "transparent",
                    color: on ? "var(--accent)" : "var(--muted)",
                    border: on ? "1px solid var(--accent)" : "1px solid transparent",
                  }}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0" />
                  <span>{label}</span>
                </button>
              );
            })}
          </div>
        </div>
        <button
          type="button"
          onClick={() => void handleSave()}
          disabled={saving || (extDirty && !extLoaded)}
          className="ml-auto inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-60"
          style={{
            backgroundColor: dirty ? "var(--accent)" : "var(--surface)",
            color: dirty ? "var(--accent-ink)" : "var(--text)",
            border: "1px solid var(--line-strong)",
          }}
        >
          {dirty ? (
            <Save className="h-3.5 w-3.5 shrink-0" />
          ) : (
            <Check className="h-3.5 w-3.5 shrink-0" />
          )}
          <span>
            {saving
              ? isZh
                ? "保存中..."
                : dict.common.loading
              : extDirty && !extLoaded
                ? isZh
                  ? "等待配置加载..."
                  : dict.common.loading
                : dirty
                  ? isZh
                    ? "保存更改"
                    : dict.common.save
                  : isZh
                    ? "已保存"
                    : dict.common.save}
          </span>
        </button>
      </div>

      {dirty && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--accent)]/55 bg-[var(--accent-soft)]/55 px-3.5 py-2 text-xs text-[var(--text)]">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            <span className="leading-relaxed">{dict.settings.unsavedBanner}</span>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-1.5">
            <button
              type="button"
              disabled={saving}
              onClick={handleDiscardUnsaved}
              className="inline-flex items-center gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:opacity-60"
            >
              <RotateCcw className="h-3 w-3" />
              <span>{dict.settings.discardUnsavedBtn}</span>
            </button>
            <button
              type="button"
              disabled={saving || (extDirty && !extLoaded)}
              onClick={() => void handleSave()}
              className="inline-flex items-center gap-1 rounded-lg bg-[var(--accent)] px-3 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              <Save className="h-3 w-3" />
              <span>
                {saving
                  ? isZh
                    ? "保存中..."
                    : dict.common.loading
                  : isZh
                    ? "立即保存"
                    : dict.common.save}
              </span>
            </button>
          </div>
        </div>
      )}

      {!extLoaded && extLoadError && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2 text-xs text-[var(--amber)]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>
              高级配置读取失败（{extLoadError}），已保护磁盘原配置不被默认值覆写。基础开关仍可正常保存。
            </span>
          </div>
          <button
            type="button"
            onClick={() => void loadExtendedConfig()}
            className="inline-flex items-center gap-1 rounded-lg border border-[var(--amber)]/50 bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] hover:border-[var(--accent)]"
          >
            <RefreshCw className="h-3 w-3" />
            <span>重试读取</span>
          </button>
        </div>
      )}

      {/* Tab 1: 常规与代理 */}
      {tab === "system" && (
        <SystemTab
          draft={draft}
          ext={ext}
          runtime={runtime}
          platformOs={platformOs}
          isWindows={isWindows}
          startupPageOptions={startupPageOptions}
          patchDraft={patchDraft}
          patchExt={patchExt}
          onDnsPortChange={handleDnsPortChange}
        />
      )}

      {/* Tab 2: 外观与壁纸 */}
      {tab === "appearance" && (
        <AppearanceTab
          uiLang={uiLang}
          dict={dict}
          personalization={storeConfig.personalization}
          resolvedTheme={resolvedTheme}
          wallpaperPreviewUrl={wallpaperPreviewUrl}
          wallpaperError={wallpaperError}
        />
      )}

      {/* Tab 3: 网络与 DNS */}
      {tab === "dns" && (
        <DnsTab
          draft={draft}
          ext={ext}
          patchDraft={patchDraft}
          patchExt={patchExt}
          onDnsListenChange={handleDnsListenChange}
        />
      )}

      {/* Tab 4: 内核与工具 */}
      {tab === "core" && (
        <CoreTab
          dict={dict}
          inTauri={inTauri}
          platformOs={platformOs}
          isWindows={isWindows}
          draft={draft}
          ext={ext}
          runtime={runtime}
          geoStatus={geoStatus}
          geoStatusLoading={geoStatusLoading}
          geoBusy={geoBusy}
          coreOpBusy={coreOpBusy}
          backupBusy={backupBusy}
          coreBinaryPath={coreBinaryPath}
          yamlPreview={yamlPreview}
          yamlSha={yamlSha}
          patchDraft={patchDraft}
          patchExt={patchExt}
          onCoreBinaryPathChange={setCoreBinaryPath}
          onYamlPreviewChange={(yaml, sha) => {
            setYamlPreview(yaml);
            setYamlSha(sha);
          }}
          onExportBackup={handleExportBackup}
          onRequestImportBackup={() => setConfirmImportBackupOpen(true)}
          onOpenSyncModal={() => setSyncModalOpen(true)}
        />
      )}

      {/* Tab 5: 关于与更新 */}
      {tab === "updates" && (
        <UpdatesTab
          uiLang={uiLang}
          isZh={isZh}
          dict={dict}
          inTauri={inTauri}
          draft={draft}
          storeSkippedVersion={storeConfig.update.skipped_version}
          runtime={runtime}
          checkingUpdate={checkingUpdate}
          downloadingUpdate={downloadingUpdate}
          updateInfo={updateInfo}
          updateMsg={updateMsg}
          pendingUpdate={pendingUpdate}
          patchDraft={patchDraft}
        />
      )}

      {/* Backup Import Two-Step Confirmation Modal */}
      <BackupImportConfirmModal
        open={confirmImportBackupOpen}
        backupBusy={backupBusy}
        onClose={() => setConfirmImportBackupOpen(false)}
        onConfirmImport={() => {
          setConfirmImportBackupOpen(false);
          openImportBackupPicker();
        }}
      />

      {syncModalOpen && (
        <Suspense fallback={null}>
          <ShareBundleModal
            open={syncModalOpen}
            mode="export"
            initialTransport="lan_send"
            allowModeSwitch
            onClose={() => setSyncModalOpen(false)}
          />
        </Suspense>
      )}
    </div>
  );
}
