import {
  Code2,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  FolderOpen,
  Play,
  Plus,
  QrCode,
  RefreshCw,
  RotateCw,
  Square,
  Terminal,
  Upload,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  type AppConfig,
  type GeoDataStatusDto,
  type RuntimeInfoDto,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import type { useUiDict } from "../../i18n";

type UiDict = ReturnType<typeof useUiDict>;
import { appActions } from "../../store/appStore";
import {
  type PlatformOs,
  type ShellEnvKind,
  buildShellEnvFallback,
  defaultShellForOs,
} from "../../utils/platform";
import { readUiPref, usePersistedState } from "../../utils/uiPrefs";
import { BTN_CLS, Card, INPUT_CLS, SegButtons, SwitchRow } from "./SettingsPrimitives";
import {
  DIR_ITEMS,
  type ExtendedSettings,
  GEO_ITEMS,
  type GeoKey,
  SHELL_ENV_VALIDATOR,
  WEB_UI_IDX_VALIDATOR,
  buildFallbackYaml,
  copySettingText,
  getShellEnvOptionsForOs,
  renderGeoStatusSummary,
  tierFromMb,
} from "./settingsPatch";

export interface CoreTabProps {
  dict: UiDict;
  inTauri: boolean;
  platformOs: PlatformOs;
  isWindows: boolean;
  draft: AppConfig;
  ext: ExtendedSettings;
  runtime: RuntimeInfoDto;
  geoStatus: GeoDataStatusDto | null;
  geoStatusLoading: boolean;
  geoBusy: string | null;
  coreOpBusy: string | null;
  backupBusy: string | null;
  coreBinaryPath: string;
  yamlPreview: string | null;
  yamlSha: string | null;
  patchDraft: (patch: Partial<AppConfig>) => void;
  patchExt: <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => void;
  onCoreBinaryPathChange: (nextPath: string) => void;
  onYamlPreviewChange: (yaml: string | null, sha: string | null) => void;
  onExportBackup: () => Promise<void>;
  onRequestImportBackup: () => void;
  onOpenSyncModal: () => void;
}

export function CoreTab({
  dict,
  inTauri,
  platformOs,
  isWindows,
  draft,
  ext,
  runtime,
  geoStatus,
  geoStatusLoading,
  geoBusy,
  coreOpBusy,
  backupBusy,
  coreBinaryPath,
  yamlPreview,
  yamlSha,
  patchDraft,
  patchExt,
  onCoreBinaryPathChange,
  onYamlPreviewChange,
  onExportBackup,
  onRequestImportBackup,
  onOpenSyncModal,
}: CoreTabProps) {
  const shellEnvOptions = useMemo(() => getShellEnvOptionsForOs(platformOs), [platformOs]);
  const [selectedShell, setSelectedShell] = usePersistedState<ShellEnvKind>(
    "settings.selectedShell",
    defaultShellForOs(platformOs),
    SHELL_ENV_VALIDATOR
  );
  const userPickedShellRef = useRef<boolean | null>(null);
  if (userPickedShellRef.current === null) {
    userPickedShellRef.current =
      readUiPref<ShellEnvKind | null>("settings.selectedShell", null, SHELL_ENV_VALIDATOR) !== null;
  }
  const prevPlatformOsRef = useRef<PlatformOs>(platformOs);

  useEffect(() => {
    if (prevPlatformOsRef.current === platformOs) return;
    prevPlatformOsRef.current = platformOs;
    if (!userPickedShellRef.current) {
      setSelectedShell(defaultShellForOs(platformOs));
    }
  }, [platformOs, setSelectedShell]);

  const [selectedWebUiIdx, setSelectedWebUiIdx] = usePersistedState<number>(
    "settings.selectedWebUiIdx",
    0,
    WEB_UI_IDX_VALIDATOR
  );
  const [newWebUiName, setNewWebUiName] = useState("");
  const [newWebUiTpl, setNewWebUiTpl] = useState("");
  const [yamlLoading, setYamlLoading] = useState(false);

  const safeWebUiIdx =
    ext.webuiUrls.length > 0
      ? Math.max(0, Math.min(selectedWebUiIdx, ext.webuiUrls.length - 1))
      : 0;

  const handleCoreAction = async (action: "start" | "stop" | "restart" | "reload") => {
    if (coreOpBusy !== null) return;
    await appActions.runCoreOperation(action);
  };

  const handleHotSwapCore = async () => {
    if (coreOpBusy !== null) return;
    const path = coreBinaryPath.trim();
    if (!path) {
      appActions.showToast("请先输入内核程序的完整路径", "warn");
      return;
    }
    await appActions.runCoreOperation("hotswap", path);
  };

  const handleCompileYaml = async () => {
    setYamlLoading(true);
    try {
      if (inTauri) {
        const res = await catcloudApi.compilePreviewYaml();
        const text = typeof res === "string" ? res : (res?.yaml ?? "");
        const sha =
          typeof res === "object" && res !== null && "sha256" in res ? res.sha256 : null;
        onYamlPreviewChange(text, sha);
        appActions.showToast("已生成最新配置预览", "ok");
      } else {
        onYamlPreviewChange(buildFallbackYaml(draft, ext), "browser-preview");
        appActions.showToast("已生成预览配置", "info");
      }
    } catch (err) {
      appActions.showToast(`生成配置预览失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setYamlLoading(false);
    }
  };

  const handleRefreshGeo = async (target: GeoKey | "all") => {
    if (geoBusy !== null) return;
    await appActions.runRefreshGeoDb(target);
  };

  const handleOpenDir = async (dir: "config" | "data" | "logs" | "core") => {
    const names = { config: "配置", data: "数据", logs: "日志", core: "内核" };
    try {
      const opened = await catcloudApi.openAppDir(dir);
      appActions.showToast(`已打开${names[dir]}目录：${opened}`, "info");
    } catch (err) {
      appActions.showToast(`打开${names[dir]}目录失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleOpenWebUi = async () => {
    const entry = ext.webuiUrls[safeWebUiIdx] ?? ext.webuiUrls[0];
    const rawTemplate = entry?.url_template?.trim() || null;
    try {
      await catcloudApi.openWebUi(rawTemplate);
      appActions.showToast("已在浏览器打开面板", "info");
    } catch (err) {
      appActions.showToast(`打开外部面板失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleAddWebUiBookmark = () => {
    const name = newWebUiName.trim();
    const tpl = newWebUiTpl.trim();
    if (!name || !tpl) {
      appActions.showToast("请填写面板名称和链接模板", "warn");
      return;
    }
    const nextList = [...ext.webuiUrls, { name, url_template: tpl }];
    patchExt("webuiUrls", nextList);
    setSelectedWebUiIdx(nextList.length - 1);
    setNewWebUiName("");
    setNewWebUiTpl("");
    appActions.showToast(`已添加面板「${name}」，记得点击顶部保存`, "ok");
  };

  const handleCopyShellEnv = async (sh: ShellEnvKind) => {
    const labelMap: Record<ShellEnvKind, string> = {
      powershell: "PowerShell",
      cmd: "CMD",
      bash: "Bash",
      zsh: "Zsh",
      fish: "Fish",
    };
    const fallback = buildShellEnvFallback(sh, draft.mixed_port);
    let text = fallback;
    if (inTauri) {
      try {
        const res = await catcloudApi.exportShellEnv(sh);
        if (res && res.trim()) text = res;
      } catch {
        /* fallback */
      }
    }
    await copySettingText(text, `${labelMap[sh]} 代理命令`);
  };

  const handleCopyDiagnostics = async () => {
    await appActions.copySanitizedDiagnosticsForAi();
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-2">
        <Card
          title="全局附加规则与脚本"
          sub="补充自定义分流规则，或预览最终生效配置"
          action={
            <button
              type="button"
              onClick={() => void handleCompileYaml()}
              disabled={yamlLoading}
              className={BTN_CLS}
            >
              <Code2 className="h-3.5 w-3.5" />
              <span>{yamlLoading ? "生成中..." : "预览最终配置"}</span>
            </button>
          }
        >
          <label className="block text-[11px] text-[var(--muted)]">
            全局附加规则（每行一条）
            <textarea
              rows={3}
              value={ext.appendRules}
              onChange={(e) => patchExt("appendRules", e.target.value)}
              className={`${INPUT_CLS} mt-1 cc-mono`}
            />
          </label>
          <p className="rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-2.5 py-2 text-[11px] leading-relaxed text-[var(--muted)]">
            {dict.settings.appendRulesAdvancedHint}
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <label className="block text-[11px] text-[var(--muted)]">
              配置覆写脚本路径（可选）
              <input
                value={ext.overrideScriptPath}
                placeholder="如 data/scripts/override.js"
                onChange={(e) => patchExt("overrideScriptPath", e.target.value)}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
            <label className="block text-[11px] text-[var(--muted)]">
              启动前执行脚本（可选）
              <input
                value={ext.startupScriptPath}
                placeholder="内核启动前自动运行"
                onChange={(e) => patchExt("startupScriptPath", e.target.value)}
                className={`${INPUT_CLS} mt-1 cc-mono`}
              />
            </label>
          </div>
          {yamlPreview !== null && (
            <div className="rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] p-2.5">
              <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--muted)]">
                <span className="truncate">
                  最终配置预览（已脱敏）{yamlSha ? ` · ${yamlSha.slice(0, 10)}` : ""}
                </span>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void copySettingText(yamlPreview, "配置预览")}
                    className="text-[var(--accent)] hover:underline"
                  >
                    复制
                  </button>
                  <button
                    type="button"
                    onClick={() => onYamlPreviewChange(null, null)}
                    aria-label="关闭预览"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
              <pre className="cc-mono cc-selectable max-h-44 overflow-auto text-[11px] text-[var(--text-secondary)]">
                {yamlPreview}
              </pre>
            </div>
          )}
        </Card>

        <Card
          title="内核控制与地理数据库"
          sub={`${runtime.core_name} ${runtime.core_version} · ${runtime.running ? "运行中" : "已停止"}`}
          action={
            <button
              type="button"
              onClick={() => void handleRefreshGeo("all")}
              disabled={geoBusy !== null}
              className={BTN_CLS}
            >
              <RefreshCw className={`h-3.5 w-3.5 ${geoBusy === "all" ? "animate-spin" : ""}`} />
              <span>{geoBusy === "all" ? "更新中..." : "更新全部数据库"}</span>
            </button>
          }
        >
          <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
            <button
              type="button"
              disabled={coreOpBusy !== null || runtime.running}
              onClick={() => void handleCoreAction("start")}
              className={BTN_CLS}
            >
              {coreOpBusy === "start" ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin text-[var(--green)]" />
              ) : (
                <Play className="h-3.5 w-3.5 text-[var(--green)]" />
              )}
              <span>{coreOpBusy === "start" ? "启动中..." : "启动内核"}</span>
            </button>
            <button
              type="button"
              disabled={coreOpBusy !== null || !runtime.running}
              onClick={() => void handleCoreAction("stop")}
              className={BTN_CLS}
            >
              {coreOpBusy === "stop" ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin text-[var(--red)]" />
              ) : (
                <Square className="h-3.5 w-3.5 text-[var(--red)]" />
              )}
              <span>{coreOpBusy === "stop" ? "停止中..." : "停止内核"}</span>
            </button>
            <button
              type="button"
              disabled={coreOpBusy !== null}
              onClick={() => void handleCoreAction("restart")}
              className={BTN_CLS}
            >
              <RotateCw
                className={`h-3.5 w-3.5 ${coreOpBusy === "restart" ? "animate-spin" : ""}`}
              />
              <span>{coreOpBusy === "restart" ? "重启中..." : "重启内核"}</span>
            </button>
            <button
              type="button"
              disabled={coreOpBusy !== null}
              onClick={() => void handleCoreAction("reload")}
              className={BTN_CLS}
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${coreOpBusy === "reload" ? "animate-spin" : ""}`}
              />
              <span>{coreOpBusy === "reload" ? "重载中..." : "热重载配置"}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {GEO_ITEMS.map(([key, dtoKey, fileName, desc]) => {
              const statusSummary = renderGeoStatusSummary(geoStatus?.[dtoKey], geoStatusLoading);
              const itemUpdating = geoBusy === key || geoBusy === "all";
              return (
                <div
                  key={key}
                  className="flex min-w-0 items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-2.5 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span
                        title={fileName}
                        className="min-w-0 truncate cc-mono text-xs font-medium text-[var(--text)]"
                      >
                        {fileName}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1 py-0.5 text-[9px] font-medium ${
                          itemUpdating
                            ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                            : statusSummary.state === "ready"
                              ? "bg-[var(--green-soft)] text-[var(--green)]"
                              : statusSummary.state === "loading"
                                ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                                : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                        }`}
                      >
                        {itemUpdating
                          ? "更新中"
                          : statusSummary.state === "ready"
                            ? "已就绪"
                            : statusSummary.state === "loading"
                              ? "检测中"
                              : "未下载"}
                      </span>
                    </div>
                    <div className="mt-0.5 truncate text-[10px] text-[var(--muted)]">
                      {desc} · <span className="cc-mono">{statusSummary.text}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleRefreshGeo(key)}
                    disabled={geoBusy !== null}
                    title={itemUpdating ? `正在更新 ${fileName}` : `更新 ${fileName}`}
                    className="shrink-0 rounded-lg border border-[var(--line)] p-1.5 text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                  >
                    {itemUpdating ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin text-[var(--accent)]" />
                    ) : (
                      <Database className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              );
            })}
          </div>

          <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-medium text-[var(--text)]">内核内存上限</div>
              <SegButtons<0 | 48 | 64 | 96>
                mono
                value={draft.gomemlimit_mb}
                onChange={(v) => patchDraft({ gomemlimit_mb: v, memory_tier: tierFromMb(v) })}
                options={[
                  [0, "自动"],
                  [48, "48 MB"],
                  [64, "64 MB"],
                  [96, "96 MB"],
                ]}
              />
            </div>
            <p className="text-[11px] leading-relaxed text-[var(--muted)]">
              「自动」省内存档已自动启用流式 GeoData 加载与活跃节点精简编译，大幅降低内核常驻内存，无需额外手动调优。
            </p>
            <SwitchRow
              title="全量加载所有订阅节点（兼容模式）"
              desc="默认仅加载当前要用的节点大幅省内存；仅当你在外部控制器里要一次看到几百个节点时才需开启"
              checked={ext.compileAllNodes}
              onChange={(v) => patchExt("compileAllNodes", v)}
            />
            <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)]/60 pt-2">
              <input
                value={coreBinaryPath}
                onChange={(e) => onCoreBinaryPathChange(e.target.value)}
                placeholder={
                  isWindows
                    ? "填写本地内核程序路径（如 C:\\path\\to\\mihomo.exe）"
                    : "填写本地内核程序路径（如 /usr/local/bin/mihomo）"
                }
                className={`${INPUT_CLS} min-w-[180px] flex-1 cc-mono`}
              />
              <button
                type="button"
                disabled={coreOpBusy !== null}
                onClick={() => void handleHotSwapCore()}
                className={`${BTN_CLS} shrink-0 whitespace-nowrap`}
              >
                {coreOpBusy === "hotswap" ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Cpu className="h-3.5 w-3.5" />
                )}
                <span>{coreOpBusy === "hotswap" ? "热换中..." : "热换内核"}</span>
              </button>
            </div>
          </div>
        </Card>
      </div>

      <Card
        title="快捷目录、配置备份与外部工具"
        sub="直达本地目录、导入导出备份、打开外部面板或复制终端代理命令"
      >
        <div className="flex flex-wrap items-center gap-2">
          {DIR_ITEMS.map(([dir, label]) => (
            <button
              key={dir}
              type="button"
              onClick={() => void handleOpenDir(dir)}
              className={BTN_CLS}
            >
              <FolderOpen className="h-3.5 w-3.5" />
              <span>{label}</span>
            </button>
          ))}
          <button
            type="button"
            disabled={backupBusy !== null}
            onClick={() => void onExportBackup()}
            className={BTN_CLS}
          >
            {backupBusy === "export" ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            <span>{backupBusy === "export" ? "导出中..." : "导出备份"}</span>
          </button>
          <button
            type="button"
            disabled={backupBusy !== null}
            onClick={onRequestImportBackup}
            className={BTN_CLS}
          >
            {backupBusy === "import" ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Upload className="h-3.5 w-3.5" />
            )}
            <span>{backupBusy === "import" ? "导入中..." : "导入备份"}</span>
          </button>
          <button type="button" onClick={onOpenSyncModal} className={BTN_CLS}>
            <QrCode className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{dict.sync.entryBtn}</span>
          </button>
        </div>

        <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-medium text-[var(--text)]">外部控制面板：</span>
              <AppSelect
                aria-label="外部控制面板"
                size="sm"
                value={String(safeWebUiIdx)}
                onChange={(v) => {
                  const parsed = Number(v);
                  const nextIdx =
                    Number.isInteger(parsed) && parsed >= 0
                      ? Math.min(parsed, Math.max(0, ext.webuiUrls.length - 1))
                      : 0;
                  setSelectedWebUiIdx(nextIdx);
                }}
                options={ext.webuiUrls.map((item, idx) => ({
                  value: String(idx),
                  label: item.name,
                }))}
                placeholder="暂无面板书签"
                disabled={ext.webuiUrls.length === 0}
                className="min-w-[150px]"
                buttonClassName="rounded-lg"
              />
            </div>
            <button type="button" onClick={() => void handleOpenWebUi()} className={BTN_CLS}>
              <ExternalLink className="h-3.5 w-3.5" />
              <span>打开面板</span>
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
            <input
              value={newWebUiName}
              onChange={(e) => setNewWebUiName(e.target.value)}
              placeholder="新增面板名称（如 Zashboard）"
              className={`${INPUT_CLS} min-w-0 sm:col-span-3`}
            />
            <input
              value={newWebUiTpl}
              onChange={(e) => setNewWebUiTpl(e.target.value)}
              placeholder="粘贴外部面板网址，打开时自动填入本机端口与口令"
              className={`${INPUT_CLS} min-w-0 sm:col-span-6 min-[1160px]:col-span-7`}
            />
            <button
              type="button"
              onClick={handleAddWebUiBookmark}
              className={`${BTN_CLS} justify-center whitespace-nowrap sm:col-span-3 min-[1160px]:col-span-2`}
            >
              <Plus className="h-3.5 w-3.5 shrink-0" />
              <span>添加书签</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)] pt-2.5">
          <span className="text-xs text-[var(--muted)]">终端代理命令：</span>
          <AppSelect
            aria-label="选择终端类型"
            size="sm"
            value={selectedShell}
            onChange={(v) => {
              userPickedShellRef.current = true;
              setSelectedShell(v as ShellEnvKind);
            }}
            options={shellEnvOptions.map((opt) => ({
              value: opt.value,
              label: opt.label,
            }))}
            className="min-w-[180px]"
            buttonClassName="rounded-lg"
          />
          <button
            type="button"
            onClick={() => void handleCopyShellEnv(selectedShell)}
            className={BTN_CLS}
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>复制代理命令</span>
          </button>
          <button type="button" onClick={() => void handleCopyDiagnostics()} className={BTN_CLS}>
            <Copy className="h-3.5 w-3.5" />
            <span>🤖 复制诊断包给 AI</span>
          </button>
        </div>
      </Card>
    </div>
  );
}
