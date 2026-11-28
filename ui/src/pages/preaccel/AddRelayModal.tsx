import { AlertTriangle, Eye, EyeOff, Plus, Upload, X } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { type PreAccelRelay, catcloudApi, formatErrorMessage } from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import { appActions } from "../../store/appStore";
import {
  type AddModalTab,
  DEMO_IMPORT_JSON,
  IMPORT_URI_PREFIX,
  INPUT_CLS,
  REGION_QUICK_PICKS,
  RELAY_PROTOCOL_OPTIONS,
  UUID_PATTERN,
  encodeBase64UrlUtf8,
  looksLikeIpAddress,
  parseRelayImportInput,
} from "./relayImportParser";

export interface AddRelayModalProps {
  open: boolean;
  initialTab: AddModalTab;
  relays: PreAccelRelay[];
  inTauri: boolean;
  onClose: () => void;
  onRelaysChange: (next: PreAccelRelay[]) => void;
  onImportWarnings: (warnings: string[]) => void;
}

export function AddRelayModal({
  open,
  initialTab,
  relays,
  inTauri,
  onClose,
  onRelaysChange,
  onImportWarnings,
}: AddRelayModalProps) {
  const [addModalTab, setAddModalTab] = useState<AddModalTab>(initialTab);

  // Manual Add Form State
  const [manualName, setManualName] = useState("");
  const [manualServer, setManualServer] = useState("");
  const [manualPort, setManualPort] = useState("443");
  const [manualProtocol, setManualProtocol] = useState<string>("anytls");
  const [manualPassword, setManualPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [manualRegion, setManualRegion] = useState("");
  const [manualNote, setManualNote] = useState("");
  const [manualExpiresAt, setManualExpiresAt] = useState("");
  const [manualError, setManualError] = useState<string | null>(null);
  const [savingManual, setSavingManual] = useState(false);

  // Import Tab State
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setAddModalTab(initialTab);
      setManualError(null);
      setImportError(null);
    }
  }, [open, initialTab]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !savingManual && !importing) {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, savingManual, importing, onClose]);

  const resetManualForm = () => {
    setManualName("");
    setManualServer("");
    setManualPort("443");
    setManualProtocol("anytls");
    setManualPassword("");
    setShowPassword(false);
    setManualRegion("");
    setManualNote("");
    setManualExpiresAt("");
    setManualError(null);
  };

  const handleManualSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (savingManual) return;

    const trimmedName = manualName.trim();
    const trimmedServer = manualServer.trim();
    const trimmedPassword = manualPassword.trim();
    const trimmedRegion = manualRegion.trim();
    const trimmedNote = manualNote.trim();
    const trimmedExpiry = manualExpiresAt.trim();
    const parsedPort = Number.parseInt(manualPort.trim() || "443", 10);

    if (!trimmedName) {
      setManualError("请填写线路名称，方便区分不同服务器");
      return;
    }
    if (!trimmedServer) {
      setManualError("请填写中转服务器的 IP 地址");
      return;
    }
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setManualError("端口范围应为 1 ～ 65535，推荐使用默认的 443");
      return;
    }
    if (!trimmedPassword) {
      setManualError(
        manualProtocol === "vless" ? "请填写 VLESS 协议的 UUID 密钥" : "请填写连接密码"
      );
      return;
    }
    if (manualProtocol === "vless" && !UUID_PATTERN.test(trimmedPassword)) {
      setManualError("VLESS 密钥需为标准 UUID 格式（如 00000000-0000-4000-8000-000000000000）");
      return;
    }

    const nextPriority =
      relays.length > 0 ? Math.max(...relays.map((r) => r.priority)) + 1 : 1;

    const newRelay: PreAccelRelay = {
      id: `relay-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      name: trimmedName,
      provider: trimmedNote || "自建中转",
      region: trimmedRegion || "国内",
      server: trimmedServer,
      port: parsedPort,
      protocol: manualProtocol,
      password: trimmedPassword,
      sni: null,
      skip_cert_verify: true,
      priority: nextPriority,
      expires_at: trimmedExpiry || null,
      enabled: true,
      last_probe_ms: null,
      last_mbps: null,
      last_up_mbps: null,
      last_down_mbps: null,
    };

    setSavingManual(true);
    setManualError(null);
    try {
      const saved = await catcloudApi.upsertPreAccelRelay(newRelay);
      if (inTauri) {
        const refreshed = await catcloudApi.listPreAccelRelays();
        onRelaysChange(refreshed);
        appActions.syncPreAccelRelays(refreshed);
      } else {
        const nextList = [...relays, saved];
        onRelaysChange(nextList);
        appActions.syncPreAccelRelays(nextList);
      }
      resetManualForm();
      onClose();
      appActions.showToast(`已添加中转线路「${saved.name}」`, "ok");
    } catch (err) {
      const msg = formatErrorMessage(err);
      setManualError(msg);
      appActions.showToast(`添加中转线路失败：${msg}`, "warn");
    } finally {
      setSavingManual(false);
    }
  };

  const handleImportSubmit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (importing) return;
    const raw = importText.trim();
    if (!raw) {
      setImportError("请先粘贴导入码或 JSON 配置内容");
      return;
    }

    if (inTauri) {
      setImporting(true);
      setImportError(null);
      onImportWarnings([]);
      try {
        const imported = await catcloudApi.importMmRelayInput(raw);
        const refreshed = await catcloudApi.listPreAccelRelays();
        onRelaysChange(refreshed);
        appActions.syncPreAccelRelays(refreshed);
        setImportText("");
        onClose();
        appActions.showToast(`成功导入 ${imported.length} 条中转线路`, "ok");
      } catch (err) {
        const msg = formatErrorMessage(err);
        setImportError(msg);
        appActions.showToast(`导入中转线路失败：${msg}`, "warn");
      } finally {
        setImporting(false);
      }
      return;
    }

    const res = parseRelayImportInput(raw);
    if (res.error) {
      setImportError(res.error);
      onImportWarnings([]);
      return;
    }
    setImportError(null);
    onImportWarnings(res.warnings);
    const byId = new Map(relays.map((r) => [r.id, r]));
    for (const incoming of res.relays) {
      byId.set(incoming.id, incoming);
    }
    const next = Array.from(byId.values());
    onRelaysChange(next);
    appActions.syncPreAccelRelays(next);
    setImportText("");
    onClose();
    appActions.showToast(
      `成功导入 ${res.relays.length} 条中转线路${res.warnings.length > 0 ? "（请留意配置提醒）" : ""}`,
      res.warnings.length > 0 ? "warn" : "ok"
    );
  };

  const handleFillDemoUri = () => {
    const uri = `${IMPORT_URI_PREFIX}${encodeBase64UrlUtf8(DEMO_IMPORT_JSON)}`;
    setImportText(uri);
    setImportError(null);
  };

  const manualPortNum = Number.parseInt(manualPort.trim() || "443", 10);
  const manualShowNon443Hint =
    manualPort.trim() !== "" && Number.isInteger(manualPortNum) && manualPortNum !== 443;
  const manualShowDomainHint =
    manualServer.trim() !== "" && !looksLikeIpAddress(manualServer);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={() => {
        if (!savingManual && !importing) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="添加中转线路"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text)]">添加中转线路</h3>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              可以手动填写服务器信息，也可以直接粘贴导入码一键添加
            </p>
          </div>
          <button
            type="button"
            disabled={savingManual || importing}
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
            aria-label="关闭弹窗"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* 双标签切换 */}
        <div className="mt-4 grid grid-cols-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-1 text-xs">
          <button
            type="button"
            onClick={() => {
              setAddModalTab("manual");
              setManualError(null);
            }}
            className={`rounded-lg py-1.5 font-medium transition-colors ${
              addModalTab === "manual"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            手动填表添加
          </button>
          <button
            type="button"
            onClick={() => {
              setAddModalTab("import");
              setImportError(null);
            }}
            className={`rounded-lg py-1.5 font-medium transition-colors ${
              addModalTab === "import"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            粘贴导入码 / JSON
          </button>
        </div>

        {/* 标签 1：手动填表添加 */}
        {addModalTab === "manual" && (
          <form onSubmit={(ev) => void handleManualSubmit(ev)} className="mt-4 space-y-3.5">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  线路名称 <span className="text-[var(--red)]">*</span>
                </label>
                <input
                  type="text"
                  value={manualName}
                  onChange={(e) => {
                    setManualName(e.target.value);
                    setManualError(null);
                  }}
                  placeholder="例如：上海轻量 1 号"
                  className={INPUT_CLS}
                />
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  地区
                </label>
                <input
                  type="text"
                  value={manualRegion}
                  onChange={(e) => setManualRegion(e.target.value)}
                  placeholder="例如：华东 / 华南 / 香港"
                  className={INPUT_CLS}
                />
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {REGION_QUICK_PICKS.map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setManualRegion(r)}
                      className={`rounded-md border px-1.5 py-0.5 text-[10px] transition-colors ${
                        manualRegion === r
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  服务器 IP <span className="text-[var(--red)]">*</span>
                </label>
                <input
                  type="text"
                  value={manualServer}
                  onChange={(e) => {
                    setManualServer(e.target.value);
                    setManualError(null);
                  }}
                  placeholder="例如：198.51.100.10"
                  className={`${INPUT_CLS} cc-mono`}
                />
                {manualShowDomainHint && (
                  <p className="mt-1 text-[10px] text-[var(--amber)]">
                    建议直接填写服务器纯 IP，连接更稳定
                  </p>
                )}
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  端口
                </label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={manualPort}
                  onChange={(e) => {
                    setManualPort(e.target.value);
                    setManualError(null);
                  }}
                  placeholder="443"
                  className={`${INPUT_CLS} cc-mono`}
                />
                {manualShowNon443Hint && (
                  <p className="mt-1 text-[10px] text-[var(--amber)]">推荐 443</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <span className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  连接协议
                </span>
                <AppSelect
                  aria-label="连接协议"
                  size="md"
                  value={manualProtocol}
                  onChange={(v) => {
                    setManualProtocol(v);
                    setManualError(null);
                  }}
                  options={RELAY_PROTOCOL_OPTIONS.map((opt) => ({
                    value: opt.value,
                    label: opt.label,
                  }))}
                  className="w-full"
                  buttonClassName="bg-[var(--card)]"
                />
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  {manualProtocol === "vless" ? "UUID 密钥" : "连接密码"}{" "}
                  <span className="text-[var(--red)]">*</span>
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={manualPassword}
                    onChange={(e) => {
                      setManualPassword(e.target.value);
                      setManualError(null);
                    }}
                    placeholder={
                      manualProtocol === "vless" ? "粘贴标准 UUID" : "填写服务端设置的密码"
                    }
                    className={`${INPUT_CLS} cc-mono pr-9`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                    aria-label={showPassword ? "隐藏密码" : "显示密码"}
                  >
                    {showPassword ? (
                      <EyeOff className="h-3.5 w-3.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  备注（选填）
                </label>
                <input
                  type="text"
                  value={manualNote}
                  onChange={(e) => setManualNote(e.target.value)}
                  placeholder="例如：轻量云服务器、月付"
                  className={INPUT_CLS}
                />
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                  到期日期（选填）
                </label>
                <input
                  type="date"
                  value={manualExpiresAt}
                  onChange={(e) => setManualExpiresAt(e.target.value)}
                  className={`${INPUT_CLS} cc-mono`}
                />
              </div>
            </div>

            {manualError && (
              <div className="flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span>{manualError}</span>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                disabled={savingManual}
                onClick={onClose}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={savingManual}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>{savingManual ? "保存中..." : "保存并添加"}</span>
              </button>
            </div>
          </form>
        )}

        {/* 标签 2：粘贴导入码 / JSON */}
        {addModalTab === "import" && (
          <form onSubmit={(ev) => void handleImportSubmit(ev)} className="mt-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="text-[var(--text-secondary)]">支持单行导入码或 JSON 配置</span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setImportText(DEMO_IMPORT_JSON);
                    setImportError(null);
                  }}
                  className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                >
                  填入示例 JSON
                </button>
                <button
                  type="button"
                  onClick={handleFillDemoUri}
                  className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                >
                  填入示例导入码
                </button>
              </div>
            </div>

            <textarea
              rows={6}
              value={importText}
              onChange={(e) => {
                setImportText(e.target.value);
                setImportError(null);
              }}
              spellCheck={false}
              placeholder="直接粘贴导入码，或 JSON 格式的中转配置内容..."
              className="cc-mono cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />

            {importError && (
              <div className="flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span>{importError}</span>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                disabled={importing}
                onClick={onClose}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={importing}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Upload className="h-3.5 w-3.5" />
                <span>{importing ? "导入中..." : "识别并导入"}</span>
              </button>
            </div>
          </form>
        )}
      </div>
    </div>,
    document.body
  );
}
