import { ShieldAlert, X } from "lucide-react";
import { type FormEvent, useEffect } from "react";
import { createPortal } from "react-dom";
import { DOMESTIC_PROBE_PRESETS } from "./relayImportParser";

export interface ProbeSourceModalProps {
  open: boolean;
  probeUrl: string;
  probeValidation: { ok: boolean; error: string | null };
  onProbeUrlChange: (url: string) => void;
  onSelectPreset: (url: string, label: string) => Promise<void>;
  onSaveCustom: (ev: FormEvent) => Promise<void>;
  onClose: () => void;
}

export function ProbeSourceModal({
  open,
  probeUrl,
  probeValidation,
  onProbeUrlChange,
  onSelectPreset,
  onSaveCustom,
  onClose,
}: ProbeSourceModalProps) {
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="国内连通检测地址"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text)]">国内连通检测地址</h3>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              用于检测国内网络连通与校园网登录页，请保持国内直连地址
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
            aria-label="关闭弹窗"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {DOMESTIC_PROBE_PRESETS.map((preset) => {
            const selected = probeUrl.trim() === preset.url;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => void onSelectPreset(preset.url, preset.label)}
                className={`rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                  selected
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                }`}
              >
                {preset.label}
              </button>
            );
          })}
        </div>

        <form onSubmit={(ev) => void onSaveCustom(ev)} className="mt-3.5 space-y-3">
          <div>
            <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
              当前检测网址
            </label>
            <input
              type="text"
              value={probeUrl}
              onChange={(e) => onProbeUrlChange(e.target.value)}
              placeholder="http://connectivitycheck.platform.hicloud.com/generate_204"
              className={`cc-mono w-full rounded-xl border bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] outline-none ${
                probeValidation.ok
                  ? "border-[var(--line)] focus:border-[var(--accent)]"
                  : "border-[var(--red)] focus:border-[var(--red)]"
              }`}
            />
          </div>

          {!probeValidation.ok && (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
              <span className="inline-flex items-center gap-1.5 text-[11px] font-medium">
                <ShieldAlert className="h-4 w-4 shrink-0" />
                <span>{probeValidation.error}</span>
              </span>
              <button
                type="button"
                onClick={() =>
                  void onSelectPreset(
                    DOMESTIC_PROBE_PRESETS[0].url,
                    DOMESTIC_PROBE_PRESETS[0].label
                  )
                }
                className="shrink-0 rounded-lg border border-[var(--red)]/40 bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
              >
                恢复华为默认地址
              </button>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
            >
              关闭
            </button>
            <button
              type="submit"
              disabled={!probeValidation.ok}
              className="rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-45"
            >
              保存地址
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  );
}
