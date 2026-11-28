import { AlertTriangle, Upload, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";

export interface BackupImportConfirmModalProps {
  open: boolean;
  backupBusy: string | null;
  onClose: () => void;
  onConfirmImport: () => void;
}

export function BackupImportConfirmModal({
  open,
  backupBusy,
  onClose,
  onConfirmImport,
}: BackupImportConfirmModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
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
        aria-label="确认导入备份配置"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-start gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--amber-soft)] text-[var(--amber)]">
              <AlertTriangle className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1">
              <h3 className="break-words text-sm font-semibold text-[var(--text)]">
                确认导入配置备份？
              </h3>
              <p className="mt-1 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                导入备份将会覆盖当前的代理参数、智能多选组和国内中转配置。建议先点「导出备份」保留一份当前配置，再继续导入。
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
            aria-label="关闭弹窗"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)]"
          >
            取消
          </button>
          <button
            type="button"
            disabled={backupBusy !== null}
            onClick={onConfirmImport}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>确认覆盖并选择文件</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
