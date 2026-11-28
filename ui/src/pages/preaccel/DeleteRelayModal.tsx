import { AlertTriangle, Trash2, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";
import type { PreAccelRelay } from "../../api/tauri";

export interface DeleteRelayModalProps {
  relay: PreAccelRelay | null;
  deleting: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export function DeleteRelayModal({
  relay,
  deleting,
  onClose,
  onConfirm,
}: DeleteRelayModalProps) {
  useEffect(() => {
    if (!relay) return;
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !deleting) {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [relay, deleting, onClose]);

  if (!relay || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={() => {
        if (!deleting) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="确认删除国内中转机"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--red-soft)] text-[var(--red)]">
              <AlertTriangle className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-[var(--text)]">确认删除国内中转机？</h3>
              <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                即将移除中转线路「
                <span className="font-semibold text-[var(--text)]">{relay.name}</span>
                」（<span className="cc-mono">{relay.server}:{relay.port}</span>
                ）。删除后无法撤销，如仍在使用将自动回落至其它中转或直连。
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={deleting}
            onClick={onClose}
            className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
            aria-label="关闭弹窗"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            disabled={deleting}
            onClick={onClose}
            className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
          >
            取消
          </button>
          <button
            type="button"
            disabled={deleting}
            onClick={() => void onConfirm()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--red)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>{deleting ? "删除中…" : "确认删除"}</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
