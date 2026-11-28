import { AlertTriangle, GitMerge, RefreshCw, ShieldCheck, Trash2, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";
import type { SubscriptionRecord } from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";

export interface MergeSubscriptionsModalProps {
  open: boolean;
  title: string;
  subscriptions: SubscriptionRecord[];
  subNodeCountMap: Map<string, number>;
  sourceSubId: string;
  targetSubId: string;
  newName: string;
  dedup: boolean;
  busy: boolean;
  error: string | null;
  onChangeSource: (nextSource: string) => void;
  onChangeTarget: (nextTarget: string) => void;
  onChangeNewName: (name: string) => void;
  onChangeDedup: (checked: boolean) => void;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export function MergeSubscriptionsModal({
  open,
  title,
  subscriptions,
  subNodeCountMap,
  sourceSubId,
  targetSubId,
  newName,
  dedup,
  busy,
  error,
  onChangeSource,
  onChangeTarget,
  onChangeNewName,
  onChangeDedup,
  onClose,
  onConfirm,
}: MergeSubscriptionsModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !busy) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, busy, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
              <GitMerge className="h-4 w-4" />
            </span>
            <div>
              <h3 className="text-sm font-semibold text-[var(--text)]">{title}</h3>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                把源分组中的节点安全整合进目标分组，便于统一管理
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            aria-label="关闭合并分组弹窗"
            className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <span className="block text-[11px] font-medium text-[var(--text-secondary)]">
                源分组（将被合并移入）
              </span>
              <AppSelect
                aria-label="选择源分组"
                size="sm"
                disabled={busy}
                value={sourceSubId}
                onChange={onChangeSource}
                options={subscriptions.map((s) => ({
                  value: s.id,
                  label: `${s.name}（${subNodeCountMap.get(s.id) ?? 0} 节点）`,
                }))}
                className="w-full"
                buttonClassName="bg-[var(--card)]"
              />
            </div>

            <div className="space-y-1">
              <span className="block text-[11px] font-medium text-[var(--text-secondary)]">
                目标分组（合并后保留）
              </span>
              <AppSelect
                aria-label="选择目标分组"
                size="sm"
                disabled={busy}
                value={targetSubId}
                onChange={onChangeTarget}
                options={subscriptions.map((s) => ({
                  value: s.id,
                  label: `${s.name}（${subNodeCountMap.get(s.id) ?? 0} 节点）`,
                }))}
                className="w-full"
                buttonClassName="bg-[var(--card)]"
              />
            </div>
          </div>

          <label className="block text-[11px] font-medium text-[var(--text-secondary)]">
            合并后的分组名称
            <input
              type="text"
              disabled={busy}
              value={newName}
              onChange={(e) => onChangeNewName(e.target.value)}
              placeholder="留空则沿用目标分组原名"
              className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />
          </label>

          <label className="flex cursor-pointer items-start gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 px-3 py-2 text-xs">
            <input
              type="checkbox"
              checked={dedup}
              disabled={busy}
              onChange={(e) => onChangeDedup(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
            />
            <div className="min-w-0">
              <div className="font-medium text-[var(--text)]">
                按节点物理指纹自动去重（推荐）
              </div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                自动过滤协议、地址与端口完全一致的重复线路，避免合并后出现重复条目
              </div>
            </div>
          </label>

          <div className="flex items-start gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/55 px-3 py-2.5 text-[11px] leading-relaxed text-[var(--amber)]">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              合并后，源分组中的节点将安全整合进目标分组并移除源分组外壳；原有的测速记录与智能多选组中的节点引用均会自动保留，不会丢失。
            </span>
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
          >
            取消
          </button>
          <button
            type="button"
            disabled={
              busy || !sourceSubId || !targetSubId || sourceSubId === targetSubId
            }
            onClick={() => void onConfirm()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <GitMerge className="h-3.5 w-3.5" />
            )}
            <span>{busy ? "正在合并…" : "确认合并分组"}</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}

export interface DeleteSubscriptionModalProps {
  sub: SubscriptionRecord | null;
  nodeCount: number;
  deleting: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export function DeleteSubscriptionModal({
  sub,
  nodeCount,
  deleting,
  onClose,
  onConfirm,
}: DeleteSubscriptionModalProps) {
  useEffect(() => {
    if (!sub) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !deleting) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [sub, deleting, onClose]);

  if (!sub || typeof document === "undefined") return null;

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
        aria-label="确认删除订阅"
        onClick={(e) => e.stopPropagation()}
        className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--red-soft)] text-[var(--red)]">
              <AlertTriangle className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-[var(--text)]">
                确认删除整条订阅？
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                即将删除订阅「
                <span className="font-semibold text-[var(--text)]">{sub.name}</span>
                」，并同时移除该订阅下的{" "}
                <strong className="cc-mono text-[var(--red)]">{nodeCount} 个节点</strong>
                。此操作无法撤销，请确认后再继续。
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
