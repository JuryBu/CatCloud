import {
  AlertTriangle,
  Check,
  ChevronRight,
  GitMerge,
  Package,
  Pencil,
  QrCode,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import {
  type ProxyNode,
  type SubscriptionRecord,
  formatErrorMessage,
} from "../../api/tauri";
import type { ShareBundleTransport } from "../../components/ShareBundleModal";
import type { useUiDict } from "../../i18n";
import { appActions } from "../../store/appStore";
import {
  SUB_KIND_LABELS,
  formatExpireInfo,
  formatQuotaBytes,
  formatTimeShort,
  getSubSource,
  maskSubscriptionSource,
} from "./utils";

export interface SubscriptionCardsSectionProps {
  subscriptions: SubscriptionRecord[];
  nodes: ProxyNode[];
  subNodeCountMap: Map<string, number>;
  inTauri: boolean;
  refreshingAll: boolean;
  refreshingIdSet: Set<string>;
  renamingSubId: string | null;
  renamingSubName: string;
  renamingBusy: boolean;
  dict: ReturnType<typeof useUiDict>;
  onOpenShareImport: () => void;
  onOpenShareExport: (
    initialNodeIds?: string[],
    defaultPackName?: string,
    initialTransport?: ShareBundleTransport
  ) => void;
  onOpenMergeModal: () => void;
  onRefreshAll: () => void;
  onRefreshSingle: (sub: SubscriptionRecord, simulateFault: boolean) => void;
  onStartRename: (sub: SubscriptionRecord) => void;
  onChangeRenamingName: (name: string) => void;
  onSubmitRename: (sub: SubscriptionRecord) => void;
  onCancelRename: () => void;
  onRequestDelete: (sub: SubscriptionRecord) => void;
  onViewSubNodes?: (subId: string | null) => void;
}

export function SubscriptionCardsSection({
  subscriptions,
  nodes,
  subNodeCountMap,
  inTauri,
  refreshingAll,
  refreshingIdSet,
  renamingSubId,
  renamingSubName,
  renamingBusy,
  dict,
  onOpenShareImport,
  onOpenShareExport,
  onOpenMergeModal,
  onRefreshAll,
  onRefreshSingle,
  onStartRename,
  onChangeRenamingName,
  onSubmitRename,
  onCancelRename,
  onRequestDelete,
  onViewSubNodes,
}: SubscriptionCardsSectionProps) {
  return (
    <section aria-label="已导入订阅卡片" className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-xs font-semibold text-[var(--text)]">
            已导入订阅（{subscriptions.length}）
          </h2>
          <span className="inline-flex items-center gap-1 text-[11px] text-[var(--green)]">
            <ShieldCheck className="h-3.5 w-3.5" />
            刷新失败时自动保留原有节点
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={onOpenShareImport}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
            title={dict.share.importZipTooltip}
          >
            <Package className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{dict.common.importShareBundle} (.zip)</span>
          </button>

          <button
            type="button"
            onClick={() => onOpenShareExport(undefined, dict.share.defaultPackName)}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
            title={dict.share.exportZipTooltip}
          >
            <Upload className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{dict.common.exportShareBundle} (.zip)</span>
          </button>

          <button
            type="button"
            onClick={() => onOpenShareExport(undefined, undefined, "lan_send")}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--accent)]/45 bg-[var(--accent-soft)]/50 px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
            title={dict.sync.entryBtn}
          >
            <QrCode className="h-3.5 w-3.5" />
            <span>{dict.sync.entryBtn}</span>
          </button>

          <button
            type="button"
            disabled={subscriptions.length < 2}
            onClick={onOpenMergeModal}
            title={
              subscriptions.length < 2
                ? dict.nodes.mergeSubsNeedTwoTip
                : dict.nodes.mergeSubsTooltip
            }
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
          >
            <GitMerge className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>{dict.nodes.mergeSubsBtn}</span>
          </button>

          <button
            type="button"
            disabled={refreshingAll || subscriptions.length === 0}
            onClick={onRefreshAll}
            title={dict.nodes.refreshAllBtn}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-[var(--accent)] ${refreshingAll ? "animate-spin" : ""}`}
            />
            {dict.nodes.refreshAllBtn}
          </button>
        </div>
      </div>

      {subscriptions.length === 0 ? (
        <div className="cc-card cc-glass rounded-2xl px-4 py-6 text-center text-xs text-[var(--muted)]">
          还没有导入订阅来源，请先在上方任选一种方式添加节点
        </div>
      ) : (
        <div
          className={
            subscriptions.length >= 3
              ? "grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3"
              : "grid grid-cols-1 gap-3 md:grid-cols-2"
          }
        >
          {subscriptions.map((sub) => {
            const hasQuota = sub.traffic_total_bytes > 0;
            const usedBytes = Math.max(0, sub.traffic_used_bytes);
            const remainingBytes = hasQuota
              ? Math.max(0, sub.traffic_total_bytes - usedBytes)
              : 0;
            const usagePct = hasQuota
              ? Math.min(100, Math.round((usedBytes / sub.traffic_total_bytes) * 100))
              : 0;
            const barColor =
              usagePct >= 90
                ? "var(--red)"
                : usagePct >= 75
                  ? "var(--amber)"
                  : "var(--accent)";
            const expire = formatExpireInfo(sub.expires_at);
            const nodeCount = subNodeCountMap.get(sub.id) ?? 0;
            const isRefreshing = refreshingIdSet.has(sub.id) || refreshingAll;
            const maskedSource = maskSubscriptionSource(getSubSource(sub));
            const isRenamingThis = renamingSubId === sub.id;

            return (
              <article
                key={sub.id}
                className="cc-card cc-glass flex min-w-0 flex-col justify-between rounded-2xl p-3.5"
              >
                <div>
                  {/* Card Top Header */}
                  <div className="flex items-start justify-between gap-2">
                    {isRenamingThis ? (
                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        <input
                          type="text"
                          autoFocus
                          disabled={renamingBusy}
                          value={renamingSubName}
                          onChange={(e) => onChangeRenamingName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              onSubmitRename(sub);
                            } else if (e.key === "Escape") {
                              e.preventDefault();
                              onCancelRename();
                            }
                          }}
                          aria-label={dict.nodes.renameSubTitle}
                          className="min-w-0 flex-1 rounded-lg border border-[var(--accent)] bg-[var(--card)] px-2 py-1 text-xs font-semibold text-[var(--text)] outline-none"
                        />
                        <button
                          type="button"
                          disabled={renamingBusy}
                          onClick={() => onSubmitRename(sub)}
                          title={dict.common.confirm}
                          aria-label="确认修改分组名"
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                        >
                          <Check className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={renamingBusy}
                          onClick={onCancelRename}
                          title={dict.common.cancel}
                          aria-label="取消修改分组名"
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          if (onViewSubNodes) {
                            onViewSubNodes(sub.id);
                          } else {
                            appActions.openNodesWorkspace("nodes", sub.id);
                          }
                        }}
                        className="min-w-0 text-left"
                        title="查看这个订阅下的节点"
                      >
                        <div className="flex items-center gap-1.5">
                          <span className="truncate text-sm font-semibold text-[var(--text)]">
                            {sub.name}
                          </span>
                          <span className="shrink-0 rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            {SUB_KIND_LABELS[sub.kind]}
                          </span>
                        </div>
                        <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                          {maskedSource}
                        </div>
                      </button>
                    )}

                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        disabled={isRefreshing}
                        onClick={() => onRefreshSingle(sub, false)}
                        className="inline-flex h-7 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                        title="刷新节点列表（失败自动保留原有节点）"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${isRefreshing ? "animate-spin" : ""}`}
                        />
                        刷新
                      </button>
                      <button
                        type="button"
                        disabled={renamingBusy}
                        onClick={() => onStartRename(sub)}
                        className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                        title={dict.nodes.renameSubTitle}
                        aria-label={`改名：${sub.name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          onOpenShareExport(
                            nodes.filter((n) => n.sub_id === sub.id).map((n) => n.id),
                            `${sub.name} 分享包`
                          )
                        }
                        className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        title="导出该组节点为 .zip 分享包"
                        aria-label={`导出分组：${sub.name}`}
                      >
                        <Upload className="h-3.5 w-3.5" />
                      </button>
                      {!inTauri && (
                        <button
                          type="button"
                          disabled={isRefreshing}
                          onClick={() => onRefreshSingle(sub, true)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--amber)] hover:text-[var(--amber)] disabled:opacity-50"
                          title="演示刷新失败保护效果"
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                        </button>
                      )}
                      {(inTauri || subscriptions.length > 1) && (
                        <button
                          type="button"
                          onClick={() => onRequestDelete(sub)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
                          title="删除此订阅"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Traffic Progress Bar */}
                  <div className="mt-3">
                    {hasQuota ? (
                      <>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-[var(--muted)]">
                            已用{" "}
                            <span className="cc-mono text-[var(--text)]">
                              {formatQuotaBytes(usedBytes)}
                            </span>{" "}
                            / {formatQuotaBytes(sub.traffic_total_bytes)}
                          </span>
                          <span className="cc-mono font-medium text-[var(--text-secondary)]">
                            余 {formatQuotaBytes(remainingBytes)} ({100 - usagePct}%)
                          </span>
                        </div>
                        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-elevated)]">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${usagePct}%`,
                              backgroundColor: barColor,
                            }}
                          />
                        </div>
                      </>
                    ) : (
                      <div className="rounded-lg bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] text-[var(--muted)]">
                        暂未提供流量统计 · 当前共{" "}
                        <span className="cc-mono text-[var(--text)]">{nodeCount}</span>{" "}
                        个节点
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Bottom Meta & Error Protection Status */}
                <div className="mt-3 space-y-1.5 border-t border-[var(--line)] pt-2.5 text-[11px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">到期时间</span>
                    <span
                      className="cc-mono"
                      style={{
                        color:
                          expire.tone === "danger"
                            ? "var(--red)"
                            : expire.tone === "warn"
                              ? "var(--amber)"
                              : "var(--text-secondary)",
                      }}
                    >
                      {expire.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">
                      最近刷新 · {nodeCount} 节点
                    </span>
                    <span className="cc-mono text-[var(--text-secondary)]">
                      {formatTimeShort(sub.last_ok_at)}
                    </span>
                  </div>

                  {sub.last_error && (
                    <div className="flex items-start gap-1.5 rounded-lg bg-[var(--amber-soft)] px-2 py-1.5 text-[10px] leading-snug text-[var(--amber)]">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>{formatErrorMessage(sub.last_error)}</span>
                    </div>
                  )}

                  {onViewSubNodes && (
                    <div className="flex items-center justify-end pt-1">
                      <button
                        type="button"
                        onClick={() => onViewSubNodes(sub.id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                      >
                        <span>查看节点（{nodeCount}）</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    </div>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
