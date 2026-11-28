import { AlertTriangle, CheckCircle2, RefreshCw, Sparkles, X } from "lucide-react";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { EvaluatedCandidate, GroupEvaluationReport } from "../../api/tauri";
import { appActions } from "../../store/appStore";

interface GroupEvalModalProps {
  open: boolean;
  groupDisplayName: string;
  report: GroupEvaluationReport;
  untestedCount: number;
  onClose: () => void;
}

function CandidateList({
  title,
  items,
  tone,
}: {
  title: string;
  items: EvaluatedCandidate[];
  tone: "green" | "amber" | "red";
}) {
  if (items.length === 0) return null;
  const badgeCls =
    tone === "green"
      ? "bg-[var(--green-soft)] text-[var(--green)]"
      : tone === "amber"
        ? "bg-[var(--amber-soft)] text-[var(--amber)]"
        : "bg-[var(--red-soft)] text-[var(--red)]";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-[11px] font-semibold text-[var(--text-secondary)]">
        <span>{title}</span>
        <span className={`cc-mono rounded-full px-2 py-0.5 text-[10px] ${badgeCls}`}>
          {items.length}
        </span>
      </div>
      <div className="max-h-48 divide-y divide-[var(--line)] overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]">
        {items.slice(0, 40).map((c) => (
          <div
            key={c.node_id}
            className="flex items-center justify-between gap-2 px-3 py-1.5 text-[11px]"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="cc-mono rounded border border-[var(--line)] bg-[var(--card)] px-1 py-0.2 text-[9.5px] text-[var(--muted)]">
                  {c.region_code || "--"}
                </span>
                <span className="truncate font-medium text-[var(--text)]">{c.node_name}</span>
              </div>
              {c.failed_hard_gates.length > 0 && (
                <div className="mt-0.5 truncate text-[10px] text-[var(--amber)]">
                  未过门槛：{c.failed_hard_gates.join("、")}
                </div>
              )}
            </div>
            <span className="cc-mono shrink-0 text-[11px] font-semibold text-[var(--text-secondary)]">
              {Number.isFinite(c.score) ? c.score.toFixed(1) : "--"}
            </span>
          </div>
        ))}
        {items.length > 40 && (
          <div className="px-3 py-1.5 text-center text-[10px] text-[var(--muted)]">
            … 其余 {items.length - 40} 个候选已省略
          </div>
        )}
      </div>
    </div>
  );
}

export function GroupEvalModal({
  open,
  groupDisplayName,
  report,
  untestedCount,
  onClose,
}: GroupEvalModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
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
        aria-label={`模拟打分详情 - ${groupDisplayName}`}
        onClick={(ev) => ev.stopPropagation()}
        className="cc-surface flex max-h-[calc(100vh-2.5rem)] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] shadow-2xl"
      >
        <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--line)] px-4 py-3">
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold text-[var(--text)]">
              模拟打分排序详情 · {groupDisplayName}
            </h3>
            <p className="mt-0.5 cc-mono text-[11px] text-[var(--muted)]">
              候选 {report.pool_size} · 过门槛 {report.gate_passed.length} · 健康{" "}
              {report.healthy_candidates.length} · 淘汰 {report.gate_rejected.length}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭详情"
            className="rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          {untestedCount > 0 && (
            <div className="flex items-center gap-1.5 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/50 px-3 py-2 text-[11px] text-[var(--amber)]">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>其中 {untestedCount} 个尚未测速（先测速再按门槛筛）</span>
            </div>
          )}

          {report.all_failed_hard_gates && (
            <div className="flex items-center gap-1.5 rounded-xl border border-[var(--red)]/40 bg-[var(--red-soft)] px-3 py-2 text-[11px] text-[var(--red)]">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>当前没有节点满足全部硬门槛，将按「全部不达标怎么办」策略执行兜底。</span>
            </div>
          )}

          {report.healthy_candidates.length > 0 && (
            <div className="flex items-center gap-1.5 rounded-xl border border-[var(--green)]/40 bg-[var(--green-soft)]/45 px-3 py-2 text-[11px] text-[var(--green)]">
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
              <span>
                首选推荐：{report.healthy_candidates[0].node_name}（得分{" "}
                {report.healthy_candidates[0].score.toFixed(1)}）
              </span>
            </div>
          )}

          <CandidateList
            title="健康优胜候选（按公式得分降序）"
            items={report.healthy_candidates}
            tone="green"
          />
          <CandidateList
            title="通过门槛的候选"
            items={report.gate_passed.filter(
              (c) => !report.healthy_candidates.some((h) => h.node_id === c.node_id)
            )}
            tone="amber"
          />
          <CandidateList
            title="未过门槛的节点"
            items={report.gate_rejected}
            tone="red"
          />
        </div>

        <div className="flex shrink-0 justify-end border-t border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-2.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
          >
            关闭
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}

interface GroupEvalSectionProps {
  groupDisplayName: string;
  evaluating: boolean;
  anyEvaluating: boolean;
  savingGroup: boolean;
  evalReport: GroupEvaluationReport | null;
  evalUntestedCount: number;
  onEvaluateBackend: () => void;
}

export function GroupEvalSection({
  groupDisplayName,
  evaluating,
  anyEvaluating,
  savingGroup,
  evalReport,
  evalUntestedCount,
  onEvaluateBackend,
}: GroupEvalSectionProps) {
  const [detailOpen, setDetailOpen] = useState(false);

  return (
    <div className="space-y-2 border-t border-[var(--line)]/70 pt-2.5">
      <button
        type="button"
        disabled={evaluating || anyEvaluating || savingGroup}
        onClick={onEvaluateBackend}
        className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
      >
        <RefreshCw className={`h-3 w-3 ${evaluating || anyEvaluating ? "animate-spin" : ""}`} />
        <span>
          {evaluating ? "模拟打分中..." : anyEvaluating ? "其它分组评估中..." : "立即模拟打分排序"}
        </span>
      </button>

      {evalReport && (
        <div className="space-y-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-2 text-[10px] text-[var(--text-secondary)]">
          <div className="flex items-center justify-between gap-2">
            <span className="cc-mono">
              候选 {evalReport.pool_size} · 过门槛 {evalReport.gate_passed.length} · 健康{" "}
              {evalReport.healthy_candidates.length}
            </span>
            <button
              type="button"
              onClick={() => setDetailOpen(true)}
              className="shrink-0 font-medium text-[var(--accent)] hover:underline"
            >
              详情
            </button>
          </div>
          {evalUntestedCount > 0 && (
            <div className="text-[var(--amber)]">
              其中 {evalUntestedCount} 个尚未测速（先测速再按门槛筛）
            </div>
          )}
        </div>
      )}

      <button
        type="button"
        onClick={() => appActions.openAiAssistant("multigroup")}
        className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
      >
        <Sparkles className="h-3.5 w-3.5 text-[var(--accent)]" />
        <span>打开 AI 助手 · 多选组指南</span>
      </button>

      {evalReport && (
        <GroupEvalModal
          open={detailOpen}
          groupDisplayName={groupDisplayName}
          report={evalReport}
          untestedCount={evalUntestedCount}
          onClose={() => setDetailOpen(false)}
        />
      )}
    </div>
  );
}
