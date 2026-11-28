import { ArrowLeft, Layers, Plus, Trash2, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import {
  type MultiGroup,
  type MultiGroupMode,
  type ProxyNode,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import { formatI18nTemplate, type useUiDict } from "../../i18n";
import { appActions, useAppSelector } from "../../store/appStore";
import {
  FORMULA_COST_EFFECTIVE,
  FORMULA_MAX_PERF,
  FORMULA_WSF_CLEAN,
} from "../../utils/formulaEvaluator";
import { formatGroupDisplayName } from "../../utils/releaseUrl";
import { GROUP_MODES } from "./GroupConfigDrawer";
import { handleCardKeyDown } from "./GroupNodeCard";

type UiDict = ReturnType<typeof useUiDict>;

export type CreateTemplateId = "manual" | "wsf" | "ai" | "download";

interface CreateTemplateMeta {
  id: CreateTemplateId;
  title: string;
  desc: string;
  mode: MultiGroupMode;
  switchMode: "force_close_old" | "graceful_new_only";
  independentRouting?: boolean;
  hardGates?: string[];
  formula: string;
  matchRules: string[];
}

export const WSF_AUTHORITATIVE_MATCH_RULES: readonly string[] = [
  "DOMAIN-SUFFIX,codeium.com",
  "DOMAIN-SUFFIX,codeiumdata.com",
  "DOMAIN-SUFFIX,windsurf.com",
  "DOMAIN-SUFFIX,devin.ai",
  "DOMAIN-SUFFIX,cognition.ai",
  "DOMAIN-SUFFIX,exafunction.com",
];

export const CREATE_TEMPLATES: readonly CreateTemplateMeta[] = [
  {
    id: "manual",
    title: "日常通用",
    desc: "智能默认，稳选低延迟常用节点",
    mode: "sticky_best",
    switchMode: "graceful_new_only",
    formula: FORMULA_COST_EFFECTIVE,
    matchRules: [],
  },
  {
    id: "wsf",
    title: "Windsurf / Devin 纯净专用",
    desc: "自动开启独立分流，拦截代理风控并优先纯净家宽",
    mode: "sticky_best",
    switchMode: "force_close_old",
    independentRouting: true,
    hardGates: ['site_unlocked("windsurf") == 1'],
    formula: FORMULA_WSF_CLEAN,
    matchRules: [...WSF_AUTHORITATIVE_MATCH_RULES],
  },
  {
    id: "ai",
    title: "AI 专线防跳 IP",
    desc: "稳选最优防频繁换地区，切线断旧连接",
    mode: "sticky_best",
    switchMode: "force_close_old",
    formula: FORMULA_COST_EFFECTIVE,
    matchRules: [
      "DOMAIN-SUFFIX,chatgpt.com",
      "DOMAIN-SUFFIX,ab.chatgpt.com",
      "DOMAIN-SUFFIX,openai.com",
      "DOMAIN-SUFFIX,anthropic.com",
      "DOMAIN-SUFFIX,claude.ai",
      "DOMAIN-SUFFIX,googleapis.com",
      ...WSF_AUTHORITATIVE_MATCH_RULES,
    ],
  },
  {
    id: "download",
    title: "均衡高速",
    desc: "多条线路并发轮询分摊，下载传文件更快",
    mode: "load_balance_round_robin",
    switchMode: "graceful_new_only",
    formula: FORMULA_MAX_PERF,
    matchRules: [],
  },
];

export interface GroupSidebarListProps {
  groups: MultiGroup[];
  selectedGroupId: string | null;
  isGroupMode: boolean;
  runtimeActiveGroupId: string | null;
  runtimeActiveNodeName: string | null;
  nodeById: Map<string, ProxyNode>;
  dirtyGroupIds: Record<string, boolean>;
  dict: UiDict;
  onSelectGroup: (groupId: string) => void;
  onGroupCreated: (saved: MultiGroup) => void;
  onGroupDeleted: (group: MultiGroup) => void;
}

export function GroupSidebarList({
  groups,
  selectedGroupId,
  isGroupMode,
  runtimeActiveGroupId,
  runtimeActiveNodeName,
  nodeById,
  dirtyGroupIds,
  dict,
  onSelectGroup,
  onGroupCreated,
  onGroupDeleted,
}: GroupSidebarListProps) {
  const multiGroupCreateHint = useAppSelector((s) => s.multiGroupCreateHint);

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupTemplate, setNewGroupTemplate] = useState<CreateTemplateId>("manual");
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingGroupId, setDeletingGroupId] = useState<string | null>(null);
  const deleteConfirmTimerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!multiGroupCreateHint) return;
    setNewGroupTemplate(multiGroupCreateHint);
    setShowCreateForm(true);
    if (multiGroupCreateHint === "wsf") {
      setNewGroupName((prev) => prev.trim() || "WSF / Devin 纯净专用");
    }
    appActions.consumeMultiGroupCreateHint();
  }, [multiGroupCreateHint]);

  useEffect(() => {
    return () => {
      if (deleteConfirmTimerRef.current !== null) {
        window.clearTimeout(deleteConfirmTimerRef.current);
      }
    };
  }, []);

  const handleCreateGroup = async (ev: FormEvent) => {
    ev.preventDefault();
    const name = newGroupName.trim();
    if (!name) {
      appActions.showToast("请先给新多选组起个名字", "warn");
      return;
    }
    if (creatingGroup) return;
    setCreatingGroup(true);

    const tpl = CREATE_TEMPLATES.find((t) => t.id === newGroupTemplate) ?? CREATE_TEMPLATES[0];
    const created: MultiGroup = {
      id: `grp-${Date.now().toString(36)}`,
      name,
      mode: tpl.mode,
      independent_routing: Boolean(tpl.independentRouting),
      match_rules: [...tpl.matchRules],
      member_node_ids: [],
      dynamic_filter: null,
      primary_probe_id: null,
      hard_gates: [...(tpl.hardGates ?? [])],
      trigger_rules: [],
      trigger_expr: null,
      formula_expr: tpl.formula,
      fallback_policy: "degrade_best_warn",
      fallback_pool_id: null,
      escalated_since: null,
      recover_probe_interval_sec: 120,
      switch_mode: tpl.switchMode,
      cooldown_sec: 60,
      hysteresis_pct: 20,
      active_node_id: null,
    };

    try {
      const saved = await catcloudApi.upsertMultiGroup(created);
      onGroupCreated(saved);
      setNewGroupName("");
      setShowCreateForm(false);
      appActions.showToast(`已新建「${saved.name}」，点击中间节点卡片即可加入`, "ok");
    } catch (err) {
      appActions.showToast(`新建失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCreatingGroup(false);
    }
  };

  const handleRequestDeleteGroup = (groupId: string) => {
    if (groups.length <= 1) return;
    setConfirmDeleteId(groupId);
    if (deleteConfirmTimerRef.current !== null) {
      window.clearTimeout(deleteConfirmTimerRef.current);
    }
    deleteConfirmTimerRef.current = window.setTimeout(() => {
      setConfirmDeleteId(null);
      deleteConfirmTimerRef.current = null;
    }, 4000);
  };

  const handleConfirmDeleteGroup = async (group: MultiGroup) => {
    if (deletingGroupId || groups.length <= 1) return;
    setDeletingGroupId(group.id);
    try {
      await catcloudApi.deleteMultiGroup(group.id);
      onGroupDeleted(group);
      setConfirmDeleteId(null);
      appActions.showToast(`已删除多选组：${formatGroupDisplayName(group.name)}`, "info");
    } catch (err) {
      appActions.showToast(`删除失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingGroupId(null);
    }
  };

  return (
    <aside className="flex w-full shrink-0 flex-col lg:w-[216px] xl:w-[232px]">
      <div className="cc-card cc-glass flex flex-1 flex-col rounded-2xl p-3">
        <button
          type="button"
          onClick={() => setShowCreateForm((v) => !v)}
          className={`flex w-full items-center justify-center gap-1.5 rounded-xl px-3.5 py-2.5 text-xs font-semibold transition-opacity ${
            showCreateForm
              ? "border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
              : "bg-[var(--accent)] text-[var(--accent-ink)] shadow-sm hover:opacity-90"
          }`}
        >
          {showCreateForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          <span>{showCreateForm ? "取消新建" : "新建多选组"}</span>
        </button>

        {showCreateForm && (
          <form
            onSubmit={(ev) => void handleCreateGroup(ev)}
            className="mt-3 space-y-2.5 rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] p-2.5"
          >
            <div>
              <label className="mb-1 block text-[11px] font-medium text-[var(--text-secondary)]">
                多选组名称
              </label>
              <input
                type="text"
                autoFocus
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                placeholder="例如：日常主力、AI 专线"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div>
              <div className="mb-1 text-[11px] font-medium text-[var(--text-secondary)]">
                快捷场景（可选）
              </div>
              <div className="space-y-1.5">
                {CREATE_TEMPLATES.map((tpl) => {
                  const picked = newGroupTemplate === tpl.id;
                  return (
                    <button
                      key={tpl.id}
                      type="button"
                      onClick={() => setNewGroupTemplate(tpl.id)}
                      className={`w-full rounded-lg border px-2.5 py-1.5 text-left transition-colors ${
                        picked
                          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                          : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                      }`}
                    >
                      <div className="text-[11px] font-semibold text-[var(--text)]">
                        {tpl.id === "wsf" ? dict.groups.wsfTemplateTitle : tpl.title}
                      </div>
                      <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                        {tpl.id === "wsf" ? dict.groups.wsfTemplateDesc : tpl.desc}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="text-[10px] leading-relaxed text-[var(--muted)]">
              {newGroupTemplate === "wsf"
                ? "将自动开启独立分流与 Windsurf 防风控门禁（含 6 条官方域名并优先纯净家宽），去中间点选节点加入即可。"
                : "新建后直接去中间点选节点加入即可，随时可在右侧抽屉调整门槛与分流规则。"}
            </div>

            <button
              type="submit"
              disabled={creatingGroup}
              className="w-full rounded-lg bg-[var(--accent)] py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {creatingGroup ? "创建中..." : "确认创建"}
            </button>
          </form>
        )}

        <div className="mt-3.5 mb-2 flex items-center justify-between px-0.5">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-[var(--text-secondary)]">
            <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
            <span>我的多选组</span>
          </div>
          <span className="cc-mono text-[10px] text-[var(--muted)]">{groups.length} 组</span>
        </div>

        {!isGroupMode && (
          <div className="mb-2.5 rounded-xl border border-[var(--green)]/35 bg-[var(--green-soft)]/55 px-2.5 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
            <div className="flex items-start gap-1.5">
              <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--green)]" />
              <span>
                当前首页正在使用单节点（
                <span className="font-semibold text-[var(--text)]">
                  {runtimeActiveNodeName || "单节点"}
                </span>
                ），点下方组的「使用此组」可切回智能多选组
              </span>
            </div>
            <button
              type="button"
              onClick={() => appActions.setNav("overview")}
              className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-[var(--green)] hover:underline"
            >
              <ArrowLeft className="h-3 w-3 shrink-0" />
              <span>返回总览</span>
            </button>
          </div>
        )}

        <div className="space-y-1.5">
          {groups.map((g) => {
            const isSelected = selectedGroupId === g.id;
            const isSystemActive = isGroupMode && runtimeActiveGroupId === g.id;
            const isIndependentEnabled = Boolean(g.independent_routing);
            const activeNode = g.active_node_id ? nodeById.get(g.active_node_id) : null;
            const modeMeta = GROUP_MODES.find((m) => m.id === g.mode) ?? GROUP_MODES[0];
            const isDirty = Boolean(dirtyGroupIds[g.id]);
            const isConfirmingDel = confirmDeleteId === g.id;
            const displayName = formatGroupDisplayName(g.name);

            return (
              <div
                key={g.id}
                role="button"
                tabIndex={0}
                onClick={() => onSelectGroup(g.id)}
                onKeyDown={(ev) => handleCardKeyDown(ev, () => onSelectGroup(g.id))}
                className={`group relative cursor-pointer rounded-xl border p-2.5 transition-colors ${
                  isSystemActive && isSelected
                    ? "border-[var(--green)] bg-[var(--green-soft)]/55 shadow-xs"
                    : isSystemActive
                      ? "border-[var(--green)]/65 bg-[var(--green-soft)]/30 hover:border-[var(--green)]"
                      : isSelected
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] shadow-xs"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                }`}
              >
                <div className="flex items-start justify-between gap-1.5">
                  <div className="flex min-w-0 items-center gap-1.5">
                    {isSystemActive && (
                      <span
                        className="h-2 w-2 shrink-0 rounded-full bg-[var(--green)]"
                        title="当前系统正在使用此组"
                      />
                    )}
                    <span className="truncate text-xs font-semibold text-[var(--text)]">
                      {displayName}
                    </span>
                    {isDirty && (
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                        title="右侧策略尚未点应用"
                      />
                    )}
                  </div>

                  {groups.length > 1 && !isConfirmingDel && (
                    <button
                      type="button"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        handleRequestDeleteGroup(g.id);
                      }}
                      className="shrink-0 rounded-md p-0.5 text-[var(--muted)] opacity-0 transition-opacity hover:bg-[var(--red-soft)] hover:text-[var(--red)] group-hover:opacity-100 focus:opacity-100"
                      title="删除此多选组"
                      aria-label={`删除多选组 ${displayName}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>

                {isConfirmingDel ? (
                  <div
                    className="mt-2 flex items-center justify-between gap-1.5 rounded-lg border border-[var(--red)]/40 bg-[var(--red-soft)] px-2 py-1"
                    onClick={(ev) => ev.stopPropagation()}
                  >
                    <span className="text-[10px] font-medium text-[var(--red)]">确认删除？</span>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        disabled={deletingGroupId === g.id}
                        onClick={() => void handleConfirmDeleteGroup(g)}
                        className="rounded bg-[var(--red)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                      >
                        {deletingGroupId === g.id ? "..." : "删"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteId(null)}
                        className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] hover:text-[var(--text)]"
                      >
                        取消
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="mt-1.5 flex flex-wrap items-center justify-between gap-1.5 text-[11px]">
                      <span className="cc-mono font-medium text-[var(--text-secondary)]">
                        {g.member_node_ids.filter((id) => nodeById.has(id)).length} 个节点
                      </span>
                      <div className="flex flex-wrap items-center gap-1">
                        {isIndependentEnabled && (
                          <span
                            title={
                              g.match_rules.length > 0
                                ? `已开启独立分流：即使首页在用其它组，命中本组 ${g.match_rules.length} 条分流规则的流量也会单独走此组`
                                : "已开启独立分流开关（在右侧第 5 节添加至少一条规则后将单独接管对应流量）"
                            }
                            className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${
                              g.match_rules.length > 0
                                ? "border-[var(--amber)]/50 bg-[var(--amber-soft)] text-[var(--amber)]"
                                : "border-dashed border-[var(--amber)]/50 bg-[var(--amber-soft)]/45 text-[var(--amber)]"
                            }`}
                          >
                            <span className="h-1.5 w-1.5 rounded-full bg-[var(--amber)]" />
                            <span>
                              {g.match_rules.length > 0
                                ? formatI18nTemplate(dict.groups.indepRoutingCount, {
                                    count: g.match_rules.length,
                                  })
                                : dict.groups.indepRoutingPending}
                            </span>
                          </span>
                        )}
                        <span className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          {modeMeta.shortLabel}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between gap-1.5">
                      <span className="min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">
                        {activeNode
                          ? `${isSystemActive ? "正在用" : "组内选定"}：${activeNode.name}`
                          : "尚未选定节点"}
                      </span>
                      {isSystemActive ? (
                        <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                          {dict.groups.mainFallbackActive}
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={(ev) => {
                            ev.stopPropagation();
                            onSelectGroup(g.id);
                            void appActions.setActiveGroup(g.id);
                          }}
                          className="shrink-0 whitespace-nowrap rounded-md border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                        >
                          使用此组
                        </button>
                      )}
                    </div>
                  </>
                )}
              </div>
            );
          })}

          {groups.length === 0 && (
            <div className="rounded-xl border border-dashed border-[var(--line)] px-3 py-5 text-center text-[11px] text-[var(--muted)]">
              还没有多选组，点上方按钮新建一个吧
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
