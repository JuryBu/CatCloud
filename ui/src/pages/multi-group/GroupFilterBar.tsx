import {
  AlertTriangle,
  ArrowUpDown,
  ChevronDown,
  Filter,
  Plus,
  RotateCcw,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { AppSelect } from "../../components/AppSelect";
import { ContinentRegionFilter } from "../../components/ContinentRegionFilter";
import { formatI18nTemplate, type useUiDict } from "../../i18n";
import type { ContinentId, buildContinentRegionStats } from "../../utils/regions";

type ContinentRegionStats = ReturnType<typeof buildContinentRegionStats>;

type UiDict = ReturnType<typeof useUiDict>;

export type NodeViewMode = "all" | "members";
export type NodeSortMode = "default" | "up_desc" | "down_desc" | "latency_asc";

export interface GroupFilterBarProps {
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  viewMode: NodeViewMode;
  setViewMode: (v: NodeViewMode) => void;
  effectiveMemberCount: number;
  filterGoogleClean: boolean;
  setFilterGoogleClean: (updater: (v: boolean) => boolean) => void;
  filterAiReady: boolean;
  setFilterAiReady: (updater: (v: boolean) => boolean) => void;
  moreFiltersOpen: boolean;
  setMoreFiltersOpen: (updater: (v: boolean) => boolean) => void;
  moreFilterActiveCount: number;
  hasAnyActiveFilter: boolean;
  onResetFilters: () => void;
  selectedSubId: string;
  setSelectedSubId: (v: string) => void;
  enabledNodesCount: number;
  providerTabs: Array<{ id: string; name: string; count: number }>;
  regionStats: ContinentRegionStats;
  filterContinent: ContinentId;
  filterRegion: string;
  onContinentChange: (c: ContinentId) => void;
  onRegionChange: (r: string) => void;
  sortMode: NodeSortMode;
  setSortMode: (v: NodeSortMode) => void;
  unjoinedInFilterCount: number;
  onAddFilteredToGroup: () => void;
  confirmClearMembers: boolean;
  hasProtectedActiveMember: boolean;
  onClearGroupMembers: () => void;
  onCancelClearGroupMembers: () => void;
  onConfirmClearGroupMembers: () => void;
  filteredCount: number;
  safeNodePage: number;
  totalNodePages: number;
  dict: UiDict;
}

export function GroupFilterBar({
  searchQuery,
  setSearchQuery,
  viewMode,
  setViewMode,
  effectiveMemberCount,
  filterGoogleClean,
  setFilterGoogleClean,
  filterAiReady,
  setFilterAiReady,
  moreFiltersOpen,
  setMoreFiltersOpen,
  moreFilterActiveCount,
  hasAnyActiveFilter,
  onResetFilters,
  selectedSubId,
  setSelectedSubId,
  enabledNodesCount,
  providerTabs,
  regionStats,
  filterContinent,
  filterRegion,
  onContinentChange,
  onRegionChange,
  sortMode,
  setSortMode,
  unjoinedInFilterCount,
  onAddFilteredToGroup,
  confirmClearMembers,
  hasProtectedActiveMember,
  onClearGroupMembers,
  onCancelClearGroupMembers,
  onConfirmClearGroupMembers,
  filteredCount,
  safeNodePage,
  totalNodePages,
  dict,
}: GroupFilterBarProps) {
  return (
    <div className="cc-card cc-glass space-y-2.5 rounded-2xl px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[160px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="搜索节点名、地区或来源..."
            className="h-9 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              aria-label="清空搜索"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <div className="inline-flex shrink-0 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-xs">
          <button
            type="button"
            onClick={() => setViewMode("all")}
            className={`whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors ${
              viewMode === "all"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            全部节点
          </button>
          <button
            type="button"
            onClick={() => setViewMode("members")}
            className={`whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors ${
              viewMode === "members"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            仅看本组 ({effectiveMemberCount})
          </button>
        </div>

        <button
          type="button"
          aria-pressed={filterGoogleClean}
          onClick={() => setFilterGoogleClean((v) => !v)}
          title="仅看已测出谷歌地区正常的节点（不送中）"
          className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
            filterGoogleClean
              ? "border-[var(--green)]/60 bg-[var(--green-soft)] text-[var(--green)]"
              : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--green)]/50 hover:text-[var(--text)]"
          }`}
        >
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
          <span>谷歌正常</span>
        </button>

        <button
          type="button"
          aria-pressed={filterAiReady}
          onClick={() => setFilterAiReady((v) => !v)}
          title="仅看已测出支持 ChatGPT / Gemini / Claude / Windsurf 任一 AI 的节点"
          className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
            filterAiReady
              ? "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)]"
              : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)]/50 hover:text-[var(--text)]"
          }`}
        >
          <Sparkles className="h-3.5 w-3.5 shrink-0" />
          <span>AI 可用</span>
        </button>

        <button
          type="button"
          aria-expanded={moreFiltersOpen}
          onClick={() => setMoreFiltersOpen((v) => !v)}
          className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
            moreFiltersOpen
              ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
              : moreFilterActiveCount > 0
                ? "border-[var(--amber)]/60 bg-[var(--amber-soft)]/50 text-[var(--text)] hover:border-[var(--amber)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
          }`}
        >
          <Filter className="h-3.5 w-3.5 shrink-0" />
          <span>{dict.groups.moreFiltersBtn}</span>
          {moreFilterActiveCount > 0 && (
            <span className="cc-mono rounded-full border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--amber)]">
              {formatI18nTemplate(dict.groups.activeFiltersCount, {
                count: moreFilterActiveCount,
              })}
            </span>
          )}
          <ChevronDown
            className={`h-3.5 w-3.5 shrink-0 transition-transform ${
              moreFiltersOpen ? "rotate-180" : ""
            }`}
          />
        </button>

        {hasAnyActiveFilter && (
          <button
            type="button"
            onClick={onResetFilters}
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <RotateCcw className="h-3 w-3 shrink-0" />
            <span>{dict.groups.resetFiltersBtn}</span>
          </button>
        )}
      </div>

      {moreFiltersOpen && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)]/60 pt-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex shrink-0 items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <AppSelect
                aria-label="按来源筛选"
                size="md"
                value={selectedSubId}
                onChange={setSelectedSubId}
                options={[
                  { value: "all", label: `全部来源 (${enabledNodesCount})` },
                  ...providerTabs.map((sub) => ({
                    value: sub.id,
                    label: `${sub.name} (${sub.count})`,
                  })),
                ]}
                className="w-[168px]"
              />
            </div>

            <ContinentRegionFilter
              variant="select"
              stats={regionStats}
              continent={filterContinent}
              region={filterRegion}
              onContinentChange={onContinentChange}
              onRegionChange={onRegionChange}
            />

            <div className="inline-flex shrink-0 items-center gap-1.5">
              <ArrowUpDown
                className={`h-3.5 w-3.5 shrink-0 ${
                  sortMode !== "default" ? "text-[var(--accent)]" : "text-[var(--muted)]"
                }`}
              />
              <AppSelect
                aria-label="节点排序方式"
                size="md"
                value={sortMode}
                onChange={(v) => setSortMode(v as NodeSortMode)}
                options={[
                  { value: "default", label: "排序：默认（在用优先）" },
                  { value: "up_desc", label: "排序：上传最快" },
                  { value: "down_desc", label: "排序：下载最快" },
                  { value: "latency_asc", label: "排序：延迟最低" },
                ]}
                className="w-[184px]"
                buttonClassName={`font-medium ${
                  sortMode !== "default" ? "border-[var(--accent)]/60" : ""
                }`}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {viewMode === "all" && unjoinedInFilterCount > 0 && (
              <button
                type="button"
                onClick={onAddFilteredToGroup}
                className="inline-flex items-center gap-1 rounded-xl border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>当前筛选全加入 ({unjoinedInFilterCount})</span>
              </button>
            )}

            {effectiveMemberCount > 0 && (
              <button
                type="button"
                onClick={onClearGroupMembers}
                className={`rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  confirmClearMembers
                    ? "border-[var(--red)] bg-[var(--red-soft)] text-[var(--red)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--red)]/50 hover:text-[var(--red)]"
                }`}
              >
                {confirmClearMembers
                  ? hasProtectedActiveMember
                    ? dict.groups.confirmBelowHint
                    : "再点一次确认清空"
                  : "清空本组"}
              </button>
            )}
          </div>
        </div>
      )}

      {confirmClearMembers && hasProtectedActiveMember && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/75 px-3 py-2 text-xs"
        >
          <div className="flex min-w-0 flex-1 items-start gap-2 text-[var(--amber)]">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span className="leading-relaxed">{dict.groups.clearActiveProtectedConfirm}</span>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              onClick={onCancelClearGroupMembers}
              className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:text-[var(--text)]"
            >
              {dict.common.cancel}
            </button>
            <button
              type="button"
              onClick={onConfirmClearGroupMembers}
              className="rounded-lg bg-[var(--red)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
            >
              {dict.groups.confirmClear}
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <div className="flex flex-wrap items-center gap-3">
          <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span className="h-3 w-3 shrink-0 rounded-[4px] bg-[var(--green)] shadow-xs" />
            <span className="font-medium">正在用</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span className="h-3 w-3 shrink-0 rounded-[4px] bg-[var(--accent)] shadow-xs" />
            <span className="font-medium">已在本组</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-[var(--muted)]">
            <span className="h-3 w-3 shrink-0 rounded-[4px] border-2 border-[var(--line-strong)] bg-[var(--card)]" />
            <span>未加入</span>
          </span>
          <span className="cc-mono text-[11px] text-[var(--muted)]">
            · 匹配 {filteredCount} 个
            {totalNodePages > 1 ? `（第 ${safeNodePage}/${totalNodePages} 页）` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}
