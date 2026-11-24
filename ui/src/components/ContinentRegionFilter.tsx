import { ChevronLeft, ChevronRight, Globe } from "lucide-react";
import { useState } from "react";
import {
  CONTINENT_ORDER,
  type ContinentId,
  type ContinentStatsSummary,
  getContinentLabel,
} from "../utils/regions";
import { AppSelect, type AppSelectOption } from "./AppSelect";

export interface ContinentRegionFilterProps {
  variant: "pills" | "select";
  stats: ContinentStatsSummary;
  continent: ContinentId;
  region: string;
  onContinentChange: (next: ContinentId) => void;
  onRegionChange: (next: string) => void;
  className?: string;
}

export function ContinentRegionFilter({
  variant,
  stats,
  continent,
  region,
  onContinentChange,
  onRegionChange,
  className = "",
}: ContinentRegionFilterProps) {
  const visibleContinents = CONTINENT_ORDER.filter(
    (c) => c.id === "all" || stats.continentCounts[c.id] > 0
  );

  const handleContinentSelect = (next: ContinentId) => {
    onContinentChange(next);
    if (next === "all") {
      if (region !== "all") {
        onRegionChange("all");
      }
      return;
    }
    if (region !== "all") {
      const allowed = stats.regionsByContinent[next] ?? [];
      if (!allowed.some((r) => r.code === region)) {
        onRegionChange("all");
      }
    }
  };

  if (variant === "select") {
    const activeContinentRegions = stats.regionsByContinent[continent] ?? [];
    const groupedContinents = CONTINENT_ORDER.filter(
      (c) =>
        c.id !== "all" &&
        c.id !== "common" &&
        (stats.regionsByContinent[c.id]?.length ?? 0) > 0
    );

    const continentOptions: AppSelectOption[] = visibleContinents.map((c) => ({
      value: c.id,
      label:
        c.id === "all"
          ? `全部大洲 (${stats.total})`
          : `${c.label} (${stats.continentCounts[c.id]})`,
    }));

    const regionOptions: AppSelectOption[] = [
      {
        value: "all",
        label:
          continent === "all"
            ? "全部国家/地区"
            : `全部${getContinentLabel(continent)} (${stats.continentCounts[continent]})`,
      },
      ...(continent === "all"
        ? groupedContinents.flatMap((c) => {
            const groupLabel = `${c.label} (${stats.continentCounts[c.id]})`;
            return stats.regionsByContinent[c.id].map((r) => ({
              value: r.code,
              label: `${r.label} (${r.count})`,
              group: groupLabel,
            }));
          })
        : activeContinentRegions.map((r) => ({
            value: r.code,
            label: `${r.label} (${r.count})`,
          }))),
    ];

    return (
      <div className={`flex flex-wrap items-center gap-2 ${className}`}>
        {/* 1. Continent Select */}
        <div className="relative inline-flex items-center">
          <Globe className="pointer-events-none absolute left-2.5 top-1/2 z-10 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
          <AppSelect
            value={continent}
            onChange={(val) => handleContinentSelect(val as ContinentId)}
            options={continentOptions}
            aria-label="按大洲筛选"
            size="md"
            buttonClassName="pl-8"
          />
        </div>

        {/* 2. Country / Region Select (linked to selected continent) */}
        <AppSelect
          value={region}
          onChange={onRegionChange}
          options={regionOptions}
          aria-label="按国家或地区筛选"
          size="md"
        />
      </div>
    );
  }

  // variant === "pills": 通用分洲分组标准两级「大洲 -> 国家/地区」筛选胶囊
  const countryPills = continent === "all" ? [] : stats.regionsByContinent[continent] ?? [];

  return (
    <div className={`space-y-2 ${className}`}>
      {/* Tier 1: Continents (全部 / 常用 / 亚洲 / 中东 / 欧洲 / 北美洲 / 南美洲 / 大洋洲 / 非洲 / 其他) */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-0.5 text-[11px] font-medium text-[var(--muted)]">大洲</span>
        {visibleContinents.map((c) => {
          const active = continent === c.id;
          const count = c.id === "all" ? stats.total : stats.continentCounts[c.id];
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => handleContinentSelect(c.id)}
              className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors ${
                active
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              {c.label}
              <span className="cc-mono ml-1 text-[10px] opacity-80">({count})</span>
            </button>
          );
        })}
      </div>

      {/* Tier 2: Countries inside selected continent (auto-expanded when continent != all) */}
      {continent !== "all" && countryPills.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-[var(--line)]/70 bg-[var(--bg-elevated)]/65 px-2.5 py-2">
          <span className="mr-0.5 text-[11px] font-medium text-[var(--muted)]">
            {getContinentLabel(continent)}
          </span>
          <button
            type="button"
            onClick={() => onRegionChange("all")}
            className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
              region === "all"
                ? "border-[var(--accent)] bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
            }`}
          >
            全部 ({stats.continentCounts[continent]})
          </button>
          {countryPills.map((r) => {
            const active = region === r.code;
            return (
              <button
                key={r.code}
                type="button"
                onClick={() => onRegionChange(active ? "all" : r.code)}
                className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
                  active
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                }`}
              >
                {r.label}
                <span className="cc-mono ml-1 text-[10px] opacity-75">({r.count})</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ============================================================================
 * Reusable Compact Pagination Bar with Direct Page Jump
 * ============================================================================ */

export interface PaginationBarProps {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  pageSizeOptions?: readonly number[];
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  itemUnit?: string;
  compact?: boolean;
  className?: string;
}

export function PaginationBar({
  currentPage,
  totalPages,
  totalItems,
  pageSize,
  pageSizeOptions = [24, 48, 96],
  onPageChange,
  onPageSizeChange,
  itemUnit = "个节点",
  compact = false,
  className = "",
}: PaginationBarProps) {
  const [jumpInput, setJumpInput] = useState("");
  const safePage = Math.max(1, Math.min(currentPage, Math.max(1, totalPages)));
  const startIdx = totalItems === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const endIdx = Math.min(safePage * pageSize, totalItems);

  const commitJump = () => {
    const parsed = Number.parseInt(jumpInput.trim(), 10);
    if (!Number.isFinite(parsed)) {
      setJumpInput("");
      return;
    }
    const clamped = Math.max(1, Math.min(totalPages, parsed));
    onPageChange(clamped);
    setJumpInput("");
  };

  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-2 text-[11px] text-[var(--muted)] ${className}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="cc-mono">
          {totalItems === 0
            ? `共 0 ${itemUnit}`
            : `第 ${startIdx}-${endIdx}，共 ${totalItems} ${itemUnit}`}
        </span>
        {onPageSizeChange && !compact && (
          <div className="inline-flex items-center gap-1">
            <span>每页</span>
            {pageSizeOptions.map((size) => (
              <button
                key={size}
                type="button"
                onClick={() => onPageSizeChange(size)}
                className={`cc-mono rounded-md border px-1.5 py-0.5 text-[11px] transition-colors ${
                  pageSize === size
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                }`}
              >
                {size}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          disabled={safePage <= 1}
          onClick={() => onPageChange(Math.max(1, safePage - 1))}
          className="inline-flex items-center gap-0.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)]"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          上一页
        </button>
        <span className="cc-mono px-1 text-[var(--text-secondary)]">
          {safePage} / {Math.max(1, totalPages)}
        </span>
        <button
          type="button"
          disabled={safePage >= totalPages}
          onClick={() => onPageChange(Math.min(totalPages, safePage + 1))}
          className="inline-flex items-center gap-0.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[var(--bg-elevated)] disabled:text-[var(--muted)]"
        >
          下一页
          <ChevronRight className="h-3.5 w-3.5" />
        </button>

        {totalPages > 1 && (
          <div className="ml-1 inline-flex items-center gap-1">
            <span>跳至</span>
            <input
              type="text"
              inputMode="numeric"
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value.replace(/[^\d]/g, ""))}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commitJump();
                }
              }}
              placeholder={String(safePage)}
              aria-label="输入跳转页码"
              className="cc-mono h-6 w-11 rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 text-center text-[11px] text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />
            <button
              type="button"
              onClick={commitJump}
              className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              跳转
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
