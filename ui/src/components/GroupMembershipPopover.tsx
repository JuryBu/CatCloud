import { Check, Layers, Plus, RefreshCw } from "lucide-react";
import {
  type JSX,
  type MouseEvent as ReactMouseEvent,
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import {
  type MultiGroup,
  type ProxyNode,
  catcloudApi,
  formatErrorMessage,
} from "../api/tauri";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import {
  TITLE_BAR_SAFE_TOP_PX,
  isAnchorVisibleInScrollHierarchy,
} from "../utils/viewportVisibility";

const FRIENDLY_GROUP_NAME_MAP: Record<string, string> = {
  流媒体与下载受控均衡: "影音下载均衡组",
  高优家宽备援池: "备用精选组",
};

function defaultFormatGroupName(name: string): string {
  return FRIENDLY_GROUP_NAME_MAP[name] ?? name;
}

interface PopoverPosition {
  left: number;
  width: number;
  maxHeight: number;
  placement: "bottom" | "top";
  top?: number;
  bottom?: number;
}

const POPOVER_MAX_HEIGHT = 296;
const POPOVER_WIDTH = 256;
const POPOVER_GAP = 6;
const VIEWPORT_PADDING = 8;
const TOP_PADDING = 44; // Reserve clearance for 36px frameless TitleBar + 8px gap

/* ============================================================================
 * Per-Group Serialized Mutation Queue & Optimistic Version Guard
 * Ensures rapid multi-clicks (same node or multiple nodes in the same group)
 * never race or drop members by reading latest confirmed state in strict order.
 * ============================================================================ */

const groupSerialQueues = new Map<string, Promise<void>>();
const groupLatestIntentVersion = new Map<string, number>();
const groupConfirmedMembers = new Map<string, string[]>();

function enqueueGroupMembershipToggle(
  groupId: string,
  node: ProxyNode,
  desiredInGroup: boolean,
  formatGroupName: (name: string) => string,
  onSettled?: () => void
): void {
  const storeState = appStore.getState();
  const currentGroup = storeState.groups.find((g) => g.id === groupId);
  if (!currentGroup) {
    onSettled?.();
    return;
  }

  // Snapshot confirmed baseline before any queued optimistic edits exist for this group
  if (!groupSerialQueues.has(groupId)) {
    groupConfirmedMembers.set(groupId, [...currentGroup.member_node_ids]);
  }

  const nextVersion = (groupLatestIntentVersion.get(groupId) ?? 0) + 1;
  groupLatestIntentVersion.set(groupId, nextVersion);

  // Immediate optimistic UI update so rapid clicks feel instant
  const optimisticIds = desiredInGroup
    ? Array.from(new Set([...currentGroup.member_node_ids, node.id]))
    : currentGroup.member_node_ids.filter((id) => id !== node.id);

  appActions.syncGroups(
    storeState.groups.map((g) =>
      g.id === groupId ? { ...g, member_node_ids: optimisticIds } : g
    )
  );

  const prevChain = groupSerialQueues.get(groupId) ?? Promise.resolve();

  const task = prevChain
    .catch(() => {
      /* isolate previous error so subsequent queued toggles proceed cleanly */
    })
    .then(async () => {
      const latestState = appStore.getState();
      const latestGroup = latestState.groups.find((g) => g.id === groupId);
      if (!latestGroup) return;

      const baseMembers =
        groupConfirmedMembers.get(groupId) ?? latestGroup.member_node_ids;
      const wasActiveNode =
        !desiredInGroup &&
        (latestGroup.active_node_id === node.id ||
          (latestState.runtime.route_mode !== "single" &&
            latestState.runtime.active_group_id === groupId &&
            latestState.runtime.active_node_id === node.id));

      const nextMembers = desiredInGroup
        ? Array.from(new Set([...baseMembers, node.id]))
        : baseMembers.filter((id) => id !== node.id);

      const groupDisplayName = formatGroupName(latestGroup.name);

      try {
        const updated = await catcloudApi.updateMultiGroupMembers(
          groupId,
          nextMembers
        );
        groupConfirmedMembers.set(groupId, [...updated.member_node_ids]);

        // Only write authoritative member list back when no newer optimistic intent is pending
        const isLatestIntent =
          groupLatestIntentVersion.get(groupId) === nextVersion;
        if (isLatestIntent) {
          appActions.syncGroups(
            appStore
              .getState()
              .groups.map((g) => (g.id === updated.id ? updated : g))
          );
          if (desiredInGroup) {
            appActions.showToast(
              `已将「${node.name}」加入「${groupDisplayName}」`,
              "ok"
            );
          } else if (wasActiveNode) {
            appActions.showToast(
              `已将当前在用节点「${node.name}」移出「${groupDisplayName}」，多选组将自动切换至其它可用节点`,
              "info",
              3800
            );
          } else {
            appActions.showToast(
              `已将「${node.name}」移出「${groupDisplayName}」`,
              "info"
            );
          }
        }
      } catch (err) {
        const isLatestIntent =
          groupLatestIntentVersion.get(groupId) === nextVersion;
        if (isLatestIntent) {
          const rollbackMembers = groupConfirmedMembers.get(groupId) ?? baseMembers;
          appActions.syncGroups(
            appStore
              .getState()
              .groups.map((g) =>
                g.id === groupId ? { ...g, member_node_ids: [...rollbackMembers] } : g
              )
          );
          appActions.showToast(
            `${desiredInGroup ? "加入" : "移出"}「${groupDisplayName}」失败：${formatErrorMessage(err)}`,
            "warn"
          );
        }
      } finally {
        onSettled?.();
      }
    });

  const cleanupChain = task.finally(() => {
    if (groupSerialQueues.get(groupId) === cleanupChain) {
      groupSerialQueues.delete(groupId);
      groupConfirmedMembers.delete(groupId);
    }
  });
  groupSerialQueues.set(groupId, cleanupChain);
}

export interface GroupMembershipPopoverProps {
  node: ProxyNode;
  variant?: "icon" | "pill";
  formatGroupName?: (name: string) => string;
  className?: string;
}

export function GroupMembershipPopover({
  node,
  variant = "icon",
  formatGroupName = defaultFormatGroupName,
  className = "",
}: GroupMembershipPopoverProps): JSX.Element | null {
  const groups = useAppSelector((s) => s.groups);
  const runtime = useAppSelector((s) => s.runtime);
  const activeNav = useAppSelector((s) => s.activeNav);
  const workspaceTab = useAppSelector((s) => s.sessionDrafts.nodesWorkspace.tab);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const popoverId = useId();

  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const mountedRef = useRef(true);

  const [open, setOpen] = useState(false);
  const [popoverPos, setPopoverPos] = useState<PopoverPosition | null>(null);
  const [pendingGroupCounts, setPendingGroupCounts] = useState<
    Record<string, number>
  >({});
  const [confirmRemoveGroupId, setConfirmRemoveGroupId] = useState<string | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const joinedGroups = useMemo(
    () => groups.filter((g) => g.member_node_ids.includes(node.id)),
    [groups, node.id]
  );

  const joinedGroupIdSet = useMemo(
    () => new Set(joinedGroups.map((g) => g.id)),
    [joinedGroups]
  );

  const isTriggerHidden = useCallback((): boolean => {
    const trigger = triggerRef.current;
    if (!trigger || !trigger.isConnected) return true;
    if (trigger.offsetParent === null) return true;
    return !isAnchorVisibleInScrollHierarchy(trigger, TITLE_BAR_SAFE_TOP_PX);
  }, []);

  const computePosition = useCallback((): PopoverPosition | null => {
    const trigger = triggerRef.current;
    if (!trigger || !trigger.isConnected || typeof window === "undefined") return null;
    if (trigger.offsetParent === null) return null;

    // Close automatically when trigger hides or scrolls outside any clipping ancestor / under TitleBar
    if (!isAnchorVisibleInScrollHierarchy(trigger, TITLE_BAR_SAFE_TOP_PX)) {
      return null;
    }

    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    const width = Math.min(POPOVER_WIDTH, Math.max(196, vw - VIEWPORT_PADDING * 2));
    const estimatedHeight = Math.min(
      POPOVER_MAX_HEIGHT,
      Math.max(84, groups.length * 42 + 44)
    );

    const spaceBelow = Math.max(0, vh - rect.bottom - POPOVER_GAP - VIEWPORT_PADDING);
    const spaceAbove = Math.max(0, rect.top - POPOVER_GAP - TOP_PADDING);
    const shouldOpenUpward = spaceBelow < estimatedHeight && spaceAbove > spaceBelow;
    const maxViewportSpan = Math.max(72, vh - TOP_PADDING - VIEWPORT_PADDING);

    // Right-align to trigger button so row actions stay visually anchored
    let left = rect.right - width;
    if (left < VIEWPORT_PADDING) {
      left = VIEWPORT_PADDING;
    }
    if (left + width > vw - VIEWPORT_PADDING) {
      left = Math.max(VIEWPORT_PADDING, vw - VIEWPORT_PADDING - width);
    }

    if (shouldOpenUpward) {
      const maxHeight = Math.min(
        maxViewportSpan,
        Math.min(POPOVER_MAX_HEIGHT, Math.max(88, spaceAbove))
      );
      const rawBottom = vh - rect.top + POPOVER_GAP;
      const bottom = Math.max(
        VIEWPORT_PADDING,
        Math.min(rawBottom, vh - TOP_PADDING - maxHeight)
      );
      return {
        left,
        width,
        maxHeight,
        placement: "top",
        bottom,
      };
    }

    const maxHeight = Math.min(
      maxViewportSpan,
      Math.min(POPOVER_MAX_HEIGHT, Math.max(88, spaceBelow))
    );
    const rawTop = rect.bottom + POPOVER_GAP;
    const top = Math.max(
      TOP_PADDING,
      Math.min(rawTop, vh - VIEWPORT_PADDING - maxHeight)
    );
    return {
      left,
      width,
      maxHeight,
      placement: "bottom",
      top,
    };
  }, [groups.length]);

  const closePopover = useCallback((restoreFocus = false) => {
    setOpen(false);
    setConfirmRemoveGroupId(null);
    if (restoreFocus) {
      triggerRef.current?.focus();
    }
  }, []);

  const openPopover = useCallback(() => {
    const pos = computePosition();
    if (!pos) return;
    setPopoverPos(pos);
    setOpen(true);
  }, [computePosition]);

  // Close if all groups were deleted while open
  useEffect(() => {
    if (open && groups.length === 0) {
      setOpen(false);
    }
  }, [open, groups.length]);

  // Close when switching routes or workspace tabs hides the trigger element (e.g. CSS `hidden` keep-alive)
  useEffect(() => {
    if (!open) return;
    if (isTriggerHidden()) {
      setOpen(false);
    }
  }, [open, activeNav, workspaceTab, isTriggerHidden]);

  // Keep horizontal alignment clamped after actual render
  useLayoutEffect(() => {
    if (!open || !popoverPos || !popoverRef.current || typeof window === "undefined") {
      return;
    }
    const menuRect = popoverRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    if (menuRect.right > vw - VIEWPORT_PADDING) {
      const clampedLeft = Math.max(
        VIEWPORT_PADDING,
        vw - VIEWPORT_PADDING - menuRect.width
      );
      if (Math.abs(clampedLeft - popoverPos.left) > 1) {
        setPopoverPos((prev) => (prev ? { ...prev, left: clampedLeft } : prev));
      }
    }
  }, [open, popoverPos]);

  // Outside click, Escape, scroll/resize repositioning, visibility/tab hide & window blur close
  useEffect(() => {
    if (!open) return;

    if (isTriggerHidden()) {
      setOpen(false);
      return;
    }

    const handlePointerDown = (ev: MouseEvent) => {
      const target = ev.target as Node | null;
      if (!target) return;
      if (triggerRef.current?.contains(target)) return;
      if (popoverRef.current?.contains(target)) return;
      closePopover(false);
    };

    const handleKeyDown = (ev: globalThis.KeyboardEvent) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
        closePopover(true);
      }
    };

    const handleScrollOrResize = (ev: Event) => {
      if (ev.type === "scroll") {
        const target = ev.target as Node | null;
        if (target && popoverRef.current?.contains(target)) {
          return;
        }
      }
      if (isTriggerHidden()) {
        setOpen(false);
        return;
      }
      const nextPos = computePosition();
      if (!nextPos) {
        closePopover(false);
      } else {
        setPopoverPos(nextPos);
      }
    };

    const handleWindowBlur = () => {
      closePopover(false);
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState !== "visible" || isTriggerHidden()) {
        setOpen(false);
      }
    };

    const triggerEl = triggerRef.current;
    const resizeObserver =
      triggerEl && typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            if (isTriggerHidden()) {
              setOpen(false);
            }
          })
        : null;
    if (triggerEl && resizeObserver) {
      resizeObserver.observe(triggerEl);
    }

    const intersectionObserver =
      triggerEl && typeof IntersectionObserver !== "undefined"
        ? new IntersectionObserver((entries) => {
            const entry = entries[0];
            if (!entry || !entry.isIntersecting || isTriggerHidden()) {
              setOpen(false);
            }
          })
        : null;
    if (triggerEl && intersectionObserver) {
      intersectionObserver.observe(triggerEl);
    }

    document.addEventListener("mousedown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown, true);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("resize", handleScrollOrResize);
    window.addEventListener("scroll", handleScrollOrResize, true);
    window.addEventListener("blur", handleWindowBlur);
    return () => {
      resizeObserver?.disconnect();
      intersectionObserver?.disconnect();
      document.removeEventListener("mousedown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown, true);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("resize", handleScrollOrResize);
      window.removeEventListener("scroll", handleScrollOrResize, true);
      window.removeEventListener("blur", handleWindowBlur);
    };
  }, [closePopover, computePosition, isTriggerHidden, open]);

  if (groups.length === 0) {
    return null;
  }

  const joinedCount = joinedGroups.length;
  const isJoinedAny = joinedCount > 0;

  const triggerTitle = isJoinedAny
    ? `所属多选组（${joinedCount}）：${joinedGroups
        .map((g) => formatGroupName(g.name))
        .join("、")}（点击勾选或移出）`
    : `将「${node.name}」加入多选组（点击任选组别）`;

  const triggerAriaLabel = isJoinedAny
    ? `管理「${node.name}」所属多选组（已在 ${joinedCount} 个组）`
    : `将「${node.name}」加入多选组`;

  const stopRowBubble = (ev: ReactMouseEvent<HTMLElement>) => {
    ev.stopPropagation();
  };

  const commitToggleGroup = (group: MultiGroup, desiredInGroup: boolean) => {
    setConfirmRemoveGroupId(null);
    setPendingGroupCounts((prev) => ({
      ...prev,
      [group.id]: (prev[group.id] ?? 0) + 1,
    }));

    enqueueGroupMembershipToggle(
      group.id,
      node,
      desiredInGroup,
      formatGroupName,
      () => {
        if (!mountedRef.current) return;
        setPendingGroupCounts((prev) => {
          const nextCount = (prev[group.id] ?? 1) - 1;
          if (nextCount <= 0) {
            const copy = { ...prev };
            delete copy[group.id];
            return copy;
          }
          return { ...prev, [group.id]: nextCount };
        });
      }
    );
  };

  const handleToggleGroup = (group: MultiGroup) => {
    const currentlyJoined = joinedGroupIdSet.has(group.id);
    const desiredInGroup = !currentlyJoined;
    const isActiveNodeHere =
      currentlyJoined &&
      (group.active_node_id === node.id ||
        (runtime.route_mode !== "single" &&
          runtime.active_group_id === group.id &&
          runtime.active_node_id === node.id));

    if (!desiredInGroup && isActiveNodeHere) {
      setConfirmRemoveGroupId((prev) => (prev === group.id ? null : group.id));
      return;
    }

    commitToggleGroup(group, desiredInGroup);
  };

  return (
    <span
      className={`relative inline-flex shrink-0 ${variant === "icon" ? "pr-1 pt-1" : ""} ${className}`}
      onMouseDown={stopRowBubble}
      onClick={stopRowBubble}
    >
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? popoverId : undefined}
        aria-label={triggerAriaLabel}
        title={triggerTitle}
        onMouseDown={(ev) => {
          ev.stopPropagation();
        }}
        onClick={(ev) => {
          ev.stopPropagation();
          if (open) {
            closePopover(false);
          } else {
            openPopover();
          }
        }}
        className={
          variant === "pill"
            ? `inline-flex shrink-0 cursor-pointer items-center gap-1 whitespace-nowrap rounded-lg border px-2 py-1 text-[11px] font-medium transition-colors ${
                open
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)] ring-1 ring-[var(--accent)]/30"
                  : isJoinedAny
                    ? "border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)] hover:opacity-85"
                    : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
              }`
            : `relative inline-flex shrink-0 cursor-pointer items-center justify-center rounded-lg border p-1 transition-colors ${
                open
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)] ring-1 ring-[var(--accent)]/30"
                  : isJoinedAny
                    ? "border-[var(--green)]/50 bg-[var(--green-soft)] text-[var(--green)] hover:border-[var(--green)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
              }`
        }
      >
        {isJoinedAny ? (
          <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
        ) : (
          <Plus className="h-3 w-3 shrink-0" aria-hidden="true" />
        )}
        {variant === "pill" ? (
          <span>
            {joinedCount >= 2
              ? `已在 ${joinedCount} 组`
              : joinedCount === 1
                ? "已在组"
                : "加组"}
          </span>
        ) : (
          joinedCount >= 2 && (
            <span
              className="pointer-events-none absolute -right-1 -top-1 inline-flex h-3.5 min-w-[14px] items-center justify-center rounded-full bg-[var(--green)] px-1 cc-mono text-[9px] font-bold leading-none text-[var(--accent-ink)] shadow-xs"
              aria-hidden="true"
            >
              {joinedCount}
            </span>
          )
        )}
      </button>

      {open &&
        popoverPos &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            ref={popoverRef}
            id={popoverId}
            role="menu"
            aria-label={`选择「${node.name}」所属多选组`}
            onMouseDown={(ev) => {
              ev.stopPropagation();
            }}
            onClick={(ev) => {
              ev.stopPropagation();
            }}
            className="fixed z-[9999] flex flex-col overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] text-[var(--text)]"
            style={{
              left: `${popoverPos.left}px`,
              top: popoverPos.placement === "bottom" ? `${popoverPos.top}px` : undefined,
              bottom: popoverPos.placement === "top" ? `${popoverPos.bottom}px` : undefined,
              width: `${popoverPos.width}px`,
              maxHeight: `${popoverPos.maxHeight}px`,
              boxShadow: "var(--shadow-popover)",
            }}
          >
            {/* Compact Header */}
            <div className="flex items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-2.5 py-2">
              <div className="flex min-w-0 items-center gap-1.5">
                <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                <span className="truncate text-[11px] font-semibold text-[var(--text)]">
                  加入 / 移出多选组
                </span>
              </div>
              <span className="cc-mono shrink-0 rounded-full bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                {joinedCount}/{groups.length}
              </span>
            </div>

            {/* Group Checklist */}
            <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto overscroll-contain p-1">
              {groups.map((group) => {
                const checked = joinedGroupIdSet.has(group.id);
                const isRunningGroup =
                  runtime.route_mode !== "single" &&
                  runtime.active_group_id === group.id;
                const isActiveNodeHere =
                  checked &&
                  (group.active_node_id === node.id ||
                    (isRunningGroup && runtime.active_node_id === node.id));
                const isConfirmingRemove = checked && confirmRemoveGroupId === group.id;
                const isPending = (pendingGroupCounts[group.id] ?? 0) > 0;
                const displayName = formatGroupName(group.name);

                return (
                  <div key={group.id} className="space-y-1">
                    <button
                      type="button"
                      role="menuitemcheckbox"
                      aria-checked={checked}
                      onMouseDown={(ev) => {
                        ev.preventDefault();
                        ev.stopPropagation();
                      }}
                      onClick={(ev) => {
                        ev.stopPropagation();
                        handleToggleGroup(group);
                      }}
                      className={`flex w-full cursor-pointer items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-left text-xs transition-colors ${
                        checked
                          ? "bg-[var(--green-soft)]/70 text-[var(--text)] hover:bg-[var(--green-soft)]"
                          : "text-[var(--text)] hover:bg-[var(--card-hover)]"
                      }`}
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <span
                          className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                            checked
                              ? "border-[var(--green)] bg-[var(--green)] text-[var(--accent-ink)]"
                              : "border-[var(--line-strong)] bg-[var(--bg-elevated)]"
                          }`}
                          aria-hidden="true"
                        >
                          {checked && <Check className="h-3 w-3 stroke-[2.5]" />}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1">
                            <span
                              className={`truncate text-xs ${
                                checked ? "font-semibold text-[var(--text)]" : "font-medium"
                              }`}
                              title={displayName}
                            >
                              {displayName}
                            </span>
                            {isRunningGroup && (
                              <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--accent-soft)] px-1.5 py-0.2 text-[9.5px] font-semibold text-[var(--accent)]">
                                当前运行
                              </span>
                            )}
                          </div>
                          {isActiveNodeHere && (
                            <div className="mt-0.5 text-[10px] text-[var(--amber)]">
                              {dict.groups.activeRemoveConfirmTip}
                            </div>
                          )}
                        </div>
                      </div>

                      <span className="inline-flex shrink-0 items-center gap-1 cc-mono text-[10px] text-[var(--muted)]">
                        {isPending && (
                          <RefreshCw className="h-2.5 w-2.5 animate-spin text-[var(--accent)]" />
                        )}
                        <span>{group.member_node_ids.length} 节点</span>
                      </span>
                    </button>

                    {isConfirmingRemove && (
                      <div
                        className="rounded-lg border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-2.5 py-2 text-[10.5px]"
                        onMouseDown={(ev) => ev.stopPropagation()}
                        onClick={(ev) => ev.stopPropagation()}
                      >
                        <p className="leading-snug text-[var(--text)]">
                          {dict.groups.removeActiveProtectedHint}
                        </p>
                        <div className="mt-1.5 flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setConfirmRemoveGroupId(null);
                            }}
                            className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10px] font-medium text-[var(--text-secondary)] hover:text-[var(--text)]"
                          >
                            {dict.common.cancel}
                          </button>
                          <button
                            type="button"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              commitToggleGroup(group, false);
                            }}
                            className="rounded-md bg-[var(--amber)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)] hover:opacity-90"
                          >
                            {dict.common.confirm}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>,
          document.body
        )}
    </span>
  );
}
