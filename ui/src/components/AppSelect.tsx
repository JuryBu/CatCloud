import { Check, ChevronDown } from "lucide-react";
import {
  type JSX,
  type KeyboardEvent as ReactKeyboardEvent,
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

export interface AppSelectOption {
  value: string;
  label: string;
  disabled?: boolean;
  group?: string;
}

export interface AppSelectProps {
  value: string;
  onChange: (value: string) => void;
  options: AppSelectOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  buttonClassName?: string;
  menuClassName?: string;
  "aria-label"?: string;
  title?: string;
  size?: "xs" | "sm" | "md";
}

interface IndexedOption {
  option: AppSelectOption;
  flatIndex: number;
}

interface OptionSection {
  group: string | null;
  items: IndexedOption[];
}

interface MenuPosition {
  left: number;
  minWidth: number;
  maxWidth: number;
  maxHeight: number;
  placement: "bottom" | "top";
  top?: number;
  bottom?: number;
}

const MENU_MAX_HEIGHT = 280;
const MENU_GAP = 6;
const VIEWPORT_PADDING = 8;
const TOP_PADDING = 44; // Reserve clearance for 36px frameless TitleBar + 8px gap

function isModalBackdropTarget(trigger: HTMLElement | null, target: Node): boolean {
  if (!trigger || !(target instanceof HTMLElement)) return false;
  const dialog = trigger.closest<HTMLElement>('[role="dialog"], [aria-modal="true"]');
  if (!dialog) return false;
  // Backdrop either wraps the dialog (`target.contains(dialog)`) or carries `role="dialog"` itself (`target === dialog`)
  return target === dialog || target.contains(dialog);
}

const SIZE_CLASSES: Record<NonNullable<AppSelectProps["size"]>, string> = {
  xs: "h-7 rounded-lg px-2 text-[11px]",
  sm: "h-8 rounded-xl px-2.5 text-xs",
  md: "h-9 rounded-xl px-3 text-xs",
};

const ITEM_SIZE_CLASSES: Record<NonNullable<AppSelectProps["size"]>, string> = {
  xs: "px-2 py-1 text-[11px]",
  sm: "px-2.5 py-1.5 text-xs",
  md: "px-2.5 py-1.5 text-xs",
};

export function AppSelect({
  value,
  onChange,
  options,
  placeholder = "请选择",
  disabled = false,
  className = "",
  buttonClassName = "",
  menuClassName = "",
  "aria-label": ariaLabel,
  title,
  size = "sm",
}: AppSelectProps): JSX.Element {
  const listboxId = useId();
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const backdropClickSuppressCleanupRef = useRef<(() => void) | null>(null);

  const [open, setOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState<number>(-1);
  const [menuPos, setMenuPos] = useState<MenuPosition | null>(null);

  // Organize options by group while preserving first-appearance ordering.
  const { sections, flatOptions } = useMemo(() => {
    const builtSections: OptionSection[] = [];
    const groupSectionMap = new Map<string, OptionSection>();
    const ordered: AppSelectOption[] = [];

    for (const opt of options) {
      const groupName = opt.group?.trim() ? opt.group.trim() : null;
      if (groupName === null) {
        const prev = builtSections[builtSections.length - 1];
        if (prev && prev.group === null) {
          prev.items.push({ option: opt, flatIndex: -1 });
        } else {
          builtSections.push({ group: null, items: [{ option: opt, flatIndex: -1 }] });
        }
      } else {
        let section = groupSectionMap.get(groupName);
        if (!section) {
          section = { group: groupName, items: [] };
          groupSectionMap.set(groupName, section);
          builtSections.push(section);
        }
        section.items.push({ option: opt, flatIndex: -1 });
      }
    }

    let cursor = 0;
    for (const section of builtSections) {
      for (const entry of section.items) {
        entry.flatIndex = cursor;
        ordered.push(entry.option);
        cursor += 1;
      }
    }

    return { sections: builtSections, flatOptions: ordered };
  }, [options]);

  const selectedIndex = useMemo(
    () => flatOptions.findIndex((o) => o.value === value),
    [flatOptions, value]
  );
  const selectedOption = selectedIndex >= 0 ? flatOptions[selectedIndex] : null;

  const findNextEnabledIndex = useCallback(
    (start: number, step: 1 | -1): number => {
      const len = flatOptions.length;
      if (len === 0) return -1;
      for (let offset = 1; offset <= len; offset++) {
        const idx = (start + step * offset + len) % len;
        if (!flatOptions[idx].disabled) {
          return idx;
        }
      }
      return -1;
    },
    [flatOptions]
  );

  const findFirstEnabledIndex = useCallback((): number => {
    return flatOptions.findIndex((o) => !o.disabled);
  }, [flatOptions]);

  const findLastEnabledIndex = useCallback((): number => {
    for (let i = flatOptions.length - 1; i >= 0; i--) {
      if (!flatOptions[i].disabled) return i;
    }
    return -1;
  }, [flatOptions]);

  const computeMenuPosition = useCallback((): MenuPosition | null => {
    const trigger = triggerRef.current;
    if (!trigger || typeof window === "undefined") return null;

    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    // Close if trigger scrolled completely outside the viewport
    if (rect.bottom < 0 || rect.top > vh || rect.right < 0 || rect.left > vw) {
      return null;
    }

    const groupHeaderCount = sections.reduce(
      (acc, sec) => acc + (sec.group ? 1 : 0),
      0
    );
    const estimatedHeight = Math.min(
      MENU_MAX_HEIGHT,
      Math.max(44, flatOptions.length * 32 + groupHeaderCount * 26 + 12)
    );

    const spaceBelow = Math.max(0, vh - rect.bottom - MENU_GAP - VIEWPORT_PADDING);
    const spaceAbove = Math.max(0, rect.top - MENU_GAP - TOP_PADDING);
    const shouldOpenUpward = spaceBelow < estimatedHeight && spaceAbove > spaceBelow;
    const maxViewportSpan = Math.max(44, vh - TOP_PADDING - VIEWPORT_PADDING);

    const minWidth = Math.min(Math.max(rect.width, 132), vw - VIEWPORT_PADDING * 2);
    const maxWidth = Math.max(minWidth, Math.min(380, vw - VIEWPORT_PADDING * 2));
    let left = rect.left;
    if (left + minWidth > vw - VIEWPORT_PADDING) {
      left = Math.max(VIEWPORT_PADDING, rect.right - minWidth);
    }
    if (left < VIEWPORT_PADDING) {
      left = VIEWPORT_PADDING;
    }

    if (shouldOpenUpward) {
      const maxHeight = Math.min(
        maxViewportSpan,
        Math.min(MENU_MAX_HEIGHT, Math.max(88, spaceAbove))
      );
      const rawBottom = vh - rect.top + MENU_GAP;
      const bottom = Math.max(
        VIEWPORT_PADDING,
        Math.min(rawBottom, vh - TOP_PADDING - maxHeight)
      );
      return {
        left,
        minWidth,
        maxWidth,
        maxHeight,
        placement: "top",
        bottom,
      };
    }

    const maxHeight = Math.min(
      maxViewportSpan,
      Math.min(MENU_MAX_HEIGHT, Math.max(88, spaceBelow))
    );
    const rawTop = rect.bottom + MENU_GAP;
    const top = Math.max(
      TOP_PADDING,
      Math.min(rawTop, vh - VIEWPORT_PADDING - maxHeight)
    );
    return {
      left,
      minWidth,
      maxWidth,
      maxHeight,
      placement: "bottom",
      top,
    };
  }, [flatOptions.length, sections]);

  const closeMenu = useCallback((restoreFocus = false) => {
    setOpen(false);
    setHighlightedIndex(-1);
    if (restoreFocus) {
      triggerRef.current?.focus();
    }
  }, []);

  const openMenu = useCallback(
    (initialHighlight?: number) => {
      if (disabled) return;
      const pos = computeMenuPosition();
      if (!pos) return;
      setMenuPos(pos);
      const nextHighlight =
        initialHighlight !== undefined &&
        initialHighlight >= 0 &&
        initialHighlight < flatOptions.length &&
        !flatOptions[initialHighlight].disabled
          ? initialHighlight
          : selectedIndex >= 0 && !flatOptions[selectedIndex]?.disabled
            ? selectedIndex
            : findFirstEnabledIndex();
      setHighlightedIndex(nextHighlight);
      setOpen(true);
    },
    [computeMenuPosition, disabled, findFirstEnabledIndex, flatOptions, selectedIndex]
  );

  const commitSelection = useCallback(
    (opt: AppSelectOption) => {
      if (opt.disabled) return;
      if (opt.value !== value) {
        onChange(opt.value);
      }
      closeMenu(true);
    },
    [closeMenu, onChange, value]
  );

  // Close automatically if component becomes disabled
  useEffect(() => {
    if (disabled && open) {
      setOpen(false);
      setHighlightedIndex(-1);
    }
  }, [disabled, open]);

  // Reposition horizontally if actual rendered menu width overflows right edge
  useLayoutEffect(() => {
    if (!open || !menuPos || !menuRef.current || typeof window === "undefined") return;
    const menuRect = menuRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    if (menuRect.right > vw - VIEWPORT_PADDING) {
      const triggerRect = triggerRef.current?.getBoundingClientRect();
      const alignedLeft = triggerRect
        ? Math.max(VIEWPORT_PADDING, triggerRect.right - menuRect.width)
        : Math.max(VIEWPORT_PADDING, vw - VIEWPORT_PADDING - menuRect.width);
      if (Math.abs(alignedLeft - menuPos.left) > 1) {
        setMenuPos((prev) => (prev ? { ...prev, left: alignedLeft } : prev));
      }
    }
  }, [open, menuPos]);

  // Keep highlighted option scrolled into view
  useEffect(() => {
    if (!open || highlightedIndex < 0) return;
    const el = optionRefs.current[highlightedIndex];
    if (el) {
      el.scrollIntoView({ block: "nearest" });
    }
  }, [open, highlightedIndex]);

  // Clean up any one-shot backdrop click suppressor on unmount
  useEffect(() => {
    return () => {
      backdropClickSuppressCleanupRef.current?.();
      backdropClickSuppressCleanupRef.current = null;
    };
  }, []);

  // Outside click, Escape, scroll, resize & window blur tracking while open
  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (ev: MouseEvent) => {
      const target = ev.target as Node | null;
      if (!target) return;
      if (triggerRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;

      if (isModalBackdropTarget(triggerRef.current, target)) {
        backdropClickSuppressCleanupRef.current?.();
        let releaseTimer: number | null = null;
        const cleanup = () => {
          if (releaseTimer !== null) {
            window.clearTimeout(releaseTimer);
            releaseTimer = null;
          }
          document.removeEventListener("click", suppressNextClick, true);
          document.removeEventListener("mouseup", scheduleCleanupAfterMouseUp, true);
          if (backdropClickSuppressCleanupRef.current === cleanup) {
            backdropClickSuppressCleanupRef.current = null;
          }
        };
        const suppressNextClick = (clickEv: MouseEvent) => {
          cleanup();
          const clickTarget = clickEv.target as Node | null;
          if (
            clickTarget &&
            (clickTarget === target ||
              (target instanceof HTMLElement && target.contains(clickTarget)))
          ) {
            clickEv.preventDefault();
            clickEv.stopPropagation();
          }
        };
        const scheduleCleanupAfterMouseUp = () => {
          if (releaseTimer !== null) {
            window.clearTimeout(releaseTimer);
          }
          releaseTimer = window.setTimeout(() => {
            cleanup();
          }, 0);
        };
        backdropClickSuppressCleanupRef.current = cleanup;
        document.addEventListener("click", suppressNextClick, true);
        document.addEventListener("mouseup", scheduleCleanupAfterMouseUp, true);
      }

      closeMenu(false);
    };

    const handleKeyDown = (ev: globalThis.KeyboardEvent) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
        closeMenu(true);
      }
    };

    const handleScrollOrResize = (ev: Event) => {
      if (ev.type === "scroll") {
        const target = ev.target as Node | null;
        if (target && menuRef.current?.contains(target)) {
          return;
        }
      }
      const nextPos = computeMenuPosition();
      if (!nextPos) {
        closeMenu(false);
      } else {
        setMenuPos(nextPos);
      }
    };

    const handleWindowBlur = () => {
      closeMenu(false);
    };

    document.addEventListener("mousedown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown, true);
    window.addEventListener("resize", handleScrollOrResize);
    window.addEventListener("scroll", handleScrollOrResize, true);
    window.addEventListener("blur", handleWindowBlur);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown, true);
      window.removeEventListener("resize", handleScrollOrResize);
      window.removeEventListener("scroll", handleScrollOrResize, true);
      window.removeEventListener("blur", handleWindowBlur);
    };
  }, [closeMenu, computeMenuPosition, open]);

  const handleTriggerKeyDown = (ev: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;

    if (!open) {
      if (ev.key === "ArrowDown" || ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        ev.stopPropagation();
        openMenu();
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        ev.stopPropagation();
        openMenu(selectedIndex >= 0 ? selectedIndex : findLastEnabledIndex());
      }
      return;
    }

    switch (ev.key) {
      case "ArrowDown": {
        ev.preventDefault();
        ev.stopPropagation();
        const base = highlightedIndex >= 0 ? highlightedIndex : selectedIndex;
        setHighlightedIndex(findNextEnabledIndex(base, 1));
        break;
      }
      case "ArrowUp": {
        ev.preventDefault();
        ev.stopPropagation();
        const base = highlightedIndex >= 0 ? highlightedIndex : selectedIndex;
        setHighlightedIndex(findNextEnabledIndex(base < 0 ? 0 : base, -1));
        break;
      }
      case "Home": {
        ev.preventDefault();
        ev.stopPropagation();
        setHighlightedIndex(findFirstEnabledIndex());
        break;
      }
      case "End": {
        ev.preventDefault();
        ev.stopPropagation();
        setHighlightedIndex(findLastEnabledIndex());
        break;
      }
      case "Enter":
      case " ": {
        ev.preventDefault();
        ev.stopPropagation();
        if (highlightedIndex >= 0 && highlightedIndex < flatOptions.length) {
          commitSelection(flatOptions[highlightedIndex]);
        } else {
          closeMenu(true);
        }
        break;
      }
      case "Tab": {
        closeMenu(false);
        break;
      }
      case "Escape": {
        ev.preventDefault();
        ev.stopPropagation();
        closeMenu(true);
        break;
      }
    }
  };

  const displayText = selectedOption ? selectedOption.label : placeholder;
  const isPlaceholder = !selectedOption;

  optionRefs.current.length = flatOptions.length;

  return (
    <div className={`inline-flex min-w-0 max-w-full ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        disabled={disabled}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listboxId : undefined}
        aria-label={ariaLabel}
        title={title ?? (selectedOption ? selectedOption.label : undefined)}
        onClick={() => {
          if (open) {
            closeMenu(false);
          } else {
            openMenu();
          }
        }}
        onKeyDown={handleTriggerKeyDown}
        className={`inline-flex w-full min-w-0 cursor-pointer items-center justify-between gap-2 border bg-[var(--bg-elevated)] font-medium text-[var(--text)] outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-55 ${
          SIZE_CLASSES[size]
        } ${
          open
            ? "border-[var(--accent)] ring-1 ring-[var(--accent)]/35"
            : "border-[var(--line)] hover:border-[var(--line-strong)] focus-visible:border-[var(--accent)]"
        } ${buttonClassName}`}
      >
        <span
          className={`min-w-0 flex-1 truncate text-left ${
            isPlaceholder ? "text-[var(--muted)]" : ""
          }`}
        >
          {displayText}
        </span>
        <ChevronDown
          className={`h-3.5 w-3.5 shrink-0 text-[var(--muted)] transition-transform ${
            open ? "rotate-180 text-[var(--accent)]" : ""
          }`}
          aria-hidden="true"
        />
      </button>

      {open &&
        menuPos &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            ref={menuRef}
            id={listboxId}
            role="listbox"
            aria-label={ariaLabel ?? "下拉选项"}
            className={`fixed z-[9999] overflow-y-auto overscroll-contain rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] p-1 text-[var(--text)] ${menuClassName}`}
            style={{
              left: `${menuPos.left}px`,
              top: menuPos.placement === "bottom" ? `${menuPos.top}px` : undefined,
              bottom: menuPos.placement === "top" ? `${menuPos.bottom}px` : undefined,
              minWidth: `${menuPos.minWidth}px`,
              maxWidth: `${menuPos.maxWidth}px`,
              maxHeight: `${menuPos.maxHeight}px`,
              boxShadow: "var(--shadow-popover)",
            }}
          >
            {flatOptions.length === 0 ? (
              <div className="px-2.5 py-2 text-center text-xs text-[var(--muted)]">
                暂无可选项
              </div>
            ) : (
              sections.map((section, sectionIdx) => (
                <div
                  key={section.group ?? `ungrouped-${sectionIdx}`}
                  role={section.group ? "group" : undefined}
                  aria-label={section.group ?? undefined}
                >
                  {section.group && (
                    <div
                      className={`select-none px-2.5 pb-1 pt-1.5 text-[10px] font-semibold tracking-wide text-[var(--muted)] ${
                        sectionIdx > 0 ? "mt-1 border-t border-[var(--line)]/70 pt-2" : ""
                      }`}
                    >
                      {section.group}
                    </div>
                  )}
                  {section.items.map(({ option, flatIndex }) => {
                    const isSelected = option.value === value;
                    const isHighlighted = flatIndex === highlightedIndex;
                    return (
                      <button
                        key={`${option.value}-${flatIndex}`}
                        ref={(el) => {
                          optionRefs.current[flatIndex] = el;
                        }}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        disabled={option.disabled}
                        onMouseDown={(ev) => {
                          // Prevent focus stealing from combobox trigger
                          ev.preventDefault();
                        }}
                        onMouseEnter={() => {
                          if (!option.disabled) {
                            setHighlightedIndex(flatIndex);
                          }
                        }}
                        onClick={() => commitSelection(option)}
                        className={`flex w-full items-center justify-between gap-2 rounded-lg text-left transition-colors ${
                          ITEM_SIZE_CLASSES[size]
                        } ${
                          option.disabled
                            ? "cursor-not-allowed text-[var(--muted)] opacity-45"
                            : isSelected
                              ? "bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                              : isHighlighted
                                ? "bg-[var(--card-hover)] text-[var(--text)]"
                                : "text-[var(--text)] hover:bg-[var(--card-hover)]"
                        }`}
                      >
                        <span className="min-w-0 flex-1 truncate">{option.label}</span>
                        {isSelected && (
                          <Check
                            className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]"
                            aria-hidden="true"
                          />
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>,
          document.body
        )}
    </div>
  );
}
