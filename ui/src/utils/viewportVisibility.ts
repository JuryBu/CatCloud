/**
 * Viewport & ancestor scroll-container visibility helper for Portal popovers
 * (`AppSelect`, `GroupMembershipPopover`, Home quick-pick, etc.).
 *
 * Computes the effective visible intersection of the viewport (below the 36px
 * frameless `TitleBar`) and every scrolling/clipping ancestor container, so
 * floating portals automatically close when their anchor scrolls out of view
 * horizontally or vertically (e.g., behind the left Sidebar or top TitleBar).
 */

export const TITLE_BAR_SAFE_TOP_PX = 36;

export interface VisibleBounds {
  top: number;
  right: number;
  bottom: number;
  left: number;
}

export function getClippedVisibleBounds(
  anchor: HTMLElement,
  safeTopPx: number = TITLE_BAR_SAFE_TOP_PX,
): VisibleBounds {
  let top = safeTopPx;
  let left = 0;
  let right = window.innerWidth;
  let bottom = window.innerHeight;

  let parent = anchor.parentElement;
  while (parent && parent !== document.body && parent !== document.documentElement) {
    const style = window.getComputedStyle(parent);
    const ox = style.overflowX;
    const oy = style.overflowY;
    const clipsX = ox === "auto" || ox === "scroll" || ox === "hidden" || ox === "clip";
    const clipsY = oy === "auto" || oy === "scroll" || oy === "hidden" || oy === "clip";
    if (clipsX || clipsY) {
      const pr = parent.getBoundingClientRect();
      if (clipsX) {
        left = Math.max(left, pr.left);
        right = Math.min(right, pr.right);
      }
      if (clipsY) {
        top = Math.max(top, pr.top);
        bottom = Math.min(bottom, pr.bottom);
      }
    }
    parent = parent.parentElement;
  }

  return { top, right, bottom, left };
}

/**
 * Returns `true` when the anchor element's center point lies inside the
 * visible intersection bounds and the anchor has not slid under the TitleBar.
 */
export function isAnchorVisibleInScrollHierarchy(
  anchor: HTMLElement | null,
  safeTopPx: number = TITLE_BAR_SAFE_TOP_PX,
): boolean {
  if (!anchor || !anchor.isConnected) return false;
  const rect = anchor.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return false;
  if (rect.bottom <= safeTopPx || rect.top >= window.innerHeight) return false;

  const bounds = getClippedVisibleBounds(anchor, safeTopPx);
  if (bounds.right <= bounds.left || bounds.bottom <= bounds.top) return false;

  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;
  return (
    centerX >= bounds.left &&
    centerX <= bounds.right &&
    centerY >= bounds.top &&
    centerY <= bounds.bottom
  );
}
