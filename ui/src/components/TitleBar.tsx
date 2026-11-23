import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";
import { isTauriEnv } from "../api/tauri";
import { useAppSelector } from "../store/appStore";

function resolveModeBadge(
  running: boolean,
  status: string,
  proxyMode: string,
  preaccelActive: boolean
): { label: string; dotColor: string } {
  const dotColor =
    status === "error"
      ? "var(--red)"
      : status === "warn"
        ? "var(--amber)"
        : status === "preaccel"
          ? "var(--accent)"
          : running
            ? "var(--green)"
            : "var(--muted)";

  if (!running && status === "idle") {
    return { label: "待命", dotColor };
  }

  const modeLabel =
    proxyMode === "global" ? "全局" : proxyMode === "direct" ? "直连" : "规则";
  const label = preaccelActive ? `${modeLabel} · 提速` : modeLabel;
  return { label, dotColor };
}

export function TitleBar() {
  const runtime = useAppSelector((s) => s.runtime);
  const minimizeToTrayOnClose = useAppSelector(
    (s) => s.config?.behavior?.minimize_to_tray_on_close ?? true
  );
  const [maximized, setMaximized] = useState(false);
  const inTauri = isTauriEnv();

  useEffect(() => {
    if (!isTauriEnv()) return;
    let disposed = false;
    let unlistenResize: (() => void) | null = null;
    const win = getCurrentWindow();

    const syncMaximized = async () => {
      try {
        const next = await win.isMaximized();
        if (!disposed) {
          setMaximized(next);
        }
      } catch {
        /* ignore transient window query errors */
      }
    };

    void syncMaximized();
    void win
      .onResized(() => {
        void syncMaximized();
      })
      .then((unlisten) => {
        if (disposed) {
          unlisten();
        } else {
          unlistenResize = unlisten;
        }
      })
      .catch(() => {
        /* fallback to DOM resize listener */
      });

    const handleDomResize = () => {
      void syncMaximized();
    };
    window.addEventListener("resize", handleDomResize);

    return () => {
      disposed = true;
      unlistenResize?.();
      window.removeEventListener("resize", handleDomResize);
    };
  }, []);

  const handleMinimize = async () => {
    if (!isTauriEnv()) return;
    try {
      await getCurrentWindow().minimize();
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const handleToggleMaximize = async () => {
    if (!isTauriEnv()) {
      setMaximized((prev) => !prev);
      return;
    }
    try {
      const win = getCurrentWindow();
      await win.toggleMaximize();
      const next = await win.isMaximized();
      setMaximized(next);
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const handleClose = async () => {
    if (!isTauriEnv()) return;
    try {
      await getCurrentWindow().close();
    } catch {
      /* gracefully ignore in non-native or restricted environments */
    }
  };

  const badge = resolveModeBadge(
    runtime.running,
    runtime.status,
    runtime.proxy_mode,
    runtime.preaccel_active
  );

  const closeButtonLabel = minimizeToTrayOnClose
    ? "关闭（最小化到托盘）"
    : "关闭并退出";

  return (
    <header className="cc-surface relative z-30 flex h-9 shrink-0 select-none items-center justify-between border-b border-[var(--line)]/60">
      {/* Left brand + compact mode badge + center drag region */}
      <div
        data-tauri-drag-region
        onDoubleClick={inTauri ? undefined : () => void handleToggleMaximize()}
        className="flex h-full min-w-0 flex-1 items-center gap-2 pl-3 pr-2"
      >
        <img
          src="./icons/icon_a_cream_cat.png"
          alt="猫猫云梯"
          className="pointer-events-none h-[18px] w-[18px] shrink-0 rounded-[5px] object-cover ring-1 ring-[var(--line)]"
          draggable={false}
        />

        <span className="pointer-events-none truncate text-xs font-semibold tracking-tight text-[var(--text)]">
          猫猫云梯
          <span className="ml-1 font-normal text-[var(--muted)]">· CatCloud</span>
        </span>

        <span className="pointer-events-none inline-flex shrink-0 items-center gap-1 rounded-full border border-[var(--line)]/80 bg-[var(--card)]/85 px-2 py-0.5 text-[10px] font-medium leading-none text-[var(--text-secondary)]">
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{ backgroundColor: badge.dotColor }}
            aria-hidden="true"
          />
          <span>{badge.label}</span>
        </span>
      </div>

      {/* Right native-style window controls (never marked as drag region) */}
      <div className="flex h-full shrink-0 items-center">
        <button
          type="button"
          onClick={() => void handleMinimize()}
          className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--card-hover)] hover:text-[var(--text)]"
          aria-label="最小化窗口"
          title="最小化"
        >
          <Minus className="h-3.5 w-3.5" />
        </button>

        <button
          type="button"
          onClick={() => void handleToggleMaximize()}
          className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--card-hover)] hover:text-[var(--text)]"
          aria-label={maximized ? "还原窗口" : "最大化窗口"}
          title={maximized ? "还原" : "最大化"}
        >
          {maximized ? <Copy className="h-3 w-3" /> : <Square className="h-3 w-3" />}
        </button>

        <button
          type="button"
          onClick={() => void handleClose()}
          className="inline-flex h-9 w-11 cursor-pointer items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[#e5534b]/90 hover:text-white"
          aria-label={closeButtonLabel}
          title={closeButtonLabel}
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </header>
  );
}
