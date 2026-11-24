import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";
import { isTauriEnv } from "../api/tauri";
import { useAppSelector } from "../store/appStore";
import { resolvePlatformOs } from "../utils/platform";
import { type PreAccelSummary, resolvePreAccelSummary } from "../utils/preaccelStatus";

function resolveModeBadge(
  status: string,
  proxyMode: string,
  preaccel: PreAccelSummary
): { label: string; dotColor: string } {
  if (!preaccel.proxyActive) {
    if (status === "error") {
      return { label: "核心异常", dotColor: "var(--red)" };
    }
    if (preaccel.realWinDivertActive) {
      return {
        label: "全局提速中",
        dotColor: status === "warn" ? "var(--amber)" : "var(--accent)",
      };
    }
    if (preaccel.enabled) {
      if (preaccel.installState === "downloading" || preaccel.installState === "verifying") {
        return { label: "准备提速组件…", dotColor: "var(--amber)" };
      }
      if (preaccel.installState === "need_elevation") {
        return { label: "提速需管理员", dotColor: "var(--amber)" };
      }
      return { label: "本地通道待命", dotColor: "var(--amber)" };
    }
    if (status === "warn") {
      return { label: "待认证", dotColor: "var(--amber)" };
    }
    return { label: "待命", dotColor: "var(--muted)" };
  }

  const dotColor =
    status === "error"
      ? "var(--red)"
      : status === "warn"
        ? "var(--amber)"
        : preaccel.enabled
          ? "var(--accent)"
          : "var(--green)";

  const modeLabel =
    proxyMode === "global" ? "全局" : proxyMode === "direct" ? "直连" : "规则";
  const label = preaccel.enabled
    ? preaccel.realWinDivertActive
      ? `${modeLabel} · 全局提速`
      : `${modeLabel} · 提速`
    : modeLabel;
  return { label, dotColor };
}

export function TitleBar() {
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const preAccelEnabledConfig = useAppSelector((s) => s.config.preaccel.enabled);
  const minimizeToTrayOnClose = useAppSelector(
    (s) => s.config?.behavior?.minimize_to_tray_on_close ?? true
  );
  const [maximized, setMaximized] = useState(false);
  const inTauri = isTauriEnv();
  const isMac = resolvePlatformOs(runtime.os_label) === "macos";

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

  const preaccelSummary = resolvePreAccelSummary(
    runtime,
    globalPreAccel,
    preAccelEnabledConfig
  );

  const badge = resolveModeBadge(runtime.status, runtime.proxy_mode, preaccelSummary);

  const closeButtonLabel = minimizeToTrayOnClose
    ? "关闭（最小化到托盘）"
    : "关闭并退出";

  return (
    <header className="cc-surface relative z-30 flex h-9 shrink-0 select-none items-center justify-between border-b border-[var(--line)]/60">
      {/* Left brand + compact mode badge + center drag region (macOS reserves 76px for native traffic lights) */}
      <div
        data-tauri-drag-region
        onDoubleClick={inTauri ? undefined : () => void handleToggleMaximize()}
        className={`flex h-full min-w-0 flex-1 items-center gap-2 pr-2 ${
          isMac ? "pl-[76px]" : "pl-3"
        }`}
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

      {/* Right native-style window controls (Windows / Linux only; macOS uses native left traffic lights) */}
      {!isMac && (
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
      )}
    </header>
  );
}
