import { Maximize2, Minimize2, Zap } from "lucide-react";
import { catcloudApi, formatErrorMessage } from "../api/tauri";
import { MascotSprite } from "../components/MascotSprite";
import {
  appActions,
  useAppSelector,
  useLatestTraffic,
} from "../store/appStore";

function resolveStatusAccent(status: string): { color: string; label: string } {
  switch (status) {
    case "error":
      return { color: "var(--red)", label: "核心异常" };
    case "warn":
      return { color: "var(--amber)", label: "节点降级预警" };
    case "preaccel":
      return { color: "var(--accent)", label: "国内预加速双活运行" };
    case "ok":
      return { color: "var(--green)", label: "代理运行正常" };
    default:
      return { color: "var(--muted)", label: "待机中" };
  }
}

function formatCompactRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "0B/s";
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)}B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb < 100 ? kb.toFixed(1) : Math.round(kb)}K/s`;
  const mb = kb / 1024;
  return `${mb < 10 ? mb.toFixed(2) : mb.toFixed(1)}M/s`;
}

export function CapsuleWindow() {
  const isTauri = useAppSelector((s) => s.isTauri);
  const runtime = useAppSelector((s) => s.runtime);
  const trayIconMode = useAppSelector((s) => s.config.personalization.tray_icon_mode);
  const traffic = useLatestTraffic();

  const statusMeta = resolveStatusAccent(runtime.status);

  const useStarryIcon =
    trayIconMode === "always_c" ||
    (trayIconMode === "auto_ac" &&
      (runtime.status === "preaccel" ||
        runtime.status === "warn" ||
        runtime.status === "error"));

  const usePixelIcon = trayIconMode === "always_pixel";
  const iconSrc = useStarryIcon
    ? "./icons/icon_c_starry_neko.png"
    : "./icons/icon_a_cream_cat.png";

  const handleCloseToWindowless = async () => {
    if (isTauri) {
      try {
        await catcloudApi.enterWindowlessMode();
      } catch (err) {
        appActions.showToast(`进入无窗模式失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }
    appActions.showToast("已关闭悬浮胶囊并切换至纯无窗省内存模式（预览已返回主窗）", "info");
    await appActions.showMainFromCapsule();
  };

  const capsulePill = (
    <div
      data-tauri-drag-region
      className="flex h-[60px] w-[296px] select-none items-center gap-2 rounded-full border border-[var(--line-strong)] bg-[var(--surface)]/95 px-2.5 text-[var(--text)]"
      style={{ boxShadow: "var(--shadow-popover)" }}
    >
      {/* A / C / Pixel status badge with semantic status dot */}
      <div
        className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)]"
        data-tauri-drag-region
        title={`${statusMeta.label}${runtime.preaccel_relay_name && runtime.preaccel_active ? ` · ${runtime.preaccel_relay_name}` : ""}`}
      >
        {usePixelIcon ? (
          <MascotSprite
            state="idle"
            scale={1}
            animationsEnabled={false}
            title={statusMeta.label}
          />
        ) : (
          <img
            src={iconSrc}
            alt={useStarryIcon ? "CatCloud 午夜星云状态" : "CatCloud 奶油云朵状态"}
            className="h-9 w-9 rounded-full object-cover"
            draggable={false}
          />
        )}
        <span
          className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-[var(--surface)]"
          style={{ backgroundColor: statusMeta.color }}
        />
      </div>

      {/* Active node & live up/down rates */}
      <div
        className="min-w-0 flex-1"
        data-tauri-drag-region
        title={`${runtime.active_group_name} · ${runtime.active_node_name}${runtime.active_node_latency_ms !== null ? ` (${runtime.active_node_latency_ms} ms)` : ""}`}
      >
        <div className="flex items-center gap-1">
          <span className="truncate text-[11px] font-semibold leading-tight text-[var(--text)]">
            {runtime.active_node_name}
          </span>
        </div>
        <div className="mt-1 flex items-center gap-2 cc-mono text-[10px] leading-none whitespace-nowrap">
          <span className="text-[var(--coral)]">↑{formatCompactRate(traffic.up_bps)}</span>
          <span className="text-[var(--sky)]">↓{formatCompactRate(traffic.down_bps)}</span>
        </div>
      </div>

      {/* Compact single-click action cluster */}
      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          onClick={() => void appActions.switchNextBestNode()}
          className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--accent)] hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
          title="一键秒切下一优节点"
          aria-label="一键秒切下一优节点"
        >
          <Zap className="h-3.5 w-3.5" />
        </button>

        <button
          type="button"
          onClick={() => void appActions.showMainFromCapsule()}
          className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
          title="展开主窗口"
          aria-label="展开主窗口"
        >
          <Maximize2 className="h-3 w-3" />
        </button>

        <button
          type="button"
          onClick={() => void handleCloseToWindowless()}
          className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)]"
          title="关闭胶囊进入纯无窗省内存模式"
          aria-label="关闭胶囊进入纯无窗省内存模式"
        >
          <Minimize2 className="h-3 w-3" />
        </button>
      </div>
    </div>
  );

  if (isTauri) {
    return (
      <div className="flex h-[64px] w-[300px] items-center justify-center overflow-hidden bg-transparent p-[2px]">
        {capsulePill}
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[var(--bg)] p-6">
      <div className="text-center">
        <div className="text-xs font-semibold text-[var(--text)]">
          悬浮胶囊微窗预览（300 × 64 透明圆角窗）
        </div>
        <div className="mt-1 text-[11px] text-[var(--muted)]">
          当前状态：{statusMeta.label} · 图标策略：{trayIconMode}
        </div>
      </div>

      <div className="flex h-[64px] w-[300px] items-center justify-center rounded-full border border-dashed border-[var(--line)] bg-transparent p-[2px]">
        {capsulePill}
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => void appActions.showMainFromCapsule()}
          className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
        >
          返回主窗口视图
        </button>
      </div>
    </div>
  );
}
