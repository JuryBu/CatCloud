import { Check, Loader2, Maximize2, X, Zap } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { catcloudApi, formatErrorMessage } from "../api/tauri";
import { MascotSprite } from "../components/MascotSprite";
import {
  appActions,
  appStore,
  useAppSelector,
  useLatestTraffic,
} from "../store/appStore";

function resolveStatusAccent(status: string): { color: string; label: string } {
  switch (status) {
    case "error":
      return { color: "var(--red)", label: "核心异常" };
    case "warn":
      return { color: "var(--amber)", label: "路线存在波动" };
    case "preaccel":
      return { color: "var(--accent)", label: "国内提速运行中" };
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
  const groups = useAppSelector((s) => s.groups);
  const trayIconMode = useAppSelector((s) => s.config.personalization.tray_icon_mode);
  const traffic = useLatestTraffic();

  const [switching, setSwitching] = useState<boolean>(false);
  const [justSwitched, setJustSwitched] = useState<boolean>(false);
  const switchFeedbackTimerRef = useRef<number | null>(null);
  const mountedRef = useRef<boolean>(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (switchFeedbackTimerRef.current !== null) {
        window.clearTimeout(switchFeedbackTimerRef.current);
      }
    };
  }, []);

  const triggerSwitchedFeedback = () => {
    if (!mountedRef.current) return;
    setJustSwitched(true);
    if (switchFeedbackTimerRef.current !== null) {
      window.clearTimeout(switchFeedbackTimerRef.current);
    }
    switchFeedbackTimerRef.current = window.setTimeout(() => {
      switchFeedbackTimerRef.current = null;
      if (mountedRef.current) {
        setJustSwitched(false);
      }
    }, 1600);
  };

  const statusMeta = resolveStatusAccent(runtime.status);
  const isSingleMode = runtime.route_mode === "single";
  const displayNodeName =
    runtime.active_node_name?.trim() || runtime.active_group_name?.trim() || "待选节点";
  const displayGroupName = runtime.active_group_name?.trim() || "默认分组";

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

  const handleSwitchNextBest = async () => {
    if (switching) return;
    setSwitching(true);
    try {
      if (isSingleMode) {
        const res = await catcloudApi.switchNextBestNode("single");
        const latestRt = await catcloudApi.getRuntimeInfo().catch(() => null);
        if (latestRt) {
          appActions.syncRuntime(latestRt);
        } else {
          const curRt = appStore.getState().runtime;
          appActions.syncRuntime({
            ...curRt,
            route_mode: "single",
            active_node_id: res.active_node_id,
            active_node_name: res.active_node_name,
            active_node_region: res.active_node_region,
            active_node_latency_ms: res.latency_ms,
            active_node_up_mbps: res.up_mbps,
          });
        }
        appActions.showToast(`已切至 ${res.active_node_name}`, "ok");
        triggerSwitchedFeedback();
        return;
      }

      const groupId = runtime.active_group_id || groups[0]?.id || "";
      if (!groupId) {
        appActions.showToast("暂无可用分组，请先在主窗口创建", "warn");
        return;
      }
      const res = await catcloudApi.switchNextBestNode(groupId);
      const curState = appStore.getState();
      appActions.syncRuntime({
        ...curState.runtime,
        active_group_id: res.group_id,
        active_node_id: res.active_node_id,
        active_node_name: res.active_node_name,
        active_node_region: res.active_node_region,
        active_node_latency_ms: res.latency_ms,
        active_node_up_mbps: res.up_mbps,
      });
      appActions.syncGroups(
        curState.groups.map((g) =>
          g.id === res.group_id ? { ...g, active_node_id: res.active_node_id } : g
        )
      );
      appActions.showToast(
        `已切至 ${res.active_node_name}${res.closed_connections > 0 ? `（断 ${res.closed_connections} 旧连）` : ""}`,
        "ok"
      );
      triggerSwitchedFeedback();
    } catch (err) {
      appActions.showToast(`切下一优失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      if (mountedRef.current) {
        setSwitching(false);
      }
    }
  };

  const handleCloseCapsule = async () => {
    if (isTauri) {
      try {
        await catcloudApi.toggleCapsuleWindow();
      } catch (err) {
        appActions.showToast(`关闭悬浮小窗失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }
    appActions.showToast("已关闭悬浮小窗（预览已返回主窗）", "info");
    await appActions.showMainFromCapsule();
  };

  const routeSummaryTitle = isSingleMode
    ? `单节点模式 · ${displayNodeName}${runtime.active_node_latency_ms !== null ? ` (${Math.round(runtime.active_node_latency_ms)} ms)` : ""}`
    : `分组：${displayGroupName} · ${displayNodeName}${runtime.active_node_latency_ms !== null ? ` (${Math.round(runtime.active_node_latency_ms)} ms)` : ""}`;

  const capsulePill = (
    <div
      data-tauri-drag-region
      className="cc-glass flex h-[60px] w-[296px] select-none items-center gap-1.5 rounded-full border border-[var(--line-strong)] bg-[var(--surface)]/95 px-2 text-[var(--text)]"
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

      {/* Route mode badge, active node/group, live up/down rates & proxy/TUN indicators */}
      <div
        className="min-w-0 flex-1"
        data-tauri-drag-region
        title={routeSummaryTitle}
      >
        <div className="flex min-w-0 items-center gap-1" data-tauri-drag-region>
          <span
            className={`shrink-0 rounded px-1 py-[1px] text-[9px] font-medium leading-none border ${
              isSingleMode
                ? "border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--sky)]/40 bg-[var(--sky-soft)] text-[var(--sky)]"
            }`}
            title={isSingleMode ? "当前为单节点直选模式" : `当前多选组：${displayGroupName}`}
          >
            {isSingleMode ? "单节点" : "组"}
          </span>
          <span className="truncate text-[11px] font-semibold leading-tight text-[var(--text)]">
            {displayNodeName}
          </span>
        </div>

        <div className="mt-1 flex items-center justify-between gap-1 leading-none">
          <div className="cc-mono flex min-w-0 items-center gap-1 truncate text-[9px] whitespace-nowrap">
            <span className="text-[var(--coral)]">↑{formatCompactRate(traffic.up_bps)}</span>
            <span className="text-[var(--sky)]">↓{formatCompactRate(traffic.down_bps)}</span>
          </div>

          <div className="flex shrink-0 items-center gap-0.5">
            <span
              className={`whitespace-nowrap rounded border px-1 py-[1px] text-[8.5px] font-medium leading-none transition-colors ${
                runtime.system_proxy_enabled
                  ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[var(--muted)]/55"
              }`}
              title={runtime.system_proxy_enabled ? "系统代理：已开启" : "系统代理：未开启"}
            >
              代理
            </span>
            <span
              className={`whitespace-nowrap rounded border px-1 py-[1px] text-[8.5px] font-medium leading-none transition-colors ${
                runtime.tun_enabled
                  ? "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[var(--muted)]/55"
              }`}
              title={runtime.tun_enabled ? "虚拟网卡：已开启" : "虚拟网卡：未开启"}
            >
              虚拟网卡
            </span>
          </div>
        </div>
      </div>

      {/* Compact single-click action cluster */}
      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          disabled={switching}
          onClick={() => void handleSwitchNextBest()}
          className={`inline-flex h-[26px] w-[26px] items-center justify-center rounded-full border transition-colors disabled:opacity-60 ${
            justSwitched
              ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)]"
              : "border-[var(--line)] bg-[var(--card)] text-[var(--accent)] hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
          }`}
          title={switching ? "正在切换下一优节点..." : "切下一优节点"}
          aria-label="切下一优节点"
        >
          {switching ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : justSwitched ? (
            <Check className="h-3 w-3" />
          ) : (
            <Zap className="h-3 w-3" />
          )}
        </button>

        <button
          type="button"
          onClick={() => void appActions.showMainFromCapsule()}
          className="inline-flex h-[26px] w-[26px] items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
          title="展开主窗口"
          aria-label="展开主窗口"
        >
          <Maximize2 className="h-3 w-3" />
        </button>

        <button
          type="button"
          onClick={() => void handleCloseCapsule()}
          className="inline-flex h-[26px] w-[26px] items-center justify-center rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)]"
          title="关闭悬浮小窗"
          aria-label="关闭悬浮小窗"
        >
          <X className="h-3 w-3" />
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
          悬浮小窗预览（300 × 64 透明圆角窗）
        </div>
        <div className="mt-1 text-[11px] text-[var(--muted)]">
          状态：{statusMeta.label} · 模式：{isSingleMode ? "单节点" : `多选组（${displayGroupName}）`} · 系统代理：
          {runtime.system_proxy_enabled ? "开" : "关"} · 虚拟网卡：{runtime.tun_enabled ? "开" : "关"}
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
