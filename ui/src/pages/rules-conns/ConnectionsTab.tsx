import {
  ChevronLeft,
  ChevronRight,
  Filter,
  Pause,
  Play,
  RefreshCw,
  Search,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type MultiGroup,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { AppSelect, type AppSelectOption } from "../../components/AppSelect";
import { formatBytes, formatRate } from "../../components/TrafficSparkline";
import { appActions, appStore, useAppSelector } from "../../store/appStore";
import { isBoolPref, usePersistedState } from "../../utils/uiPrefs";
import {
  CONNECTIONS_PAGE_SIZE,
  CONN_SORT_VALIDATOR,
  type ConnSortKey,
  type ConnTrafficSnap,
  type ConnectionBreakdown,
  type LiveConnection,
  computeConnectionBreakdown,
  formatConnectionRuleLabel,
  formatDuration,
  formatRuleTargetLabel,
  mapDtoConnection,
  matchesPreAccelChain,
} from "./rulesCodec";

let pausedConnectionsSnapshot: LiveConnection[] | null = null;

interface ConnectionRowProps {
  conn: LiveConnection;
  preAccelEnabled: boolean;
  nowTick: number;
  onCloseSingle: (conn: LiveConnection) => void;
}

const ConnectionRow = memo(function ConnectionRow({
  conn,
  preAccelEnabled,
  nowTick,
  onCloseSingle,
}: ConnectionRowProps) {
  const isPreAccelInner = conn.isInnerTunnel && (preAccelEnabled || conn.viaPreAccel);
  const displayProcess = conn.isInnerTunnel
    ? isPreAccelInner
      ? "底层提速隧道 (Inner)"
      : "内核内部连接 (Inner)"
    : conn.process;

  return (
    <tr
      className={`hover:bg-[var(--card-hover)] ${
        conn.isInnerTunnel ? "bg-[var(--amber-soft)]/15" : ""
      }`}
    >
      <td className="max-w-[140px] px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-1">
          <span
            title={displayProcess}
            className={`cc-mono max-w-[126px] truncate font-semibold ${
              conn.isInnerTunnel ? "text-[var(--amber)]" : "text-[var(--text)]"
            }`}
          >
            {displayProcess}
          </span>
          {conn.isInnerTunnel && (
            <span className="rounded bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
              {isPreAccelInner ? "底层隧道" : "内核内部"}
            </span>
          )}
          {!conn.isInnerTunnel && conn.isLoopback && (
            <span className="rounded bg-[var(--sky-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--sky)]">
              本机内部通信
            </span>
          )}
        </div>
        <span className="cc-mono mt-0.5 inline-block rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--muted)]">
          {conn.network}
        </span>
      </td>

      <td className="max-w-[185px] px-2.5 py-2.5">
        <div
          title={`${conn.host}:${conn.port}`}
          className="cc-mono cc-selectable truncate font-medium text-[var(--text)]"
        >
          {conn.host}:{conn.port}
        </div>
        <div className="cc-mono truncate text-[10px] text-[var(--muted)]">
          {conn.dstIp}
          {!conn.isInnerTunnel && conn.isLoopback ? " · 本机内部通信" : ""}
        </div>
      </td>

      <td className="px-2.5 py-2.5">
        <span
          title={
            conn.isInnerTunnel
              ? isPreAccelInner
                ? "国内提速拨号（Inner 底层隧道）"
                : "内核内部连接（如加密 DNS、规则探测）"
              : conn.rule
          }
          className={`inline-block max-w-[132px] truncate rounded-lg border px-2 py-0.5 text-[11px] ${
            conn.isInnerTunnel
              ? "border-[var(--amber)]/40 bg-[var(--amber-soft)]/70 font-medium text-[var(--amber)]"
              : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
          }`}
        >
          {formatConnectionRuleLabel(conn.rule, conn.isInnerTunnel, isPreAccelInner)}
        </span>
      </td>

      <td className="min-w-[136px] max-w-[165px] px-2.5 py-2.5">
        <div className="flex flex-wrap items-center gap-1">
          <span
            title={formatRuleTargetLabel(conn.groupName)}
            className="max-w-[125px] truncate text-[11px] font-medium text-[var(--accent)]"
          >
            {formatRuleTargetLabel(conn.groupName)}
          </span>
          {conn.viaPreAccel && (
            <span className="shrink-0 whitespace-nowrap rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] text-[var(--green)]">
              走国内提速
            </span>
          )}
        </div>
        <div
          title={formatRuleTargetLabel(conn.nodeName)}
          className="cc-mono mt-0.5 max-w-[155px] truncate text-[11px] text-[var(--text-secondary)]"
        >
          {formatRuleTargetLabel(conn.nodeName)}
        </div>
      </td>

      <td className="cc-mono whitespace-nowrap px-2.5 py-2.5 text-right">
        <div className="text-[11px] font-medium">
          <span className="text-[var(--coral)]">↑ {formatRate(conn.upBps)}</span>
          <span className="mx-1 text-[var(--muted)]">·</span>
          <span className="text-[var(--sky)]">↓ {formatRate(conn.downBps)}</span>
        </div>
        <div className="mt-0.5 text-[10px] text-[var(--muted)]">
          累计 ↑ {formatBytes(conn.uploadBytes)} · ↓ {formatBytes(conn.downloadBytes)}
        </div>
      </td>

      <td className="cc-mono whitespace-nowrap px-2.5 py-2.5 text-right text-[11px] text-[var(--muted)]">
        {formatDuration(conn.startedAtMs, nowTick)}
      </td>

      <td className="whitespace-nowrap px-3 py-2.5 text-right">
        <button
          type="button"
          onClick={() => onCloseSingle(conn)}
          className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] font-medium text-[var(--muted)] hover:border-[var(--red)] hover:bg-[var(--red-soft)] hover:text-[var(--red)]"
        >
          <X className="h-3 w-3 shrink-0" />
          断开
        </button>
      </td>
    </tr>
  );
});

interface ConnectionsTabProps {
  onBreakdownChange: (breakdown: ConnectionBreakdown) => void;
}

export function ConnectionsTab({ onBreakdownChange }: ConnectionsTabProps) {
  const groups = useAppSelector((s) => s.groups);
  const preAccelRelays = useAppSelector((s) => s.preAccelRelays);
  const runtimeRunning = useAppSelector((s) => s.runtime.running);
  const preAccelEnabled = useAppSelector(
    (s) => s.runtime.preaccel_active || s.config.preaccel.enabled
  );
  const connSearch = useAppSelector((s) => s.sessionDrafts.rulesConns.connSearch);
  const connPaused = useAppSelector((s) => s.sessionDrafts.rulesConns.connPaused);
  const inTauri = isTauriEnv();

  const setConnSearch = useCallback((value: string) => {
    appActions.patchSessionDraft("rulesConns", { connSearch: value });
  }, []);

  const [connections, setConnections] = useState<LiveConnection[]>(() =>
    connPaused && pausedConnectionsSnapshot ? pausedConnectionsSnapshot : []
  );
  const [connGroupFilter, setConnGroupFilter] = useState<string>("all");
  const [connSort, setConnSort] = usePersistedState<ConnSortKey>(
    "rulesconns.connSort",
    "down",
    CONN_SORT_VALIDATOR
  );
  const [showInnerTunnels, setShowInnerTunnels] = usePersistedState<boolean>(
    "rulesconns.showInnerTunnels",
    false,
    isBoolPref
  );
  const [hideLoopback, setHideLoopback] = usePersistedState<boolean>(
    "rulesconns.hideLoopback",
    false,
    isBoolPref
  );
  const [connPage, setConnPage] = useState<number>(1);
  const [pageJumpInput, setPageJumpInput] = useState<string>("");
  const [confirmCloseAll, setConfirmCloseAll] = useState<boolean>(false);
  const [nowTick, setNowTick] = useState<number>(() => Date.now());
  const [refreshingConns, setRefreshingConns] = useState<boolean>(false);

  const confirmCloseAllTimerRef = useRef<number | null>(null);
  const groupsRef = useRef<MultiGroup[]>(groups);
  groupsRef.current = groups;
  const relaysRef = useRef<PreAccelRelay[]>(preAccelRelays);
  relaysRef.current = preAccelRelays;
  const runtimeRunningRef = useRef<boolean>(runtimeRunning);
  runtimeRunningRef.current = runtimeRunning;
  const preAccelEnabledRef = useRef<boolean>(preAccelEnabled);
  preAccelEnabledRef.current = preAccelEnabled;
  const connPausedRef = useRef<boolean>(connPaused);
  connPausedRef.current = connPaused;
  const inFlightRef = useRef<boolean>(false);
  const prevSnapRef = useRef<Map<string, ConnTrafficSnap>>(new Map());
  const mountedRef = useRef<boolean>(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (confirmCloseAllTimerRef.current !== null) {
        window.clearTimeout(confirmCloseAllTimerRef.current);
      }
    };
  }, []);

  const fetchLiveConnections = useCallback(
    async (manual = false, notifyOnError = false): Promise<boolean> => {
      if (inFlightRef.current) return false;
      if (!inTauri) {
        const mod = await import("./previewConnections");
        if (!mountedRef.current) return false;
        setConnections(mod.buildPreviewConnections(preAccelEnabledRef.current));
        setNowTick(Date.now());
        return true;
      }
      if (!runtimeRunningRef.current) {
        prevSnapRef.current = new Map();
        setConnections([]);
        if (notifyOnError) {
          appActions.showToast("代理核心尚未启动，开启代理后这里会实时显示连接", "info");
        }
        return false;
      }

      inFlightRef.current = true;
      if (manual) {
        setRefreshingConns(true);
      }
      try {
        const snap = await catcloudApi.getActiveConnections();
        if (!mountedRef.current) return false;
        const nowMs = Date.now();
        const prevMap = prevSnapRef.current;
        const nextMap = new Map<string, ConnTrafficSnap>();

        const mapped = snap.connections.map((dto) => {
          const item = mapDtoConnection(
            dto,
            groupsRef.current,
            relaysRef.current,
            preAccelEnabledRef.current
          );
          const prev = prevMap.get(item.id);
          if (prev && nowMs > prev.atMs) {
            const dtSec = Math.max(0.2, (nowMs - prev.atMs) / 1000);
            item.upBps = Math.max(0, (item.uploadBytes - prev.uploadBytes) / dtSec);
            item.downBps = Math.max(0, (item.downloadBytes - prev.downloadBytes) / dtSec);
          }
          nextMap.set(item.id, {
            uploadBytes: item.uploadBytes,
            downloadBytes: item.downloadBytes,
            atMs: nowMs,
          });
          return item;
        });

        prevSnapRef.current = nextMap;
        setConnections(mapped);
        setNowTick(nowMs);
        return true;
      } catch (err) {
        if (notifyOnError) {
          appActions.showToast(`获取当前连接失败：${formatErrorMessage(err)}`, "warn");
        }
        return false;
      } finally {
        inFlightRef.current = false;
        if (manual && mountedRef.current) {
          setRefreshingConns(false);
        }
      }
    },
    [inTauri]
  );

  // Hydrate initial preview or live connections on mount / runtime state change
  useEffect(() => {
    if (!inTauri) {
      if (connPausedRef.current && pausedConnectionsSnapshot !== null) {
        return;
      }
      void fetchLiveConnections(false, false);
      return;
    }
    if (!runtimeRunning) {
      prevSnapRef.current = new Map();
      pausedConnectionsSnapshot = null;
      setConnections([]);
      return;
    }
    if (connPausedRef.current && pausedConnectionsSnapshot !== null) {
      return;
    }
    void fetchLiveConnections(false, false);
  }, [fetchLiveConnections, inTauri, runtimeRunning]);

  useEffect(() => {
    if (connPaused) {
      pausedConnectionsSnapshot = connections;
    } else {
      pausedConnectionsSnapshot = null;
    }
  }, [connPaused, connections]);

  // Re-evaluate custom relay names whenever preAccelRelays updates
  useEffect(() => {
    if (preAccelRelays.length === 0) return;
    setConnections((prev) => {
      let changed = false;
      const next = prev.map((c) => {
        const via = matchesPreAccelChain(c.chains, preAccelRelays);
        if (via !== c.viaPreAccel) {
          changed = true;
          return { ...c, viaPreAccel: via };
        }
        return c;
      });
      return changed ? next : prev;
    });
  }, [preAccelRelays]);

  // 2.5s polling timer ONLY runs while ConnectionsTab is mounted, gated by document.visibilityState,
  // and immediately refreshes on returning to visible.
  useEffect(() => {
    if (connPaused) return;
    if (inTauri && !runtimeRunning) return;

    const tickPreview = (nowMs: number) => {
      setNowTick(nowMs);
      setConnections((prev) => {
        const prevMap = prevSnapRef.current;
        const nextMap = new Map<string, ConnTrafficSnap>();
        const updated = prev.map((c, idx) => {
          const deltaUp = (idx + 1) * 14_500;
          const deltaDown = (idx + 2) * 58_000;
          const nextUp = c.uploadBytes + deltaUp;
          const nextDown = c.downloadBytes + deltaDown;
          const last = prevMap.get(c.id);
          const dtSec =
            last && nowMs > last.atMs ? Math.max(0.2, (nowMs - last.atMs) / 1000) : 2.5;
          const upBps = last ? Math.max(0, (nextUp - last.uploadBytes) / dtSec) : deltaUp / 2.5;
          const downBps = last
            ? Math.max(0, (nextDown - last.downloadBytes) / dtSec)
            : deltaDown / 2.5;
          nextMap.set(c.id, { uploadBytes: nextUp, downloadBytes: nextDown, atMs: nowMs });
          return {
            ...c,
            uploadBytes: nextUp,
            downloadBytes: nextDown,
            upBps,
            downBps,
          };
        });
        prevSnapRef.current = nextMap;
        return updated;
      });
    };

    const timer = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      const nowMs = Date.now();
      if (inTauri) {
        if (runtimeRunningRef.current) {
          void fetchLiveConnections(false, false);
        }
      } else {
        tickPreview(nowMs);
      }
    }, 2500);

    const handleVisibilityChange = () => {
      if (document.visibilityState !== "visible" || connPausedRef.current) return;
      if (inTauri) {
        if (runtimeRunningRef.current) {
          void fetchLiveConnections(false, false);
        }
      } else {
        tickPreview(Date.now());
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [connPaused, fetchLiveConnections, inTauri, runtimeRunning]);

  const connectionBreakdown = useMemo(
    () => computeConnectionBreakdown(connections),
    [connections]
  );

  useEffect(() => {
    onBreakdownChange(connectionBreakdown);
  }, [connectionBreakdown, onBreakdownChange]);

  const filteredConnections = useMemo(() => {
    const kw = connSearch.trim().toLowerCase();
    const list = connections.filter((c) => {
      if (!showInnerTunnels && c.isInnerTunnel) return false;
      if (hideLoopback && !c.isInnerTunnel && c.isLoopback) return false;
      if (connGroupFilter !== "all") {
        if (connGroupFilter === "DIRECT") {
          const isDirect =
            c.groupId.toUpperCase() === "DIRECT" ||
            c.groupName.toUpperCase() === "DIRECT" ||
            c.nodeName.toUpperCase() === "DIRECT";
          if (!isDirect) return false;
        } else if (c.groupId !== connGroupFilter && c.groupName !== connGroupFilter) {
          return false;
        }
      }
      if (!kw) return true;
      const isPreAccelInner = c.isInnerTunnel && (preAccelEnabled || c.viaPreAccel);
      const friendlyRule = formatConnectionRuleLabel(
        c.rule,
        c.isInnerTunnel,
        isPreAccelInner
      ).toLowerCase();
      const displayProcess = c.isInnerTunnel
        ? isPreAccelInner
          ? "底层提速隧道 (Inner)"
          : "内核内部连接 (Inner)"
        : c.process;
      const extraTag = c.isInnerTunnel
        ? isPreAccelInner
          ? "底层提速隧道 inner 国内提速拨号"
          : "内核内部连接 inner dns 加密dns 规则探测"
        : c.isLoopback
          ? "本机内部通信 loopback 回环"
          : "";
      return (
        displayProcess.toLowerCase().includes(kw) ||
        c.host.toLowerCase().includes(kw) ||
        c.dstIp.includes(kw) ||
        c.rule.toLowerCase().includes(kw) ||
        friendlyRule.includes(kw) ||
        c.nodeName.toLowerCase().includes(kw) ||
        c.groupName.toLowerCase().includes(kw) ||
        extraTag.includes(kw)
      );
    });

    list.sort((a, b) => {
      if (connSort === "rate") return b.upBps + b.downBps - (a.upBps + a.downBps);
      if (connSort === "down") return b.downloadBytes - a.downloadBytes;
      if (connSort === "up") return b.uploadBytes - a.uploadBytes;
      if (connSort === "age") return a.startedAtMs - b.startedAtMs;
      return a.process.localeCompare(b.process);
    });
    return list;
  }, [
    connGroupFilter,
    connSearch,
    connSort,
    connections,
    hideLoopback,
    preAccelEnabled,
    showInnerTunnels,
  ]);

  const totalConnPages = Math.max(
    1,
    Math.ceil(filteredConnections.length / CONNECTIONS_PAGE_SIZE)
  );
  const safeConnPage = Math.min(connPage, totalConnPages);

  useEffect(() => {
    setConnPage(1);
  }, [connGroupFilter, connSearch, connSort, hideLoopback, showInnerTunnels]);

  useEffect(() => {
    if (connPage > totalConnPages) {
      setConnPage(totalConnPages);
    }
  }, [connPage, totalConnPages]);

  const pagedConnections = useMemo(() => {
    const start = (safeConnPage - 1) * CONNECTIONS_PAGE_SIZE;
    return filteredConnections.slice(start, start + CONNECTIONS_PAGE_SIZE);
  }, [filteredConnections, safeConnPage]);

  const handleJumpConnPage = () => {
    const parsed = Number.parseInt(pageJumpInput.trim(), 10);
    if (!Number.isFinite(parsed)) {
      appActions.showToast("请输入有效的页码数字", "warn");
      return;
    }
    const target = Math.max(1, Math.min(totalConnPages, parsed));
    setConnPage(target);
    setPageJumpInput("");
  };

  // Strictly exclude `isInnerTunnel` connections from aggregate bytes & rates to avoid double-counting
  const filteredAppConnCount = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + 1), 0),
    [filteredConnections]
  );
  const totalConnUpload = useMemo(
    () =>
      filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.uploadBytes), 0),
    [filteredConnections]
  );
  const totalConnDownload = useMemo(
    () =>
      filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.downloadBytes), 0),
    [filteredConnections]
  );
  const totalConnUpBps = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.upBps), 0),
    [filteredConnections]
  );
  const totalConnDownBps = useMemo(
    () => filteredConnections.reduce((acc, c) => (c.isInnerTunnel ? acc : acc + c.downBps), 0),
    [filteredConnections]
  );

  const connGroupFilterOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "all", label: "全部分组" },
      { value: "DIRECT", label: "直接连接" },
      ...groups.map((g) => ({ value: g.id, label: g.name })),
    ],
    [groups]
  );

  const connSortOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "down", label: "按下载量排序" },
      { value: "up", label: "按上传量排序" },
      { value: "rate", label: "按实时速率排序" },
      { value: "age", label: "按连接时长排序" },
      { value: "process", label: "按软件名排序" },
    ],
    []
  );

  const handleCloseSingleConn = useCallback(async (conn: LiveConnection) => {
    try {
      await catcloudApi.closeConnection(conn.id);
      prevSnapRef.current.delete(conn.id);
      setConnections((prev) => prev.filter((c) => c.id !== conn.id));
      appActions.showToast(`已断开连接：${conn.process} -> ${conn.host}`, "ok");
    } catch (err) {
      appActions.showToast(`断开连接失败：${formatErrorMessage(err)}`, "warn");
    }
  }, []);

  const handleCloseByGroup = async () => {
    const targetGroupId =
      connGroupFilter !== "all" ? connGroupFilter : (groups[0]?.id ?? "");
    const targetGroupName =
      groups.find((g) => g.id === targetGroupId)?.name ??
      connections.find((c) => c.groupId === targetGroupId)?.groupName ??
      targetGroupId;

    if (!targetGroupName) {
      appActions.showToast("请先选择要清理连接的分组", "warn");
      return;
    }

    try {
      const closed = await catcloudApi.closeGroupConnections(targetGroupName);
      setConnections((prev) =>
        prev.filter((c) => c.groupId !== targetGroupId && c.groupName !== targetGroupName)
      );
      appActions.showToast(`已断开「${targetGroupName}」的 ${closed} 条旧连接`, "ok");
    } catch (err) {
      appActions.showToast(`按分组断开连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleCloseAllConns = async () => {
    if (!confirmCloseAll) {
      setConfirmCloseAll(true);
      if (confirmCloseAllTimerRef.current !== null) {
        window.clearTimeout(confirmCloseAllTimerRef.current);
      }
      confirmCloseAllTimerRef.current = window.setTimeout(() => {
        confirmCloseAllTimerRef.current = null;
        setConfirmCloseAll(false);
      }, 3500);
      return;
    }
    if (confirmCloseAllTimerRef.current !== null) {
      window.clearTimeout(confirmCloseAllTimerRef.current);
      confirmCloseAllTimerRef.current = null;
    }
    try {
      const closed = await catcloudApi.closeAllConnections();
      const shownCount = inTauri ? closed : connections.length;
      prevSnapRef.current = new Map();
      setConnections([]);
      setConfirmCloseAll(false);
      appActions.showToast(`已断开全部 ${shownCount} 条连接`, "ok");
    } catch (err) {
      setConfirmCloseAll(false);
      appActions.showToast(`断开全部连接失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleRefreshConns = async () => {
    const ok = await fetchLiveConnections(true, true);
    if (ok) {
      appActions.showToast("已刷新当前连接列表", "info");
    }
  };

  const innerCountShortLabel = preAccelEnabled ? "提速隧道" : "内核内部连接";

  return (
    <div className="space-y-4">
      {/* 连接概览与批量操作 */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex flex-wrap items-center gap-4 text-xs">
          <div>
            <span className="text-[var(--muted)]">真实应用连接</span>
            <div className="cc-mono mt-0.5 text-base font-semibold text-[var(--text)]">
              {filteredAppConnCount}
              <span className="ml-1 text-[11px] font-normal text-[var(--muted)]">
                / {connectionBreakdown.appCount}
              </span>
            </div>
            {(connectionBreakdown.innerTunnelCount > 0 ||
              connectionBreakdown.loopbackCount > 0) && (
              <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                {connectionBreakdown.innerTunnelCount > 0 &&
                connectionBreakdown.loopbackCount > 0
                  ? `另含 ${connectionBreakdown.innerTunnelCount} 条${innerCountShortLabel} · ${connectionBreakdown.loopbackCount} 条本机回环`
                  : connectionBreakdown.innerTunnelCount > 0
                    ? `另含 ${connectionBreakdown.innerTunnelCount} 条${innerCountShortLabel}`
                    : `含 ${connectionBreakdown.loopbackCount} 条本机回环`}
              </div>
            )}
          </div>
          <div className="h-7 w-px bg-[var(--line)]" />
          <div
            title={
              preAccelEnabled
                ? "已自动排除底层提速隧道，避免应用层与隧道层重复累计"
                : "已自动排除内核内部连接（如加密 DNS、规则探测），仅统计真实应用流量"
            }
          >
            <span className="text-[var(--muted)]">实时上传 / 累计</span>
            <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--coral)]">
              ↑ {formatRate(totalConnUpBps)}
              <span className="ml-1.5 text-[11px] font-normal text-[var(--muted)]">
                ({formatBytes(totalConnUpload)})
              </span>
            </div>
          </div>
          <div
            title={
              preAccelEnabled
                ? "已自动排除底层提速隧道，避免应用层与隧道层重复累计"
                : "已自动排除内核内部连接（如加密 DNS、规则探测），仅统计真实应用流量"
            }
          >
            <span className="text-[var(--muted)]">实时下载 / 累计</span>
            <div className="cc-mono mt-0.5 text-sm font-semibold text-[var(--sky)]">
              ↓ {formatRate(totalConnDownBps)}
              <span className="ml-1.5 text-[11px] font-normal text-[var(--muted)]">
                ({formatBytes(totalConnDownload)})
              </span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const nextPaused = !appStore.getState().sessionDrafts.rulesConns.connPaused;
              pausedConnectionsSnapshot = nextPaused ? connections : null;
              appActions.patchSessionDraft("rulesConns", { connPaused: nextPaused });
            }}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--line-strong)]"
          >
            {connPaused ? (
              <Play className="h-3.5 w-3.5 text-[var(--accent)]" />
            ) : (
              <Pause className="h-3.5 w-3.5 text-[var(--muted)]" />
            )}
            {connPaused ? "继续刷新" : "暂停刷新"}
          </button>

          <button
            type="button"
            onClick={() => void handleCloseByGroup()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--amber)] hover:opacity-90"
            title="断开所选分组下的旧连接，切换节点后可让新线路立刻生效"
          >
            <Zap className="h-3.5 w-3.5" />
            按分组断开旧连接
          </button>

          <button
            type="button"
            onClick={() => void handleCloseAllConns()}
            className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold transition-colors ${
              confirmCloseAll
                ? "border-[var(--red)] bg-[var(--red)] text-[var(--accent-ink)]"
                : "border-[var(--red)]/50 bg-[var(--red-soft)] text-[var(--red)] hover:border-[var(--red)]"
            }`}
          >
            <Trash2 className="h-3.5 w-3.5" />
            {confirmCloseAll ? "再点一次确认全部断开" : "断开全部连接"}
          </button>
        </div>
      </section>

      {/* 筛选与排序栏 */}
      <section className="cc-card cc-glass flex flex-wrap items-center gap-2.5 rounded-2xl p-3.5">
        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
          <input
            type="text"
            value={connSearch}
            onChange={(e) => setConnSearch(e.target.value)}
            placeholder="按软件名、目标网址/IP、规则或节点搜索..."
            className="h-8 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] pl-8 pr-7 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
          />
          {connSearch && (
            <button
              type="button"
              onClick={() => setConnSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <div className="flex max-w-full flex-wrap items-center gap-2 text-xs">
          <label
            className={`inline-flex h-8 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-xl border px-2.5 text-[11px] font-medium transition-colors ${
              showInnerTunnels
                ? "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
            title={
              preAccelEnabled
                ? "默认隐藏 Mihomo 底层国内提速拨号隧道（Inner），勾选后可展开排查中转连接"
                : "默认隐藏 Mihomo 内核内部连接（如加密 DNS、规则探测），勾选后可展开排查"
            }
          >
            <input
              type="checkbox"
              checked={showInnerTunnels}
              onChange={(e) => setShowInnerTunnels(e.target.checked)}
              className="h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
            />
            <span>
              {preAccelEnabled ? "显示底层提速隧道 (Inner)" : "显示内核内部连接 (Inner)"}
            </span>
            {connectionBreakdown.innerTunnelCount > 0 && (
              <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px]">
                {connectionBreakdown.innerTunnelCount}
              </span>
            )}
          </label>

          <label
            className={`inline-flex h-8 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-xl border px-2.5 text-[11px] font-medium transition-colors ${
              hideLoopback
                ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
            title="隐藏发往 127.0.0.1 / localhost / ::1 的本机内部通信"
          >
            <input
              type="checkbox"
              checked={hideLoopback}
              onChange={(e) => setHideLoopback(e.target.checked)}
              className="h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
            />
            <span>隐藏本机回环 (127.0.0.1)</span>
            {connectionBreakdown.loopbackCount > 0 && (
              <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px]">
                {connectionBreakdown.loopbackCount}
              </span>
            )}
          </label>

          <div className="flex max-w-full flex-wrap items-center gap-2">
            <Filter className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
            <AppSelect
              size="sm"
              aria-label="按分组筛选连接"
              value={connGroupFilter}
              onChange={setConnGroupFilter}
              options={connGroupFilterOptions}
              className="min-w-[128px] max-w-[200px]"
              buttonClassName="rounded-xl"
            />

            <AppSelect
              size="sm"
              aria-label="连接排序方式"
              value={connSort}
              onChange={(v) => setConnSort(v as ConnSortKey)}
              options={connSortOptions}
              className="min-w-[132px] max-w-[200px]"
              buttonClassName="rounded-xl"
            />

            <button
              type="button"
              disabled={refreshingConns}
              onClick={() => void handleRefreshConns()}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
              title="刷新当前连接"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshingConns ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>
      </section>

      {/* 当前连接表格 */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <div className="flex items-center justify-between border-b border-[var(--line)]/70 bg-[var(--bg-elevated)]/45 px-3 py-1 text-[10.5px] text-[var(--muted)] min-[1160px]:hidden">
          <span>窄窗模式下可左右滑动查看完整连接列</span>
          <span className="cc-mono">← →</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 text-[11px] text-[var(--muted)]">
                <th className="min-w-[132px] whitespace-nowrap px-3 py-2.5 font-medium">
                  软件 / 协议
                </th>
                <th className="min-w-[164px] whitespace-nowrap px-2.5 py-2.5 font-medium">
                  访问地址与端口
                </th>
                <th className="min-w-[112px] whitespace-nowrap px-2.5 py-2.5 font-medium">
                  命中规则
                </th>
                <th className="min-w-[144px] whitespace-nowrap px-2.5 py-2.5 font-medium">
                  分组与当前节点
                </th>
                <th className="min-w-[156px] whitespace-nowrap px-2.5 py-2.5 text-right font-medium">
                  实时速率 / 累计流量
                </th>
                <th className="min-w-[58px] whitespace-nowrap px-2.5 py-2.5 text-right font-medium">
                  时长
                </th>
                <th className="min-w-[74px] whitespace-nowrap px-3 py-2.5 text-right font-medium">
                  操作
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]">
              {filteredConnections.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-xs text-[var(--muted)]">
                    {!runtimeRunning
                      ? "代理核心尚未启动，开启代理后这里会实时显示每个软件的连接去向"
                      : connections.length === 0
                        ? "当前没有进行中的连接"
                        : "没有符合当前筛选条件的连接"}
                  </td>
                </tr>
              ) : (
                pagedConnections.map((conn) => (
                  <ConnectionRow
                    key={conn.id}
                    conn={conn}
                    preAccelEnabled={preAccelEnabled}
                    nowTick={nowTick}
                    onCloseSingle={handleCloseSingleConn}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>

        {filteredConnections.length > CONNECTIONS_PAGE_SIZE && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-2.5 text-xs">
            <div className="text-[11px] text-[var(--muted)]">
              显示第 {(safeConnPage - 1) * CONNECTIONS_PAGE_SIZE + 1}–
              {Math.min(safeConnPage * CONNECTIONS_PAGE_SIZE, filteredConnections.length)} 条，共{" "}
              {filteredConnections.length} 条（每页 {CONNECTIONS_PAGE_SIZE} 条）
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={safeConnPage <= 1}
                onClick={() => setConnPage((p) => Math.max(1, p - 1))}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-45"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                上一页
              </button>

              <span className="cc-mono text-[11px] text-[var(--text-secondary)]">
                第 {safeConnPage} / {totalConnPages} 页
              </span>

              <button
                type="button"
                disabled={safeConnPage >= totalConnPages}
                onClick={() => setConnPage((p) => Math.min(totalConnPages, p + 1))}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-45"
              >
                下一页
                <ChevronRight className="h-3.5 w-3.5" />
              </button>

              <div className="ml-1 flex items-center gap-1">
                <input
                  type="number"
                  min={1}
                  max={totalConnPages}
                  value={pageJumpInput}
                  onChange={(e) => setPageJumpInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleJumpConnPage();
                  }}
                  placeholder="页码"
                  className="cc-mono w-14 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-center text-[11px] text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleJumpConnPage}
                  className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                >
                  跳转
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
