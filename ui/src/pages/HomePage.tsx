import {
  Activity,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  Clock,
  Cpu,
  Eye,
  EyeOff,
  Globe,
  HardDriveDownload,
  HardDriveUpload,
  Layers,
  Minimize2,
  Monitor,
  PictureInPicture2,
  Plus,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import {
  type ExitIpInfo,
  type ProxyMode,
  type SiteCheckItem,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { MASCOT_STATE_LABELS, type MascotState, MascotSprite } from "../components/MascotSprite";
import { TrafficSparkline, formatBytes, formatRate } from "../components/TrafficSparkline";
import { appActions, useAppSelector, useLatestTraffic } from "../store/appStore";

const PROXY_MODE_OPTIONS: ReadonlyArray<{ id: ProxyMode; label: string; hint: string }> = [
  { id: "rule", label: "规则", hint: "按分流规则智能路由" },
  { id: "global", label: "全局", hint: "全部流量经主力代理组" },
  { id: "direct", label: "直连", hint: "绕过代理直连出站" },
];

function formatUptime(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "0m";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function getLatencyColor(latencyMs: number | null, ok: boolean | null): string {
  if (ok === false) return "var(--red)";
  if (latencyMs === null) return "var(--muted)";
  if (latencyMs <= 140) return "var(--green)";
  if (latencyMs <= 300) return "var(--amber)";
  return "var(--red)";
}

export function HomePage() {
  const runtime = useAppSelector((s) => s.runtime);
  const config = useAppSelector((s) => s.config);
  const storeExitIp = useAppSelector((s) => s.exitIp);
  const storeQuickSites = useAppSelector((s) => s.quickSites);
  const mascotState = useAppSelector((s) => s.mascotState);
  const initialized = useAppSelector((s) => s.initialized);
  const traffic = useLatestTraffic();

  const [sites, setSites] = useState<SiteCheckItem[]>(storeQuickSites);
  const [customSiteIds, setCustomSiteIds] = useState<string[]>([]);
  const [showAddSite, setShowAddSite] = useState(false);
  const [newSiteName, setNewSiteName] = useState("");
  const [newSiteUrl, setNewSiteUrl] = useState("");
  const [checkingSites, setCheckingSites] = useState(false);

  const [exitIp, setExitIp] = useState<ExitIpInfo>(storeExitIp);
  const [ipMasked, setIpMasked] = useState(true);
  const [refreshingIp, setRefreshingIp] = useState(false);
  const [switchingNode, setSwitchingNode] = useState(false);

  const syncedSitesRef = useRef(false);
  const timerIdsRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      for (const id of timerIdsRef.current) {
        window.clearTimeout(id);
      }
      timerIdsRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (initialized && !syncedSitesRef.current) {
      syncedSitesRef.current = true;
      setSites(storeQuickSites);
    }
  }, [storeQuickSites, initialized]);

  useEffect(() => {
    if (initialized) {
      setExitIp(storeExitIp);
    }
  }, [storeExitIp, initialized]);

  const scheduleTimeout = (fn: () => void, ms: number) => {
    const id = window.setTimeout(() => {
      timerIdsRef.current = timerIdsRef.current.filter((item) => item !== id);
      fn();
    }, ms);
    timerIdsRef.current.push(id);
  };

  // Dual-form mascot: cream cat idle by default, working sprite during probing/switching/preaccel transition
  const effectiveMascotState: MascotState = checkingSites
    ? "searching"
    : switchingNode
      ? "thinking"
      : mascotState;

  const persistQuickSites = async (nextSites: SiteCheckItem[]): Promise<boolean> => {
    const payload = nextSites.map((s) => ({
      id: s.id,
      name: s.name,
      url: s.url,
    }));
    try {
      await catcloudApi.saveExtendedSettings({ core_runtime: { quick_check_sites: payload } });
      appActions.syncQuickSites(nextSites);
      return true;
    } catch (err) {
      appActions.showToast(`保存测活站点失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  };

  const handleSwitchNextBest = async () => {
    if (switchingNode) return;
    setSwitchingNode(true);
    try {
      await appActions.switchNextBestNode();
    } finally {
      setSwitchingNode(false);
    }
  };

  const handleEnterWindowless = async () => {
    try {
      await catcloudApi.enterWindowlessMode();
      appActions.showToast("已切换至无窗省内存托盘模式（点击托盘图标秒开）", "info");
    } catch (err) {
      appActions.showToast(`进入无窗模式失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleCheckSites = async () => {
    if (checkingSites) return;
    setCheckingSites(true);
    appActions.setMascotState("searching");
    try {
      const freshSites = await catcloudApi.checkQuickSites();
      if (isTauriEnv()) {
        setSites(freshSites);
        appActions.syncQuickSites(freshSites);
      } else {
        const freshById = new Map(freshSites.map((item) => [item.id, item]));
        setSites((prev) => {
          const baseList = prev.length > 0 ? prev : freshSites;
          return baseList.map((site) => {
            const updated = freshById.get(site.id);
            if (updated) return updated;
            return { ...site, latency_ms: 88, ok: true };
          });
        });
      }
      appActions.showToast("网站快捷测活完成", "ok");
    } catch (err) {
      appActions.showToast(`网站快捷测活失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCheckingSites(false);
      appActions.setMascotState("idle");
    }
  };

  const handleAddSite = async (ev: FormEvent) => {
    ev.preventDefault();
    const trimmedName = newSiteName.trim();
    const trimmedUrl = newSiteUrl.trim();
    if (!trimmedName || !trimmedUrl) {
      appActions.showToast("请填写网站名称与测活地址", "warn");
      return;
    }
    const normalizedUrl = /^https?:\/\//i.test(trimmedUrl) ? trimmedUrl : `https://${trimmedUrl}`;
    try {
      const parsed = new URL(normalizedUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        appActions.showToast("测活地址仅支持 HTTP / HTTPS 协议", "warn");
        return;
      }
    } catch {
      appActions.showToast("请输入合法的测活 URL", "warn");
      return;
    }

    const id = `site-custom-${Date.now()}`;
    const item: SiteCheckItem = {
      id,
      name: trimmedName,
      url: normalizedUrl,
      latency_ms: null,
      ok: null,
    };
    const nextSites = [...sites, item];
    const saved = await persistQuickSites(nextSites);
    if (!saved) return;

    setSites(nextSites);
    setCustomSiteIds((prev) => [...prev, id]);
    setNewSiteName("");
    setNewSiteUrl("");
    setShowAddSite(false);
    appActions.showToast(`已添加并保存测活站点：${trimmedName}`, "ok");
  };

  const handleRemoveSite = async (id: string) => {
    const nextSites = sites.filter((item) => item.id !== id);
    const saved = await persistQuickSites(nextSites);
    if (!saved) return;
    setSites(nextSites);
    setCustomSiteIds((prev) => prev.filter((item) => item !== id));
    appActions.showToast("已移除测活站点", "info");
  };

  const handleRefreshExitIp = async () => {
    if (refreshingIp) return;
    setRefreshingIp(true);
    appActions.setMascotState("searching");
    try {
      const info = await catcloudApi.getExitIpInfo();
      setExitIp(info);
      appActions.syncExitIp(info);
      appActions.showToast("出口 IP 与区域洁净状态已刷新", "ok");
    } catch (err) {
      appActions.showToast(`刷新出口 IP 失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      scheduleTimeout(() => {
        setRefreshingIp(false);
        appActions.setMascotState("idle");
      }, 240);
    }
  };

  const memSubLabel =
    config.gomemlimit_mb === 0
      ? "自动挡位 (Auto)"
      : `软上限 ${config.gomemlimit_mb} MB`;

  const kpiCards = [
    {
      label: "上传速率",
      value: formatRate(traffic.up_bps),
      sub: "实时上行",
      accent: "var(--coral)",
      icon: ArrowUp,
    },
    {
      label: "下载速率",
      value: formatRate(traffic.down_bps),
      sub: "实时下行",
      accent: "var(--sky)",
      icon: ArrowDown,
    },
    {
      label: "活跃连接数",
      value: `${traffic.connections}`,
      sub: runtime.tun_enabled ? "TUN + 混合口" : `混合口 :${runtime.mixed_port}`,
      accent: "var(--text)",
      icon: Activity,
    },
    {
      label: "累计上传量",
      value: formatBytes(traffic.up_total_bytes),
      sub: "本次会话",
      accent: "var(--accent)",
      icon: HardDriveUpload,
    },
    {
      label: "累计下载量",
      value: formatBytes(traffic.down_total_bytes),
      sub: "本次会话",
      accent: "var(--accent)",
      icon: HardDriveDownload,
    },
    {
      label: "实时内核内存",
      value: `${traffic.memory_mb.toFixed(1)} MB`,
      sub: memSubLabel,
      accent: "var(--green)",
      icon: Cpu,
    },
  ];

  const displayedIp = ipMasked
    ? exitIp.ip_masked || "--.--.--.***"
    : exitIp.ip_raw && exitIp.ip_raw.trim().length > 0
      ? exitIp.ip_raw.trim()
      : "核心未运行或暂未获取";

  const googleCleanTone =
    exitIp.google_clean === true
      ? {
          cls: "bg-[var(--green-soft)] text-[var(--green)]",
          label: "Google 洁净",
          state: "clean" as const,
        }
      : exitIp.google_clean === false
        ? {
            cls: "bg-[var(--red-soft)] text-[var(--red)]",
            label: "送中风险",
            state: "risk" as const,
          }
        : {
            cls: "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]",
            label: "待探测",
            state: "unknown" as const,
          };

  return (
    <div className="space-y-4">
      {/* Top Compact Status Bar with Mode Switcher, Active Node, Quick Actions & Dual-Form Mascot */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="flex flex-col gap-3.5 xl:flex-row xl:items-center xl:justify-between">
          {/* Left: Proxy Mode + Active Primary Group & Node */}
          <div className="min-w-0 flex-1 space-y-2.5">
            <div className="flex flex-wrap items-center gap-2">
              {/* Proxy Mode Segmented Control */}
              <div
                className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-xs"
                role="group"
                aria-label="代理模式切换"
              >
                {PROXY_MODE_OPTIONS.map((mode) => {
                  const selected = runtime.proxy_mode === mode.id;
                  return (
                    <button
                      key={mode.id}
                      type="button"
                      onClick={() => void appActions.setProxyMode(mode.id)}
                      title={mode.hint}
                      className={`rounded-lg px-3 py-1 font-medium transition-colors ${
                        selected
                          ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                          : "text-[var(--muted)] hover:text-[var(--text)]"
                      }`}
                    >
                      {mode.label}
                    </button>
                  );
                })}
              </div>

              {/* Active Group Tag */}
              <button
                type="button"
                onClick={() => appActions.setNav("groups")}
                className="inline-flex items-center gap-1.5 rounded-full bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
                title="前往智能多选组"
              >
                <Layers className="h-3 w-3" />
                <span>{runtime.active_group_name}</span>
              </button>

              {/* Domestic Pre-Acceleration Dual-Active Status Tag */}
              <button
                type="button"
                onClick={() => appActions.setNav("preaccel")}
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium transition-opacity hover:opacity-85 ${
                  runtime.preaccel_active
                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                    : "border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)]"
                }`}
                title="查看国内预加速双活主备池"
              >
                <Zap className="h-3 w-3" />
                <span>
                  {runtime.preaccel_active
                    ? `国内预加速双活 · ${runtime.preaccel_relay_name ?? "在线"}`
                    : "国内预加速未开启"}
                </span>
              </button>

              {runtime.captive_portal_required && (
                <button
                  type="button"
                  onClick={() => appActions.setNav("preaccel")}
                  className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--amber)]"
                >
                  <ShieldAlert className="h-3 w-3" />
                  <span>校园网待认证</span>
                </button>
              )}
            </div>

            {/* Active Node Title + Key Telemetry */}
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h1 className="truncate text-lg font-semibold tracking-tight text-[var(--text)]">
                {runtime.active_node_name}
              </h1>
              <div className="flex flex-wrap items-center gap-2.5 text-xs text-[var(--muted)] cc-mono">
                <span className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
                  {runtime.active_node_region}
                </span>
                <span>
                  延迟{" "}
                  <strong className="font-semibold text-[var(--text)]">
                    {runtime.active_node_latency_ms !== null
                      ? `${Math.round(runtime.active_node_latency_ms)} ms`
                      : "--"}
                  </strong>
                </span>
                <span>
                  实测上行{" "}
                  <strong className="font-semibold text-[var(--green)]">
                    {runtime.active_node_up_mbps !== null
                      ? `${runtime.active_node_up_mbps.toFixed(1)} Mbps`
                      : "--"}
                  </strong>
                </span>
              </div>
            </div>
          </div>

          {/* Right: Quick Action Buttons + Dual-Form MascotSprite */}
          <div className="flex flex-wrap items-center justify-between gap-3 xl:justify-end">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={switchingNode}
                onClick={() => void handleSwitchNextBest()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Zap className="h-3.5 w-3.5" />
                <span>{switchingNode ? "切换中..." : "一键秒切下一优"}</span>
              </button>

              <button
                type="button"
                onClick={() => void handleEnterWindowless()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                title="关闭 WebView2 主窗并常驻托盘，释放前端内存"
              >
                <Minimize2 className="h-3.5 w-3.5 text-[var(--green)]" />
                <span>无窗省内存</span>
              </button>

              <button
                type="button"
                onClick={() => void appActions.toggleCapsule()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
                title="切换轻量悬浮胶囊微窗"
              >
                <PictureInPicture2 className="h-3.5 w-3.5 text-[var(--accent)]" />
                <span>悬浮胶囊</span>
              </button>
            </div>

            {/* Dual-Form Mascot Panel */}
            <button
              type="button"
              onClick={() =>
                appActions.setMascotState(
                  effectiveMascotState === "idle"
                    ? runtime.preaccel_active
                      ? "complete"
                      : "searching"
                    : "idle"
                )
              }
              className="flex items-center gap-2.5 rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-left transition-colors hover:border-[var(--line-strong)]"
              title="点击在奶油猫饼待机态与猫咪工作态间预览切换"
            >
              <div className="flex h-11 w-12 shrink-0 items-center justify-center">
                <MascotSprite state={effectiveMascotState} scale={2} />
              </div>
              <div className="hidden sm:block">
                <div className="text-[11px] font-semibold text-[var(--text)]">
                  {effectiveMascotState === "idle" ? "待机形态" : "工作形态"}
                </div>
                <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                  {MASCOT_STATE_LABELS[effectiveMascotState]}
                </div>
              </div>
            </button>
          </div>
        </div>
      </section>

      {/* 10-Minute Traffic Statistics Section: Sparkline + 6 Core Metric Cards */}
      <section className="space-y-3">
        <TrafficSparkline variant="full" />

        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {kpiCards.map((card) => {
            const Icon = card.icon;
            return (
              <div
                key={card.label}
                className="cc-card cc-glass rounded-2xl px-3.5 py-3"
              >
                <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                  <span>{card.label}</span>
                  <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: card.accent }} />
                </div>
                <div
                  className="mt-1.5 cc-mono cc-tabular text-base font-semibold tracking-tight"
                  style={{ color: card.accent }}
                >
                  {card.value}
                </div>
                <div className="mt-0.5 truncate text-[10px] text-[var(--muted)] cc-mono">
                  {card.sub}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Middle Row: Quick Site Availability Check + Sanitized Exit IP Info */}
      <section className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Quick Site Check Card */}
        <div className="cc-card cc-glass rounded-2xl p-4 lg:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">网站快捷测活</h2>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                支持自定义增删目标站点并持久化保存，实时核验代理出口响应耗时
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setShowAddSite((v) => !v)}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                title="新增自定义测活网站"
              >
                {showAddSite ? <X className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                <span>{showAddSite ? "收起" : "添加"}</span>
              </button>
              <button
                type="button"
                disabled={checkingSites}
                onClick={() => void handleCheckSites()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${checkingSites ? "animate-spin" : ""}`} />
                <span>{checkingSites ? "测活中..." : "一键测活"}</span>
              </button>
            </div>
          </div>

          {showAddSite && (
            <form
              onSubmit={(ev) => void handleAddSite(ev)}
              className="mb-3 grid grid-cols-1 gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 sm:grid-cols-12"
            >
              <input
                type="text"
                value={newSiteName}
                onChange={(e) => setNewSiteName(e.target.value)}
                placeholder="站点名称（如 Claude）"
                className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-4"
              />
              <input
                type="text"
                value={newSiteUrl}
                onChange={(e) => setNewSiteUrl(e.target.value)}
                placeholder="https://example.com/generate_204"
                className="cc-mono rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-6"
              />
              <button
                type="submit"
                className="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 sm:col-span-2"
              >
                确认添加
              </button>
            </form>
          )}

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {sites.map((site) => {
              const isCustom = customSiteIds.includes(site.id);
              const color = getLatencyColor(site.latency_ms, site.ok);
              return (
                <div
                  key={site.id}
                  className="group flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2.5 transition-colors hover:border-[var(--line-strong)]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: color }}
                      />
                      <span className="truncate text-xs font-medium text-[var(--text)]">
                        {site.name}
                      </span>
                      {isCustom && (
                        <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          自定义
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]">
                      {site.url}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      className="cc-mono cc-tabular text-xs font-semibold"
                      style={{ color }}
                    >
                      {site.ok === false
                        ? "超时"
                        : site.latency_ms !== null
                          ? `${site.latency_ms} ms`
                          : "待测"}
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleRemoveSite(site.id)}
                      className="rounded-md p-1 text-[var(--muted)] opacity-0 transition-opacity hover:bg-[var(--card)] hover:text-[var(--red)] group-hover:opacity-100"
                      title={`移除 ${site.name}`}
                      aria-label={`移除 ${site.name}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
            {sites.length === 0 && (
              <div className="col-span-full rounded-xl border border-dashed border-[var(--line)] py-6 text-center text-xs text-[var(--muted)]">
                暂无测活目标，点击右上角「添加」创建快捷测活站点。
              </div>
            )}
          </div>
        </div>

        {/* Sanitized Exit IP Info Card */}
        <div className="cc-card cc-glass flex flex-col justify-between rounded-2xl p-4 lg:col-span-5">
          <div>
            <div className="mb-3 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">出口 IP 信息</h2>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setIpMasked((prev) => !prev)}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                  title={ipMasked ? "点击解除脱敏遮掩" : "点击恢复脱敏遮掩"}
                >
                  {ipMasked ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  <span>{ipMasked ? "已遮掩" : "已展开"}</span>
                </button>
                <button
                  type="button"
                  disabled={refreshingIp}
                  onClick={() => void handleRefreshExitIp()}
                  className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)] disabled:opacity-60"
                  title="手动刷新出口 IP"
                  aria-label="手动刷新出口 IP"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${refreshingIp ? "animate-spin" : ""}`} />
                </button>
              </div>
            </div>

            <div className="mb-3 flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider text-[var(--muted)]">
                  Exit IPv4
                </div>
                <div className="mt-0.5 truncate cc-mono cc-selectable text-base font-semibold tracking-tight text-[var(--text)]">
                  {displayedIp}
                </div>
              </div>
              <span
                className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2.5 py-1 text-[11px] font-medium ${googleCleanTone.cls}`}
              >
                {googleCleanTone.state === "clean" ? (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                ) : googleCleanTone.state === "risk" ? (
                  <ShieldAlert className="h-3.5 w-3.5" />
                ) : (
                  <Clock className="h-3.5 w-3.5" />
                )}
                <span>{googleCleanTone.label}</span>
              </span>
            </div>

            <dl className="space-y-2 text-xs">
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="text-[var(--muted)]">运营商 (ISP)</dt>
                <dd className="truncate font-medium text-[var(--text-secondary)]">
                  {exitIp.isp}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="text-[var(--muted)]">归属地区</dt>
                <dd className="font-medium text-[var(--text-secondary)]">{exitIp.location}</dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-[var(--muted)]">出口时区</dt>
                <dd className="cc-mono text-[var(--muted)]">{exitIp.timezone}</dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      {/* Bottom Row: Core Info Card + System Info Card */}
      <section className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* Core Information Card */}
        <div className="cc-card cc-glass rounded-2xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-[var(--accent)]" />
              <h2 className="text-sm font-semibold text-[var(--text)]">内核信息</h2>
            </div>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-medium ${
                runtime.running
                  ? "bg-[var(--green-soft)] text-[var(--green)]"
                  : "bg-[var(--amber-soft)] text-[var(--amber)]"
              }`}
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  backgroundColor: runtime.running ? "var(--green)" : "var(--amber)",
                }}
              />
              {runtime.running ? "运行中" : "待启动"}
            </span>
          </div>

          <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">核心名称与版本</dt>
              <dd className="mt-0.5 truncate cc-mono font-medium text-[var(--text)]">
                {runtime.core_name} {runtime.core_version}
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">混合端口 (HTTP / SOCKS5)</dt>
              <dd className="mt-0.5 cc-mono font-medium text-[var(--text)]">
                127.0.0.1:{runtime.mixed_port}
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">外部控制地址</dt>
              <dd className="mt-0.5 truncate cc-mono font-medium text-[var(--text-secondary)]">
                {runtime.controller_addr}
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">持续运行时间 / 规则数</dt>
              <dd className="mt-0.5 cc-mono font-medium text-[var(--text-secondary)]">
                {formatUptime(runtime.uptime_sec)} · {runtime.rule_count.toLocaleString()} 条
              </dd>
            </div>
          </dl>
        </div>

        {/* System Information Card */}
        <div className="cc-card cc-glass rounded-2xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Monitor className="h-4 w-4 text-[var(--accent)]" />
              <h2 className="text-sm font-semibold text-[var(--text)]">系统信息</h2>
            </div>
            <span className="inline-flex items-center gap-1 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 cc-mono text-[11px] text-[var(--accent)]">
              <ShieldCheck className="h-3 w-3" />
              v{runtime.app_version}
            </span>
          </div>

          <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">操作系统</dt>
              <dd className="mt-0.5 truncate font-medium text-[var(--text)]">
                {runtime.os_label}
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">开机自启</dt>
              <dd className="mt-0.5 font-medium">
                <span
                  style={{
                    color: runtime.autostart_enabled ? "var(--green)" : "var(--muted)",
                  }}
                >
                  {runtime.autostart_enabled ? "已开启" : "未开启"}
                </span>
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">运行模式</dt>
              <dd className="mt-0.5 font-medium text-[var(--text-secondary)]">
                {runtime.portable_mode ? "便携模式（data/ 隔离）" : "标准安装模式"}
              </dd>
            </div>
            <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2">
              <dt className="text-[11px] text-[var(--muted)]">上次检查更新</dt>
              <dd className="mt-0.5 truncate cc-mono font-medium text-[var(--text-secondary)]">
                {runtime.last_update_check ?? "尚未检查"}
              </dd>
            </div>
          </dl>
        </div>
      </section>
    </div>
  );
}
