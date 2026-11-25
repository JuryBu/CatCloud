import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  FileArchive,
  FileLock2,
  FolderPlus,
  KeyRound,
  Layers,
  Link2,
  Loader2,
  Package,
  QrCode,
  Radio,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  StopCircle,
  Upload,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type ShareBundlePreview,
  type SubscriptionUpdateMode,
  type SyncEncryptedFileExportDto,
  type SyncPreviewDto,
  type SyncReceiveSessionDto,
  type SyncReceivedEvent,
  type SyncSendSessionDto,
  catcloudApi,
  formatErrorMessage,
} from "../api/tauri";
import { type UiLanguage, normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";
import { getRegionLabel, resolveNodeRegionCode } from "../utils/regions";
import { AppSelect } from "./AppSelect";

export type ShareBundleTransport =
  | "zip"
  | "lan_send"
  | "relay_file"
  | "pull_input"
  | "listen_qr";

type ExportTransport = "zip" | "lan_send" | "relay_file";
type ImportTransport = "zip" | "pull_input" | "listen_qr";

export interface ShareBundleModalProps {
  open: boolean;
  mode: "export" | "import";
  onClose: () => void;
  initialNodeIds?: string[];
  initialRelayIds?: string[];
  defaultTab?: "nodes" | "relays";
  defaultPackName?: string;
  allowModeSwitch?: boolean;
  initialTransport?: ShareBundleTransport;
}

interface SyncMicroDict {
  pickCcsyncBtn: string;
  copyQrUri: string;
  copyKeyUri: string;
  waitingPush: string;
  sessionExpired: string;
  reExportBtn: string;
  backToEdit: string;
  savedFileLabel: string;
  fingerprintLabel: string;
  customUrlTag: string;
  syncSubTitle: string;
  pullEmptyHint: string;
  clearPreview: string;
  fetchingPreview: string;
  needSourceInput: string;
  needExportSelection: string;
  needImportSelection: string;
  needTargetSub: string;
  statusCompleted: string;
  statusEnded: string;
  groupsIncludedPrefix: string;
  groupsTabBadge: string;
  syncActionBusy: string;
  listenActionBusy: string;
  relayActionBusy: string;
  importOkPrefix: string;
}

const SYNC_MICRO_TEXT: Record<UiLanguage, SyncMicroDict> = {
  "zh-CN": {
    pickCcsyncBtn: "导入加密文件 (.ccsync)",
    copyQrUri: "复制同步链接",
    copyKeyUri: "复制密钥链接",
    waitingPush: "正在等待另一台设备扫码推送…",
    sessionExpired: "本次加密通道已超时关闭，请重新生成",
    reExportBtn: "重新导出",
    backToEdit: "返回修改勾选",
    savedFileLabel: "加密包已保存",
    fingerprintLabel: "校验指纹",
    customUrlTag: "穿透 / 组网",
    syncSubTitle: "端到端加密传输 · 支持局域网扫码、6位配对码、公网穿透与 .ccsync 离线中转",
    pullEmptyHint:
      "输入发送端显示的局域网地址 + 6 位码，粘贴完整同步链接，或直接选择 .ccsync 加密文件，拉取后可先预览勾选再导入。",
    clearPreview: "清除当前预览",
    fetchingPreview: "正在安全拉取并解析…",
    needSourceInput: "请输入发送方地址（ip:port）或同步链接",
    needExportSelection: "请至少勾选 1 个节点或 1 条国内提速中转线路",
    needImportSelection: "请至少勾选 1 个要导入的节点、中转或智能多选组",
    needTargetSub: "请选择要并入的目标已有分组",
    statusCompleted: "已完成传输",
    statusEnded: "本次会话已结束",
    groupsIncludedPrefix: "当前含智能多选组",
    groupsTabBadge: "多选组",
    syncActionBusy: "正在生成加密通道…",
    listenActionBusy: "正在开启接收通道…",
    relayActionBusy: "正在加密打包…",
    importOkPrefix: "配置导入完成",
  },
  en: {
    pickCcsyncBtn: "Import Encrypted File (.ccsync)",
    copyQrUri: "Copy Sync URI",
    copyKeyUri: "Copy Key URI",
    waitingPush: "Waiting for another device to scan & push…",
    sessionExpired: "This encrypted session has expired. Please generate a new code.",
    reExportBtn: "Export Again",
    backToEdit: "Back to Selection",
    savedFileLabel: "Encrypted File Saved",
    fingerprintLabel: "Fingerprint",
    customUrlTag: "Custom URL",
    syncSubTitle: "End-to-end encrypted · LAN QR, 6-digit PIN, overlay URL & .ccsync relay",
    pullEmptyHint:
      "Enter the sender's LAN address + 6-digit PIN, paste a sync URI, or choose a .ccsync file to safely preview and select items before importing.",
    clearPreview: "Clear Preview",
    fetchingPreview: "Fetching & decrypting…",
    needSourceInput: "Please enter a sender address (ip:port) or sync URI",
    needExportSelection: "Please select at least 1 node or domestic relay",
    needImportSelection: "Please select at least 1 node, relay, or smart group to import",
    needTargetSub: "Please select an existing target group",
    statusCompleted: "Transfer completed",
    statusEnded: "Session ended",
    groupsIncludedPrefix: "Smart groups in bundle",
    groupsTabBadge: "Groups",
    syncActionBusy: "Starting encrypted channel…",
    listenActionBusy: "Starting receive listener…",
    relayActionBusy: "Encrypting bundle…",
    importOkPrefix: "Import complete",
  },
  ja: {
    pickCcsyncBtn: "暗号化ファイルを取込 (.ccsync)",
    copyQrUri: "同期 URI をコピー",
    copyKeyUri: "鍵 URI をコピー",
    waitingPush: "別端末からのスキャン・送信を待機中…",
    sessionExpired: "セッションの有効期限が切れました。再生成してください。",
    reExportBtn: "もう一度出力",
    backToEdit: "選択に戻る",
    savedFileLabel: "暗号化ファイルを保存しました",
    fingerprintLabel: "指紋",
    customUrlTag: "外部 URL",
    syncSubTitle: "E2E 暗号化転送 · LAN QR・6桁コード・外部 URL・.ccsync 中継に対応",
    pullEmptyHint:
      "送信元の LAN アドレスと 6桁コード、同期 URI、または .ccsync ファイルを選択して、安全にプレビュー・選択取込できます。",
    clearPreview: "プレビューをクリア",
    fetchingPreview: "取得・復号中…",
    needSourceInput: "送信元アドレス（ip:port）または同期 URI を入力してください",
    needExportSelection: "ノードまたは国内中継を 1 件以上選択してください",
    needImportSelection: "取込むノード・中継・グループを 1 件以上選択してください",
    needTargetSub: "統合先の既存グループを選択してください",
    statusCompleted: "転送完了",
    statusEnded: "セッション終了",
    groupsIncludedPrefix: "同梱スマートグループ",
    groupsTabBadge: "グループ",
    syncActionBusy: "暗号化チャネルを作成中…",
    listenActionBusy: "受信待機を開始中…",
    relayActionBusy: "暗号化パックを作成中…",
    importOkPrefix: "取込が完了しました",
  },
  ru: {
    pickCcsyncBtn: "Импорт шифр-файла (.ccsync)",
    copyQrUri: "Копировать URI",
    copyKeyUri: "Копировать URI ключа",
    waitingPush: "Ожидание сканирования и отправки с другого устройства…",
    sessionExpired: "Сеанс истёк. Создайте новый QR-код.",
    reExportBtn: "Экспортировать снова",
    backToEdit: "Назад к выбору",
    savedFileLabel: "Шифр-файл сохранён",
    fingerprintLabel: "Отпечаток",
    customUrlTag: "Внешний URL",
    syncSubTitle: "Сквозное шифрование · LAN QR, 6-значный PIN, туннель и .ccsync",
    pullEmptyHint:
      "Введите LAN-адрес и 6-значный PIN отправителя, вставьте URI синхронизации или выберите .ccsync для предпросмотра перед импортом.",
    clearPreview: "Сбросить предпросмотр",
    fetchingPreview: "Загрузка и расшифровка…",
    needSourceInput: "Введите адрес отправителя (ip:port) или URI синхронизации",
    needExportSelection: "Выберите хотя бы 1 узел или реле",
    needImportSelection: "Выберите хотя бы 1 узел, реле или умную группу",
    needTargetSub: "Выберите существующую целевую группу",
    statusCompleted: "Передача завершена",
    statusEnded: "Сеанс завершён",
    groupsIncludedPrefix: "Умные группы в пакете",
    groupsTabBadge: "Группы",
    syncActionBusy: "Запуск канала…",
    listenActionBusy: "Открытие приёма…",
    relayActionBusy: "Шифрование пакета…",
    importOkPrefix: "Импорт завершён",
  },
};

function formatCreatedAt(raw: string | null | undefined): string {
  if (!raw) return "--";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}

function formatBytesShort(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatCountdown(remainingSec: number): string {
  const clamped = Math.max(0, Math.floor(remainingSec));
  const mm = String(Math.floor(clamped / 60)).padStart(2, "0");
  const ss = String(clamped % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

function formatPinDisplay(pin: string): string {
  const digits = pin.replace(/\s+/g, "");
  if (digits.length === 6) {
    return `${digits.slice(0, 3)} ${digits.slice(3)}`;
  }
  return pin;
}

function buildSafeSvgDataUri(rawSvg: string | null | undefined): string | null {
  if (!rawSvg) return null;
  const trimmed = rawSvg.trim();
  if (!trimmed.startsWith("<svg") && !trimmed.startsWith("<?xml")) return null;
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(trimmed)}`;
}

function resolveInitialExportTransport(t?: ShareBundleTransport): ExportTransport {
  if (t === "lan_send" || t === "relay_file" || t === "zip") return t;
  return "zip";
}

function resolveInitialImportTransport(t?: ShareBundleTransport): ImportTransport {
  if (t === "pull_input" || t === "listen_qr" || t === "zip") return t;
  return "zip";
}

export function ShareBundleModal({
  open,
  mode,
  onClose,
  initialNodeIds,
  initialRelayIds,
  defaultTab = "nodes",
  defaultPackName,
  allowModeSwitch = true,
  initialTransport,
}: ShareBundleModalProps) {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const relays = useAppSelector((s) => s.preAccelRelays);
  const groups = useAppSelector((s) => s.groups);
  const uiLang = useAppSelector((s) => s.config.personalization.ui_language);
  const normalizedLang = normalizeUiLanguage(uiLang);
  const dict = useUiDict(normalizedLang);
  const micro = SYNC_MICRO_TEXT[normalizedLang];

  const [activeMode, setActiveMode] = useState<"export" | "import">(mode);
  const [exportTransport, setExportTransport] = useState<ExportTransport>(() =>
    resolveInitialExportTransport(initialTransport)
  );
  const [importTransport, setImportTransport] = useState<ImportTransport>(() =>
    resolveInitialImportTransport(initialTransport)
  );

  // Export mode state
  const [exportTab, setExportTab] = useState<"nodes" | "relays">(defaultTab);
  const [packName, setPackName] = useState<string>(defaultPackName || "猫猫云梯分享包");
  const [packDesc, setPackDesc] = useState<string>("");
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(() => new Set());
  const [selectedRelayIds, setSelectedRelayIds] = useState<Set<string>>(() => new Set());
  const [exportSubFilter, setExportSubFilter] = useState<string>("all");
  const [exportRegionFilter, setExportRegionFilter] = useState<string>("all");
  const [exportNodeSearch, setExportNodeSearch] = useState<string>("");
  const [exporting, setExporting] = useState<boolean>(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Sync export options & active sessions
  const [includeGroups, setIncludeGroups] = useState<boolean>(true);
  const [allowMultipleSend, setAllowMultipleSend] = useState<boolean>(false);
  const [sendCustomEndpoint, setSendCustomEndpoint] = useState<string>("");
  const [startingSend, setStartingSend] = useState<boolean>(false);
  const [sendSession, setSendSession] = useState<SyncSendSessionDto | null>(null);
  const [sendSessionStatus, setSendSessionStatus] = useState<{
    status: string;
    message: string;
  } | null>(null);
  const [relayExportResult, setRelayExportResult] = useState<SyncEncryptedFileExportDto | null>(
    null
  );

  // Import mode state
  const [pickingZip, setPickingZip] = useState<boolean>(false);
  const [previewingSync, setPreviewingSync] = useState<boolean>(false);
  const [preview, setPreview] = useState<ShareBundlePreview | null>(null);
  const [syncPreview, setSyncPreview] = useState<SyncPreviewDto | null>(null);
  const [importGroups, setImportGroups] = useState<boolean>(true);
  const [importTab, setImportTab] = useState<"nodes" | "relays">("nodes");
  const [importNodeSearch, setImportNodeSearch] = useState<string>("");
  const [importNodeIds, setImportNodeIds] = useState<Set<string>>(() => new Set());
  const [importRelayIds, setImportRelayIds] = useState<Set<string>>(() => new Set());
  const [importDestMode, setImportDestMode] = useState<"new" | "existing">("new");
  const [importNewSubName, setImportNewSubName] = useState<string>("");
  const [importTargetSubId, setImportTargetSubId] = useState<string>("");
  const [importUpdateMode, setImportUpdateMode] = useState<SubscriptionUpdateMode>("merge_dedup");
  const [importing, setImporting] = useState<boolean>(false);
  const [importError, setImportError] = useState<string | null>(null);

  // Sync import pull & listen state
  const [syncSourceInput, setSyncSourceInput] = useState<string>("");
  const [syncPinInput, setSyncPinInput] = useState<string>("");
  const [receiveCustomEndpoint, setReceiveCustomEndpoint] = useState<string>("");
  const [allowMultipleReceive, setAllowMultipleReceive] = useState<boolean>(false);
  const [startingReceive, setStartingReceive] = useState<boolean>(false);
  const [receiveSession, setReceiveSession] = useState<SyncReceiveSessionDto | null>(null);
  const [receiveSessionStatus, setReceiveSessionStatus] = useState<{
    status: string;
    message: string;
  } | null>(null);
  const [receivedEventNotice, setReceivedEventNotice] = useState<SyncReceivedEvent | null>(null);

  // Shared UI helpers
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [nowUnixSec, setNowUnixSec] = useState<number>(() => Math.floor(Date.now() / 1000));

  // Refs for race-free cancellation & unmount cleanup
  const activeSendSessionRef = useRef<string | null>(null);
  const activeSendAllowMultiRef = useRef<boolean>(false);
  const activeReceiveSessionRef = useRef<string | null>(null);
  const modalOpenRef = useRef<boolean>(open);
  const sendRequestGenRef = useRef<number>(0);
  const receiveRequestGenRef = useRef<number>(0);
  const copyTimerRef = useRef<number | null>(null);
  const subscriptionsLenRef = useRef<number>(subscriptions.length);

  modalOpenRef.current = open;
  subscriptionsLenRef.current = subscriptions.length;

  const busy =
    exporting || pickingZip || importing || startingSend || startingReceive || previewingSync;

  const cancelActiveSendSession = useCallback(() => {
    sendRequestGenRef.current += 1;
    const sid = activeSendSessionRef.current;
    activeSendSessionRef.current = null;
    activeSendAllowMultiRef.current = false;
    setSendSession(null);
    setSendSessionStatus(null);
    if (sid) {
      void catcloudApi.cancelSyncSendSession(sid).catch(() => {
        /* ignore cleanup failure */
      });
    }
  }, []);

  const cancelActiveReceiveSession = useCallback(() => {
    receiveRequestGenRef.current += 1;
    const sid = activeReceiveSessionRef.current;
    activeReceiveSessionRef.current = null;
    setReceiveSession(null);
    setReceiveSessionStatus(null);
    if (sid) {
      void catcloudApi.cancelSyncReceiveSession(sid).catch(() => {
        /* ignore cleanup failure */
      });
    }
  }, []);

  const cancelAllSyncSessions = useCallback(() => {
    cancelActiveSendSession();
    cancelActiveReceiveSession();
  }, [cancelActiveSendSession, cancelActiveReceiveSession]);

  const handleRequestClose = useCallback(() => {
    if (busy) return;
    cancelAllSyncSessions();
    onClose();
  }, [busy, cancelAllSyncSessions, onClose]);

  const copyToClipboard = useCallback(async (key: string, value: string) => {
    if (!value) return;
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else if (typeof document !== "undefined") {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopiedKey(key);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
        copyTimerRef.current = null;
      }, 1800);
    } catch {
      /* ignore clipboard failure */
    }
  }, []);

  const applySyncPreviewState = useCallback((res: SyncPreviewDto) => {
    setSyncPreview(res);
    setPreview(res.preview);
    setImportGroups(res.group_count > 0);
    setImportNodeIds(new Set(res.preview.nodes.map((n) => n.id)));
    setImportRelayIds(new Set(res.preview.relays.map((r) => r.id)));
    setImportNodeSearch("");
    setImportNewSubName(res.preview.manifest.name?.trim() || "CatCloud Sync");
    setImportTab(res.preview.nodes.length > 0 ? "nodes" : "relays");
    if (subscriptionsLenRef.current === 0) {
      setImportDestMode("new");
    }
  }, []);

  // Ensure active backend sync sessions and timers are cleaned up on unmount
  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
      const sendSid = activeSendSessionRef.current;
      activeSendSessionRef.current = null;
      if (sendSid) {
        void catcloudApi.cancelSyncSendSession(sendSid).catch(() => {});
      }
      const recvSid = activeReceiveSessionRef.current;
      activeReceiveSessionRef.current = null;
      if (recvSid) {
        void catcloudApi.cancelSyncReceiveSession(recvSid).catch(() => {});
      }
    };
  }, []);

  // Cancel any active sync sessions whenever modal closes
  useEffect(() => {
    if (!open) {
      cancelAllSyncSessions();
    }
  }, [open, cancelAllSyncSessions]);

  // Reset modal session cleanly whenever opened
  useEffect(() => {
    if (!open) return;

    const nextExportTransport = resolveInitialExportTransport(initialTransport);
    const nextImportTransport = resolveInitialImportTransport(initialTransport);

    setActiveMode(mode);
    setExportTransport(nextExportTransport);
    setImportTransport(nextImportTransport);
    setExportTab(defaultTab);
    setPackName(defaultPackName?.trim() || "猫猫云梯分享包");
    setPackDesc("");
    setExportSubFilter("all");
    setExportRegionFilter("all");
    setExportNodeSearch("");
    setExportError(null);

    setIncludeGroups(true);
    setAllowMultipleSend(false);
    setSendCustomEndpoint("");
    setSendSession(null);
    setSendSessionStatus(null);
    setRelayExportResult(null);

    const existingNodeIdSet = new Set(nodes.map((n) => n.id));
    const initNodes = new Set<string>();
    const hasExplicitSelection =
      (Array.isArray(initialNodeIds) && initialNodeIds.length > 0) ||
      (Array.isArray(initialRelayIds) && initialRelayIds.length > 0);
    const isSyncQuickExport =
      mode === "export" &&
      (nextExportTransport === "lan_send" || nextExportTransport === "relay_file");

    if (Array.isArray(initialNodeIds)) {
      for (const id of initialNodeIds) {
        if (existingNodeIdSet.has(id)) initNodes.add(id);
      }
    } else if (isSyncQuickExport && !hasExplicitSelection) {
      for (const n of nodes) initNodes.add(n.id);
    }
    setSelectedNodeIds(initNodes);

    const existingRelayIdSet = new Set(relays.map((r) => r.id));
    const initRelays = new Set<string>();
    if (Array.isArray(initialRelayIds)) {
      for (const id of initialRelayIds) {
        if (existingRelayIdSet.has(id)) initRelays.add(id);
      }
    } else if (isSyncQuickExport && !hasExplicitSelection) {
      for (const r of relays) {
        if (r.enabled) initRelays.add(r.id);
      }
    }
    setSelectedRelayIds(initRelays);

    setPreview(null);
    setSyncPreview(null);
    setImportGroups(true);
    setImportTab("nodes");
    setImportNodeSearch("");
    setImportNodeIds(new Set());
    setImportRelayIds(new Set());
    setImportDestMode("new");
    setImportNewSubName("");
    setImportTargetSubId(subscriptions[0]?.id ?? "");
    setImportUpdateMode("merge_dedup");
    setImportError(null);
    setSyncSourceInput("");
    setSyncPinInput("");
    setReceiveCustomEndpoint("");
    setAllowMultipleReceive(false);
    setReceiveSession(null);
    setReceiveSessionStatus(null);
    setReceivedEventNotice(null);
    setCopiedKey(null);
    // Intentionally initialize only when opening modal or changing entry props
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, mode, defaultTab, defaultPackName, initialNodeIds, initialRelayIds, initialTransport]);

  // Keep valid targetSubId if subscriptions change
  useEffect(() => {
    if (!open) return;
    if (subscriptions.length === 0) {
      if (importDestMode === "existing") setImportDestMode("new");
      if (importTargetSubId !== "") setImportTargetSubId("");
    } else if (!subscriptions.some((s) => s.id === importTargetSubId)) {
      setImportTargetSubId(subscriptions[0].id);
    }
  }, [open, subscriptions, importDestMode, importTargetSubId]);

  // Escape to close when not busy
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !busy) {
        handleRequestClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, busy, handleRequestClose]);

  // Countdown ticker only while an active send or receive session is displayed
  const hasCountdownSession = sendSession !== null || receiveSession !== null;
  useEffect(() => {
    if (!open || !hasCountdownSession) return;
    setNowUnixSec(Math.floor(Date.now() / 1000));
    const tid = window.setInterval(() => {
      setNowUnixSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(tid);
  }, [open, hasCountdownSession]);

  // Subscribe to Tauri sync events while modal is open
  useEffect(() => {
    if (!open) return;

    const unsubReceived = catcloudApi.subscribeSyncReceived((ev) => {
      if (!modalOpenRef.current || !ev?.pending_token) return;
      if (
        activeReceiveSessionRef.current &&
        ev.session_id &&
        ev.session_id !== activeReceiveSessionRef.current
      ) {
        return;
      }
      setReceivedEventNotice(ev);
      setImportError(null);
      setPreviewingSync(true);
      void catcloudApi
        .previewSyncSource({ pendingToken: ev.pending_token })
        .then((res) => {
          if (!modalOpenRef.current || !res) return;
          applySyncPreviewState(res);
          appActions.showToast(`${dict.sync.receivedTitle}: ${ev.pack_name}`, "ok", 4200);
        })
        .catch((err) => {
          if (!modalOpenRef.current) return;
          const msg = formatErrorMessage(err);
          setImportError(msg);
          appActions.showToast(msg, "warn");
        })
        .finally(() => {
          if (modalOpenRef.current) {
            setPreviewingSync(false);
          }
        });
    });

    const unsubUpdated = catcloudApi.subscribeSyncSessionUpdated((ev) => {
      if (!modalOpenRef.current || !ev) return;
      if (ev.session_id && ev.session_id === activeSendSessionRef.current) {
        setSendSessionStatus({ status: ev.status, message: ev.message });
        if (
          ev.status === "expired" ||
          ev.status === "destroyed" ||
          ev.status === "cancelled" ||
          (ev.status === "completed" && !activeSendAllowMultiRef.current)
        ) {
          activeSendSessionRef.current = null;
        }
      } else if (ev.session_id && ev.session_id === activeReceiveSessionRef.current) {
        setReceiveSessionStatus({ status: ev.status, message: ev.message });
        if (
          ev.status === "expired" ||
          ev.status === "destroyed" ||
          ev.status === "cancelled"
        ) {
          activeReceiveSessionRef.current = null;
        }
      }
    });

    return () => {
      unsubReceived();
      unsubUpdated();
    };
  }, [open, applySyncPreviewState, dict.sync.receivedTitle]);

  const subNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) {
      map.set(s.id, s.name);
    }
    return map;
  }, [subscriptions]);

  const subNodeCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  const exportRegionOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      if (exportSubFilter !== "all" && n.sub_id !== exportSubFilter) continue;
      const code = resolveNodeRegionCode(n);
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    const items = Array.from(counts.entries())
      .map(([code, count]) => ({
        value: code,
        label: `${getRegionLabel(code)} (${code}) · ${count}`,
        count,
      }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    return [{ value: "all", label: "全部地区" }, ...items.map(({ value, label }) => ({ value, label }))];
  }, [nodes, exportSubFilter]);

  const filteredExportNodes = useMemo(() => {
    const kw = exportNodeSearch.trim().toLowerCase();
    return nodes.filter((n) => {
      if (exportSubFilter !== "all" && n.sub_id !== exportSubFilter) return false;
      const regionCode = resolveNodeRegionCode(n);
      if (exportRegionFilter !== "all" && regionCode !== exportRegionFilter) return false;
      if (kw) {
        const subName = subNameMap.get(n.sub_id) ?? "";
        const regionLabel = getRegionLabel(regionCode);
        const hay = `${n.name} ${subName} ${regionCode} ${regionLabel} ${n.protocol}`.toLowerCase();
        if (!hay.includes(kw)) return false;
      }
      return true;
    });
  }, [nodes, exportSubFilter, exportRegionFilter, exportNodeSearch, subNameMap]);

  const allFilteredExportNodesSelected = useMemo(
    () =>
      filteredExportNodes.length > 0 &&
      filteredExportNodes.every((n) => selectedNodeIds.has(n.id)),
    [filteredExportNodes, selectedNodeIds]
  );

  const filteredImportNodes = useMemo(() => {
    if (!preview) return [];
    const kw = importNodeSearch.trim().toLowerCase();
    if (!kw) return preview.nodes;
    return preview.nodes.filter((n) => {
      const code = resolveNodeRegionCode(n);
      const label = getRegionLabel(code);
      const hay = `${n.name} ${code} ${label} ${n.protocol} ${n.server}`.toLowerCase();
      return hay.includes(kw);
    });
  }, [preview, importNodeSearch]);

  const sendQrSrc = useMemo(() => buildSafeSvgDataUri(sendSession?.qr_svg), [sendSession?.qr_svg]);
  const relayQrSrc = useMemo(
    () => buildSafeSvgDataUri(relayExportResult?.qr_svg),
    [relayExportResult?.qr_svg]
  );
  const receiveQrSrc = useMemo(
    () => buildSafeSvgDataUri(receiveSession?.qr_svg),
    [receiveSession?.qr_svg]
  );

  const toggleExportNode = (id: string) => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleExportRelay = (id: string) => {
    setSelectedRelayIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAllFilteredExportNodes = () => {
    if (filteredExportNodes.length === 0) return;
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      for (const n of filteredExportNodes) next.add(n.id);
      return next;
    });
  };

  const handleClearFilteredExportNodes = () => {
    if (filteredExportNodes.length === 0) return;
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      for (const n of filteredExportNodes) next.delete(n.id);
      return next;
    });
  };

  const handleSwitchMode = (nextMode: "export" | "import") => {
    if (busy || nextMode === activeMode) return;
    if (nextMode === "export") {
      cancelActiveReceiveSession();
    } else {
      cancelActiveSendSession();
    }
    setActiveMode(nextMode);
  };

  const handleSwitchExportTransport = (next: ExportTransport) => {
    if (busy || next === exportTransport) return;
    if (exportTransport === "lan_send") {
      cancelActiveSendSession();
    }
    if (next !== "relay_file") {
      setRelayExportResult(null);
    }
    setExportError(null);
    setExportTransport(next);
  };

  const handleSwitchImportTransport = (next: ImportTransport) => {
    if (busy || next === importTransport) return;
    if (importTransport === "listen_qr") {
      cancelActiveReceiveSession();
    }
    setImportError(null);
    setImportTransport(next);
  };

  const handleExportBundle = async () => {
    if (busy) return;
    const nodeIds = Array.from(selectedNodeIds);
    const relayIds = Array.from(selectedRelayIds);
    if (nodeIds.length === 0 && relayIds.length === 0) {
      setExportError(micro.needExportSelection);
      return;
    }

    setExporting(true);
    setExportError(null);
    try {
      const res = await catcloudApi.exportShareBundleDialog({
        name: packName.trim() || "猫猫云梯分享包",
        description: packDesc.trim() || null,
        nodeIds,
        relayIds,
      });
      if (res.cancelled) {
        return;
      }
      const savedPath = res.path ? `：${res.path}` : "";
      appActions.showToast(
        `${dict.share.exportBtn} (${nodeIds.length} / ${relayIds.length})${savedPath}`,
        "ok",
        5200
      );
      handleRequestClose();
    } catch (err) {
      const msg = formatErrorMessage(err);
      setExportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      setExporting(false);
    }
  };

  const handleStartSyncSend = async () => {
    if (busy) return;
    const nodeIds = Array.from(selectedNodeIds);
    const relayIds = Array.from(selectedRelayIds);
    if (nodeIds.length === 0 && relayIds.length === 0) {
      setExportError(micro.needExportSelection);
      return;
    }

    cancelActiveSendSession();
    const reqGen = ++sendRequestGenRef.current;
    setStartingSend(true);
    setExportError(null);
    try {
      const session = await catcloudApi.startSyncSendSession({
        name: packName.trim() || "CatCloud Sync",
        description: packDesc.trim() || null,
        nodeIds,
        relayIds,
        includeGroups,
        customEndpoint: sendCustomEndpoint.trim() || null,
        ttlSec: 180,
        allowMultiple: allowMultipleSend,
      });
      if (!modalOpenRef.current || sendRequestGenRef.current !== reqGen) {
        void catcloudApi.cancelSyncSendSession(session.session_id).catch(() => {});
        return;
      }
      activeSendSessionRef.current = session.session_id;
      activeSendAllowMultiRef.current = session.allow_multiple;
      setSendSession(session);
      setSendSessionStatus(null);
      setNowUnixSec(Math.floor(Date.now() / 1000));
    } catch (err) {
      if (sendRequestGenRef.current !== reqGen) return;
      const msg = formatErrorMessage(err);
      setExportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      if (sendRequestGenRef.current === reqGen) {
        setStartingSend(false);
      }
    }
  };

  const handleExportEncryptedSync = async () => {
    if (busy) return;
    const nodeIds = Array.from(selectedNodeIds);
    const relayIds = Array.from(selectedRelayIds);
    if (nodeIds.length === 0 && relayIds.length === 0) {
      setExportError(micro.needExportSelection);
      return;
    }

    setExporting(true);
    setExportError(null);
    try {
      const res = await catcloudApi.exportEncryptedSyncFile({
        name: packName.trim() || "CatCloud Sync",
        description: packDesc.trim() || null,
        nodeIds,
        relayIds,
        includeGroups,
      });
      if (res.cancelled) {
        return;
      }
      setRelayExportResult(res);
      appActions.showToast(
        res.path ? `${micro.savedFileLabel}: ${res.path}` : micro.savedFileLabel,
        "ok",
        4600
      );
    } catch (err) {
      const msg = formatErrorMessage(err);
      setExportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      setExporting(false);
    }
  };

  const handlePickPreviewZip = async () => {
    if (busy) return;
    setPickingZip(true);
    setImportError(null);
    try {
      const res = await catcloudApi.pickAndPreviewShareBundle();
      if (!res) {
        return;
      }
      setSyncPreview(null);
      setReceivedEventNotice(null);
      setPreview(res);
      setImportNodeIds(new Set(res.nodes.map((n) => n.id)));
      setImportRelayIds(new Set(res.relays.map((r) => r.id)));
      setImportNodeSearch("");
      setImportNewSubName(res.manifest.name?.trim() || "朋友分享包");
      setImportTab(res.nodes.length > 0 ? "nodes" : "relays");
      if (subscriptions.length === 0) {
        setImportDestMode("new");
      }
    } catch (err) {
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      setPickingZip(false);
    }
  };

  const handlePreviewSyncPull = async (pickCcsyncFile: boolean) => {
    if (busy) return;
    const trimmedSource = syncSourceInput.trim();
    const cleanedPin = syncPinInput.replace(/\s+/g, "").trim();
    if (!pickCcsyncFile && !trimmedSource) {
      setImportError(micro.needSourceInput);
      return;
    }

    setPreviewingSync(true);
    setImportError(null);
    try {
      const res = await catcloudApi.previewSyncSource({
        sourceInput: trimmedSource || null,
        pin: cleanedPin || null,
        pendingToken: null,
        pickCcsyncFile,
      });
      if (!res) {
        return;
      }
      setReceivedEventNotice(null);
      applySyncPreviewState(res);
    } catch (err) {
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      setPreviewingSync(false);
    }
  };

  const handleStartReceiveListener = async () => {
    if (busy) return;
    cancelActiveReceiveSession();
    const reqGen = ++receiveRequestGenRef.current;
    setStartingReceive(true);
    setImportError(null);
    setReceivedEventNotice(null);
    try {
      const session = await catcloudApi.startSyncReceiveListener({
        customEndpoint: receiveCustomEndpoint.trim() || null,
        ttlSec: 180,
        allowMultiple: allowMultipleReceive,
      });
      if (!modalOpenRef.current || receiveRequestGenRef.current !== reqGen) {
        void catcloudApi.cancelSyncReceiveSession(session.session_id).catch(() => {});
        return;
      }
      activeReceiveSessionRef.current = session.session_id;
      setReceiveSession(session);
      setReceiveSessionStatus(null);
      setNowUnixSec(Math.floor(Date.now() / 1000));
    } catch (err) {
      if (receiveRequestGenRef.current !== reqGen) return;
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      if (receiveRequestGenRef.current === reqGen) {
        setStartingReceive(false);
      }
    }
  };

  const handleClearImportPreview = () => {
    if (busy) return;
    setPreview(null);
    setSyncPreview(null);
    setReceivedEventNotice(null);
    setImportNodeIds(new Set());
    setImportRelayIds(new Set());
    setImportError(null);
  };

  const toggleImportNode = (id: string) => {
    setImportNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleImportRelay = (id: string) => {
    setImportRelayIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleConfirmImport = async () => {
    if (!preview || busy) return;
    const pickedNodes = Array.from(importNodeIds);
    const pickedRelays = Array.from(importRelayIds);
    const willImportGroups = Boolean(syncPreview && syncPreview.group_count > 0 && importGroups);

    if (pickedNodes.length === 0 && pickedRelays.length === 0 && !willImportGroups) {
      setImportError(micro.needImportSelection);
      return;
    }
    if (pickedNodes.length > 0 && importDestMode === "existing" && !importTargetSubId) {
      setImportError(micro.needTargetSub);
      return;
    }

    setImporting(true);
    setImportError(null);
    try {
      const targetSubId =
        pickedNodes.length > 0 && importDestMode === "existing" ? importTargetSubId : null;
      const newSubName =
        pickedNodes.length > 0 && importDestMode === "new"
          ? importNewSubName.trim() || preview.manifest.name?.trim() || "CatCloud Sync"
          : null;

      const outcome = syncPreview
        ? await catcloudApi.applySyncImport({
            pendingToken: syncPreview.pending_token,
            selectedNodeIds: pickedNodes,
            selectedRelayIds: pickedRelays,
            importGroups: willImportGroups,
            targetSubId,
            newSubName,
            updateMode: importUpdateMode,
          })
        : await catcloudApi.importShareBundle({
            zipPath: preview.zip_path,
            selectedNodeIds: pickedNodes,
            selectedRelayIds: pickedRelays,
            targetSubId,
            newSubName,
            updateMode: importUpdateMode,
          });

      await appActions.refreshAllData();

      const summaryParts: string[] = [];
      if (outcome.imported_nodes > 0) {
        const subSuffix = outcome.target_sub_name ? ` (${outcome.target_sub_name})` : "";
        summaryParts.push(`${outcome.imported_nodes} nodes${subSuffix}`);
      }
      if (outcome.imported_relays > 0) {
        summaryParts.push(`${outcome.imported_relays} relays`);
      }
      if (willImportGroups && syncPreview) {
        summaryParts.push(`${syncPreview.group_count} ${micro.groupsTabBadge}`);
      }
      const warnSuffix =
        outcome.warnings.length > 0 ? ` (${outcome.warnings.length} warnings)` : "";
      appActions.showToast(
        `${micro.importOkPrefix}: ${summaryParts.join(" · ") || dict.common.confirm}${warnSuffix}`,
        "ok",
        5000
      );
      cancelAllSyncSessions();
      onClose();
    } catch (err) {
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(msg, "warn");
    } finally {
      setImporting(false);
    }
  };

  if (!open || typeof document === "undefined") return null;

  const totalExportSelected = selectedNodeIds.size + selectedRelayIds.size;
  const effectiveGroupImportCount =
    syncPreview && syncPreview.group_count > 0 && importGroups ? syncPreview.group_count : 0;
  const totalImportSelected =
    importNodeIds.size + importRelayIds.size + effectiveGroupImportCount;

  const isSyncExportTab = exportTransport === "lan_send" || exportTransport === "relay_file";
  const isSyncImportTab = importTransport === "pull_input" || importTransport === "listen_qr";

  const sendRemainingSec = sendSession
    ? Math.max(0, sendSession.expires_at_unix - nowUnixSec)
    : 0;
  const sendExpired = sendSession !== null && sendRemainingSec <= 0;

  const receiveRemainingSec = receiveSession
    ? Math.max(0, receiveSession.expires_at_unix - nowUnixSec)
    : 0;
  const receiveExpired = receiveSession !== null && receiveRemainingSec <= 0;

  const modalTitle =
    activeMode === "export"
      ? isSyncExportTab
        ? dict.sync.entryBtn
        : dict.share.exportTitle
      : isSyncImportTab
        ? dict.sync.entryBtn
        : dict.share.importTitle;

  const modalSubtitle =
    (activeMode === "export" && isSyncExportTab) || (activeMode === "import" && isSyncImportTab)
      ? micro.syncSubTitle
      : activeMode === "export"
        ? "把精选节点或国内提速中转打包成单个 .zip，方便私发给信任的朋友一键导入"
        : "选择朋友发来的猫云 .zip 分享包，预览并自由勾选要导入的节点与中转";

  const sendUrlsToShow = sendSession
    ? [
        ...(sendSession.custom_endpoint
          ? [{ url: sendSession.custom_endpoint, isCustom: true }]
          : []),
        ...sendSession.lan_urls
          .filter((u) => u && u !== sendSession.custom_endpoint)
          .map((u) => ({ url: u, isCustom: false })),
      ]
    : [];

  const receiveUrlsToShow = receiveSession
    ? [
        ...(receiveSession.custom_endpoint
          ? [{ url: receiveSession.custom_endpoint, isCustom: true }]
          : []),
        ...receiveSession.lan_urls
          .filter((u) => u && u !== receiveSession.custom_endpoint)
          .map((u) => ({ url: u, isCustom: false })),
      ]
    : [];

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={handleRequestClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={modalTitle}
        onClick={(e) => e.stopPropagation()}
        className="cc-surface flex max-h-[88vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] shadow-2xl"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between gap-3 border-b border-[var(--line)] px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
              {(activeMode === "export" && isSyncExportTab) ||
              (activeMode === "import" && isSyncImportTab) ? (
                <QrCode className="h-4 w-4" />
              ) : (
                <Package className="h-4 w-4" />
              )}
            </span>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-[var(--text)]">{modalTitle}</h3>
              <p className="mt-0.5 truncate text-[11px] text-[var(--muted)]">{modalSubtitle}</p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            {allowModeSwitch && (
              <div
                className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
                role="tablist"
                aria-label={dict.common.shareBundle}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeMode === "export"}
                  disabled={busy}
                  onClick={() => handleSwitchMode("export")}
                  className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    activeMode === "export"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  <Upload className="h-3 w-3" />
                  <span>{dict.common.export}</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeMode === "import"}
                  disabled={busy}
                  onClick={() => handleSwitchMode("import")}
                  className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    activeMode === "import"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  <Download className="h-3 w-3" />
                  <span>{dict.common.import}</span>
                </button>
              </div>
            )}

            <button
              type="button"
              disabled={busy}
              onClick={handleRequestClose}
              aria-label={dict.common.close}
              className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-45"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Transport Segmented Switcher Bar */}
        <div className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/45 px-5 py-2">
          {activeMode === "export" ? (
            <div
              className="grid grid-cols-1 gap-1.5 sm:grid-cols-3"
              role="tablist"
              aria-label={dict.common.export}
            >
              <button
                type="button"
                role="tab"
                aria-selected={exportTransport === "zip"}
                disabled={busy}
                onClick={() => handleSwitchExportTransport("zip")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  exportTransport === "zip"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <FileArchive className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modeZipExport}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={exportTransport === "lan_send"}
                disabled={busy}
                onClick={() => handleSwitchExportTransport("lan_send")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  exportTransport === "lan_send"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <QrCode className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modeLanSend}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={exportTransport === "relay_file"}
                disabled={busy}
                onClick={() => handleSwitchExportTransport("relay_file")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  exportTransport === "relay_file"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <KeyRound className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modeRelayExport}</span>
              </button>
            </div>
          ) : (
            <div
              className="grid grid-cols-1 gap-1.5 sm:grid-cols-3"
              role="tablist"
              aria-label={dict.common.import}
            >
              <button
                type="button"
                role="tab"
                aria-selected={importTransport === "zip"}
                disabled={busy}
                onClick={() => handleSwitchImportTransport("zip")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  importTransport === "zip"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <FileArchive className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modeZipImport}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={importTransport === "pull_input"}
                disabled={busy}
                onClick={() => handleSwitchImportTransport("pull_input")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  importTransport === "pull_input"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <Link2 className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modePullInput}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={importTransport === "listen_qr"}
                disabled={busy}
                onClick={() => handleSwitchImportTransport("listen_qr")}
                className={`inline-flex items-center justify-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  importTransport === "listen_qr"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                <Radio className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{dict.sync.modeListenQr}</span>
              </button>
            </div>
          )}
        </div>

        {/* Scrollable Body */}
        <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto px-5 py-4">
          {activeMode === "export" ? (
            exportTransport === "lan_send" && sendSession ? (
              /* ======================== ACTIVE LAN SEND QR VIEW ======================== */
              <div className="space-y-3.5">
                {/* Status Strip */}
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 px-3.5 py-2.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 cc-mono text-[11px] font-semibold ${
                        sendExpired
                          ? "bg-[var(--red-soft)] text-[var(--red)]"
                          : "bg-[var(--accent-soft)] text-[var(--accent)]"
                      }`}
                    >
                      <Clock className="h-3 w-3" />
                      <span>{formatCountdown(sendRemainingSec)}</span>
                    </span>
                    <span className="cc-mono text-[11px] text-[var(--muted)]">
                      {formatBytesShort(sendSession.payload_bytes)}
                    </span>
                    {sendSession.fingerprint && (
                      <span
                        title={sendSession.fingerprint}
                        className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 cc-mono text-[10.5px] text-[var(--text-secondary)]"
                      >
                        {micro.fingerprintLabel}: {sendSession.fingerprint.slice(0, 10)}
                      </span>
                    )}
                  </div>

                  {sendSessionStatus && (
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-medium ${
                        sendSessionStatus.status === "completed"
                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                          : sendSessionStatus.status === "expired" ||
                              sendSessionStatus.status === "destroyed"
                            ? "bg-[var(--red-soft)] text-[var(--red)]"
                            : "bg-[var(--amber-soft)] text-[var(--amber)]"
                      }`}
                    >
                      <CheckCircle2 className="h-3 w-3" />
                      <span>
                        {sendSessionStatus.message ||
                          (sendSessionStatus.status === "completed"
                            ? micro.statusCompleted
                            : micro.statusEnded)}
                      </span>
                    </span>
                  )}
                </div>

                {sendExpired && (
                  <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3.5 py-2.5 text-xs text-[var(--red)]">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                      <span>{micro.sessionExpired}</span>
                    </div>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleStartSyncSend()}
                      className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] hover:opacity-90"
                    >
                      <RotateCcw className="h-3 w-3" />
                      <span>{dict.sync.startSendBtn}</span>
                    </button>
                  </div>
                )}

                {/* Centered QR + PIN + Addresses */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-12">
                  <div className="flex flex-col items-center justify-center rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)]/60 p-4 sm:col-span-5">
                    {sendQrSrc && (
                      <div className="rounded-2xl border border-black/10 bg-white p-2.5 shadow-sm">
                        <img
                          src={sendQrSrc}
                          alt={dict.sync.modeLanSend}
                          draggable={false}
                          className="h-44 w-44 select-none object-contain"
                        />
                      </div>
                    )}
                    <button
                      type="button"
                      onClick={() => void copyToClipboard("send-qr-uri", sendSession.qr_uri)}
                      className="mt-3 inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    >
                      {copiedKey === "send-qr-uri" ? (
                        <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {copiedKey === "send-qr-uri" ? dict.common.copied : micro.copyQrUri}
                      </span>
                    </button>
                  </div>

                  <div className="flex flex-col justify-between gap-3 sm:col-span-7">
                    {/* Large Monospace 6-Digit PIN */}
                    <div className="rounded-2xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/35 p-3.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                          {dict.sync.pinLabel}
                        </span>
                        <button
                          type="button"
                          onClick={() => void copyToClipboard("send-pin", sendSession.pin_code)}
                          className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          {copiedKey === "send-pin" ? (
                            <Check className="h-3 w-3 text-[var(--green)]" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          <span>
                            {copiedKey === "send-pin" ? dict.common.copied : dict.common.copy}
                          </span>
                        </button>
                      </div>
                      <div className="mt-1.5 select-all cc-mono text-3xl font-bold tracking-[0.26em] text-[var(--accent)]">
                        {formatPinDisplay(sendSession.pin_code)}
                      </div>
                    </div>

                    {/* LAN & Custom Endpoint URLs */}
                    <div className="space-y-1.5 rounded-2xl border border-[var(--line)] bg-[var(--card)]/75 p-3">
                      <div className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)]">
                        <Wifi className="h-3.5 w-3.5 text-[var(--accent)]" />
                        <span>{dict.sync.addressLabel}</span>
                      </div>
                      <div className="max-h-32 space-y-1.5 overflow-y-auto pr-0.5">
                        {sendUrlsToShow.map((item, idx) => {
                          const copyId = `send-url-${idx}`;
                          return (
                            <div
                              key={`${item.url}-${idx}`}
                              className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5"
                            >
                              <div className="flex min-w-0 items-center gap-1.5">
                                {item.isCustom && (
                                  <span className="shrink-0 rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                                    {micro.customUrlTag}
                                  </span>
                                )}
                                <span
                                  className="truncate cc-mono text-[11px] text-[var(--text)]"
                                  title={item.url}
                                >
                                  {item.url}
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => void copyToClipboard(copyId, item.url)}
                                className="inline-flex shrink-0 items-center gap-1 rounded-lg px-2 py-0.5 text-[10.5px] font-medium text-[var(--text-secondary)] transition-colors hover:bg-[var(--card)] hover:text-[var(--accent)]"
                              >
                                {copiedKey === copyId ? (
                                  <Check className="h-3 w-3 text-[var(--green)]" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                                <span>
                                  {copiedKey === copyId ? dict.common.copied : dict.common.copy}
                                </span>
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Firewall & TTL Hints */}
                <div className="space-y-1.5 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/50 px-3.5 py-2.5 text-[11.5px] leading-relaxed text-[var(--amber)]">
                  <p>{dict.sync.firewallHint}</p>
                  <p className="text-[11px] opacity-90">{dict.sync.ttlHint}</p>
                </div>
              </div>
            ) : exportTransport === "relay_file" && relayExportResult ? (
              /* ======================== ENCRYPTED RELAY KEY QR VIEW ======================== */
              <div className="space-y-3.5">
                <div className="flex items-start gap-2.5 rounded-xl border border-[var(--green)]/45 bg-[var(--green-soft)]/55 px-3.5 py-2.5 text-xs text-[var(--green)]">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="font-semibold">
                      {micro.savedFileLabel} · {formatBytesShort(relayExportResult.payload_bytes)} (
                      {relayExportResult.node_count} / {relayExportResult.relay_count}
                      {relayExportResult.group_count > 0
                        ? ` / ${relayExportResult.group_count} ${micro.groupsTabBadge}`
                        : ""}
                      )
                    </div>
                    {relayExportResult.path && (
                      <div
                        className="mt-0.5 truncate cc-mono text-[11px] opacity-90"
                        title={relayExportResult.path}
                      >
                        {relayExportResult.path}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex flex-col items-center rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)]/65 p-5">
                  {relayQrSrc && (
                    <div className="rounded-2xl border border-black/10 bg-white p-2.5 shadow-sm">
                      <img
                        src={relayQrSrc}
                        alt={dict.sync.modeRelayExport}
                        draggable={false}
                        className="h-48 w-48 select-none object-contain"
                      />
                    </div>
                  )}

                  {relayExportResult.fingerprint && (
                    <span className="mt-2.5 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-0.5 cc-mono text-[10.5px] text-[var(--muted)]">
                      {micro.fingerprintLabel}: {relayExportResult.fingerprint.slice(0, 12)}
                    </span>
                  )}

                  <div className="mt-3 flex w-full max-w-lg items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2">
                    <code
                      className="min-w-0 flex-1 truncate cc-mono text-[11px] text-[var(--text)]"
                      title={relayExportResult.key_uri}
                    >
                      {relayExportResult.key_uri}
                    </code>
                    <button
                      type="button"
                      onClick={() => void copyToClipboard("relay-key-uri", relayExportResult.key_uri)}
                      className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] hover:opacity-90"
                    >
                      {copiedKey === "relay-key-uri" ? (
                        <Check className="h-3 w-3" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                      <span>
                        {copiedKey === "relay-key-uri" ? dict.common.copied : micro.copyKeyUri}
                      </span>
                    </button>
                  </div>
                </div>

                <div className="flex items-start gap-2 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/50 px-3.5 py-2.5 text-xs text-[var(--amber)]">
                  <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
                  <p className="leading-relaxed">{dict.sync.relayKeyHint}</p>
                </div>
              </div>
            ) : (
              /* ======================== SHARED EXPORT SELECTION VIEW ======================== */
              <>
                {/* Warm Amber Privacy Notice */}
                <div className="flex items-start gap-2.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/70 px-3.5 py-2.5 text-xs text-[var(--amber)]">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  <p className="leading-relaxed">{dict.share.privacyWarn}</p>
                </div>

                {/* Pack Name & Optional Description */}
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-12">
                  <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-5">
                    {dict.share.packNameLabel}
                    <input
                      type="text"
                      disabled={busy}
                      value={packName}
                      onChange={(e) => setPackName(e.target.value)}
                      placeholder={dict.share.packNamePlaceholder}
                      className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                    />
                  </label>

                  <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-7">
                    简短备注（可选）
                    <input
                      type="text"
                      disabled={busy}
                      value={packDesc}
                      onChange={(e) => setPackDesc(e.target.value)}
                      placeholder="例如：晚高峰延迟低，含日本与台湾节点"
                      className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                    />
                  </label>
                </div>

                {/* Dual Tabs: Nodes & Relays */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2.5">
                  <div className="inline-flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setExportTab("nodes")}
                      className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                        exportTab === "nodes"
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                      }`}
                    >
                      <Server className="h-3.5 w-3.5" />
                      <span>{dict.share.selectNodesTab}</span>
                      <span
                        className={`cc-mono rounded-full px-1.5 py-0.2 text-[10px] font-semibold ${
                          selectedNodeIds.size > 0
                            ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                            : "bg-[var(--card)] text-[var(--muted)]"
                        }`}
                      >
                        {selectedNodeIds.size}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setExportTab("relays")}
                      className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                        exportTab === "relays"
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                      }`}
                    >
                      <Zap className="h-3.5 w-3.5" />
                      <span>{dict.share.selectRelaysTab}</span>
                      <span
                        className={`cc-mono rounded-full px-1.5 py-0.2 text-[10px] font-semibold ${
                          selectedRelayIds.size > 0
                            ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                            : "bg-[var(--card)] text-[var(--muted)]"
                        }`}
                      >
                        {selectedRelayIds.size}
                      </span>
                    </button>
                  </div>

                  {exportTab === "nodes" ? (
                    <div className="flex items-center gap-1.5 text-[11px]">
                      <button
                        type="button"
                        disabled={filteredExportNodes.length === 0}
                        onClick={
                          allFilteredExportNodesSelected
                            ? handleClearFilteredExportNodes
                            : handleSelectAllFilteredExportNodes
                        }
                        className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                      >
                        {allFilteredExportNodesSelected ? "清空当前筛选" : "全选当前筛选"}
                      </button>
                      {selectedNodeIds.size > 0 && (
                        <button
                          type="button"
                          onClick={() => setSelectedNodeIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空全部
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 text-[11px]">
                      <button
                        type="button"
                        disabled={relays.length === 0}
                        onClick={() =>
                          setSelectedRelayIds(
                            new Set(relays.filter((r) => r.enabled).map((r) => r.id))
                          )
                        }
                        className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                      >
                        全选已启用
                      </button>
                      <button
                        type="button"
                        disabled={relays.length === 0}
                        onClick={() => setSelectedRelayIds(new Set(relays.map((r) => r.id)))}
                        className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                      >
                        全选全部
                      </button>
                      {selectedRelayIds.size > 0 && (
                        <button
                          type="button"
                          onClick={() => setSelectedRelayIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {/* Export Nodes Selector */}
                {exportTab === "nodes" && (
                  <div className="space-y-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <AppSelect
                        aria-label="按订阅来源筛选"
                        size="sm"
                        value={exportSubFilter}
                        onChange={(val) => {
                          setExportSubFilter(val);
                          setExportRegionFilter("all");
                        }}
                        options={[
                          { value: "all", label: `全部来源 (${nodes.length})` },
                          ...subscriptions.map((sub) => ({
                            value: sub.id,
                            label: `${sub.name} (${subNodeCounts.get(sub.id) ?? 0})`,
                          })),
                        ]}
                        className="min-w-[140px] max-w-[200px]"
                      />

                      <AppSelect
                        aria-label="按地区筛选"
                        size="sm"
                        value={exportRegionFilter}
                        onChange={setExportRegionFilter}
                        options={exportRegionOptions}
                        className="min-w-[125px] max-w-[180px]"
                      />

                      <div className="relative min-w-[160px] flex-1">
                        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                        <input
                          type="text"
                          value={exportNodeSearch}
                          onChange={(e) => setExportNodeSearch(e.target.value)}
                          placeholder="搜索节点名称、地区或协议…"
                          className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                        {exportNodeSearch && (
                          <button
                            type="button"
                            onClick={() => setExportNodeSearch("")}
                            aria-label="清空搜索"
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </div>

                    {filteredExportNodes.length === 0 ? (
                      <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-8 text-center text-xs text-[var(--muted)]">
                        {nodes.length === 0
                          ? "当前还没有可导出的节点，也可以切到「选择国内提速中转」仅打包中转线路"
                          : "当前筛选条件下没有匹配节点"}
                      </div>
                    ) : (
                      <div className="max-h-56 space-y-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                        {filteredExportNodes.map((node) => {
                          const checked = selectedNodeIds.has(node.id);
                          const regionCode = resolveNodeRegionCode(node);
                          const subName = subNameMap.get(node.sub_id) ?? node.sub_id;
                          return (
                            <label
                              key={node.id}
                              className={`flex cursor-pointer items-center justify-between gap-2.5 rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                                checked
                                  ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/50"
                                  : "border-transparent bg-[var(--bg-elevated)]/65 hover:border-[var(--line)]"
                              }`}
                            >
                              <div className="flex min-w-0 flex-1 items-center gap-2">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => toggleExportNode(node.id)}
                                  className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                />
                                <div className="min-w-0 flex-1">
                                  <div className="truncate font-medium text-[var(--text)]">
                                    {node.name}
                                  </div>
                                  <div className="truncate text-[10.5px] text-[var(--muted)]">
                                    {subName} · {node.protocol.toUpperCase()}
                                  </div>
                                </div>
                              </div>
                              <div className="flex shrink-0 items-center gap-1 cc-mono text-[10px]">
                                <span
                                  title={getRegionLabel(regionCode)}
                                  className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                                >
                                  {regionCode}
                                </span>
                                <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]">
                                  {node.multiplier}x
                                </span>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* Export Relays Selector (strictly never expose plaintext password) */}
                {exportTab === "relays" && (
                  <div className="space-y-2">
                    {relays.length === 0 ? (
                      <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-8 text-center text-xs text-[var(--muted)]">
                        还没有添加国内提速中转线路
                      </div>
                    ) : (
                      <div className="max-h-56 space-y-1.5 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                        {relays.map((relay) => {
                          const checked = selectedRelayIds.has(relay.id);
                          return (
                            <label
                              key={relay.id}
                              className={`flex cursor-pointer items-center justify-between gap-2.5 rounded-lg border px-3 py-2 text-xs transition-colors ${
                                checked
                                  ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/50"
                                  : "border-transparent bg-[var(--bg-elevated)]/65 hover:border-[var(--line)]"
                              }`}
                            >
                              <div className="flex min-w-0 flex-1 items-center gap-2.5">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => toggleExportRelay(relay.id)}
                                  className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                />
                                <div className="min-w-0 flex-1">
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <span className="truncate font-semibold text-[var(--text)]">
                                      {relay.name}
                                    </span>
                                    <span
                                      className={`rounded-full px-1.5 py-0.2 text-[10px] font-medium ${
                                        relay.enabled
                                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                                          : "bg-[var(--card)] text-[var(--muted)]"
                                      }`}
                                    >
                                      {relay.enabled ? "已启用" : "已停用"}
                                    </span>
                                  </div>
                                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10.5px] text-[var(--muted)]">
                                    <span>{relay.region || "国内"}</span>
                                    <span>·</span>
                                    <span className="cc-mono uppercase">{relay.protocol}</span>
                                    <span>·</span>
                                    <span className="cc-mono">端口 {relay.port}</span>
                                  </div>
                                </div>
                              </div>
                              <span className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 cc-mono text-[10px] text-[var(--muted)]">
                                凭据已隐藏
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* Sync-Specific Compact Options Card */}
                {isSyncExportTab && (
                  <div className="space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 p-3">
                    <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                      <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-[var(--text)]">
                        <input
                          type="checkbox"
                          checked={includeGroups}
                          disabled={busy}
                          onChange={(e) => setIncludeGroups(e.target.checked)}
                          className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                        />
                        <span>{dict.sync.includeGroupsToggle}</span>
                        {groups.length > 0 && (
                          <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] text-[var(--muted)]">
                            {groups.length}
                          </span>
                        )}
                      </label>

                      {exportTransport === "lan_send" && (
                        <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-[var(--text)]">
                          <input
                            type="checkbox"
                            checked={allowMultipleSend}
                            disabled={busy}
                            onChange={(e) => setAllowMultipleSend(e.target.checked)}
                            className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                          />
                          <span>{dict.sync.allowMultiToggle}</span>
                        </label>
                      )}
                    </div>

                    {exportTransport === "lan_send" && (
                      <>
                        <label className="block text-[11px] font-medium text-[var(--text-secondary)]">
                          {dict.sync.customEndpointLabel}
                          <input
                            type="text"
                            disabled={busy}
                            value={sendCustomEndpoint}
                            onChange={(e) => setSendCustomEndpoint(e.target.value)}
                            placeholder={dict.sync.customEndpointPlaceholder}
                            className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                          />
                        </label>
                        <p className="text-[11px] leading-relaxed text-[var(--muted)]">
                          {dict.sync.ttlHint}
                        </p>
                      </>
                    )}

                    {exportTransport === "relay_file" && (
                      <p className="text-[11px] leading-relaxed text-[var(--muted)]">
                        {dict.sync.relayKeyHint}
                      </p>
                    )}
                  </div>
                )}

                {exportError && (
                  <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{exportError}</span>
                  </div>
                )}
              </>
            )
          ) : (
            /* ======================== IMPORT MODE ======================== */
            <>
              {/* Received Push Notification Banner */}
              {receivedEventNotice && (
                <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--green)]/45 bg-[var(--green-soft)]/55 px-3.5 py-2.5 text-xs text-[var(--green)]">
                  <div className="flex min-w-0 items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    <span className="truncate font-semibold">
                      {dict.sync.receivedTitle}: {receivedEventNotice.pack_name}
                    </span>
                  </div>
                  <span className="shrink-0 cc-mono text-[11px]">
                    {receivedEventNotice.node_count} / {receivedEventNotice.relay_count}
                    {receivedEventNotice.group_count > 0
                      ? ` / ${receivedEventNotice.group_count} ${micro.groupsTabBadge}`
                      : ""}
                  </span>
                </div>
              )}

              {/* Import Source Controls by Active Transport */}
              {importTransport === "zip" && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/80 px-4 py-3">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                      <FileArchive className="h-4 w-4" />
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-xs font-semibold text-[var(--text)]">
                        {preview && !syncPreview ? preview.manifest.name : "选择朋友分享的 .zip 文件"}
                      </div>
                      <div
                        className="mt-0.5 truncate cc-mono text-[10.5px] text-[var(--muted)]"
                        title={preview && !syncPreview ? preview.zip_path : undefined}
                      >
                        {preview && !syncPreview
                          ? `${preview.zip_path} · ${formatCreatedAt(preview.manifest.created_at)}`
                          : "支持 catcloud-share/v1 标准分享包（节点 + 国内中转）"}
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void handlePickPreviewZip()}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-55"
                  >
                    {pickingZip ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <FileArchive className="h-3.5 w-3.5" />
                    )}
                    <span>
                      {pickingZip
                        ? dict.common.loading
                        : preview && !syncPreview
                          ? "重新选择 .zip"
                          : dict.share.pickZipBtn}
                    </span>
                  </button>
                </div>
              )}

              {importTransport === "pull_input" && (
                <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-3.5">
                  <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-12">
                    <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-8">
                      {dict.sync.sourceInputLabel}
                      <input
                        type="text"
                        disabled={busy}
                        value={syncSourceInput}
                        onChange={(e) => setSyncSourceInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            void handlePreviewSyncPull(false);
                          }
                        }}
                        placeholder={dict.sync.sourceInputPlaceholder}
                        className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                      />
                    </label>

                    <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-4">
                      {dict.sync.pinLabel}
                      <input
                        type="text"
                        inputMode="numeric"
                        maxLength={12}
                        disabled={busy}
                        value={syncPinInput}
                        onChange={(e) => setSyncPinInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            void handlePreviewSyncPull(false);
                          }
                        }}
                        placeholder={dict.sync.pinInputPlaceholder}
                        className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono text-xs tracking-wider text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                      />
                    </label>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handlePreviewSyncPull(false)}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-55"
                      >
                        {previewingSync ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Download className="h-3.5 w-3.5" />
                        )}
                        <span>
                          {previewingSync ? micro.fetchingPreview : dict.sync.previewSourceBtn}
                        </span>
                      </button>

                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handlePreviewSyncPull(true)}
                        className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-55"
                      >
                        <FileLock2 className="h-3.5 w-3.5" />
                        <span>{micro.pickCcsyncBtn}</span>
                      </button>
                    </div>

                    {preview && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={handleClearImportPreview}
                        className="rounded-lg px-2 py-1 text-[11px] text-[var(--muted)] hover:text-[var(--text)]"
                      >
                        {micro.clearPreview}
                      </button>
                    )}
                  </div>
                </div>
              )}

              {importTransport === "listen_qr" && !preview && (
                !receiveSession ? (
                  <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 p-4">
                    <label className="block text-[11px] font-medium text-[var(--text-secondary)]">
                      {dict.sync.customEndpointLabel}
                      <input
                        type="text"
                        disabled={busy}
                        value={receiveCustomEndpoint}
                        onChange={(e) => setReceiveCustomEndpoint(e.target.value)}
                        placeholder={dict.sync.customEndpointPlaceholder}
                        className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 cc-mono text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                      />
                    </label>

                    <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-[var(--text)]">
                      <input
                        type="checkbox"
                        checked={allowMultipleReceive}
                        disabled={busy}
                        onChange={(e) => setAllowMultipleReceive(e.target.checked)}
                        className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                      />
                      <span>{dict.sync.allowMultiToggle}</span>
                    </label>

                    <div className="pt-1">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleStartReceiveListener()}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-55"
                      >
                        {startingReceive ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <QrCode className="h-3.5 w-3.5" />
                        )}
                        <span>
                          {startingReceive ? micro.listenActionBusy : dict.sync.startListenBtn}
                        </span>
                      </button>
                    </div>

                    <div className="space-y-1 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)]/45 px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
                      <p>{dict.sync.firewallHint}</p>
                      <p className="opacity-90">{dict.sync.ttlHint}</p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/75 px-3.5 py-2.5 text-xs">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 cc-mono text-[11px] font-semibold ${
                            receiveExpired
                              ? "bg-[var(--red-soft)] text-[var(--red)]"
                              : "bg-[var(--accent-soft)] text-[var(--accent)]"
                          }`}
                        >
                          <Clock className="h-3 w-3" />
                          <span>{formatCountdown(receiveRemainingSec)}</span>
                        </span>
                        <span className="inline-flex items-center gap-1.5 text-[11.5px] text-[var(--text-secondary)]">
                          {!receiveExpired && (
                            <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--accent)]" />
                          )}
                          <span>
                            {receiveSessionStatus?.message ||
                              (receiveExpired ? micro.sessionExpired : micro.waitingPush)}
                          </span>
                        </span>
                      </div>

                      <button
                        type="button"
                        disabled={busy}
                        onClick={cancelActiveReceiveSession}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--red)]/45 bg-[var(--red-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--red)] hover:opacity-90"
                      >
                        <StopCircle className="h-3.5 w-3.5" />
                        <span>{dict.sync.stopSessionBtn}</span>
                      </button>
                    </div>

                    {receiveExpired && (
                      <div className="flex items-center justify-between gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3.5 py-2.5 text-xs text-[var(--red)]">
                        <span>{micro.sessionExpired}</span>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleStartReceiveListener()}
                          className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)]"
                        >
                          <RotateCcw className="h-3 w-3" />
                          <span>{dict.sync.startListenBtn}</span>
                        </button>
                      </div>
                    )}

                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-12">
                      <div className="flex flex-col items-center justify-center rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)]/60 p-4 sm:col-span-5">
                        {receiveQrSrc && (
                          <div className="rounded-2xl border border-black/10 bg-white p-2.5 shadow-sm">
                            <img
                              src={receiveQrSrc}
                              alt={dict.sync.modeListenQr}
                              draggable={false}
                              className="h-44 w-44 select-none object-contain"
                            />
                          </div>
                        )}
                        <button
                          type="button"
                          onClick={() =>
                            void copyToClipboard("recv-qr-uri", receiveSession.qr_uri)
                          }
                          className="mt-3 inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          {copiedKey === "recv-qr-uri" ? (
                            <Check className="h-3.5 w-3.5 text-[var(--green)]" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                          <span>
                            {copiedKey === "recv-qr-uri" ? dict.common.copied : micro.copyQrUri}
                          </span>
                        </button>
                      </div>

                      <div className="flex flex-col justify-between gap-3 sm:col-span-7">
                        <div className="rounded-2xl border border-[var(--accent)]/40 bg-[var(--accent-soft)]/35 p-3.5">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                              {dict.sync.pinLabel}
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                void copyToClipboard("recv-pin", receiveSession.pin_code)
                              }
                              className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                            >
                              {copiedKey === "recv-pin" ? (
                                <Check className="h-3 w-3 text-[var(--green)]" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                              <span>
                                {copiedKey === "recv-pin" ? dict.common.copied : dict.common.copy}
                              </span>
                            </button>
                          </div>
                          <div className="mt-1.5 select-all cc-mono text-3xl font-bold tracking-[0.26em] text-[var(--accent)]">
                            {formatPinDisplay(receiveSession.pin_code)}
                          </div>
                        </div>

                        <div className="space-y-1.5 rounded-2xl border border-[var(--line)] bg-[var(--card)]/75 p-3">
                          <div className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)]">
                            <Wifi className="h-3.5 w-3.5 text-[var(--accent)]" />
                            <span>{dict.sync.addressLabel}</span>
                          </div>
                          <div className="max-h-32 space-y-1.5 overflow-y-auto pr-0.5">
                            {receiveUrlsToShow.map((item, idx) => {
                              const copyId = `recv-url-${idx}`;
                              return (
                                <div
                                  key={`${item.url}-${idx}`}
                                  className="flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5"
                                >
                                  <div className="flex min-w-0 items-center gap-1.5">
                                    {item.isCustom && (
                                      <span className="shrink-0 rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent)]">
                                        {micro.customUrlTag}
                                      </span>
                                    )}
                                    <span
                                      className="truncate cc-mono text-[11px] text-[var(--text)]"
                                      title={item.url}
                                    >
                                      {item.url}
                                    </span>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={() => void copyToClipboard(copyId, item.url)}
                                    className="inline-flex shrink-0 items-center gap-1 rounded-lg px-2 py-0.5 text-[10.5px] font-medium text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--accent)]"
                                  >
                                    {copiedKey === copyId ? (
                                      <Check className="h-3 w-3 text-[var(--green)]" />
                                    ) : (
                                      <Copy className="h-3 w-3" />
                                    )}
                                    <span>
                                      {copiedKey === copyId
                                        ? dict.common.copied
                                        : dict.common.copy}
                                    </span>
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-1.5 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/50 px-3.5 py-2.5 text-[11.5px] leading-relaxed text-[var(--amber)]">
                      <p>{dict.sync.firewallHint}</p>
                      <p className="text-[11px] opacity-90">{dict.sync.ttlHint}</p>
                    </div>
                  </div>
                )
              )}

              {/* Empty Placeholder when No Preview Yet */}
              {!preview && importTransport === "zip" && (
                <div className="space-y-3 rounded-xl border border-dashed border-[var(--line)] px-5 py-8 text-center">
                  <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                    点击上方「{dict.share.pickZipBtn}」后，猫猫会先安全解析包内清单，供你自由挑选需要导入的节点或国内中转，确认后才会写入本地。
                  </p>
                  <p className="text-[11px] text-[var(--muted)]">
                    只导入来自你信任的朋友的分享包，避免导入陌生来源配置。
                  </p>
                </div>
              )}

              {!preview && importTransport === "pull_input" && (
                <div className="space-y-2 rounded-xl border border-dashed border-[var(--line)] px-5 py-6 text-center">
                  <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                    {micro.pullEmptyHint}
                  </p>
                  <p className="text-[11px] text-[var(--muted)]">{dict.sync.ttlHint}</p>
                </div>
              )}

              {/* Unified Preview & Selective Import Confirmation View */}
              {preview && (
                <>
                  {/* Manifest Details & Source Trust Banner */}
                  <div className="space-y-2 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/60 px-3.5 py-2.5 text-xs">
                    <div className="flex items-start justify-between gap-2 text-[var(--amber)]">
                      <div className="flex min-w-0 items-start gap-2">
                        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                        <div className="min-w-0 flex-1 leading-relaxed">
                          <div className="flex flex-wrap items-center gap-2 font-semibold">
                            <span>{preview.manifest.name}</span>
                            {syncPreview?.fingerprint && (
                              <span className="rounded bg-[var(--card)]/80 px-1.5 py-0.5 cc-mono text-[10px] font-normal text-[var(--text-secondary)]">
                                {micro.fingerprintLabel}: {syncPreview.fingerprint.slice(0, 10)}
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-[11px]">
                            {preview.manifest.sanitized_notice || dict.share.privacyWarn}
                          </p>
                        </div>
                      </div>
                      {importTransport === "listen_qr" && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={handleClearImportPreview}
                          className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--text-secondary)] hover:text-[var(--text)]"
                        >
                          {micro.clearPreview}
                        </button>
                      )}
                    </div>
                    {preview.manifest.description && (
                      <div className="rounded-lg bg-[var(--card)]/80 px-2.5 py-1.5 text-[11px] text-[var(--text-secondary)]">
                        {preview.manifest.description}
                      </div>
                    )}
                  </div>

                  {preview.warnings.length > 0 && (
                    <div className="rounded-xl border border-[var(--amber)]/45 bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px] text-[var(--amber)]">
                      <ul className="list-disc space-y-0.5 pl-4">
                        {preview.warnings.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Import Selection Tabs */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2">
                    <div className="inline-flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => setImportTab("nodes")}
                        className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                          importTab === "nodes"
                            ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                        }`}
                      >
                        <Server className="h-3.5 w-3.5" />
                        <span>{dict.share.selectNodesTab}</span>
                        <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold">
                          {importNodeIds.size}/{preview.nodes.length}
                        </span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setImportTab("relays")}
                        className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                          importTab === "relays"
                            ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                        }`}
                      >
                        <Zap className="h-3.5 w-3.5" />
                        <span>{dict.share.selectRelaysTab}</span>
                        <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold">
                          {importRelayIds.size}/{preview.relays.length}
                        </span>
                      </button>
                    </div>

                    {importTab === "nodes" && preview.nodes.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() =>
                            setImportNodeIds(new Set(preview.nodes.map((n) => n.id)))
                          }
                          className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          全选
                        </button>
                        <button
                          type="button"
                          onClick={() => setImportNodeIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空
                        </button>
                      </div>
                    )}

                    {importTab === "relays" && preview.relays.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() =>
                            setImportRelayIds(new Set(preview.relays.map((r) => r.id)))
                          }
                          className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          全选
                        </button>
                        <button
                          type="button"
                          onClick={() => setImportRelayIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Preview Nodes Checklist */}
                  {importTab === "nodes" && (
                    <div className="space-y-2">
                      {preview.nodes.length > 6 && (
                        <div className="relative">
                          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                          <input
                            type="text"
                            value={importNodeSearch}
                            onChange={(e) => setImportNodeSearch(e.target.value)}
                            placeholder="筛选包内节点…"
                            className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                          />
                        </div>
                      )}

                      {preview.nodes.length === 0 ? (
                        <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-6 text-center text-xs text-[var(--muted)]">
                          0
                        </div>
                      ) : (
                        <div className="max-h-44 space-y-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                          {filteredImportNodes.map((node) => {
                            const checked = importNodeIds.has(node.id);
                            const code = resolveNodeRegionCode(node);
                            return (
                              <label
                                key={node.id}
                                className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                                  checked
                                    ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/45"
                                    : "border-transparent bg-[var(--bg-elevated)]/55 opacity-60 hover:opacity-100"
                                }`}
                              >
                                <div className="flex min-w-0 flex-1 items-center gap-2">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => toggleImportNode(node.id)}
                                    className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate font-medium text-[var(--text)]">
                                      {node.name}
                                    </div>
                                    <div className="cc-mono text-[10px] text-[var(--muted)]">
                                      {node.protocol.toUpperCase()} · :{node.port}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex shrink-0 items-center gap-1 cc-mono text-[10px]">
                                  <span
                                    title={getRegionLabel(code)}
                                    className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                                  >
                                    {code}
                                  </span>
                                  <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]">
                                    {node.multiplier}x
                                  </span>
                                </div>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Preview Relays Checklist (never display password) */}
                  {importTab === "relays" && (
                    <div>
                      {preview.relays.length === 0 ? (
                        <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-6 text-center text-xs text-[var(--muted)]">
                          0
                        </div>
                      ) : (
                        <div className="max-h-44 space-y-1.5 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                          {preview.relays.map((relay) => {
                            const checked = importRelayIds.has(relay.id);
                            return (
                              <label
                                key={relay.id}
                                className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs transition-colors ${
                                  checked
                                    ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/45"
                                    : "border-transparent bg-[var(--bg-elevated)]/55 opacity-60 hover:opacity-100"
                                }`}
                              >
                                <div className="flex min-w-0 flex-1 items-center gap-2">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => toggleImportRelay(relay.id)}
                                    className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate font-semibold text-[var(--text)]">
                                      {relay.name}
                                    </div>
                                    <div className="text-[10.5px] text-[var(--muted)]">
                                      {relay.region || "CN"} ·{" "}
                                      <span className="cc-mono uppercase">{relay.protocol}</span> · :
                                      <span className="cc-mono">{relay.port}</span>
                                    </div>
                                  </div>
                                </div>
                                <span className="shrink-0 rounded bg-[var(--card)] px-2 py-0.5 cc-mono text-[10px] text-[var(--muted)]">
                                  •••
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Smart Groups Sync Checkbox (when SyncPreviewDto includes smart groups) */}
                  {syncPreview && syncPreview.group_count > 0 && (
                    <div className="space-y-2 rounded-xl border border-[var(--accent)]/35 bg-[var(--accent-soft)]/25 p-3">
                      <label className="flex cursor-pointer items-center justify-between gap-2 text-xs font-medium text-[var(--text)]">
                        <span className="inline-flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={importGroups}
                            disabled={importing}
                            onChange={(e) => setImportGroups(e.target.checked)}
                            className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                          />
                          <span>{dict.sync.includeGroupsToggle}</span>
                        </span>
                        <span className="cc-mono rounded-full bg-[var(--accent)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                          {syncPreview.group_count} {micro.groupsTabBadge}
                        </span>
                      </label>
                      {syncPreview.group_names.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 pl-5">
                          {syncPreview.group_names.slice(0, 8).map((gName, idx) => (
                            <span
                              key={`${gName}-${idx}`}
                              className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10.5px] text-[var(--text-secondary)]"
                            >
                              {gName}
                            </span>
                          ))}
                          {syncPreview.group_names.length > 8 && (
                            <span className="cc-mono text-[10.5px] text-[var(--muted)]">
                              +{syncPreview.group_names.length - 8}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Destination Grouping Selector (skip when only relays/groups are selected) */}
                  {importNodeIds.size > 0 ? (
                    <div className="space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 p-3.5">
                      <div className="text-xs font-semibold text-[var(--text)]">节点导入去向</div>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        <button
                          type="button"
                          onClick={() => setImportDestMode("new")}
                          className={`flex items-start gap-2 rounded-xl border p-2.5 text-left text-xs transition-colors ${
                            importDestMode === "new"
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]/50 text-[var(--text)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <FolderPlus className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                          <div className="min-w-0">
                            <div className="font-semibold">{dict.nodes.captureSaveNew}</div>
                            <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                              单独建一个新分组存放，不影响旧订阅
                            </div>
                          </div>
                        </button>

                        <button
                          type="button"
                          disabled={subscriptions.length === 0}
                          onClick={() => setImportDestMode("existing")}
                          className={`flex items-start gap-2 rounded-xl border p-2.5 text-left text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${
                            importDestMode === "existing"
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]/50 text-[var(--text)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <Layers className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                          <div className="min-w-0">
                            <div className="font-semibold">{dict.nodes.captureUpdateExisting}</div>
                            <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                              {subscriptions.length === 0
                                ? "当前暂无已有分组"
                                : "合并进现有分组，可选择替换或去重"}
                            </div>
                          </div>
                        </button>
                      </div>

                      {importDestMode === "new" ? (
                        <label className="block text-[11px] text-[var(--muted)]">
                          {dict.share.packNameLabel}
                          <input
                            type="text"
                            disabled={importing}
                            value={importNewSubName}
                            onChange={(e) => setImportNewSubName(e.target.value)}
                            placeholder={preview.manifest.name || "CatCloud Sync"}
                            className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                          />
                        </label>
                      ) : (
                        <div className="space-y-2.5">
                          <div className="flex flex-col gap-1">
                            <span className="text-[11px] text-[var(--muted)]">
                              {dict.nodes.captureUpdateExisting}
                            </span>
                            <AppSelect
                              aria-label={dict.nodes.captureUpdateExisting}
                              size="sm"
                              value={importTargetSubId}
                              onChange={setImportTargetSubId}
                              options={subscriptions.map((sub) => ({
                                value: sub.id,
                                label: `${sub.name} (${subNodeCounts.get(sub.id) ?? 0})`,
                              }))}
                              className="w-full"
                              buttonClassName="bg-[var(--card)]"
                            />
                          </div>

                          <div className="flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setImportUpdateMode("merge_dedup")}
                              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-[11px] font-medium transition-colors ${
                                importUpdateMode === "merge_dedup"
                                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                              }`}
                            >
                              {importUpdateMode === "merge_dedup" && <Check className="h-3 w-3" />}
                              <span>{dict.nodes.captureModeMerge}</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => setImportUpdateMode("replace_latest")}
                              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-[11px] font-medium transition-colors ${
                                importUpdateMode === "replace_latest"
                                  ? "border-[var(--amber)] bg-[var(--amber-soft)] text-[var(--amber)]"
                                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                              }`}
                            >
                              {importUpdateMode === "replace_latest" && <Check className="h-3 w-3" />}
                              <span>{dict.nodes.captureModeReplace}</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : importRelayIds.size > 0 || effectiveGroupImportCount > 0 ? (
                    <div className="flex items-center gap-2 rounded-xl border border-[var(--green)]/35 bg-[var(--green-soft)]/45 px-3.5 py-2 text-xs text-[var(--green)]">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      <span>
                        {dict.share.selectRelaysTab}: {importRelayIds.size}
                        {effectiveGroupImportCount > 0
                          ? ` · ${micro.groupsTabBadge}: ${effectiveGroupImportCount}`
                          : ""}
                      </span>
                    </div>
                  ) : null}
                </>
              )}

              {importError && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{importError}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--line)] bg-[var(--bg-elevated)]/55 px-5 py-3">
          {activeMode === "export" ? (
            exportTransport === "lan_send" && sendSession ? (
              <>
                <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                  <strong className="cc-mono font-semibold text-[var(--accent)]">
                    {selectedNodeIds.size}
                  </strong>{" "}
                  /{" "}
                  <strong className="cc-mono font-semibold text-[var(--accent)]">
                    {selectedRelayIds.size}
                  </strong>
                  {includeGroups && groups.length > 0 && (
                    <span className="ml-1.5 text-[var(--muted)]">
                      · {groups.length} {micro.groupsTabBadge}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={cancelActiveSendSession}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--red)]/50 bg-[var(--red-soft)] px-3.5 py-1.5 text-xs font-semibold text-[var(--red)] transition-opacity hover:opacity-90 disabled:opacity-50"
                  >
                    <StopCircle className="h-3.5 w-3.5" />
                    <span>{dict.sync.stopSessionBtn}</span>
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleRequestClose}
                    className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                  >
                    {dict.common.close}
                  </button>
                </div>
              </>
            ) : exportTransport === "relay_file" && relayExportResult ? (
              <>
                <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                  {formatBytesShort(relayExportResult.payload_bytes)}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => setRelayExportResult(null)}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>{micro.reExportBtn}</span>
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleRequestClose}
                    className="rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                  >
                    {dict.common.close}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                  <strong className="cc-mono font-semibold text-[var(--accent)]">
                    {selectedNodeIds.size}
                  </strong>{" "}
                  {dict.share.selectNodesTab} ·{" "}
                  <strong className="cc-mono font-semibold text-[var(--accent)]">
                    {selectedRelayIds.size}
                  </strong>{" "}
                  {dict.share.selectRelaysTab}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleRequestClose}
                    className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                  >
                    {dict.common.cancel}
                  </button>
                  {exportTransport === "zip" && (
                    <button
                      type="button"
                      disabled={busy || totalExportSelected === 0}
                      onClick={() => void handleExportBundle()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {exporting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Package className="h-3.5 w-3.5" />
                      )}
                      <span>{exporting ? dict.common.loading : dict.share.exportBtn}</span>
                    </button>
                  )}
                  {exportTransport === "lan_send" && (
                    <button
                      type="button"
                      disabled={busy || totalExportSelected === 0}
                      onClick={() => void handleStartSyncSend()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {startingSend ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <QrCode className="h-3.5 w-3.5" />
                      )}
                      <span>{startingSend ? micro.syncActionBusy : dict.sync.startSendBtn}</span>
                    </button>
                  )}
                  {exportTransport === "relay_file" && (
                    <button
                      type="button"
                      disabled={busy || totalExportSelected === 0}
                      onClick={() => void handleExportEncryptedSync()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {exporting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <KeyRound className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {exporting ? micro.relayActionBusy : dict.sync.exportEncryptedBtn}
                      </span>
                    </button>
                  )}
                </div>
              </>
            )
          ) : (
            <>
              <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                {preview ? (
                  <>
                    <strong className="cc-mono font-semibold text-[var(--accent)]">
                      {importNodeIds.size}
                    </strong>{" "}
                    {dict.share.selectNodesTab} ·{" "}
                    <strong className="cc-mono font-semibold text-[var(--accent)]">
                      {importRelayIds.size}
                    </strong>{" "}
                    {dict.share.selectRelaysTab}
                    {effectiveGroupImportCount > 0 && (
                      <>
                        {" "}
                        ·{" "}
                        <strong className="cc-mono font-semibold text-[var(--accent)]">
                          {effectiveGroupImportCount}
                        </strong>{" "}
                        {micro.groupsTabBadge}
                      </>
                    )}
                  </>
                ) : (
                  <span>
                    {importTransport === "zip"
                      ? dict.share.pickZipBtn
                      : importTransport === "pull_input"
                        ? dict.sync.modePullInput
                        : dict.sync.modeListenQr}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleRequestClose}
                  className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  {dict.common.cancel}
                </button>
                <button
                  type="button"
                  disabled={busy || !preview || totalImportSelected === 0}
                  onClick={() => void handleConfirmImport()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {importing ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Check className="h-3.5 w-3.5" />
                  )}
                  <span>{importing ? dict.common.loading : dict.share.importApplyBtn}</span>
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
