import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  Info,
  Loader2,
  RefreshCw,
  Router,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type GatewayExportOptions,
  type GatewayExportOutput,
  type GatewayExportProfile,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";

export interface GatewayExportModalProps {
  open: boolean;
  defaultProfile?: GatewayExportProfile;
  onClose: () => void;
}

interface ProfileCardMeta {
  id: GatewayExportProfile;
  title: string;
  desc: string;
  icon: "relay" | "gateway" | "nodes";
}

function parseStrictPort(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  if (!Number.isSafeInteger(n) || n < 1 || n > 65535) return null;
  return n;
}

async function copyTextWithFallback(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fallback below */
  }
  try {
    if (typeof document === "undefined") return false;
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function renderYamlLine(line: string, lineIdx: number): ReactNode {
  const trimmed = line.trimStart();
  if (!trimmed) {
    return "\n";
  }
  if (trimmed.startsWith("#")) {
    return (
      <span key={lineIdx} className="block text-[var(--muted)]">
        {line}
      </span>
    );
  }
  const indentLen = line.length - trimmed.length;
  const indent = line.slice(0, indentLen);

  // List item: "- ..."
  if (trimmed.startsWith("- ")) {
    const rest = trimmed.slice(2);
    const kvMatch = /^([^:#\s][^:]*)(:\s*)(.*)$/.exec(rest);
    if (kvMatch) {
      const [, key, sep, val] = kvMatch;
      const isRedacted = val.includes("REDACTED");
      return (
        <span key={lineIdx} className="block">
          {indent}
          <span className="text-[var(--sky)]">- </span>
          <span className="font-medium text-[var(--accent)]">{key}</span>
          <span className="text-[var(--muted)]">{sep}</span>
          <span className={isRedacted ? "font-medium text-[var(--amber)]" : "text-[var(--text)]"}>
            {val}
          </span>
        </span>
      );
    }
    return (
      <span key={lineIdx} className="block">
        {indent}
        <span className="text-[var(--sky)]">- </span>
        <span className="text-[var(--text)]">{rest}</span>
      </span>
    );
  }

  // Key: Value line
  const kvMatch = /^([^:#][^:]*)(:\s*)(.*)$/.exec(trimmed);
  if (kvMatch) {
    const [, key, sep, val] = kvMatch;
    const isRedacted = val.includes("REDACTED");
    return (
      <span key={lineIdx} className="block">
        {indent}
        <span className="font-medium text-[var(--accent)]">{key}</span>
        <span className="text-[var(--muted)]">{sep}</span>
        <span className={isRedacted ? "font-medium text-[var(--amber)]" : "text-[var(--text)]"}>
          {val}
        </span>
      </span>
    );
  }

  return (
    <span key={lineIdx} className="block text-[var(--text-secondary)]">
      {line}
    </span>
  );
}

export function GatewayExportModal({
  open,
  defaultProfile = "relay_fragment",
  onClose,
}: GatewayExportModalProps) {
  const uiLang = useAppSelector((s) => normalizeUiLanguage(s.config.personalization.ui_language));
  const dict = useUiDict(uiLang);
  const gw = dict.gatewayExport;
  const inTauri = isTauriEnv();

  const [profile, setProfile] = useState<GatewayExportProfile>(defaultProfile);
  const [tproxyPortInput, setTproxyPortInput] = useState<string>("7893");
  const [redirPortInput, setRedirPortInput] = useState<string>("7892");
  const [dnsPortInput, setDnsPortInput] = useState<string>("1053");
  const [redactSecrets, setRedactSecrets] = useState<boolean>(true);

  const [output, setOutput] = useState<GatewayExportOutput | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [lastSavedPath, setLastSavedPath] = useState<string | null>(null);

  const reqSeqRef = useRef<number>(0);
  const copyTimerRef = useRef<number | null>(null);
  const wasOpenRef = useRef<boolean>(false);

  const profileCards = useMemo<ReadonlyArray<ProfileCardMeta>>(
    () => [
      {
        id: "relay_fragment",
        title: gw.profileRelayTitle,
        desc: gw.profileRelayDesc,
        icon: "relay",
      },
      {
        id: "transparent_gateway",
        title: gw.profileGatewayTitle,
        desc: gw.profileGatewayDesc,
        icon: "gateway",
      },
      {
        id: "preferred_nodes",
        title: gw.profilePreferredTitle,
        desc: gw.profilePreferredDesc,
        icon: "nodes",
      },
    ],
    [
      gw.profileGatewayDesc,
      gw.profileGatewayTitle,
      gw.profilePreferredDesc,
      gw.profilePreferredTitle,
      gw.profileRelayDesc,
      gw.profileRelayTitle,
    ]
  );

  // Reset state cleanly each time modal opens (never leak stale secrets from previous session)
  useEffect(() => {
    if (open && !wasOpenRef.current) {
      setProfile(defaultProfile);
      setRedactSecrets(true);
      setOutput(null);
      setLoadError(null);
      setLastSavedPath(null);
      setCopied(false);
    }
    wasOpenRef.current = open;
  }, [open, defaultProfile]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const handleClose = useCallback(() => {
    if (saving) return;
    onClose();
  }, [saving, onClose]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        handleClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, handleClose]);

  const portValidation = useMemo(() => {
    const tproxyPort = parseStrictPort(tproxyPortInput);
    const redirPort = parseStrictPort(redirPortInput);
    const dnsPort = parseStrictPort(dnsPortInput);

    const tproxyOutOfRange = tproxyPort === null;
    const redirOutOfRange = redirPort === null;
    const dnsOutOfRange = dnsPort === null;

    const tproxyRedirConflict =
      tproxyPort !== null && redirPort !== null && tproxyPort === redirPort;
    const tproxyDnsConflict = tproxyPort !== null && dnsPort !== null && tproxyPort === dnsPort;
    const redirDnsConflict = redirPort !== null && dnsPort !== null && redirPort === dnsPort;

    const hasRangeError = tproxyOutOfRange || redirOutOfRange || dnsOutOfRange;
    const hasConflictError = tproxyRedirConflict || tproxyDnsConflict || redirDnsConflict;

    const tproxyInvalid = tproxyOutOfRange || tproxyRedirConflict || tproxyDnsConflict;
    const redirInvalid = redirOutOfRange || tproxyRedirConflict || redirDnsConflict;
    const dnsInvalid = dnsOutOfRange || tproxyDnsConflict || redirDnsConflict;

    return {
      tproxyPort,
      redirPort,
      dnsPort,
      hasRangeError,
      hasConflictError,
      tproxyInvalid,
      redirInvalid,
      dnsInvalid,
    };
  }, [tproxyPortInput, redirPortInput, dnsPortInput]);

  const hasInvalidPort =
    profile === "transparent_gateway" &&
    (portValidation.hasRangeError || portValidation.hasConflictError);

  const effectiveOptions = useMemo<GatewayExportOptions | null>(() => {
    if (hasInvalidPort) return null;
    return {
      profile,
      tproxy_port: portValidation.tproxyPort ?? 7893,
      redir_port: portValidation.redirPort ?? 7892,
      dns_listen_port: portValidation.dnsPort ?? 1053,
      redact_secrets: redactSecrets,
    };
  }, [
    hasInvalidPort,
    profile,
    portValidation.tproxyPort,
    portValidation.redirPort,
    portValidation.dnsPort,
    redactSecrets,
  ]);

  const fetchPreview = useCallback(async (opts: GatewayExportOptions) => {
    const seq = ++reqSeqRef.current;
    setLoading(true);
    setLoadError(null);
    try {
      const res = await catcloudApi.exportGatewayYaml(opts);
      if (seq !== reqSeqRef.current) return;
      setOutput(res);
    } catch (err) {
      if (seq !== reqSeqRef.current) return;
      setOutput(null);
      setLoadError(formatErrorMessage(err));
    } finally {
      if (seq === reqSeqRef.current) {
        setLoading(false);
      }
    }
  }, []);

  // Immediately clear stale output if switching security mode or ports become invalid
  useEffect(() => {
    if (!open) return;
    if (hasInvalidPort || !effectiveOptions) {
      reqSeqRef.current += 1;
      setOutput(null);
      setLoading(false);
      setLoadError(null);
      return;
    }
    setOutput((prev) => (prev && prev.redacted !== effectiveOptions.redact_secrets ? null : prev));
    const timer = window.setTimeout(() => {
      void fetchPreview(effectiveOptions);
    }, 140);
    return () => window.clearTimeout(timer);
  }, [open, hasInvalidPort, effectiveOptions, fetchPreview]);

  const yamlLines = useMemo(() => {
    if (!output?.yaml || loadError || hasInvalidPort) return [];
    return output.yaml.split(/\r?\n/);
  }, [output?.yaml, loadError, hasInvalidPort]);

  const canExport = !loading && Boolean(output?.yaml) && !loadError && !hasInvalidPort;

  const handleCopyYaml = async () => {
    if (!canExport || !output?.yaml) {
      appActions.showToast(gw.noYamlToast, "warn");
      return;
    }
    const ok = await copyTextWithFallback(output.yaml);
    if (ok) {
      setCopied(true);
      appActions.showToast(output.redacted ? gw.copiedRedactedToast : gw.copiedPlainToast, "ok");
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 1800);
    } else {
      appActions.showToast(gw.clipboardUnavailableToast, "warn");
    }
  };

  const handleSaveFile = async () => {
    if (saving || !canExport || !effectiveOptions) return;
    setSaving(true);
    try {
      const savedPath = await catcloudApi.saveGatewayYamlDialog(effectiveOptions);
      if (savedPath) {
        setLastSavedPath(savedPath);
        appActions.showToast(formatI18nTemplate(gw.savedToast, { path: savedPath }), "ok", 4200);
      }
    } catch (err) {
      appActions.showToast(
        formatI18nTemplate(gw.saveFailedToast, { error: formatErrorMessage(err) }),
        "warn"
      );
    } finally {
      setSaving(false);
    }
  };

  if (!open || typeof document === "undefined") return null;

  const suggestedFilename =
    profile === "relay_fragment"
      ? "catcloud-relay-fragment.yaml"
      : profile === "transparent_gateway"
        ? "catcloud-transparent-gateway.yaml"
        : "catcloud-preferred-nodes.yaml";

  const portInputBaseCls =
    "cc-mono h-8 w-full min-w-0 rounded-lg border bg-[var(--card)] px-2.5 text-xs text-[var(--text)] outline-none";

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={handleClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={gw.dialogAria}
        onClick={(e) => e.stopPropagation()}
        className="cc-surface flex max-h-[calc(100vh-2rem)] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] shadow-2xl"
      >
        {/* Fixed Header */}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] px-5 py-3.5">
          <div className="flex min-w-0 flex-1 items-center gap-2.5">
            <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
              <Router className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-[var(--text)]">{gw.title}</h3>
              <p className="mt-0.5 truncate text-[11px] text-[var(--muted)]">{gw.subtitle}</p>
            </div>
          </div>

          <button
            type="button"
            disabled={saving}
            onClick={handleClose}
            aria-label={gw.closeAria}
            className="shrink-0 rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-45"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto px-5 py-4">
          {/* 顶部 3 张紧凑模式卡 */}
          <div
            className="grid grid-cols-1 gap-2 sm:grid-cols-3"
            role="radiogroup"
            aria-label={gw.modeGroupAria}
          >
            {profileCards.map((card) => {
              const selected = profile === card.id;
              return (
                <button
                  key={card.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => setProfile(card.id)}
                  className={`flex min-w-0 flex-col items-start rounded-xl border p-3 text-left transition-colors ${
                    selected
                      ? "border-[var(--accent)] bg-[var(--accent-soft)]/55 shadow-xs"
                      : "border-[var(--line)] bg-[var(--bg-elevated)]/65 hover:border-[var(--line-strong)] hover:bg-[var(--bg-elevated)]"
                  }`}
                >
                  <div className="flex w-full items-center gap-1.5">
                    {card.icon === "relay" ? (
                      <Server
                        className={`h-3.5 w-3.5 shrink-0 ${
                          selected ? "text-[var(--accent)]" : "text-[var(--muted)]"
                        }`}
                      />
                    ) : card.icon === "gateway" ? (
                      <Router
                        className={`h-3.5 w-3.5 shrink-0 ${
                          selected ? "text-[var(--accent)]" : "text-[var(--muted)]"
                        }`}
                      />
                    ) : (
                      <Sparkles
                        className={`h-3.5 w-3.5 shrink-0 ${
                          selected ? "text-[var(--accent)]" : "text-[var(--muted)]"
                        }`}
                      />
                    )}
                    <span
                      className={`min-w-0 truncate text-xs font-semibold ${
                        selected ? "text-[var(--accent)]" : "text-[var(--text)]"
                      }`}
                    >
                      {card.title}
                    </span>
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                    {card.desc}
                  </p>
                </button>
              );
            })}
          </div>

          {/* 透明网关端口 3 列输入（带实时范围与冲突校验） */}
          {profile === "transparent_gateway" && (
            <div
              className={`rounded-xl border p-3 transition-colors ${
                hasInvalidPort
                  ? "border-[var(--red)]/55 bg-[var(--red-soft)]/20"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/60"
              }`}
            >
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-[var(--text)]">
                  {gw.portsSectionTitle}
                </span>
                <span className="text-[10.5px] text-[var(--muted)]">{gw.portsSectionHint}</span>
              </div>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                <label className="min-w-0">
                  <span className="mb-1 block text-[11px] text-[var(--text-secondary)]">
                    {gw.tproxyPortLabel}
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={tproxyPortInput}
                    aria-invalid={portValidation.tproxyInvalid}
                    onChange={(e) => setTproxyPortInput(e.target.value)}
                    placeholder="7893"
                    className={`${portInputBaseCls} ${
                      portValidation.tproxyInvalid
                        ? "border-[var(--red)] focus:border-[var(--red)]"
                        : "border-[var(--line)] focus:border-[var(--accent)]"
                    }`}
                  />
                </label>

                <label className="min-w-0">
                  <span className="mb-1 block text-[11px] text-[var(--text-secondary)]">
                    {gw.redirPortLabel}
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={redirPortInput}
                    aria-invalid={portValidation.redirInvalid}
                    onChange={(e) => setRedirPortInput(e.target.value)}
                    placeholder="7892"
                    className={`${portInputBaseCls} ${
                      portValidation.redirInvalid
                        ? "border-[var(--red)] focus:border-[var(--red)]"
                        : "border-[var(--line)] focus:border-[var(--accent)]"
                    }`}
                  />
                </label>

                <label className="min-w-0">
                  <span className="mb-1 block text-[11px] text-[var(--text-secondary)]">
                    {gw.dnsPortLabel}
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={dnsPortInput}
                    aria-invalid={portValidation.dnsInvalid}
                    onChange={(e) => setDnsPortInput(e.target.value)}
                    placeholder="1053"
                    className={`${portInputBaseCls} ${
                      portValidation.dnsInvalid
                        ? "border-[var(--red)] focus:border-[var(--red)]"
                        : "border-[var(--line)] focus:border-[var(--accent)]"
                    }`}
                  />
                </label>
              </div>

              {hasInvalidPort && (
                <div className="mt-2.5 space-y-1 rounded-lg border border-[var(--red)]/45 bg-[var(--red-soft)]/55 px-2.5 py-1.5 text-[11px] text-[var(--red)]">
                  {portValidation.hasRangeError && (
                    <div className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{gw.portRangeError}</span>
                    </div>
                  )}
                  {portValidation.hasConflictError && (
                    <div className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{gw.portConflictError}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 脱敏 / 含真实凭据切换开关 */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/65 px-3 py-2.5">
              <div className="flex min-w-0 items-center gap-2">
                {redactSecrets ? (
                  <ShieldCheck className="h-4 w-4 shrink-0 text-[var(--green)]" />
                ) : (
                  <ShieldAlert className="h-4 w-4 shrink-0 text-[var(--amber)]" />
                )}
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[var(--text)]">{gw.securityTitle}</div>
                  <div className="text-[10.5px] text-[var(--muted)]">
                    {redactSecrets ? gw.securityDescRedacted : gw.securityDescPlain}
                  </div>
                </div>
              </div>

              <div
                className="inline-flex max-w-full flex-wrap rounded-xl border border-[var(--line)] bg-[var(--card)] p-0.5 text-[11px]"
                role="radiogroup"
                aria-label={gw.securityGroupAria}
              >
                <button
                  type="button"
                  role="radio"
                  aria-checked={redactSecrets}
                  onClick={() => setRedactSecrets(true)}
                  className={`shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    redactSecrets
                      ? "bg-[var(--green-soft)] text-[var(--green)]"
                      : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                >
                  {gw.redactSafeBtn}
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={!redactSecrets}
                  onClick={() => setRedactSecrets(false)}
                  className={`shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    !redactSecrets
                      ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                      : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                >
                  {gw.redactPlainBtn}
                </button>
              </div>
            </div>

            {!redactSecrets && (
              <div className="flex items-start gap-2 rounded-xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/55 px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  {gw.plainSecretWarnPrefix}
                  <strong>{gw.plainSecretWarnStrong}</strong>
                  {gw.plainSecretWarnSuffix}
                </span>
              </div>
            )}
          </div>

          {/* 集成提示与告警 */}
          {output && !loadError && !hasInvalidPort && (
            <div className="space-y-2">
              {output.integration_hint && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--accent)]/35 bg-[var(--accent-soft)]/35 px-3 py-2 text-[11px] leading-relaxed text-[var(--text)]">
                  <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                  <div className="min-w-0 flex-1 whitespace-pre-line break-words">
                    {output.integration_hint}
                  </div>
                </div>
              )}

              {output.warnings.length > 0 && (
                <div className="rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)]/45 px-3 py-2 text-[11px] text-[var(--amber)]">
                  <div className="flex items-center gap-1.5 font-semibold">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    <span>
                      {formatI18nTemplate(gw.warningsTitle, { count: output.warnings.length })}
                    </span>
                  </div>
                  <ul className="mt-1 list-disc space-y-0.5 pl-4 leading-relaxed">
                    {output.warnings.map((w, idx) => (
                      <li key={`gw-warn-${idx}`} className="break-words">
                        {w}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* 中部高亮只读 YAML 预览区 */}
          <div className="overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--card)]">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-3 py-2 text-[11px]">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="cc-mono font-semibold text-[var(--text)]">
                  {suggestedFilename}
                </span>
                {output && !loadError && !hasInvalidPort && (
                  <>
                    <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">
                      {formatI18nTemplate(gw.statsSummary, {
                        relays: output.relay_count,
                        nodes: output.node_count,
                        rules: output.rule_count,
                      })}
                    </span>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                        output.redacted
                          ? "bg-[var(--green-soft)] text-[var(--green)]"
                          : "bg-[var(--amber-soft)] text-[var(--amber)]"
                      }`}
                    >
                      {output.redacted ? gw.badgeRedacted : gw.badgePlain}
                    </span>
                  </>
                )}
                {!inTauri && (
                  <span className="rounded-full bg-[var(--bg-elevated)] px-2 py-0.5 text-[10px] text-[var(--muted)]">
                    {gw.browserPreviewBadge}
                  </span>
                )}
              </div>

              <button
                type="button"
                disabled={loading || hasInvalidPort || !effectiveOptions}
                onClick={() => {
                  if (effectiveOptions) {
                    void fetchPreview(effectiveOptions);
                  }
                }}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10.5px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
                {gw.refreshPreviewBtn}
              </button>
            </div>

            {hasInvalidPort ? (
              <div className="flex items-start gap-2 p-4 text-xs text-[var(--red)]">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span className="break-words">{gw.portPreviewBlocked}</span>
              </div>
            ) : loading && !output ? (
              <div className="flex items-center justify-center gap-2 py-10 text-xs text-[var(--muted)]">
                <Loader2 className="h-4 w-4 animate-spin text-[var(--accent)]" />
                <span>{gw.generatingText}</span>
              </div>
            ) : loadError ? (
              <div className="flex items-start gap-2 p-4 text-xs text-[var(--red)]">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span className="break-words">
                  {gw.loadErrorPrefix}
                  {loadError}
                </span>
              </div>
            ) : (
              <pre className="cc-selectable cc-mono max-h-[280px] overflow-auto p-3.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                {yamlLines.map((line, idx) => renderYamlLine(line, idx))}
              </pre>
            )}
          </div>
        </div>

        {/* Fixed Footer */}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] bg-[var(--bg-elevated)]/65 px-5 py-3">
          <div className="min-w-0 flex-1 text-[11px] text-[var(--muted)]">
            {hasInvalidPort || loadError ? (
              <span className="block truncate text-[var(--red)]">{gw.footerErrorHint}</span>
            ) : lastSavedPath ? (
              <span className="cc-mono block truncate text-[var(--green)]" title={lastSavedPath}>
                {formatI18nTemplate(gw.savedPathLabel, { path: lastSavedPath })}
              </span>
            ) : (
              <span className="block truncate">
                {formatI18nTemplate(gw.footerLineSummary, { lines: yamlLines.length })}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              disabled={loading || !output?.yaml || Boolean(loadError) || hasInvalidPort}
              onClick={() => void handleCopyYaml()}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
              ) : (
                <Copy className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
              )}
              <span>{copied ? gw.copiedBtn : gw.copyBtn}</span>
            </button>

            <button
              type="button"
              disabled={saving || loading || !output?.yaml || Boolean(loadError) || hasInvalidPort}
              onClick={() => void handleSaveFile()}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? (
                <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5 shrink-0" />
              )}
              <span>{saving ? gw.savingBtn : gw.saveBtn}</span>
            </button>

            <button
              type="button"
              disabled={saving}
              onClick={handleClose}
              className="shrink-0 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
            >
              {gw.closeBtn}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

export default GatewayExportModal;
