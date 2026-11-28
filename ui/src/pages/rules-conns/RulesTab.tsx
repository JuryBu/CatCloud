import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  Copy,
  Eye,
  FileCode2,
  Loader2,
  Plus,
  RefreshCw,
  Router,
  Search,
  Shield,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type CompiledYamlPreview,
  type MultiGroup,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { AppSelect, type AppSelectOption } from "../../components/AppSelect";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../../i18n";
import { appActions, appStore, useAppSelector } from "../../store/appStore";
import { copyText } from "../../utils/clipboard";
import {
  KNOWN_MIHOMO_RULE_TYPES,
  STRICT_LOGICAL_RULE_TYPES,
  isRuleFlagToken,
  parseLogicalRuleParts,
  validateInlineOverrideYamlLocal,
  validateLogicalRuleExpr,
} from "../../utils/mihomoRuleParser";
import { isBoolPref, usePersistedState } from "../../utils/uiPrefs";
import {
  AI_PRESETS_TEMPLATE,
  type AiPresetBundle,
  DEMO_BULK_RULES_TEXT,
  DEMO_INLINE_OVERRIDE_YAML,
  EXTRA_RULE_TYPE_LABELS,
  IM_DIRECT_PROCESS_RULES,
  type ManagedRuleItem,
  type ParsedCompiledMeta,
  RULE_TYPE_LABELS,
  RULE_VALUE_PLACEHOLDERS,
  type RuleLayer,
  type RuleMatchType,
  buildGroupBoundRules,
  buildRulesOverridePayload,
  formatRuleTargetLabel,
  hydrateRulesFromConfig,
  parseCompiledPreviewMeta,
  parseRuleString,
  serializeRuleItem,
} from "./rulesCodec";

const GatewayExportModal = lazy(() => import("../../components/GatewayExportModal"));

interface RulesTabProps {
  onRulesCountChange: (count: number) => void;
}

export function RulesTab({ onRulesCountChange }: RulesTabProps) {
  const groups = useAppSelector((s) => s.groups);
  const uiLang = useAppSelector((s) =>
    normalizeUiLanguage(s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const geoStatus = useAppSelector((s) => s.bgTasks.settings.geoStatus);
  const geoBusy = useAppSelector((s) => s.bgTasks.settings.geoBusy);
  const geoRuleContext = useAppSelector((s) => s.geoRuleContext);
  const ruleSearch = useAppSelector((s) => s.sessionDrafts.rulesConns.ruleSearch);
  const inTauri = isTauriEnv();

  const setRuleSearch = useCallback((value: string) => {
    appActions.patchSessionDraft("rulesConns", { ruleSearch: value });
  }, []);

  const defaultGroupTarget = groups[0]?.name || "DIRECT";

  // Rules state hydrated from catcloudApi.getFullConfig
  const [aiPresets, setAiPresets] = useState<AiPresetBundle[]>(() =>
    AI_PRESETS_TEMPLATE.map((tpl) => ({
      ...tpl,
      targetGroup: defaultGroupTarget,
      enabled: false,
    }))
  );
  const [userRules, setUserRules] = useState<ManagedRuleItem[]>([]);
  const [loadingRules, setLoadingRules] = useState<boolean>(true);
  const [savingRules, setSavingRules] = useState<boolean>(false);
  const [ruleLayerFilter, setRuleLayerFilter] = useState<"all" | RuleLayer>("all");
  const [showYamlPreview, setShowYamlPreview] = usePersistedState<boolean>(
    "rulesconns.showYamlPreview",
    false,
    isBoolPref
  );
  const [compiledPreview, setCompiledPreview] = useState<CompiledYamlPreview | null>(null);
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  // New rule composer state
  const [newLayer, setNewLayer] = useState<"prepend" | "append">("prepend");
  const [newType, setNewType] = useState<RuleMatchType>("DOMAIN-SUFFIX");
  const [newValue, setNewValue] = useState<string>("");
  const [newTarget, setNewTarget] = useState<string>(defaultGroupTarget);
  const [newNoResolve, setNewNoResolve] = useState<boolean>(false);

  // Advanced rules & transparent gateway export state
  const [gatewayModalOpen, setGatewayModalOpen] = useState<boolean>(false);
  const [advancedOpen, setAdvancedOpen] = useState<boolean>(false);
  const [domesticDirectEnabled, setDomesticDirectEnabled] = useState<boolean>(
    geoRuleContext.domesticDirectEnabled
  );
  const [geodataMode, setGeodataMode] = useState<boolean>(geoRuleContext.geodataMode);
  const [customRulesOnly, setCustomRulesOnly] = useState<boolean>(false);
  const [savingCustomRulesOnly, setSavingCustomRulesOnly] = useState<boolean>(false);
  const [bulkRawText, setBulkRawText] = useState<string>("");
  const [bulkTargetLayer, setBulkTargetLayer] = useState<"prepend" | "append">("prepend");
  const [bulkApplying, setBulkApplying] = useState<boolean>(false);
  const [bulkFeedback, setBulkFeedback] = useState<{
    mode: "append" | "replace";
    layer: "prepend" | "append";
    validCount: number;
    skippedLines: string[];
  } | null>(null);
  const [inlineOverrideYaml, setInlineOverrideYaml] = useState<string>("");
  const [savedInlineOverrideYaml, setSavedInlineOverrideYaml] = useState<string>("");
  const [savingInlineYaml, setSavingInlineYaml] = useState<boolean>(false);
  const [inlineYamlError, setInlineYamlError] = useState<string | null>(null);
  const [inlineYamlVerifiedMsg, setInlineYamlVerifiedMsg] = useState<string | null>(null);

  const copiedYamlTimerRef = useRef<number | null>(null);
  const groupsRef = useRef<MultiGroup[]>(groups);
  groupsRef.current = groups;
  const aiPresetsRef = useRef<AiPresetBundle[]>(aiPresets);
  aiPresetsRef.current = aiPresets;
  const userRulesRef = useRef<ManagedRuleItem[]>(userRules);
  userRulesRef.current = userRules;
  const showYamlPreviewRef = useRef<boolean>(showYamlPreview);
  showYamlPreviewRef.current = showYamlPreview;
  const savingRulesRef = useRef<boolean>(savingRules);
  savingRulesRef.current = savingRules;
  const savingInlineYamlRef = useRef<boolean>(savingInlineYaml);
  savingInlineYamlRef.current = savingInlineYaml;
  const savingCustomRulesOnlyRef = useRef<boolean>(savingCustomRulesOnly);
  savingCustomRulesOnlyRef.current = savingCustomRulesOnly;
  const bulkApplyingRef = useRef<boolean>(bulkApplying);
  bulkApplyingRef.current = bulkApplying;
  const inlineOverrideYamlRef = useRef<string>(inlineOverrideYaml);
  inlineOverrideYamlRef.current = inlineOverrideYaml;
  const savedInlineOverrideYamlRef = useRef<string>(savedInlineOverrideYaml);
  savedInlineOverrideYamlRef.current = savedInlineOverrideYaml;
  const userPickedNewTargetRef = useRef<boolean>(false);
  const previewReqSeqRef = useRef<number>(0);
  const hydrateReqSeqRef = useRef<number>(0);

  useEffect(() => {
    return () => {
      if (copiedYamlTimerRef.current !== null) {
        window.clearTimeout(copiedYamlTimerRef.current);
      }
    };
  }, []);

  const loadCompiledPreview = useCallback(async () => {
    const seq = ++previewReqSeqRef.current;
    setLoadingPreview(true);
    setPreviewError(null);
    try {
      const res = await catcloudApi.compilePreviewYaml();
      if (seq !== previewReqSeqRef.current) return;
      setCompiledPreview(res);
    } catch (err) {
      if (seq !== previewReqSeqRef.current) return;
      const msg = formatErrorMessage(err);
      setPreviewError(msg);
      appActions.showToast(`编译配置预览失败：${msg}`, "warn");
    } finally {
      if (seq === previewReqSeqRef.current) {
        setLoadingPreview(false);
      }
    }
  }, []);

  const hydrateFromFullConfig = useCallback(
    async (options: { isInitial?: boolean; preserveDirtyInline?: boolean } = {}) => {
      const { isInitial = false, preserveDirtyInline = false } = options;
      const reqSeq = ++hydrateReqSeqRef.current;
      if (isInitial) setLoadingRules(true);
      try {
        const fullCfg = await catcloudApi.getFullConfig();
        if (reqSeq !== hydrateReqSeqRef.current) return;
        const fallbackTarget = groupsRef.current[0]?.name || "DIRECT";
        const savedOverride = fullCfg.rules_override;
        const savedDomesticDirect = savedOverride?.domestic_direct_enabled ?? true;
        const savedGeodataMode = Boolean(fullCfg.geodata_mode);
        const savedCustomOnly = Boolean(savedOverride?.custom_rules_only);
        const savedInlineYaml =
          typeof savedOverride?.inline_override_yaml === "string"
            ? savedOverride.inline_override_yaml
            : "";

        setDomesticDirectEnabled(savedDomesticDirect);
        setGeodataMode(savedGeodataMode);
        setCustomRulesOnly(savedCustomOnly);
        appActions.syncGeoRuleContext({
          domesticDirectEnabled: savedDomesticDirect,
          customRulesOnly: savedCustomOnly,
          geodataMode: savedGeodataMode,
        });

        const hasDirtyInlineDraft =
          preserveDirtyInline &&
          inlineOverrideYamlRef.current !== savedInlineOverrideYamlRef.current;
        if (!hasDirtyInlineDraft) {
          setInlineOverrideYaml(savedInlineYaml);
        }
        setSavedInlineOverrideYaml(savedInlineYaml);
        if (savedCustomOnly || savedInlineYaml.trim().length > 0) {
          setAdvancedOpen(true);
        }

        const hasSavedOverride =
          savedOverride !== undefined &&
          (Array.isArray(savedOverride.global_prepend_rules) ||
            Array.isArray(savedOverride.global_append_rules));

        if (!inTauri && !hasSavedOverride) {
          const demoPrepend = AI_PRESETS_TEMPLATE.flatMap((tpl) =>
            tpl.domains.map((d) => `DOMAIN-SUFFIX,${d},${fallbackTarget}`)
          );
          const demoAppend = ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"];
          const hydrated = hydrateRulesFromConfig(demoPrepend, demoAppend, fallbackTarget);
          setAiPresets(hydrated.presets);
          setUserRules(hydrated.userRules);
          return;
        }

        const prependList = Array.isArray(savedOverride?.global_prepend_rules)
          ? savedOverride.global_prepend_rules
          : [];
        const appendList = Array.isArray(savedOverride?.global_append_rules)
          ? savedOverride.global_append_rules
          : [];
        const hydrated = hydrateRulesFromConfig(prependList, appendList, fallbackTarget);
        setAiPresets(hydrated.presets);
        setUserRules(hydrated.userRules);
      } catch (err) {
        if (reqSeq !== hydrateReqSeqRef.current) return;
        if (isInitial) {
          appActions.showToast(`读取已保存的分流规则失败：${formatErrorMessage(err)}`, "warn");
        }
      } finally {
        if (isInitial && reqSeq === hydrateReqSeqRef.current) setLoadingRules(false);
      }
    },
    [inTauri]
  );

  useEffect(() => {
    void hydrateFromFullConfig({ isInitial: true, preserveDirtyInline: false });
    if (appStore.getState().bgTasks.settings.geoStatus === null) {
      void appActions.loadGeodataStatus();
    }
  }, [hydrateFromFullConfig]);

  useEffect(() => {
    if (!inTauri) return;
    let refreshTimer: number | null = null;
    const dispose = catcloudApi.subscribeConfigUpdate(() => {
      if (
        savingRulesRef.current ||
        savingInlineYamlRef.current ||
        savingCustomRulesOnlyRef.current ||
        bulkApplyingRef.current
      ) {
        return;
      }
      if (refreshTimer !== null) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(() => {
        refreshTimer = null;
        void hydrateFromFullConfig({ isInitial: false, preserveDirtyInline: true });
        if (showYamlPreviewRef.current) {
          void loadCompiledPreview();
        }
      }, 150);
    });
    return () => {
      if (refreshTimer !== null) window.clearTimeout(refreshTimer);
      dispose();
    };
  }, [hydrateFromFullConfig, inTauri, loadCompiledPreview]);

  const targetChoices = useMemo(() => {
    const names = groups
      .map((g) => g.name.trim())
      .filter((name) => name.length > 0);
    return Array.from(new Set([...names, "DIRECT", "REJECT"]));
  }, [groups]);

  const hadRealGroupsRef = useRef<boolean>(groups.length > 0);

  useEffect(() => {
    const firstGroup = groups[0]?.name?.trim();
    if (!firstGroup) return;
    const justLoadedGroups = !hadRealGroupsRef.current;
    hadRealGroupsRef.current = true;

    if (
      (justLoadedGroups && !userPickedNewTargetRef.current) ||
      !targetChoices.includes(newTarget)
    ) {
      setNewTarget(firstGroup);
    }
    setAiPresets((prev) =>
      prev.map((p) => {
        if (p.enabled) return p;
        if (
          !p.targetGroup ||
          !targetChoices.includes(p.targetGroup) ||
          (justLoadedGroups && p.targetGroup === "DIRECT")
        ) {
          return { ...p, targetGroup: firstGroup };
        }
        return p;
      })
    );
  }, [groups, newTarget, targetChoices]);

  const persistRulesOverride = useCallback(
    async (
      nextPresets: AiPresetBundle[],
      nextUserRules: ManagedRuleItem[],
      successToast: string
    ): Promise<boolean> => {
      const prevPresets = aiPresetsRef.current;
      const prevUserRules = userRulesRef.current;
      setAiPresets(nextPresets);
      setUserRules(nextUserRules);
      setSavingRules(true);
      try {
        const payload = buildRulesOverridePayload(nextPresets, nextUserRules);
        await catcloudApi.saveExtendedSettings({ rules_override: payload });
        appActions.showToast(successToast, "ok");
        if (showYamlPreviewRef.current) {
          void loadCompiledPreview();
        }
        return true;
      } catch (err) {
        setAiPresets(prevPresets);
        setUserRules(prevUserRules);
        appActions.showToast(`保存分流规则失败：${formatErrorMessage(err)}`, "warn");
        return false;
      } finally {
        setSavingRules(false);
      }
    },
    [loadCompiledPreview]
  );

  const groupBoundRules = useMemo<ManagedRuleItem[]>(
    () => buildGroupBoundRules(groups),
    [groups]
  );

  const enabledAiDomainCount = useMemo(
    () =>
      aiPresets
        .filter((p) => p.enabled)
        .reduce((acc, p) => acc + p.domains.length, 0),
    [aiPresets]
  );

  const totalRuleCount = userRules.length + groupBoundRules.length + enabledAiDomainCount;
  useEffect(() => {
    onRulesCountChange(totalRuleCount);
  }, [onRulesCountChange, totalRuleCount]);

  const allDisplayRules = useMemo(() => {
    const combined = [...userRules, ...groupBoundRules];
    const kw = ruleSearch.trim().toLowerCase();
    return combined.filter((item) => {
      if (ruleLayerFilter !== "all" && item.layer !== ruleLayerFilter) return false;
      if (!kw) return true;
      return (
        item.value.toLowerCase().includes(kw) ||
        item.ruleType.toLowerCase().includes(kw) ||
        item.target.toLowerCase().includes(kw) ||
        (item.rawLine?.toLowerCase().includes(kw) ?? false)
      );
    });
  }, [groupBoundRules, ruleLayerFilter, ruleSearch, userRules]);

  const compiledMeta = useMemo<ParsedCompiledMeta | null>(
    () => (compiledPreview ? parseCompiledPreviewMeta(compiledPreview) : null),
    [compiledPreview]
  );

  const autoLoadedPreviewRef = useRef<boolean>(false);

  useEffect(() => {
    if (showYamlPreview && !autoLoadedPreviewRef.current && !compiledPreview) {
      autoLoadedPreviewRef.current = true;
      void loadCompiledPreview();
    }
  }, [compiledPreview, loadCompiledPreview, showYamlPreview]);

  const handleToggleYamlPreview = () => {
    const next = !showYamlPreview;
    setShowYamlPreview(next);
    if (next) {
      autoLoadedPreviewRef.current = true;
      void loadCompiledPreview();
    }
  };

  const handleAddRule = async () => {
    if (savingRules) return;
    let rawInput = newValue.trim();
    if (!rawInput) {
      appActions.showToast("请填写要匹配的网址、IP、进程或复合条件", "warn");
      return;
    }
    if (rawInput.startsWith("- ")) {
      rawInput = rawInput.slice(2).trim();
    }

    let effectiveType: string = newType;
    let effectiveVal = rawInput;
    let effectiveTarget = newTarget.trim() || targetChoices[0] || "DIRECT";
    let effectiveNoResolve = (newType === "IP-CIDR" || newType === "GEOIP") && newNoResolve;

    // Auto-detect full pasted Mihomo rule lines (deduplicate prefix & preserve inline target/flags)
    const firstComma = rawInput.indexOf(",");
    if (firstComma > 0) {
      const prefixCandidate = rawInput.slice(0, firstComma).trim().toUpperCase();
      if (KNOWN_MIHOMO_RULE_TYPES.has(prefixCandidate)) {
        effectiveType = prefixCandidate;
        if (STRICT_LOGICAL_RULE_TYPES.has(prefixCandidate)) {
          const parsedLogical = parseLogicalRuleParts(rawInput);
          if (parsedLogical) {
            effectiveVal = parsedLogical.expr;
            if (parsedLogical.target) {
              effectiveTarget = parsedLogical.target;
            }
          } else {
            effectiveVal = rawInput.slice(firstComma + 1).trim();
          }
          effectiveNoResolve = false;
        } else if (prefixCandidate === "MATCH" || prefixCandidate === "FINAL") {
          effectiveVal = "*";
          const pastedTarget = rawInput.slice(firstComma + 1).trim();
          if (pastedTarget) effectiveTarget = pastedTarget;
          effectiveNoResolve = false;
        } else if (
          prefixCandidate === "DOMAIN-REGEX" ||
          prefixCandidate === "PROCESS-NAME-REGEX" ||
          prefixCandidate === "PROCESS-PATH-REGEX"
        ) {
          const restRegex = rawInput.slice(firstComma + 1).trim();
          const lastComma = restRegex.lastIndexOf(",");
          const knownTargets = new Set<string>([
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "PASS",
            ...groups.map((g) => g.name),
          ]);
          if (lastComma > 0) {
            const candidateTarget = restRegex.slice(lastComma + 1).trim();
            if (
              knownTargets.has(candidateTarget) ||
              knownTargets.has(candidateTarget.toUpperCase())
            ) {
              effectiveVal = restRegex.slice(0, lastComma).trim();
              effectiveTarget = candidateTarget;
            } else {
              effectiveVal = restRegex;
            }
          } else {
            effectiveVal = restRegex;
          }
          effectiveNoResolve = false;
        } else {
          const parts = rawInput.split(",").map((s) => s.trim());
          let endIdx = parts.length;
          let pastedNoResolve = false;
          while (endIdx > 2 && isRuleFlagToken(parts[endIdx - 1])) {
            if (parts[endIdx - 1].toLowerCase() === "no-resolve") pastedNoResolve = true;
            endIdx -= 1;
          }
          if (endIdx >= 3) {
            effectiveVal = parts.slice(1, endIdx - 1).join(",").trim();
            if (parts[endIdx - 1]) {
              effectiveTarget = parts[endIdx - 1];
            }
          } else if (endIdx === 2) {
            effectiveVal = parts[1];
          }
          effectiveNoResolve =
            pastedNoResolve ||
            ((effectiveType === "IP-CIDR" || effectiveType === "GEOIP") && newNoResolve);
        }
      }
    }

    if (STRICT_LOGICAL_RULE_TYPES.has(effectiveType)) {
      effectiveNoResolve = false;
      const errMsg = validateLogicalRuleExpr(effectiveVal, effectiveType);
      if (errMsg) {
        appActions.showToast(errMsg, "warn", 4600);
        return;
      }
    }

    if (!effectiveVal) {
      appActions.showToast("规则匹配值不能为空，请检查输入格式", "warn");
      return;
    }

    const rawLine =
      effectiveType === "MATCH" || effectiveType === "FINAL"
        ? `${effectiveType},${effectiveTarget}`
        : `${effectiveType},${effectiveVal},${effectiveTarget}${effectiveNoResolve ? ",no-resolve" : ""}`;

    const created: ManagedRuleItem = {
      id: `rule-custom-${Date.now()}`,
      layer: newLayer,
      ruleType: effectiveType,
      value: effectiveVal,
      target: effectiveTarget,
      noResolve: effectiveNoResolve,
      rawLine,
    };
    const nextRules = [created, ...userRules];
    const ok = await persistRulesOverride(
      aiPresets,
      nextRules,
      `已保存并生效：${created.value} → ${formatRuleTargetLabel(created.target)}`
    );
    if (ok) {
      setNewValue("");
    }
  };

  const imDirectAllPresent = useMemo(() => {
    const existingLower = new Set(
      userRules
        .filter((r) => r.layer === "prepend")
        .map((r) => serializeRuleItem(r).trim().toLowerCase())
    );
    return IM_DIRECT_PROCESS_RULES.every((item) =>
      existingLower.has(item.line.toLowerCase())
    );
  }, [userRules]);

  const handleAddImDirectRules = async () => {
    if (savingRules || loadingRules) return;
    const existingLower = new Set(
      userRules
        .filter((r) => r.layer === "prepend")
        .map((r) => serializeRuleItem(r).trim().toLowerCase())
    );
    const missing = IM_DIRECT_PROCESS_RULES.filter(
      (item) => !existingLower.has(item.line.toLowerCase())
    );
    if (missing.length === 0) {
      appActions.showToast(dict.rules.imDirectExistsToast, "info");
      return;
    }
    const stamp = Date.now();
    const toPrepend: ManagedRuleItem[] = missing.map((item, idx) => ({
      id: `rule-im-${stamp}-${idx}`,
      layer: "prepend",
      ruleType: "PROCESS-NAME",
      value: item.process,
      target: "DIRECT",
      noResolve: false,
      rawLine: item.line,
    }));
    await persistRulesOverride(
      aiPresets,
      [...toPrepend, ...userRules],
      formatI18nTemplate(dict.rules.imDirectAddedToast, { count: toPrepend.length })
    );
  };

  const handleDeleteRule = async (id: string) => {
    if (savingRules) return;
    const found = userRules.find((r) => r.id === id);
    if (!found) {
      appActions.showToast("分组自带规则请前往「智能多选组」页面修改", "info");
      return;
    }
    const nextRules = userRules.filter((r) => r.id !== id);
    await persistRulesOverride(aiPresets, nextRules, "已删除规则并保存生效");
  };

  const handleToggleAiPreset = async (id: string) => {
    if (savingRules) return;
    const targetPreset = aiPresets.find((p) => p.id === id);
    if (!targetPreset) return;
    const nextEnabled = !targetPreset.enabled;
    const nextTarget =
      targetPreset.targetGroup.trim() || groups[0]?.name || "DIRECT";
    const nextPresets = aiPresets.map((p) =>
      p.id === id ? { ...p, enabled: nextEnabled, targetGroup: nextTarget } : p
    );
    await persistRulesOverride(
      nextPresets,
      userRules,
      nextEnabled
        ? `已开启「${targetPreset.name}」分流并保存生效`
        : `已关闭「${targetPreset.name}」分流并保存生效`
    );
  };

  const handleChangeAiPresetTarget = async (id: string, targetGroup: string) => {
    if (savingRules) return;
    const targetPreset = aiPresets.find((p) => p.id === id);
    if (!targetPreset) return;
    const nextPresets = aiPresets.map((p) =>
      p.id === id ? { ...p, targetGroup } : p
    );
    if (!targetPreset.enabled) {
      setAiPresets(nextPresets);
      return;
    }
    await persistRulesOverride(
      nextPresets,
      userRules,
      `已将「${targetPreset.name}」指向「${formatRuleTargetLabel(targetGroup)}」并保存生效`
    );
  };

  const handleCopyYaml = async () => {
    const text = compiledPreview?.yaml;
    if (!text) {
      appActions.showToast("暂无可复制的编译配置", "warn");
      return;
    }
    const copied = await copyText(text);
    if (copied) {
      setCopiedYaml(true);
      appActions.showToast("已复制后端编译生成的脱敏配置", "ok");
      if (copiedYamlTimerRef.current !== null) {
        window.clearTimeout(copiedYamlTimerRef.current);
      }
      copiedYamlTimerRef.current = window.setTimeout(() => {
        copiedYamlTimerRef.current = null;
        setCopiedYaml(false);
      }, 1800);
    } else {
      appActions.showToast("剪贴板不可用，请手动选中复制", "warn");
    }
  };

  const handleBulkImport = async (mode: "append" | "replace") => {
    if (savingRules || bulkApplying || loadingRules) return;
    const raw = bulkRawText.trim();
    if (!raw) {
      appActions.showToast("请先粘贴要导入的 Mihomo 分流规则文本", "warn");
      return;
    }
    setBulkApplying(true);
    try {
      const parsed = await catcloudApi.parseBulkRulesPreview(raw);
      const validLines = Array.isArray(parsed.valid_rules) ? parsed.valid_rules : [];
      const skippedLines = Array.isArray(parsed.skipped_lines) ? parsed.skipped_lines : [];

      if (validLines.length === 0) {
        setBulkFeedback({
          mode,
          layer: bulkTargetLayer,
          validCount: 0,
          skippedLines,
        });
        appActions.showToast(
          skippedLines.length > 0
            ? `未识别出有效规则（已跳过 ${skippedLines.length} 行），请检查格式`
            : "粘贴内容中未包含有效规则",
          "warn"
        );
        return;
      }

      const stamp = Date.now();
      const importedItems: ManagedRuleItem[] = [];
      const unparsedValidLines: string[] = [];
      for (let i = 0; i < validLines.length; i++) {
        const line = validLines[i];
        const item = parseRuleString(line, bulkTargetLayer, `rule-bulk-${stamp}-${i}`);
        if (item) {
          importedItems.push(item);
        } else {
          unparsedValidLines.push(line);
        }
      }
      const mergedSkippedLines = [...skippedLines, ...unparsedValidLines];

      if (importedItems.length === 0) {
        setBulkFeedback({
          mode,
          layer: bulkTargetLayer,
          validCount: 0,
          skippedLines: mergedSkippedLines,
        });
        appActions.showToast("未能将解析结果转换为可保存的规则条目", "warn");
        return;
      }

      let nextRules: ManagedRuleItem[];
      if (mode === "replace") {
        const preservedOtherLayer = userRules.filter((r) => r.layer !== bulkTargetLayer);
        nextRules = [...preservedOtherLayer, ...importedItems];
      } else {
        const existingSerialized = new Set(
          userRules.map((r) => `${r.layer}::${serializeRuleItem(r).trim()}`)
        );
        const dedupedNew = importedItems.filter(
          (item) =>
            !existingSerialized.has(`${item.layer}::${serializeRuleItem(item).trim()}`)
        );
        nextRules = [...userRules, ...dedupedNew];
      }

      const layerLabel = bulkTargetLayer === "prepend" ? "优先匹配" : "兜底匹配";
      const ok = await persistRulesOverride(
        aiPresets,
        nextRules,
        mode === "replace"
          ? `已替换「${layerLabel}」层自定义规则：写入 ${importedItems.length} 条${mergedSkippedLines.length > 0 ? `，跳过 ${mergedSkippedLines.length} 行` : ""}`
          : `已解析并追加 ${importedItems.length} 条规则（${layerLabel}）${mergedSkippedLines.length > 0 ? `，跳过 ${mergedSkippedLines.length} 行` : ""}`
      );
      if (ok) {
        setBulkFeedback({
          mode,
          layer: bulkTargetLayer,
          validCount: importedItems.length,
          skippedLines: mergedSkippedLines,
        });
        setBulkRawText("");
      }
    } catch (err) {
      appActions.showToast(`解析批量规则失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setBulkApplying(false);
    }
  };

  const handleToggleCustomRulesOnly = async () => {
    if (savingCustomRulesOnly || loadingRules) return;
    const prev = customRulesOnly;
    const next = !prev;
    setCustomRulesOnly(next);
    setSavingCustomRulesOnly(true);
    try {
      await catcloudApi.saveExtendedSettings({
        rules_override: { custom_rules_only: next },
      });
      appActions.syncGeoRuleContext({ customRulesOnly: next });
      appActions.showToast(
        next
          ? "已开启「纯自写规则模式」：跳过内置国内/AI 规则，仅保留防环与局域网直连"
          : "已关闭「纯自写规则模式」，恢复猫云内置分流规则",
        "ok"
      );
      if (showYamlPreviewRef.current) {
        void loadCompiledPreview();
      }
    } catch (err) {
      setCustomRulesOnly(prev);
      appActions.showToast(`切换纯自写规则模式失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingCustomRulesOnly(false);
    }
  };

  const handleSaveInlineOverrideYaml = async (explicitValue?: string) => {
    if (savingInlineYaml || loadingRules) return;
    const candidateRaw = explicitValue !== undefined ? explicitValue : inlineOverrideYaml;
    const trimmed = candidateRaw.trim();
    const normalizedPayload: string | null = trimmed.length > 0 ? candidateRaw : null;

    setInlineYamlError(null);
    setInlineYamlVerifiedMsg(null);

    if (trimmed.length > 0) {
      const localErr = validateInlineOverrideYamlLocal(candidateRaw);
      if (localErr) {
        setInlineYamlError(`YAML 格式校验未通过：${localErr}（未写入配置）`);
        appActions.showToast(`内联 YAML 校验未通过：${localErr}`, "warn");
        return;
      }
    }

    const prevSaved = savedInlineOverrideYaml;
    const prevPayload: string | null = prevSaved.trim().length > 0 ? prevSaved : null;
    setSavingInlineYaml(true);
    try {
      await catcloudApi.saveExtendedSettings({
        rules_override: { inline_override_yaml: normalizedPayload },
      });

      let previewRes: CompiledYamlPreview;
      try {
        previewRes = await catcloudApi.compilePreviewYaml();
      } catch (verifyErr) {
        await catcloudApi
          .saveExtendedSettings({
            rules_override: { inline_override_yaml: prevPayload },
          })
          .catch(() => {});
        const msg = formatErrorMessage(verifyErr);
        setInlineYamlError(`编译校验失败，已自动回退未写入脏配置：${msg}`);
        appActions.showToast(`内联 YAML 校验失败：${msg}`, "warn");
        return;
      }

      const meta = parseCompiledPreviewMeta(previewRes);
      if (!meta.validationOk && meta.errors.length > 0 && trimmed.length > 0) {
        const previewErrors = meta.errors.slice(0, 3);
        const errSummary =
          previewErrors
            .map((item) => (item.code ? `[${item.code}] ${item.message}` : item.message))
            .join("；") +
          (meta.errors.length > 3 ? ` 等共 ${meta.errors.length} 项校验异常` : "");
        await catcloudApi
          .saveExtendedSettings({
            rules_override: { inline_override_yaml: prevPayload },
          })
          .catch(() => {});
        setInlineYamlError(`配置编译校验未通过，已自动回退未写入脏配置：${errSummary}`);
        appActions.showToast("内联 YAML 校验未通过，已回退原配置", "warn");
        return;
      }

      setCompiledPreview(previewRes);
      setSavedInlineOverrideYaml(trimmed.length > 0 ? candidateRaw : "");
      if (explicitValue !== undefined) {
        setInlineOverrideYaml(trimmed.length > 0 ? candidateRaw : "");
      }
      if (trimmed.length === 0) {
        setInlineYamlVerifiedMsg("已清空内联 YAML 覆写并通过编译校验");
        appActions.showToast("已清空内联 YAML 覆写并生效", "ok");
      } else if (meta.warnings.length > 0) {
        setInlineYamlVerifiedMsg(
          `已保存并通过校验（${meta.warnings.length} 条提醒，可在上方编译预览查看）`
        );
        appActions.showToast("内联 YAML 覆写已保存并通过校验", "ok");
      } else {
        setInlineYamlVerifiedMsg("已保存并通过 Mihomo 配置编译校验");
        appActions.showToast("内联 YAML 覆写已保存并通过校验", "ok");
      }
    } catch (err) {
      const msg = formatErrorMessage(err);
      setInlineYamlError(`保存或校验失败（未写入脏配置）：${msg}`);
      appActions.showToast(`保存内联 YAML 失败：${msg}`, "warn");
    } finally {
      setSavingInlineYaml(false);
    }
  };

  const ruleLayerOptions = useMemo<AppSelectOption[]>(
    () => [
      { value: "prepend", label: "优先匹配（最先判断）" },
      { value: "append", label: "兜底匹配（最后判断）" },
    ],
    []
  );

  const ruleTypeOptions = useMemo<AppSelectOption[]>(
    () =>
      (Object.keys(RULE_TYPE_LABELS) as RuleMatchType[]).map((key) => ({
        value: key,
        label: RULE_TYPE_LABELS[key],
      })),
    []
  );

  const ruleTargetOptions = useMemo<AppSelectOption[]>(
    () =>
      targetChoices.map((t) => ({
        value: t,
        label: formatRuleTargetLabel(t),
      })),
    [targetChoices]
  );

  const requiredGeoFileName = geodataMode ? "geoip.dat" : "Country.mmdb";
  const missingGeoDb = Boolean(
    !loadingRules &&
      geoStatus !== null &&
      domesticDirectEnabled &&
      !customRulesOnly &&
      (geodataMode ? !geoStatus.geoip_dat.exists : !geoStatus.country_mmdb.exists)
  );

  return (
    <div className="space-y-4">
      {/* Missing GeoData Reminder Banner (0px when healthy or custom_rules_only) */}
      {missingGeoDb && (
        <section
          role="status"
          className="cc-card cc-glass rounded-2xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/45 px-4 py-3 text-xs"
        >
          <div className="flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex min-w-0 flex-1 items-start gap-2.5">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--amber)]" />
              <div className="min-w-0">
                <div className="font-semibold text-[var(--text)]">
                  {dict.rules.geoMissingTitle}
                </div>
                <p className="mt-0.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  {formatI18nTemplate(dict.rules.geoMissingDesc, {
                    file: requiredGeoFileName,
                  })}
                </p>
              </div>
            </div>
            <button
              type="button"
              disabled={geoBusy !== null}
              onClick={() =>
                void appActions.runRefreshGeoDb(
                  geodataMode ? ["geoip", "geosite"] : ["mmdb", "geosite"]
                )
              }
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 py-1.5 text-[11.5px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${geoBusy ? "animate-spin" : ""}`} />
              <span>{geoBusy ? dict.rules.geoFetchingBtn : dict.rules.geoFetchBtn}</span>
            </button>
          </div>
        </section>
      )}

      {/* 常用网站分流 */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Sparkles className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-sm font-semibold text-[var(--text)]">常用网站分流</h2>
            <span className="text-[11px] text-[var(--muted)]">
              打开开关即可自动保存，让常用 AI 与开发网站走指定分组
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {savingRules && (
              <span className="whitespace-nowrap text-[11px] text-[var(--accent)]">保存中...</span>
            )}
            <button
              type="button"
              onClick={() => setGatewayModalOpen(true)}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
              title="一键导出透明网关 / OpenWrt / Linux 旁路由可用的 Mihomo 配置或中转片段"
            >
              <Router className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
              导出给软路由 / 透明网关
            </button>
            <button
              type="button"
              onClick={handleToggleYamlPreview}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)]"
            >
              <Code2 className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
              {showYamlPreview ? "收起实际规则" : "预览实际规则"}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {aiPresets.map((preset) => {
            const presetOptions = targetChoices.includes(preset.targetGroup)
              ? targetChoices
              : [preset.targetGroup, ...targetChoices].filter(Boolean);
            return (
              <div
                key={preset.id}
                className={`min-w-0 rounded-xl border p-3.5 transition-colors ${
                  preset.enabled
                    ? "border-[var(--line-strong)] bg-[var(--bg-elevated)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)]/50 opacity-75"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-semibold text-[var(--text)]">{preset.name}</div>
                    <div className="mt-0.5 text-[11px] text-[var(--muted)]">{preset.desc}</div>
                  </div>
                  <button
                    type="button"
                    disabled={savingRules || loadingRules}
                    onClick={() => void handleToggleAiPreset(preset.id)}
                    className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-50 ${
                      preset.enabled ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                    }`}
                    aria-label={`切换 ${preset.name}`}
                  >
                    <span
                      className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                        preset.enabled ? "translate-x-4" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>

                <div className="mt-2.5 flex flex-wrap gap-1">
                  {preset.domains.map((d) => (
                    <span
                      key={d}
                      className="cc-mono break-all rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                    >
                      {d}
                    </span>
                  ))}
                </div>

                <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] pt-2 text-[11px]">
                  <span className="shrink-0 whitespace-nowrap text-[var(--muted)]">走哪个分组</span>
                  <AppSelect
                    size="xs"
                    aria-label={`${preset.name} 目标分组`}
                    value={preset.targetGroup}
                    disabled={savingRules || loadingRules}
                    onChange={(val) => void handleChangeAiPresetTarget(preset.id, val)}
                    options={presetOptions.map((t) => ({
                      value: t,
                      label: formatRuleTargetLabel(t),
                    }))}
                    className="min-w-[132px] max-w-[200px]"
                  />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 后端真实编译配置预览（已脱敏） */}
      {showYamlPreview && (
        <section className="cc-card cc-glass overflow-hidden rounded-2xl">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-2.5">
            <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-[var(--text)]">
              <Eye className="h-3.5 w-3.5 text-[var(--accent)]" />
              <span>后端编译配置预览（已脱敏）</span>
              {compiledMeta && (
                <>
                  <span className="cc-mono rounded-full border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--text-secondary)]">
                    规则 {compiledMeta.totalRules ?? "--"} 条
                    {compiledMeta.proxyGroups !== null ? ` · 分组 ${compiledMeta.proxyGroups}` : ""}
                    {compiledMeta.totalProxies !== null ? ` · 节点 ${compiledMeta.totalProxies}` : ""}
                  </span>
                  {compiledMeta.validationOk ? (
                    compiledMeta.warnings.length > 0 ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--amber)]">
                        <AlertTriangle className="h-3 w-3" />
                        校验通过（{compiledMeta.warnings.length} 条提醒）
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--green)]">
                        <CheckCircle2 className="h-3 w-3" />
                        编译校验通过
                      </span>
                    )
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--red-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--red)]">
                      <AlertTriangle className="h-3 w-3" />
                      校验未通过（{compiledMeta.errors.length} 项错误）
                    </span>
                  )}
                </>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => setGatewayModalOpen(true)}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--accent)]/45 bg-[var(--accent-soft)]/55 px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] hover:border-[var(--accent)]"
                title="导出适配 OpenWrt / Linux 旁路由的透明网关完整配置或中转片段"
              >
                <Router className="h-3 w-3 shrink-0" />
                导出给软路由 / 透明网关
              </button>
              <button
                type="button"
                disabled={loadingPreview}
                onClick={() => void loadCompiledPreview()}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 shrink-0 ${loadingPreview ? "animate-spin" : ""}`} />
                重新编译
              </button>
              <button
                type="button"
                disabled={loadingPreview || !compiledPreview?.yaml}
                onClick={() => void handleCopyYaml()}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
              >
                {copiedYaml ? (
                  <Check className="h-3 w-3 shrink-0 text-[var(--green)]" />
                ) : (
                  <Copy className="h-3 w-3 shrink-0 text-[var(--accent)]" />
                )}
                {copiedYaml ? "已复制" : "复制配置"}
              </button>
            </div>
          </div>

          {compiledMeta && (compiledMeta.errors.length > 0 || compiledMeta.warnings.length > 0) && (
            <div className="space-y-1 border-b border-[var(--line)] bg-[var(--bg-elevated)]/50 px-4 py-2 text-[11px]">
              {compiledMeta.errors.map((issue, idx) => (
                <div key={`err-${idx}`} className="flex items-start gap-1.5 text-[var(--red)]">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>
                    {issue.code ? `[${issue.code}] ` : ""}
                    {issue.message}
                  </span>
                </div>
              ))}
              {compiledMeta.warnings.map((issue, idx) => (
                <div key={`warn-${idx}`} className="flex items-start gap-1.5 text-[var(--amber)]">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>
                    {issue.code ? `[${issue.code}] ` : ""}
                    {issue.message}
                  </span>
                </div>
              ))}
            </div>
          )}

          {loadingPreview && !compiledPreview ? (
            <div className="py-8 text-center text-xs text-[var(--muted)]">
              正在调用后端编译并校验配置...
            </div>
          ) : previewError && !compiledPreview ? (
            <div className="px-4 py-6 text-center text-xs text-[var(--red)]">
              编译预览失败：{previewError}
            </div>
          ) : (
            <pre className="cc-selectable cc-mono max-h-[300px] overflow-auto p-4 text-[11px] leading-relaxed text-[var(--text-secondary)]">
              {compiledPreview?.yaml ?? ""}
            </pre>
          )}
        </section>
      )}

      {/* 自定义分流规则表单 */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-xs font-semibold text-[var(--text)]">自定义分流规则</h2>
            <button
              type="button"
              disabled={savingRules || loadingRules}
              onClick={() => void handleAddImDirectRules()}
              title="一键向优先匹配层去重添加 QQ.exe、WeChat.exe、Weixin.exe 进程直连，防止无地理库时国内 IM 纯 IP 流量绕海外"
              className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors disabled:opacity-50 ${
                imDirectAllPresent
                  ? "border-[var(--green)]/40 bg-[var(--green-soft)]/70 text-[var(--green)]"
                  : "border-[var(--accent)]/45 bg-[var(--accent-soft)]/55 text-[var(--accent)] hover:border-[var(--accent)]"
              }`}
            >
              {imDirectAllPresent ? (
                <Check className="h-3 w-3 shrink-0" />
              ) : (
                <Plus className="h-3 w-3 shrink-0" />
              )}
              <span>
                {imDirectAllPresent
                  ? dict.rules.imDirectAlreadyAdded
                  : dict.rules.addImDirectBtn}
              </span>
            </button>
          </div>
          <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] text-[var(--green)]">
            <Shield className="h-3 w-3" />
            系统已自动保护本机直连与防绕路死循环，添加规则后立即保存生效
          </span>
        </div>
        <div className="grid grid-cols-1 items-center gap-2 sm:grid-cols-2 min-[1160px]:grid-cols-12">
          <AppSelect
            size="md"
            aria-label="规则优先级层级"
            value={newLayer}
            onChange={(v) => setNewLayer(v as "prepend" | "append")}
            options={ruleLayerOptions}
            className="w-full min-[1160px]:col-span-2"
            buttonClassName="w-full rounded-xl"
          />

          <AppSelect
            size="md"
            aria-label="规则匹配类型"
            value={newType}
            onChange={(v) => setNewType(v as RuleMatchType)}
            options={ruleTypeOptions}
            className="w-full min-[1160px]:col-span-2"
            buttonClassName="w-full rounded-xl"
          />

          <input
            type="text"
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleAddRule();
            }}
            placeholder={RULE_VALUE_PLACEHOLDERS[newType]}
            className="cc-mono h-9 min-w-0 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none sm:col-span-2 min-[1160px]:col-span-4"
          />

          <AppSelect
            size="md"
            aria-label="规则目标分组"
            value={newTarget}
            onChange={(v) => {
              userPickedNewTargetRef.current = true;
              setNewTarget(v);
            }}
            options={ruleTargetOptions}
            className="w-full min-[1160px]:col-span-2"
            buttonClassName="w-full rounded-xl"
          />

          <button
            type="button"
            disabled={savingRules || loadingRules}
            onClick={() => void handleAddRule()}
            className="inline-flex h-9 shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50 min-[1160px]:col-span-2"
          >
            <Plus className="h-3.5 w-3.5 shrink-0" />
            添加并保存
          </button>
        </div>

        {(newType === "IP-CIDR" || newType === "GEOIP") && (
          <label className="mt-2 inline-flex items-center gap-2 text-[11px] text-[var(--muted)]">
            <input
              type="checkbox"
              checked={newNoResolve}
              onChange={(e) => setNewNoResolve(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            跳过域名解析（直连规则推荐勾选，避免多余 DNS 查询）
          </label>
        )}
      </section>

      {/* 高阶：批量导入规则与自定义 YAML 覆写 */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <button
          type="button"
          onClick={() => setAdvancedOpen((prev) => !prev)}
          aria-expanded={advancedOpen}
          className="flex w-full flex-wrap items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--bg-elevated)]/55"
        >
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            <SlidersHorizontal className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            <span className="text-xs font-semibold text-[var(--text)]">
              高阶：批量导入规则与自定义 YAML 覆写（兼容手写规则 / rule-providers）
            </span>
            {customRulesOnly && (
              <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[10.5px] font-semibold text-[var(--accent)]">
                <Sparkles className="h-3 w-3 shrink-0" />
                纯自写规则已开启
              </span>
            )}
            {savedInlineOverrideYaml.trim().length > 0 && (
              <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-semibold text-[var(--green)]">
                <FileCode2 className="h-3 w-3 shrink-0" />
                YAML 覆写生效中
              </span>
            )}
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-[11px] text-[var(--muted)]">
            <span>{advancedOpen ? "收起" : "展开"}</span>
            {advancedOpen ? (
              <ChevronDown className="h-4 w-4 shrink-0" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0" />
            )}
          </span>
        </button>

        {advancedOpen && (
          <div className="space-y-4 border-t border-[var(--line)] p-4">
            {/* 1. 批量粘贴原始 Mihomo 规则区 */}
            <div className="space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/45 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="text-xs font-semibold text-[var(--text)]">
                    批量粘贴原始 Mihomo 规则
                  </h3>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    支持直接粘贴整段{" "}
                    <span className="cc-mono">- DOMAIN-SUFFIX,...</span>、
                    <span className="cc-mono">RULE-SET,...</span>、
                    <span className="cc-mono">AND,...</span> 与注释行，自动清理格式并去重写入
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <AppSelect
                    size="xs"
                    aria-label="批量导入规则层级"
                    value={bulkTargetLayer}
                    disabled={savingRules || bulkApplying || loadingRules}
                    onChange={(v) => setBulkTargetLayer(v as "prepend" | "append")}
                    options={ruleLayerOptions}
                    className="min-w-[144px] max-w-[200px]"
                  />
                  <button
                    type="button"
                    disabled={bulkApplying}
                    onClick={() => {
                      setBulkRawText(DEMO_BULK_RULES_TEXT);
                      setBulkFeedback(null);
                    }}
                    className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                  >
                    填入示例
                  </button>
                </div>
              </div>

              <textarea
                rows={5}
                value={bulkRawText}
                onChange={(e) => {
                  setBulkRawText(e.target.value);
                  if (bulkFeedback) setBulkFeedback(null);
                }}
                spellCheck={false}
                placeholder={[
                  "每行一条 Mihomo 规则，例如：",
                  "- DOMAIN-SUFFIX,example.com,DIRECT",
                  "- RULE-SET,apple_cn,DIRECT",
                  "- AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443)),PROXY",
                  "# 以 # 开头的注释行会自动忽略",
                ].join("\n")}
                className="cc-mono cc-selectable w-full min-w-0 rounded-xl border border-[var(--line)] bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />

              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] text-[var(--muted)]">
                  解析前会先经后端格式识别，无法识别的行会自动跳过并单独列出
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={savingRules || bulkApplying || loadingRules || !bulkRawText.trim()}
                    onClick={() => void handleBulkImport("append")}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {bulkApplying ? (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                    ) : (
                      <Upload className="h-3.5 w-3.5 shrink-0" />
                    )}
                    解析并追加
                  </button>
                  <button
                    type="button"
                    disabled={savingRules || bulkApplying || loadingRules || !bulkRawText.trim()}
                    onClick={() => void handleBulkImport("replace")}
                    title="仅替换上方当前所选层级（优先匹配或兜底匹配）的自定义规则，保留另一层规则"
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/70 px-3 py-1.5 text-xs font-semibold text-[var(--amber)] transition-colors hover:border-[var(--amber)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    替换当前层自定义规则
                  </button>
                </div>
              </div>

              {bulkFeedback && (
                <div
                  className={`space-y-1.5 rounded-xl border px-3 py-2 text-[11px] ${
                    bulkFeedback.validCount > 0
                      ? "border-[var(--green)]/40 bg-[var(--green-soft)]/45 text-[var(--text)]"
                      : "border-[var(--amber)]/45 bg-[var(--amber-soft)]/50 text-[var(--amber)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">
                      {bulkFeedback.validCount > 0
                        ? `${bulkFeedback.mode === "replace" ? "已替换当前层" : "已追加"}（${bulkFeedback.layer === "prepend" ? "优先匹配" : "兜底匹配"}）：成功解析 ${bulkFeedback.validCount} 条有效规则${bulkFeedback.skippedLines.length > 0 ? `，跳过 ${bulkFeedback.skippedLines.length} 行` : ""}`
                        : `未解析出有效规则（共跳过 ${bulkFeedback.skippedLines.length} 行）`}
                    </span>
                    <button
                      type="button"
                      onClick={() => setBulkFeedback(null)}
                      className="shrink-0 rounded p-0.5 text-[var(--muted)] hover:text-[var(--text)]"
                      aria-label="关闭批量解析结果"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  {bulkFeedback.skippedLines.length > 0 && (
                    <div className="space-y-0.5 border-t border-[var(--line)]/60 pt-1.5 text-[10.5px] text-[var(--amber)]">
                      <div className="font-medium">已跳过的行（格式不完整或暂不支持）：</div>
                      <ul className="cc-mono max-h-24 list-disc space-y-0.5 overflow-y-auto pl-4">
                        {bulkFeedback.skippedLines.slice(0, 20).map((line, idx) => (
                          <li key={`skip-${idx}`} className="break-all">
                            {line}
                          </li>
                        ))}
                        {bulkFeedback.skippedLines.length > 20 && (
                          <li>… 其余 {bulkFeedback.skippedLines.length - 20} 行已省略</li>
                        )}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* 2. 纯自写规则模式开关 */}
            <div
              className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border p-3.5 transition-colors ${
                customRulesOnly
                  ? "border-[var(--accent)]/60 bg-[var(--accent-soft)]/35"
                  : "border-[var(--line)] bg-[var(--bg-elevated)]/45"
              }`}
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold text-[var(--text)]">纯自写规则模式</span>
                  <span className="cc-mono rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                    custom_rules_only
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  开启后跳过猫云内置国内直连/AI 分流规则，仅保留最底层防环与局域网直连，完全以你的自写规则与下方覆写为准
                </p>
              </div>

              <button
                type="button"
                role="switch"
                aria-checked={customRulesOnly}
                aria-label="切换纯自写规则模式"
                disabled={savingCustomRulesOnly || loadingRules}
                onClick={() => void handleToggleCustomRulesOnly()}
                className={`inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-50 ${
                  customRulesOnly ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                }`}
              >
                <span
                  className={`h-5 w-5 rounded-full bg-[var(--card)] transition-transform ${
                    customRulesOnly ? "translate-x-5" : "translate-x-0"
                  }`}
                />
              </button>
            </div>

            {/* 3. 内联 YAML 覆写代码框 */}
            <div className="space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/45 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-xs font-semibold text-[var(--text)]">
                      内联 YAML 覆写（Merge Patch）
                    </h3>
                    <span className="cc-mono rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                      inline_override_yaml
                    </span>
                    {inlineOverrideYaml !== savedInlineOverrideYaml && (
                      <span className="rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                        有未保存修改
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    直接粘贴 <span className="cc-mono">rule-providers:</span>、
                    <span className="cc-mono">rules:</span>、
                    <span className="cc-mono">dns:</span> 等任意 Mihomo YAML Merge Patch 片段；保存时自动执行编译校验，语法有误绝不写入脏配置
                  </p>
                </div>
                <button
                  type="button"
                  disabled={savingInlineYaml}
                  onClick={() => {
                    setInlineOverrideYaml(DEMO_INLINE_OVERRIDE_YAML);
                    setInlineYamlError(null);
                    setInlineYamlVerifiedMsg(null);
                  }}
                  className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                >
                  填入 rule-providers 示例
                </button>
              </div>

              <textarea
                rows={7}
                value={inlineOverrideYaml}
                onChange={(e) => {
                  setInlineOverrideYaml(e.target.value);
                  if (inlineYamlError) setInlineYamlError(null);
                  if (inlineYamlVerifiedMsg) setInlineYamlVerifiedMsg(null);
                }}
                spellCheck={false}
                placeholder={[
                  "# 粘贴任意 Mihomo YAML Merge Patch 片段（留空保存即关闭内联覆写）",
                  "rule-providers:",
                  "  apple_cn:",
                  "    type: http",
                  "    behavior: domain",
                  '    url: "https://example.invalid/rules/apple-cn.yaml"',
                  "    path: ./ruleset/apple-cn.yaml",
                  "    interval: 86400",
                ].join("\n")}
                className="cc-mono cc-selectable w-full min-w-0 rounded-xl border border-[var(--line)] bg-[var(--card)] p-3 text-[11px] leading-relaxed text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />

              {inlineYamlError && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-[11px] leading-relaxed text-[var(--red)]">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span className="min-w-0 flex-1 break-words">{inlineYamlError}</span>
                </div>
              )}

              {inlineYamlVerifiedMsg && !inlineYamlError && (
                <div className="flex items-center gap-2 rounded-xl border border-[var(--green)]/40 bg-[var(--green-soft)]/50 px-3 py-2 text-[11px] text-[var(--green)]">
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                  <span className="min-w-0 flex-1 break-words">{inlineYamlVerifiedMsg}</span>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] text-[var(--muted)]">
                  留空并点击保存可清除内联覆写；支持配合上方批量规则引用自定义{" "}
                  <span className="cc-mono">RULE-SET</span>
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  {(inlineOverrideYaml.trim().length > 0 ||
                    savedInlineOverrideYaml.trim().length > 0) && (
                    <button
                      type="button"
                      disabled={savingInlineYaml || loadingRules}
                      onClick={() => void handleSaveInlineOverrideYaml("")}
                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--red)] hover:text-[var(--red)] disabled:opacity-50"
                    >
                      <Trash2 className="h-3.5 w-3.5 shrink-0" />
                      清空覆写
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={savingInlineYaml || loadingRules}
                    onClick={() => void handleSaveInlineOverrideYaml()}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {savingInlineYaml ? (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                    )}
                    {savingInlineYaml ? "正在保存并校验…" : "保存并立即校验"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* 已保存规则列表 */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-3">
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {(
              [
                { id: "all", label: "全部规则" },
                { id: "prepend", label: "优先匹配" },
                { id: "group", label: "分组自带" },
                { id: "append", label: "兜底匹配" },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setRuleLayerFilter(tab.id)}
                className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                  ruleLayerFilter === tab.id
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative min-w-[220px] flex-1 max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
            <input
              type="text"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              placeholder="搜索网址、类型或目标分组..."
              className="w-full rounded-xl border border-[var(--line)] bg-[var(--card)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
            {ruleSearch && (
              <button
                type="button"
                onClick={() => setRuleSearch("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        <div className="divide-y divide-[var(--line)]">
          {loadingRules ? (
            <div className="py-10 text-center text-xs text-[var(--muted)]">
              正在读取已保存的分流规则...
            </div>
          ) : allDisplayRules.length === 0 ? (
            <div className="py-10 text-center text-xs text-[var(--muted)]">
              暂无自定义分流规则，可在上方直接添加或开启「常用网站分流」
            </div>
          ) : (
            allDisplayRules.map((item) => {
              const typeLabel =
                RULE_TYPE_LABELS[item.ruleType as RuleMatchType] ??
                EXTRA_RULE_TYPE_LABELS[item.ruleType] ??
                item.ruleType;
              return (
                <div
                  key={item.id}
                  className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-xs hover:bg-[var(--card-hover)]"
                >
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <span
                      className="rounded-md px-2 py-0.5 text-[10px] font-medium"
                      style={{
                        backgroundColor:
                          item.layer === "prepend"
                            ? "var(--accent-soft)"
                            : item.layer === "group"
                              ? "var(--sky-soft)"
                              : "var(--bg-elevated)",
                        color:
                          item.layer === "prepend"
                            ? "var(--accent)"
                            : item.layer === "group"
                              ? "var(--sky)"
                              : "var(--muted)",
                      }}
                    >
                      {item.layer === "prepend"
                        ? "优先匹配"
                        : item.layer === "group"
                          ? "分组自带"
                          : "兜底匹配"}
                    </span>

                    <span
                      title={item.ruleType}
                      className="rounded border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                    >
                      {typeLabel}
                    </span>

                    <span className="cc-mono cc-selectable min-w-0 break-all font-medium text-[var(--text)]">
                      {item.value}
                    </span>

                    {item.noResolve && (
                      <span className="shrink-0 text-[10px] text-[var(--muted)]">跳过域名解析</span>
                    )}
                    {item.isRawFallback && (
                      <span
                        title="已存在的高级/自定义原始规则，保存其它规则时将原样回写保留"
                        className="shrink-0 rounded bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                      >
                        原始保留（只读）
                      </span>
                    )}
                  </div>

                  <div className="flex shrink-0 items-center gap-2.5">
                    {item.target ? (
                      <span
                        title={formatRuleTargetLabel(item.target)}
                        className="max-w-[220px] truncate rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]"
                      >
                        → {formatRuleTargetLabel(item.target)}
                      </span>
                    ) : (
                      <span className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--muted)]">
                        原样回写
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => void handleDeleteRule(item.id)}
                      disabled={savingRules || Boolean(item.groupId)}
                      className="rounded-lg p-1 text-[var(--muted)] hover:bg-[var(--red-soft)] hover:text-[var(--red)] disabled:cursor-not-allowed disabled:opacity-35"
                      title={
                        item.groupId ? "分组自带规则请前往「智能多选组」页调整" : "删除此规则"
                      }
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </section>

      {gatewayModalOpen && (
        <Suspense fallback={null}>
          <GatewayExportModal
            open={gatewayModalOpen}
            defaultProfile="transparent_gateway"
            onClose={() => setGatewayModalOpen(false)}
          />
        </Suspense>
      )}
    </div>
  );
}
