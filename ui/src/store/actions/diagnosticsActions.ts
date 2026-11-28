import {
  type AgentPromptMode,
  type DanglingRulesAudit,
  type ExitIpInfo,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { normalizeUiLanguage, type UiLanguage } from "../../i18n";
import { copyText } from "../../utils/clipboard";
import type { StoreCore } from "../core";

function hasRealExitIpInfo(info: ExitIpInfo): boolean {
  const masked = info.ip_masked?.trim() ?? "";
  return Boolean(masked && !masked.includes("--") && masked !== "待检测");
}

export interface DiagnosticsActionDeps {
  hydrateFromBackend: () => Promise<void>;
}

export function createDiagnosticsActions(core: StoreCore, deps: DiagnosticsActionDeps) {
  async function refreshDanglingRulesAudit(): Promise<DanglingRulesAudit | null> {
    try {
      const audit = await catcloudApi.auditDanglingRules();
      core.setState((prev) => ({
        ...prev,
        danglingRulesAudit: audit,
      }));
      return audit;
    } catch {
      return null;
    }
  }

  async function runQuickSitesCheck(): Promise<void> {
    return core.runInFlight(
      "home:quickSites",
      async () => {
        core.updateBgTasks((bg) => ({
          ...bg,
          home: { ...bg.home, checkingQuickSites: true },
        }));
        try {
          const freshSites = await catcloudApi.checkQuickSites();
          if (isTauriEnv()) {
            core.setState((prev) => ({ ...prev, quickSites: freshSites }));
          } else {
            const freshById = new Map(freshSites.map((item) => [item.id, item]));
            core.setState((prev) => {
              const baseList = prev.quickSites.length > 0 ? prev.quickSites : freshSites;
              return {
                ...prev,
                quickSites: baseList.map((site) => {
                  const updated = freshById.get(site.id);
                  return updated ?? { ...site, latency_ms: 88, ok: true };
                }),
              };
            });
          }
          core.pushToast("网站连通检测完成", "ok");
        } catch (err) {
          core.pushToast(`网站检测失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          core.updateBgTasks((bg) => ({
            ...bg,
            home: { ...bg.home, checkingQuickSites: false },
          }));
        }
      },
      { mascot: true }
    );
  }

  return {
    async copyAiOnboardingForUser(lang?: UiLanguage, moduleId?: string | null): Promise<boolean> {
      try {
        const targetLang = normalizeUiLanguage(
          lang ?? core.getState().config.personalization.ui_language
        );
        const prompt = await catcloudApi.buildAiOnboardingPrompt(targetLang, moduleId ?? null);
        const text = prompt.trim();
        if (!text) {
          core.pushToast("新手上手指南生成为空，请稍后重试", "warn");
          return false;
        }
        const copied = await copyText(text);
        if (copied) {
          core.pushToast(
            "已复制网页 AI 指南与当前脱敏进度，直接粘贴给 DeepSeek / 豆包 / ChatGPT 就能一步步带你操作",
            "ok",
            5000
          );
          return true;
        }
        core.pushToast("无法写入剪贴板，请检查系统剪贴板权限后重试", "warn");
        return false;
      } catch (err) {
        core.pushToast(`生成 AI 上手指南失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    },

    async copyAgentBootstrapPrompt(
      langOrPage?: UiLanguage | string,
      mode: AgentPromptMode = "autopilot",
      explicitLang?: UiLanguage
    ): Promise<boolean> {
      try {
        const state = core.getState();
        const knownLangs = new Set(["zh-CN", "en", "ja", "ru"]);
        const isLangArg = typeof langOrPage === "string" && knownLangs.has(langOrPage);
        const targetLang = normalizeUiLanguage(
          explicitLang ??
            (isLangArg ? (langOrPage as UiLanguage) : state.config.personalization.ui_language)
        );
        const targetPage =
          !isLangArg && typeof langOrPage === "string" && langOrPage.trim().length > 0
            ? langOrPage.trim()
            : state.activeNav;
        const resolvedMode: AgentPromptMode =
          mode === "readonly"
            ? "readonly"
            : mode === "troubleshoot_issue"
              ? "troubleshoot_issue"
              : "autopilot";
        const dto = await catcloudApi.buildAgentBootstrapPrompt(
          targetLang,
          targetPage,
          resolvedMode
        );
        const text = dto.prompt.trim();
        if (!text) {
          core.pushToast("本机 Agent 引导语生成为空，请稍后重试", "warn");
          return false;
        }
        const copied = await copyText(text);
        if (copied) {
          core.pushToast(
            resolvedMode === "readonly"
              ? "已复制只读体检指令（仅查不改），直接粘贴发给 Codex / Claude Code / Antigravity 即可"
              : resolvedMode === "troubleshoot_issue"
                ? "已复制「AI 排障 + 帮提 Issue」指令，发给你的本机 AI 即可自动排查修复或整理脱敏 Issue"
                : "已复制本机 AI 全权托管指令（含精确 CLI 路径与手册索引），直接粘贴发给 Codex / Claude Code / Antigravity 即可开始代配",
            "ok",
            5400
          );
          return true;
        }
        core.pushToast("无法写入剪贴板，请检查剪贴板权限后重试", "warn");
        return false;
      } catch (err) {
        core.pushToast(`生成本机 Agent 引导指令失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    },

    async openGithubIssueFeedback(summary?: string | null): Promise<boolean> {
      try {
        const targetLang = normalizeUiLanguage(core.getState().config.personalization.ui_language);
        const draft = await catcloudApi.buildGithubIssueUrl(summary ?? null, targetLang);
        const copied = draft.clipboard_markdown.trim()
          ? await copyText(draft.clipboard_markdown)
          : false;
        await catcloudApi.openExternalUrl(draft.issue_url);
        core.pushToast(
          copied
            ? "已打开 GitHub 反馈页，并自动复制了脱敏环境摘要（到页面内按 Ctrl+V 粘贴即可）"
            : "已打开 GitHub 反馈页，请按模板填写遇到的问题",
          "ok",
          5200
        );
        return true;
      } catch (err) {
        core.pushToast(`打开 GitHub 反馈页失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    },

    async copySanitizedDiagnosticsForAi(extraSanitizedLogs?: string): Promise<boolean> {
      try {
        const diag = await catcloudApi.exportSanitizedDiagnostics();
        const rawMd =
          typeof diag.ai_prompt_markdown === "string" ? diag.ai_prompt_markdown.trim() : "";

        let markdown: string;
        if (rawMd.length > 0) {
          markdown = rawMd;
        } else {
          const state = core.getState();
          const rt = state.runtime;
          const cfg = state.config;
          const routeLine =
            rt.route_mode === "single"
              ? `单节点模式 → ${rt.active_node_name || "--"}`
              : `智能多选组（${rt.active_group_name || "--"}）→ ${rt.active_node_name || "--"}`;
          const tunStatusLabel = rt.tun_enabled
            ? "已开启"
            : rt.tun_needs_elevation
              ? "未生效（需管理员权限）"
              : "未开启";
          markdown = [
            "# 请帮我排查猫猫云梯（CatCloud）当前问题",
            "",
            "> 以下信息已自动脱敏（不含真实密钥、账号、用户名和公网 IP）。请根据状态与日志帮我分析原因并给出排查/配置建议。",
            "",
            "## 1. 运行状态摘要",
            `- 版本：v${rt.app_version}（${rt.os_label}）`,
            `- 代理核心：${rt.core_name} ${rt.core_version}（${rt.running ? "运行中" : "已停止"}）`,
            `- 代理模式：${rt.proxy_mode} | 系统代理：${rt.system_proxy_enabled ? "已开启" : "未开启"} | 虚拟网卡：${tunStatusLabel}`,
            `- 当前路线：${routeLine}`,
            `- 国内提速：${rt.preaccel_active ? `已开启（${rt.preaccel_relay_name ?? "已启用中转"}）` : "未开启"}`,
            `- 本地端口：混合 ${cfg.mixed_port} / 控制 127.0.0.1:${cfg.controller_port} / DNS ${cfg.dns_listen_port}`,
            "",
            "## 2. 本机只读排查 CLI 命令",
            "- `catcloud status --json`",
            "- `catcloud config diag --json`",
            "- `catcloud group list --json`",
            "- `catcloud config validate --json`",
            "",
            "## 3. 脱敏诊断快照（JSON）",
            "```json",
            JSON.stringify(diag, null, 2),
            "```",
          ].join("\n");
        }

        const trimmedExtra = extraSanitizedLogs?.trim();
        if (trimmedExtra) {
          markdown = `${markdown}\n\n## 当前日志视图补充（已自动打码隐私）\n\`\`\`text\n${trimmedExtra}\n\`\`\``;
        }

        const copied = await copyText(markdown);
        if (copied) {
          core.pushToast(
            "已复制脱敏诊断包！直接粘贴给你的 AI 助手（Antigravity / Codex / ChatGPT 等）就能帮你排查",
            "ok",
            4500
          );
          return true;
        }
        core.pushToast("无法写入剪贴板，请在「运行日志」页点击导出或检查剪贴板权限", "warn");
        return false;
      } catch (err) {
        core.pushToast(`生成脱敏诊断包失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    },

    async refreshAllData(): Promise<void> {
      await deps.hydrateFromBackend();
      void refreshDanglingRulesAudit();
    },

    refreshDanglingRulesAudit,

    async repairDanglingRules(
      mode: "remove" | "rewrite",
      targetGroup?: string | null
    ): Promise<boolean> {
      if (core.getState().repairingDanglingRules) return false;
      core.setState((prev) => ({ ...prev, repairingDanglingRules: true }));
      try {
        const report = await catcloudApi.repairDanglingRules(mode, targetGroup ?? null, true);
        await deps.hydrateFromBackend();
        await refreshDanglingRulesAudit();
        if (report.removed_count > 0 || report.rewritten_count > 0) {
          const msg =
            mode === "rewrite"
              ? `已将 ${report.rewritten_count} 条悬空规则改为「${report.target_group ?? "默认路线"}」并应用`
              : `已一键清理 ${report.removed_count} 条失效分流规则并应用`;
          core.pushToast(msg, "ok", 4600);
        } else {
          core.pushToast("未发现需要清理的失效分流规则", "info");
        }
        return true;
      } catch (err) {
        core.pushToast(`修复失效规则失败：${formatErrorMessage(err)}`, "warn", 5200);
        return false;
      } finally {
        core.setState((prev) => ({ ...prev, repairingDanglingRules: false }));
      }
    },

    async refreshQuickSites(): Promise<void> {
      await runQuickSitesCheck();
    },

    runQuickSitesCheck,

    async runRefreshExitIp(): Promise<void> {
      return core.runInFlight(
        "home:exitIp",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            home: { ...bg.home, refreshingExitIp: true },
          }));
          try {
            const info = await catcloudApi.getExitIpInfo();
            core.setState((prev) => ({ ...prev, exitIp: info }));
            if (hasRealExitIpInfo(info)) {
              core.pushToast("出口信息已更新", "ok");
            } else {
              const detailParts = [info.isp, info.location]
                .map((s) => s?.trim() ?? "")
                .filter(
                  (s) =>
                    s.length > 0 &&
                    s !== "未连接" &&
                    s !== "待检测" &&
                    s !== "待核心启动探测"
                );
              const detail = Array.from(new Set(detailParts)).join(" · ");
              core.pushToast(
                detail
                  ? `未获取到出口 IP：${detail}`
                  : "未获取到出口 IP，请确认核心已启动且节点连通",
                "warn"
              );
            }
          } catch (err) {
            core.pushToast(`检测出口信息失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              home: { ...bg.home, refreshingExitIp: false },
            }));
          }
        },
        { mascot: true }
      );
    },
  };
}
