use crate::error::{CatError, CatResult};
use serde::{Deserialize, Serialize};

/// Built-in module ID for the beginner-friendly Chinese AI onboarding guide.
pub const ONBOARDING_DOC_ID: &str = "onboarding";

/// Pure-Chinese beginner AI mentor guide covering CatCloud's 5 core workflows
/// and exact UI button/page paths, with zero internal jargon.
const ZH_ONBOARDING_GUIDE: &str = r#"# 猫猫云梯（CatCloud）新手上手总纲（给 AI 导师的教学参考）

> **给 AI 助手的教学规则（请务必遵守）：**
> 1. 对面很可能是第一次使用网络代理工具的新手，请全程用**零门槛、亲切易懂的大白话**交流，不要抛源码、技术黑话或命令行指令（除非用户主动询问终端命令）。
> 2. 请严格结合本消息下方附带的「用户当前实时状态快照」判断用户正处于哪一步，**每次只教当下最需要做的下一小步**，等用户操作完回复后，再带下一步，不要一次性倾倒长篇教程。
> 3. 给用户指路时，请严格使用下文写明的**猫猫云梯真实中文界面名称与按钮路径**，不要凭空编造菜单名。

---

## 一、猫猫云梯 5 大核心玩法与界面准确路径

### 1. 导入节点（页面：`节点与测速 → 订阅与导入`）
没有节点时第一步先拿节点，界面顶部提供 3 种零门槛方式，任选其一即可：
- **方式 A · 粘贴订阅链接（最推荐）**：把服务商给的 `http://` 或 `https://` 订阅链接（也支持常见一键导入链接）粘进输入框并点击导入。猫猫云梯会先尝试快速直连拉取；若直连受阻，会自动尝试通过本机已有代理回退拉取。
- **方式 B · 粘贴配置文本 / 本地文件 / 只读扫描已有软件**：手里只有单条节点链接、配置文本或配置文件时，可直接粘贴导入；如果电脑里本来就装过常见开源代理软件，也可在迁移卡片点「自动扫描并导入」只读迁入，不会改动原软件的任何文件。
- **方式 C · `1→2→3` 实时捕捉运行中的软件**：如果手头只有专用客户端、找不到订阅链接，点「从正在运行的软件抓节点」卡片里的「打开 1→2→3 实时捕捉向导」按三步操作：
  1. **第 1 步选软件**：在列表中勾选正在运行的软件（如果它缩在右下角系统托盘里，勾选带「托盘运行中」标记的项，或点开一次它的窗口即可置顶）；
  2. **第 2 步触发动作**：回到原软件里点一次「刷新/更新订阅」或「连接」，猫猫云梯会自动监听新生成的明文节点配置；
  3. **第 3 步查看并导入**：抓到节点后点「结束捕捉并整理」查看结果并一键导入。若原软件对配置做了加密保护无法明文读取，软件会诚实提示，此时建议回服务商官网找标准订阅链接。

### 2. 选路方式：`智能多选组` vs 单节点（页面：`智能多选组` / `总览`）
导入节点后会自动建好「默认路线」，你可以按需求选两种方式：
- **智能多选组（日常最推荐）**：
  - 支持**跨多家服务商混池**，把不同来源的好节点装进同一个组里统一挑；
  - 支持**低倍率优先 + 高倍率兜底**：平时自动用省流量的低倍率节点，低倍率全挂或卡顿时自动切去高倍率应急，恢复后再切回来；
  - **平时粘性锁定（防 AI 封号/掉登录）**：只要当前节点健康流畅，就一直稳稳固定走这一条，不会像普通轮询那样动不动乱跳 IP，特别适合使用各类海外 AI 网页、AI 编程助手和需要稳定地区登录的网站。
- **单节点模式**：想手动固定只走某一条指定地区的节点时，在`总览`或`节点与测速`直接切到单节点即可。

### 3. 零干扰测速与节点体检（页面：`节点与测速`）
测速在独立沙箱里完成，**测速过程不会打断你正在看的网页、视频或对话连接**：
- **省流快测（推荐先跑）**：只花极少流量，一次性测出各节点真实延迟、是否被「谷歌送中」（IP 被误判到中国大陆导致搜索和 AI 受限）、以及主流 AI 服务的解锁状态；
- **完整测速（按需跑）**：实测节点的真实上传和下载带宽，帮助`智能多选组`自动把又快又稳的线路排到前面。

### 4. 国内提速（页面：`国内提速`）
如果你在校园网或部分宽带环境下，遇到「下载很快、但上传被限速到 2～4 Mbps、给 AI 传图片或发大文件极慢、高端口经常断流」的情况，可以启用`国内提速`：
- 通过纯 IP 443 端口加密中转突破国内宽带对非 443 端口的上传限速，并且原生 443 节点会自动跳过不绕路；
- 既能加速猫猫云梯自己管理的节点，也支持开启**全局提速**，直接给电脑上其它正在运行的代理软件同步提速。如果日常上传本来就很快，这一页完全可以保持关闭。

### 5. 日常开关、模式区别与省内存（页面：`总览`、`设置`）
- **一键代理开关**：在`总览`点主开关即可开启或关闭上网加速；
- **系统代理 vs 虚拟网卡（TUN 模式）区别**：
  - **系统代理**：日常用浏览器（Chrome / Edge 等）和大多数桌面软件开它就够了，不需要管理员权限，最省心；
  - **虚拟网卡（TUN 模式）**：当你发现终端命令行、开发工具、游戏或某些不走系统代理的桌面软件连不上外网时，再在`总览`打开「虚拟网卡（TUN 模式）」接管整机流量（Windows 首次开启会请求管理员权限）。
- **悬浮小窗与托盘省内存**：
  - 在`总览`顶部可以打开小巧的**悬浮小窗**，随时瞄一眼网速和当前线路；
  - 平时设置好以后，直接点右上角关闭主窗口，猫猫云梯会缩进右下角**系统托盘**并释放界面窗口内存，代理照常稳定在后台跑；想调整时点托盘图标就能瞬间打开。

---

## 二、建议的 4 步极简引导节奏（供 AI 对照状态推进）
1. **状态：0 个节点** → 先引导去 `节点与测速 → 订阅与导入`，问用户手头是「有订阅链接」「有配置文本/已有软件」还是「只有正在跑的专用软件」，只教对应那 1 种导入操作。
2. **状态：已有节点，但代理未开启** → 引导回到 `总览`，先打开总开关与「系统代理」，再在「常用网站连通检测」卡片点「测一下」确认已经能正常访问海外网页。
3. **状态：已连上，想挑更稳更快或用 AI 不掉线** → 引导去 `节点与测速` 先跑一次省流快测（挑延迟低、未送中、AI 解锁的节点），再在 `智能多选组` 里勾选心仪节点开启粘性优选。
4. **状态：上传特别慢/传图卡顿，或终端/游戏不走代理** → 分别引导按需了解 `国内提速` 或在 `总览` 开启「虚拟网卡（TUN 模式）」。
"#;

/// Return the pure-Chinese beginner AI onboarding guide covering all 5 core CatCloud workflows.
pub fn render_zh_onboarding_guide() -> &'static str {
    ZH_ONBOARDING_GUIDE
}

/// Four-section dual-read (Human + AI Agent) guidance contract embedded in every core module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentModuleDoc {
    pub module_id: String,
    pub title: String,
    pub summary: String,
    /// Section 1: When to enable/use this module and concrete quantitative signals.
    pub when_to_use_and_signals: Vec<String>,
    /// Section 2: External prerequisites, standard schemas, and required fields.
    pub external_prereqs_and_schema: Vec<String>,
    /// Section 3: Exact GUI paths and headless `catcloud` CLI commands for integration & verification.
    pub gui_and_cli_verification: Vec<String>,
    /// Section 4: Safe rollback and troubleshooting checklist.
    pub rollback_and_troubleshooting: Vec<String>,
    /// Optional structured contract example (JSON / YAML / CLI snippet) for copy-paste to an AI Agent.
    pub contract_example: String,
}

impl AgentModuleDoc {
    /// Render a clean, copy-ready Markdown prompt/guide for handing directly to an AI Agent.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# CatCloud Agent Guide: {} (`{}`)\n\n", self.title, self.module_id));
        out.push_str(&format!("> {}\n\n", self.summary));

        out.push_str("## 1. When to Use & Quantitative Signals\n");
        for item in &self.when_to_use_and_signals {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 2. External Prerequisites & Standard Schema\n");
        for item in &self.external_prereqs_and_schema {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 3. GUI & Headless CLI Integration / Verification\n");
        for item in &self.gui_and_cli_verification {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 4. Rollback & Troubleshooting Checklist\n");
        for item in &self.rollback_and_troubleshooting {
            out.push_str(&format!("- {item}\n"));
        }

        if !self.contract_example.trim().is_empty() {
            out.push_str("\n## Reference Contract Snippet\n```json\n");
            out.push_str(self.contract_example.trim());
            out.push_str("\n```\n");
        }
        out
    }
}

/// Return all 7 built-in four-section Agent-friendly module guides (including beginner onboarding).
pub fn list_agent_docs() -> Vec<AgentModuleDoc> {
    vec![
        AgentModuleDoc {
            module_id: ONBOARDING_DOC_ID.to_string(),
            title: "新手全中文上手总纲（给 AI 导师）".to_string(),
            summary: "面向零基础新手与陌生 AI 助手的纯中文上手总纲，涵盖猫猫云梯 5 大核心玩法与准确中文界面路径，指导 AI 按当前进度每次只教下一小步。".to_string(),
            when_to_use_and_signals: vec![
                "首次安装或刚打开猫猫云梯，还不清楚如何导入节点、测速、选路线或开启代理开关时。".to_string(),
                "准备把当前进度直接粘贴给任意陌生 AI 助手，请对方用大白话一步步带着上手操作时。".to_string(),
                "需要快速核对猫猫云梯 5 大核心功能（导入/捕捉、智能多选组、节点测速、国内提速、总览开关）的准确中文页面入口时。".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "无需提前学习任何命令行或专业术语；只需准备订阅链接、节点配置文本，或电脑里已有的代理客户端即可开始。".to_string(),
                "搭配软件自动生成的实时脱敏状态快照一起发给 AI，可让 AI 精准识别当前停在哪一步，避免答非所问。".to_string(),
            ],
            gui_and_cli_verification: vec![
                "导入节点：打开「节点与测速 → 订阅与导入」，支持订阅链接、粘贴文本/本地扫描，以及 1→2→3 实时捕捉运行中的软件（含托盘/后台软件）。".to_string(),
                "选路与测速：在「节点与测速」跑省流快测或完整测速；在「智能多选组」配置跨家混池、低倍率优先+高倍率兜底与平时粘性防 AI 封号。".to_string(),
                "国内提速与开关：上传受限时在「国内提速」配置纯 IP 443 提速或全局提速；日常在「总览」切换代理开关、系统代理、虚拟网卡（TUN 模式）与悬浮小窗。".to_string(),
                "设置与导出：在「设置」调整通用偏好、网络选项或导出完整中文新手总纲（CLI：`catcloud docs export onboarding`）。".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "若导入订阅失败，先确认链接完整且未过期，软件已内置直连失败自动回退本机代理拉取。".to_string(),
                "若浏览器正常但命令行/游戏连不上，在「总览」开启「虚拟网卡（TUN 模式）」即可接管整机流量；随时可一键关闭恢复直连。".to_string(),
                "遇到异常可点击首页「复制排障诊断给 AI」，把脱敏运行状态与关键事件一并发给 AI 定位原因。".to_string(),
            ],
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: "preaccel".to_string(),
            title: "Domestic Pre-Acceleration (国内提速)".to_string(),
            summary: "Front-end domestic TCP :443 pure-IP TLS relay chain (dialer-proxy) with active-standby failover, domestic 204 health probing, and campus portal detection.".to_string(),
            when_to_use_and_signals: vec![
                "Single-stream upload on non-443 proxy ports is throttled around 2-4 Mbps while TCP :443 TLS sustains 50-250+ Mbps.".to_string(),
                "Frequent TCP retransmissions (> 2%) or slow multi-image AI upload turns despite healthy downstream bandwidth.".to_string(),
                "Running inside campus/enterprise networks where high overseas UDP/TCP ports experience instability or Captive Portal dropouts.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Provision 1-2 lightweight domestic cloud relays listening on TCP :443 with Trojan-TLS, AnyTLS, or VLESS-TLS using a self-signed ECDSA IP certificate.".to_string(),
                "CRITICAL: Keep TLS `sni` (and VLESS `servername`) strictly EMPTY (`\"\"`) with `skip_cert_verify: true`; third-party unfiled SNI domains on domestic :443 are blocked by cloud gateways.".to_string(),
                "Deliver relay parameters to CatCloud using the `mmrelay/v1` JSON schema or single-line `mmrelay://v1/<base64url>` URI.".to_string(),
                "Health probe URL MUST remain domestic (`http://connectivitycheck.platform.hicloud.com/generate_204` or `http://connect.rom.miui.com/generate_204`); overseas `gstatic` URLs are rejected.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '国内提速' -> Import `mmrelay/v1` -> Verify '自动跳过原生 443 节点' -> Run 443 vs non-443 benchmark.".to_string(),
                "CLI import: `catcloud preaccel add --file relay.mmrelay.json --json`".to_string(),
                "CLI pool status: `catcloud preaccel pool --json`".to_string(),
                "CLI end-to-end verification: `catcloud preaccel test --json` (checks domestic 204, anti-loop DIRECT rules, and active-standby failover).".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "One-click disable via GUI switch or `catcloud preaccel bind --enabled false --json` followed by `catcloud config reload --json`.".to_string(),
                "If relay connects but loops: verify relay IP/domain and domestic 204 probe domains appear at top of compiled `rules` as `DIRECT,no-resolve` and inside `dns.fake-ip-filter`.".to_string(),
                "If campus portal returns 302: authenticate via the automatically exempted portal URL; CatCloud revokes temporary DIRECT rules once 204 returns.".to_string(),
            ],
            contract_example: r#"{
  "schema": "mmrelay/v1",
  "role": "domestic_pre_accel",
  "relays": [
    {
      "id": "relay-cn-east-1",
      "name": "CN-East-443 Primary",
      "provider": "cloud-a",
      "region": "CN-East",
      "server": "203.0.113.10",
      "port": 443,
      "protocol": "anytls",
      "password": "<YOUR_GENERATED_SECRET>",
      "sni": "",
      "skip_cert_verify": true,
      "priority": 10,
      "expires_at": "2027-08-12",
      "enabled": true
    }
  ]
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "multigroup".to_string(),
            title: "Smart Multi-Groups & Custom Weighting Engine (智能多选组)".to_string(),
            summary: "Per-site orchestration supporting sticky-best, conditional pools, filtered load-balancing, safe AST scoring formulas, and three-way below-threshold fallbacks.".to_string(),
            when_to_use_and_signals: vec![
                "AI/coding tools (OpenAI, Claude, Gemini/Antigravity, Windsurf/Devin/Codeium) break on random IP rotation or silent region-restricted exits.".to_string(),
                "Need cross-provider node pools combining low-multiplier (0.5x/1x) daily nodes with automatic escalation to premium (3x) backup pools only when needed.".to_string(),
                "Want controlled per-site load balancing without letting region-restricted nodes enter the balance set.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "At least 2 enabled nodes imported into the node library plus recent probe snapshots from the isolated probe runner.".to_string(),
                "Formula uses CatCloud safe AST (zero `eval`): supports `up_mbps`, `down_mbps`, `ping_ms`, `jitter_ms`, `loss_pct`, `multiplier`, `keepalive_ok`, `google_clean`, `unlocked`, plus per-probe functions `probe_up(\"id\")`, `probe_down(\"id\")`, `probe_ping(\"id\")`, `probe_ok(\"id\")`.".to_string(),
                "Fallback policy options when all nodes miss threshold: `degrade_best_warn` (default), `cross_pool_escalate` (with automatic hysteresis return to primary pool), or `strict_circuit_break` (switches group to `REJECT`).".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '智能多选组' -> Choose mode (`sticky_best` / `conditional_pool` / `load_balance_*`), formula template, fallback policy, and `force_close_old` vs `graceful_new_only`.".to_string(),
                "CLI list groups: `catcloud group list --json`".to_string(),
                "CLI switch next best: `catcloud group switch <group_id> --json`".to_string(),
                "CLI update policy: `catcloud group policy <group_id> --formula \"...\" --fallback degrade_best_warn --json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Reset any group formula to built-in `DEFAULT_COST_EFFECTIVE_FORMULA` if custom expression yields zero candidates.".to_string(),
                "If a group stays in `circuit_open` (`REJECT`), inspect `hard_gates` against latest probe snapshots or switch fallback policy to `degrade_best_warn`.".to_string(),
                "If switching does not unstick existing HTTP/2 streams, set `switch_mode` to `force_close_old` for that group.".to_string(),
            ],
            contract_example: r#"{
  "id": "grp-ai-core",
  "name": "AI Primary Sticky Pool",
  "mode": "sticky_best",
  "match_rules": [
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,anthropic.com",
    "DOMAIN-SUFFIX,windsurf.com",
    "DOMAIN-SUFFIX,codeium.com",
    "DOMAIN-SUFFIX,devin.ai"
  ],
  "hard_gates": ["google_clean == 1", "keepalive_ok == 1"],
  "formula_expr": "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)",
  "fallback_policy": "cross_pool_escalate",
  "switch_mode": "force_close_old"
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "probes".to_string(),
            title: "Zero-Interference Isolated Probe Registry (节点与测速)".to_string(),
            summary: "Ephemeral isolated Mihomo probe core (`127.0.0.1` only, `redir-host`, `GOMEMLIMIT=32MiB`) with extensible URL, upload/download, 60s keep-alive, Google region truth, and unlock probes.".to_string(),
            when_to_use_and_signals: vec![
                "Nodes appear 'pingable' yet stall on real AI requests, multi-image uploads, or 20-60s silent streams.".to_string(),
                "Need to measure real throughput and unlock status against custom endpoints (ChatGPT, Claude, Windsurf, custom APIs) without interrupting active traffic.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Requires a local Mihomo binary (`data/bin/mihomo` or `resources/bin/mihomo`).".to_string(),
                "Isolated runner binds strictly `127.0.0.1`, sets `enhanced-mode: redir-host` + direct physical `proxy-server-nameserver`, and forces `.no_proxy()` + `socks5h://` to avoid active TUN Fake-IP contamination.".to_string(),
                "Google cleanliness hard gate checks Google-side ground truth (`google.cn` redirect, YouTube GL, AI Studio availability); CF-vs-YT mismatch is logged as an advisory risk tag only.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '节点与测速' -> Add custom probe (`latency|upload|download|keepalive|google_cn|unlock_regex|external_cmd`) -> Run 3-stage funnel.".to_string(),
                "CLI run probes: `catcloud probe run --tier l1 --json`".to_string(),
                "CLI register custom probe: `catcloud probe add --id custom_api --kind upload --url https://example.com/up --json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Temporary probe cores are tracked by `JobGuard` and terminated immediately after completion (0 residual processes).".to_string(),
                "If all L2 upload probes time out at 512 KB fast-cut, check whether domestic :443 pre-acceleration is needed.".to_string(),
            ],
            contract_example: r#"{
  "id": "probe-ai-upload",
  "name": "Custom AI Upload Check",
  "kind": "upload",
  "target_url": "https://speed.cloudflare.com/__up",
  "method": "POST",
  "expected_status": 200,
  "payload_bytes": 524288,
  "timeout_ms": 10000
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "nodes_ingest".to_string(),
            title: "Multi-Dimensional Nodes, Live Capture & Process Adapter (订阅与导入)".to_string(),
            summary: "Multi-provider subscription pool with proxy-fallback refresh, 0-node/error protection, read-only local config migration, 1->2->3 live app capture, and open `catcloud-adapter/v1` slots.".to_string(),
            when_to_use_and_signals: vec![
                "Consolidating nodes from multiple subscriptions, local open-source proxy clients, or running desktop proxy apps into one filterable cross-provider pool.".to_string(),
                "Integrating dynamic-endpoint sources that rotate nodes via a user-supplied refresh script (`catcloud-adapter/v1`).".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Supports Clash/Mihomo YAML (with YAML merge anchors, capped at 16 MiB), sing-box JSON (`outbounds`), and Base64/plain URI lists.".to_string(),
                "External adapter scripts receive JSON on `stdin` and return `{\"schema\":\"catcloud-adapter/v1\",\"nodes\":[...],\"yaml\":\"...\"}` on `stdout` (subject to `>= 60s` anti-storm cooldown).".to_string(),
                "Process attachment and 1->2->3 live capture only inspect read-only CLI flags, plaintext config changes, and open loopback controller endpoints; never alter third-party files.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '节点与测速 → 订阅与导入' -> Import subscription URL, paste config text, scan local clients, or run 1->2->3 live capture -> Filter & multi-select across providers into any multi-group.".to_string(),
                "CLI list nodes: `catcloud node list --region TW --max-multiplier 1.0 --json`".to_string(),
                "CLI import / migrate / attach: `catcloud node import --file sub.yaml --json`, `catcloud node migrate --scan --json`, `catcloud node attach-process --list --json`.".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Failed refreshes (HTTP 500, timeout, malformed YAML, or 0 parsed nodes) are atomically rejected; existing nodes and custom rules remain untouched.".to_string(),
                "To remove a migrated source, delete only its `sub_id` via SQLite cascade without touching other subscriptions.".to_string(),
            ],
            contract_example: r#"{
  "schema": "catcloud-adapter/v1",
  "nodes": [
    {
      "name": "Example-SG-01 1x",
      "type": "trojan",
      "server": "198.51.100.20",
      "port": 443,
      "password": "<PLACEHOLDER>"
    }
  ]
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "network_reload".to_string(),
            title: "Network, DNS, TUN & Three-Level Hot Reload (网络与热加载)".to_string(),
            summary: "Full Proxy Guard, PAC, TUN stack, split core/DNS IPv6, advanced DNS/fallback-filter, and zero-restart L1/L2/L3 configuration hot reload.".to_string(),
            when_to_use_and_signals: vec![
                "External tools or AI Agents edit `data/config.json` or override YAML and need immediate validated hot apply without restarting CatCloud.".to_string(),
                "Troubleshooting DNS leaks, port collisions, Windows system proxy hijacking by other apps, or UWP loopback blocks.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "L1 changes (proxy mode, group selection, connection close) apply in milliseconds via authenticated Mihomo REST API (`Authorization: Bearer <secret>`).".to_string(),
                "L2 changes trigger 300ms debounced SHA-256 deduplicated static + anti-loop + `mihomo -t` validation; invalid configs are rejected safely with zero traffic interruption.".to_string(),
                "L3 changes (ports, TUN stack, kernel swap) restart only the core child process; toggling the main proxy switch off->on always forces a fresh disk reload.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '设置' -> Configure Proxy Guard, TUN stack, advanced DNS/Fallback-filter, GeoData 4-item refresh, or copy PowerShell/CMD/Bash env snippets.".to_string(),
                "CLI validate before apply: `catcloud config validate --json`".to_string(),
                "CLI hot reload: `catcloud config reload --json`".to_string(),
                "CLI shell env & sanitized diagnostics: `catcloud config export-env --shell powershell --json`, `catcloud config diag --json`.".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Export and restore integrity-checked config snapshots via `config::export_backup` / `config::import_backup`.".to_string(),
                "If default ports collide, `port_guard` checks both TCP and UDP and shifts cleanly when `port_guard_auto_shift` is enabled.".to_string(),
            ],
            contract_example: r#"{
  "reload_levels": {
    "L1": "REST API (mode switch, select node, close connections)",
    "L2": "300ms debounced preflight (syntax + anti-loop + mihomo -t) -> PUT /configs?force=true + replay active selections",
    "L3": "Core-only child restart (ports / TUN stack / kernel binary swap)"
  }
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "updater_lifecycle".to_string(),
            title: "Windowless Memory Saver & Next-Launch Auto Updater (无窗省内存与自动更新)".to_string(),
            summary: "Destroyable WebView2 windowless tray mode (<= 70 MB), portable data isolation, and GitHub Releases next-launch verified updater with automatic rollback.".to_string(),
            when_to_use_and_signals: vec![
                "Running CatCloud continuously in the background while keeping host RAM and CPU footprint lower than traditional Electron/always-open WebView clients.".to_string(),
                "Checking or staging new releases from `JuryBu/CatCloud` for seamless application on next launch without touching user `data/`.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Update checks strictly allow HTTPS `:443` on official GitHub hosts only, verifying `latest.json` + `SHA256SUMS.txt` before staging to `.update_staging/`.".to_string(),
                "Portable Windows updates perform same-volume `.exe.old` swap into `.update_backup/` and strictly preserve `data/`, `portable.flag`, and `*.sqlite*`.".to_string(),
                "Isolated multi-instance testing uses `--data-dir <PATH>` so sandbox instances never conflict with the daily primary instance.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Close main window to destroy WebView2 and drop to pure windowless tray mode; click tray icon or hotkey to rebuild in < 600ms.".to_string(),
                "CLI check updates: `catcloud update check --json`".to_string(),
                "CLI stage verified update for next launch: `catcloud update stage --json`".to_string(),
                "CLI export module docs: `catcloud docs export <module_id|all> --format markdown|json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Any failure during portable update swap automatically restores all original files from `.update_backup/` while keeping `data/` intact.".to_string(),
                "On exit or crash, Windows `JobGuard` (`KILL_ON_JOB_CLOSE`) and Unix process-group cleanup terminate all child cores within 500ms.".to_string(),
            ],
            contract_example: r#"{
  "repo": "JuryBu/CatCloud",
  "mode": "next_launch",
  "preserved_paths": ["data/", "portable.flag", "*.sqlite*", ".update_backup/"]
}"#.to_string(),
        },
    ]
}

/// Look up a single module's four-section Agent guide by ID (case-insensitive).
pub fn get_agent_doc(module_id: &str) -> CatResult<AgentModuleDoc> {
    let needle = module_id.trim().to_ascii_lowercase();
    list_agent_docs()
        .into_iter()
        .find(|d| d.module_id == needle)
        .ok_or_else(|| CatError::NotFound(format!("未找到指定的助手指南模块「{module_id}」")))
}

/// Export either one module or `"all"` modules as Markdown or JSON.
pub fn export_agent_docs(module_id: &str, as_json: bool) -> CatResult<String> {
    let needle = module_id.trim().to_ascii_lowercase();
    if needle.is_empty() || needle == "all" {
        let all = list_agent_docs();
        if as_json {
            Ok(serde_json::to_string_pretty(&all)?)
        } else {
            let rendered: Vec<String> = all
                .iter()
                .map(|doc| {
                    if doc.module_id == ONBOARDING_DOC_ID {
                        render_zh_onboarding_guide().to_string()
                    } else {
                        doc.to_markdown()
                    }
                })
                .collect();
            Ok(rendered.join("\n---\n\n"))
        }
    } else if needle == ONBOARDING_DOC_ID && !as_json {
        Ok(render_zh_onboarding_guide().to_string())
    } else {
        let doc = get_agent_doc(&needle)?;
        if as_json {
            Ok(serde_json::to_string_pretty(&doc)?)
        } else {
            Ok(doc.to_markdown())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_seven_core_modules_with_four_sections_and_fresh_ui_names() {
        let docs = list_agent_docs();
        assert_eq!(docs.len(), 7);
        assert!(docs.iter().any(|d| d.module_id == ONBOARDING_DOC_ID));

        for doc in &docs {
            assert!(!doc.when_to_use_and_signals.is_empty(), "{}", doc.module_id);
            assert!(!doc.external_prereqs_and_schema.is_empty(), "{}", doc.module_id);
            assert!(!doc.gui_and_cli_verification.is_empty(), "{}", doc.module_id);
            assert!(!doc.rollback_and_troubleshooting.is_empty(), "{}", doc.module_id);
            let md = doc.to_markdown();
            assert!(md.contains("## 1. When to Use"));
            assert!(md.contains("## 2. External Prerequisites"));
            assert!(md.contains("## 3. GUI & Headless CLI"));
            assert!(md.contains("## 4. Rollback & Troubleshooting"));

            // Ensure outdated Chinese UI page names never regress.
            for outdated in ["国内预加速", "隔离测速", "节点与订阅", "设置与 CLI"] {
                assert!(
                    !md.contains(outdated),
                    "module `{}` still contains outdated page name `{outdated}`",
                    doc.module_id
                );
            }
        }
    }

    #[test]
    fn zh_onboarding_guide_covers_five_core_workflows_and_exact_ui_paths() {
        let guide = render_zh_onboarding_guide();
        assert!(guide.contains("每次只教当下最需要做的下一小步"));
        assert!(guide.contains("节点与测速 → 订阅与导入"));
        assert!(guide.contains("1→2→3"));
        assert!(guide.contains("智能多选组"));
        assert!(guide.contains("节点与测速"));
        assert!(guide.contains("国内提速"));
        assert!(guide.contains("总览"));
        assert!(guide.contains("虚拟网卡（TUN 模式）"));
        assert!(guide.contains("悬浮小窗"));
        assert!(guide.contains("系统托盘"));

        for outdated in ["国内预加速", "隔离测速", "节点与订阅", "设置与 CLI"] {
            assert!(!guide.contains(outdated), "onboarding guide contains outdated `{outdated}`");
        }

        let exported_md = export_agent_docs(ONBOARDING_DOC_ID, false).expect("export onboarding md");
        assert_eq!(exported_md, guide);
    }

    #[test]
    fn export_single_and_all_in_json_and_markdown() {
        let json_all = export_agent_docs("all", true).expect("export all json");
        let parsed: Vec<AgentModuleDoc> = serde_json::from_str(&json_all).expect("parse json");
        assert_eq!(parsed.len(), 7);

        let preaccel_md = export_agent_docs("preaccel", false).expect("export preaccel md");
        assert!(preaccel_md.contains("mmrelay/v1"));
        assert!(preaccel_md.contains("hicloud.com"));
        assert!(preaccel_md.contains("国内提速"));

        assert!(export_agent_docs("nonexistent_module", false).is_err());
    }
}
