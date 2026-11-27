use crate::error::{CatError, CatResult};
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Canonical built-in module IDs (8 authoritative manuals).
pub const TROUBLESHOOTING_DOC_ID: &str = "troubleshooting";
pub const ONBOARDING_DOC_ID: &str = "onboarding";
pub const PREACCEL_DOC_ID: &str = "preaccel";
pub const MULTIGROUP_DOC_ID: &str = "multigroup";
pub const NODES_PROBES_DOC_ID: &str = "nodes_probes";
pub const ROUTING_CONNS_DOC_ID: &str = "routing_conns";
pub const NETWORK_LIFECYCLE_DOC_ID: &str = "network_lifecycle";
pub const SHARE_BUNDLE_DOC_ID: &str = "share_bundle";

/// Supported documentation languages synced to `<data_dir>/agent_docs/<lang>/`.
pub const SUPPORTED_DOC_LANGS: &[&str] = &["zh-CN", "en", "ja", "ru"];

/// Ordered catalog metadata for all 8 authoritative manuals.
#[derive(Debug, Clone, Copy)]
struct DocCatalogEntry {
    id: &'static str,
    filename: &'static str,
}

const DOC_CATALOG: &[DocCatalogEntry] = &[
    DocCatalogEntry {
        id: TROUBLESHOOTING_DOC_ID,
        filename: "00-general-troubleshooting.md",
    },
    DocCatalogEntry {
        id: ONBOARDING_DOC_ID,
        filename: "01-onboarding.md",
    },
    DocCatalogEntry {
        id: PREACCEL_DOC_ID,
        filename: "02-domestic-preaccel.md",
    },
    DocCatalogEntry {
        id: MULTIGROUP_DOC_ID,
        filename: "03-multigroup.md",
    },
    DocCatalogEntry {
        id: NODES_PROBES_DOC_ID,
        filename: "04-nodes-and-probes.md",
    },
    DocCatalogEntry {
        id: ROUTING_CONNS_DOC_ID,
        filename: "05-routing-and-connections.md",
    },
    DocCatalogEntry {
        id: NETWORK_LIFECYCLE_DOC_ID,
        filename: "06-network-and-lifecycle.md",
    },
    DocCatalogEntry {
        id: SHARE_BUNDLE_DOC_ID,
        filename: "07-share-bundle.md",
    },
];

/// Normalize an arbitrary locale/language tag to one of `"zh-CN" | "en" | "ja" | "ru"`.
/// Defaults to `"zh-CN"`.
pub fn normalize_doc_lang(raw: Option<&str>) -> &'static str {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "zh-CN";
    };
    let lower = val.to_ascii_lowercase();
    if lower == "en" || lower.starts_with("en-") || lower.starts_with("en_") {
        "en"
    } else if lower == "ja"
        || lower == "jp"
        || lower.starts_with("ja-")
        || lower.starts_with("ja_")
    {
        "ja"
    } else if lower == "ru" || lower.starts_with("ru-") || lower.starts_with("ru_") {
        "ru"
    } else {
        "zh-CN"
    }
}

/// Resolve a canonical module ID or legacy alias (`probes`, `nodes_ingest`,
/// `network_reload`, `updater_lifecycle`, or numbered filenames) to one of the 8 canonical IDs.
pub fn resolve_canonical_doc_id(module_id: &str) -> Option<&'static str> {
    match module_id.trim().to_ascii_lowercase().as_str() {
        "troubleshooting" | "00-general-troubleshooting" | "general" | "doctor" => {
            Some(TROUBLESHOOTING_DOC_ID)
        }
        "onboarding" | "01-onboarding" => Some(ONBOARDING_DOC_ID),
        "preaccel" | "02-domestic-preaccel" | "domestic-preaccel" | "domestic_preaccel" => {
            Some(PREACCEL_DOC_ID)
        }
        "multigroup" | "03-multigroup" | "groups" => Some(MULTIGROUP_DOC_ID),
        "nodes_probes" | "04-nodes-and-probes" | "probes" | "nodes_ingest" | "nodes" => {
            Some(NODES_PROBES_DOC_ID)
        }
        "routing_conns" | "05-routing-and-connections" | "routing" | "connections" => {
            Some(ROUTING_CONNS_DOC_ID)
        }
        "network_lifecycle"
        | "06-network-and-lifecycle"
        | "network_reload"
        | "updater_lifecycle"
        | "network"
        | "updater" => Some(NETWORK_LIFECYCLE_DOC_ID),
        "share_bundle" | "07-share-bundle" | "share" => Some(SHARE_BUNDLE_DOC_ID),
        _ => None,
    }
}

fn lang_lock_line(lang: &str) -> &'static str {
    match normalize_doc_lang(Some(lang)) {
        "en" => "> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.",
        "ja" => "> 【言語固定】以降の回答はすべて自然な日本語で行い、CatCloud の日本語 UI 名称を正確に使ってください。",
        "ru" => "> [ЯЗЫК ОТВЕТА] Отвечайте строго на русском языке и используйте точные названия разделов интерфейса CatCloud.",
        _ => "> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。",
    }
}

// ============================================================================
// Authoritative zh-CN Manuals (8 Chapters)
// ============================================================================

const ZH_DOC_00_TROUBLESHOOTING: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 00 · 通用网络疑难杂症 6 层排障总纲（含 GitHub Issue 反馈模板）

> 还没翻墙也能求助：把脱敏诊断直接贴给 **DeepSeek（deepseek.com）、豆包（doubao.com）、通义千问（tongyi.aliyun.com）、Kimi（kimi.moonshot.cn）** 等国内直连网页 AI，或交给本机 AI 助手排查。

> **定位本机 `catcloud.exe`（安装版默认不在 PATH）**：
> - PowerShell：`$CATCLOUD = @("$env:LOCALAPPDATA\CatCloud\resources\cli\catcloud.exe", ".\cli\catcloud.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1`
> - Bash：`CATCLOUD=$(command -v catcloud || ([ -x "./cli/catcloud.exe" ] && echo "./cli/catcloud.exe") || echo "$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe")`

## 一、6 层自底向上排障法（按顺序定位，不瞎猜）

### 第 1 层：物理网络与校园网 / 认证 Wi-Fi
- 先确认关闭代理后国内普通网站能否打开；校园网/酒店 Wi-Fi 若返回 302 登录页，需先完成网页认证。
- 检查命令：`catcloud preaccel test --campus --json`、`catcloud net doctor --json`。

### 第 2 层：冲突代理软件与残留系统服务
- 检查电脑是否同时运行了其他代理客户端、遗留的第三方虚拟网卡驱动、被锁死的系统代理地址，或终端残留的 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 环境变量。
- 安全软件（Windows Defender / 火绒 / 360 / 电脑管家）拦截核心或驱动时，需在信任区放行猫猫云梯目录并重测。
- 检查命令：`catcloud net doctor --json`（自动检查端口冲突、代理环境变量与常见冲突服务）。

### 第 3 层：猫猫云梯核心、端口与虚拟网卡（TUN 模式）
- 浏览器正常但终端/游戏/桌面软件不通：去「总览」开启「虚拟网卡（TUN 模式）」（Windows 首次开启需点 UAC 管理员确认）。
- Windows 普通权限启动后虚拟网卡未生效：若之前开过虚拟网卡但本次以普通用户启动，界面会显示「虚拟网卡 · 需管理员」（此时仅系统代理生效，桌面软件/终端可能超时而浏览器正常）；点击「虚拟网卡 · 需管理员」按提示一键以管理员权限重启即可生效，或先选「暂不开网卡」切回纯系统代理。
- 端口被占导致启动失败：在「设置 → 网络与 DNS」确认已开启端口冲突自动顺延，或改换高位端口后在「总览」关开一次代理开关触发完整重载。
- 检查命令：`catcloud status --json`、`catcloud config validate --json`。

### 第 4 层：分流规则、DNS 与 QUIC 策略
- 国内网站走代理变慢：确认「分流与连接」已开启国内直连且已下载 `Country.mmdb` / `geosite.dat`（在「设置」可一键刷新地区数据库）。
- 高校校园网 / 企业内网直连或节点域名解析超时：部分内网防火墙屏蔽外网明文 UDP 53；猫猫云梯已默认升级为纯 IP DoH 443（`223.5.5.5` / `1.12.12.12`），并通过 `nameserver-policy` 为 `+.edu.cn` / 内网后缀与校园直连域名保留 `system` 本地解析。若你曾手动填写明文 53 地址，请在「设置 → 网络与 DNS」改回纯 IP DoH 443。
- QQ / 微信 / 国内应用传图或语音卡顿：猫猫云梯已在海外 QUIC 拦截规则前自动放行国内 QUIC，并将常用腾讯/QQ 域名加入 Fake-IP 跳过列表；若异常请检查自定义前置规则是否误拦 UDP 443。
- 检查命令：`catcloud net match <域名> --json`、`catcloud net connections --json`。

### 第 5 层：国内提速中转链路
- 若开了「国内提速」后整体断流：先在「国内提速」看中转机是否到期、云安全组是否放行 TCP 443、SNI 是否严格留空（国内云机房拦截未备案 SNI）、健康检测地址是否保持国内 204（绝不能改成海外 `gstatic`）。
- 若未开主代理但开了「全局提速」：查看是否已回退为本地 SOCKS5 或被防火墙拦截。
- 急救回退：在「国内提速」关闭总开关，或执行 `catcloud preaccel bind --enabled false --json && catcloud config reload --json`。
- 检查命令：`catcloud preaccel pool --json`、`catcloud preaccel test --json`、`catcloud preaccel global-status --json`。

### 第 6 层：海外节点、订阅与 AI 地区解锁
- 节点能 ping 通但聊天/写代码 20 秒卡死或被拒：去「节点与测速」跑**省流快测**（看是否「谷歌送中」及 Claude/ChatGPT/Gemini 解锁），再跑**60 秒静默保活**淘汰假活节点；在「智能多选组」开启平时粘性锁定防 IP 乱跳。
- 订阅更新失败或到期：在「节点与测速 → 订阅与导入」看剩余流量与到期日（更新失败时猫猫云梯会原子保留旧节点，不会清空现有配置）。

## 二、听诊 CLI 常用只读命令（默认全部脱敏）

```bash
catcloud status --json
catcloud net doctor --json
catcloud net connections --json
catcloud net match api.openai.com --json
catcloud logs tail --lines 80 --level warning --json
catcloud logs tail --since 30m --level warning --json
catcloud logs tail --since "2026-11-26 03:40" --until "2026-11-26 03:50" --json
catcloud config diag --json
```

> 默认只读命令会自动掩码密码、Token、UUID、个人目录与公私网 IP 末段；`net doctor` 与 `config diag` 同时内置加密 DNS 证书校验诊断（绝不放宽 TLS 校验）；切勿把明文密码或订阅原链接发到公开讨论区。

## 三、排查仍未解决？向 GitHub 仓库 `JuryBu/CatCloud` 一键反馈 Issue

1. **软件内一键反馈**：点击「AI 全权代管」、「运行日志」顶部工具条或「设置 → 关于与更新」中的**「反馈问题到 GitHub」**按钮，软件会自动把脱敏后的环境与关键异常摘要复制到剪贴板，并打开 `https://github.com/JuryBu/CatCloud/issues/new`。
2. **手动提交脱敏 Issue 模板**（粘贴剪贴板摘要即可，严禁附带任何密码、订阅链接或真实中转 IP）：

```markdown
### 环境信息
- 猫猫云梯版本：v0.1.0（便携版 / 安装版）
- 操作系统：Windows 11 / macOS / Linux
- 网络模式：系统代理 / 虚拟网卡（TUN 模式） / 国内提速（开/关）

### 问题现象与复现步骤
1. 我在「<页面名称>」执行了 <操作>
2. 预期结果：...
3. 实际结果：...

### 已排查项与脱敏诊断摘要
- `catcloud net doctor --json` / 软件内「复制排障摘要」结果：
  （直接粘贴已脱敏摘要，确认无真实密码、UUID、订阅链接与完整公网 IP）
```
"###;

const ZH_DOC_01_ONBOARDING: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 01 · 猫猫云梯（CatCloud）新手上手总纲（给 AI 导师）

> **给 AI 导师的统一教学守则（请严格遵守）：**
> 1. **先看现状再带下一步**：结合用户提供的脱敏状态快照，先用 1～2 句大白话告诉用户当前走到哪一步；若快照里存在报错或拦截提示，优先解卡。
> 2. **每次只教当下最需要做的下一小步**：切忌一口气倾倒长篇教程；每次只给 1 个马上能点的小操作，等用户反馈再带下一步。
> 3. **严格用真实中文界面名指路**：不要编造菜单名；非用户主动追问，不抛源码、内部实现或终端命令。
> 4. **没翻墙也能用 AI**：提醒用户在还没连上外网前，直接用 **DeepSeek、豆包、通义千问、Kimi** 等国内直连网页 AI 对话即可。

---

## 一、0 节点冷启动三要素：「猫猫云梯是车，节点/订阅是油」

1. **猫猫云梯本身不内置、不售卖节点**：软件负责把你的多条线路管得更快更稳，你需要先准备至少一份「油」（服务商提供的订阅链接、朋友给的 `.zip` 分享包 / 节点文本，或电脑里已有代理软件的节点）。
2. **去哪加油**：点击左侧「节点与测速 → 订阅与导入」，任选「粘贴订阅链接」「导入分享包 / 粘贴配置 / 一键搬家已有软件」或「`1→2→3` 实时捕捉运行中的软件」。
3. **卡住随时求助**：点击左侧「AI 全权代管」一键复制当前进度发给 DeepSeek / 豆包等国内直连 AI，或直接让本机 AI 助手代办。

---

## 二、猫猫云梯 6 大核心玩法与界面准确路径

### 1. 导入节点、搬家与实时捕捉（页面：`节点与测速 → 订阅与导入`）
- **粘贴订阅链接（最推荐）**：粘入 `http://` / `https://` 订阅链接即可导入；直连受阻会自动尝试通过本机已有代理回退拉取。
- **粘贴文本 / 本地文件 / 搬家已有软件**：支持直接粘贴单条链接或配置文件，也可点「自动扫描并导入」只读迁移电脑上已有开源代理软件，不改动原软件文件。
- **`1→2→3` 实时捕捉运行中的软件**：只有专用客户端找不到订阅链接时，按 3 步选定运行中软件（含托盘程序）→ 在原软件刷新订阅或连接 → 一键整理并导入（也支持直接更新已有订阅组）。

### 2. 选路方式：`智能多选组` vs 单节点（页面：`智能多选组` / `总览`）
- **智能多选组（日常最推荐）**：支持跨多家服务商混池、低倍率省流优先 + 高倍率自动兜底、平时粘性锁定同一条健康线路不乱跳 IP（防止海外 AI 封号或掉登录）。
- **单节点模式**：想手动固定只走某一条地区节点时，在「总览」或「节点与测速」直接切单节点即可。

### 3. 零干扰测速与节点体检（页面：`节点与测速`）
- 测速在独立沙箱核运行，**不会打断当前网页、视频或 AI 对话**。
- **省流快测（建议先跑）**：低流量测延迟、是否「谷歌送中」及 Claude / ChatGPT / Gemini 等解锁；
- **完整测速（按需跑）**：实测上传与下载带宽，自动把又快又稳的「黄金节点」排在前面；
- **60 秒保活（排障跑）**：筛除聊 20 秒就卡死的静默断流线路。

### 4. 分流规则与实时连接排查（页面：`分流与连接`）
- 国内网站默认直连不绕路，主流海外 AI 域名可按组独立分流，海外 QUIC 自动拦截同时放行国内 QQ/微信 QUIC。
- 网页或软件走错路线时，在「分流与连接」查看实时连接命中了哪条规则、走了哪条节点。

### 5. 国内提速（页面：`国内提速`）
- 校园网或宽带遇到「下载很快、上传被限到 2～4 Mbps、给 AI 传图极慢」时开启，通过纯 IP 443 加密中转突破限速，原生 443 节点自动跳过不绕路；还支持关闭主代理时开启**全局提速**给其他代理软件提速。日常上传本来就快则保持关闭即可。

### 6. 日常开关、朋友间 `.zip` 分享包与省内存（页面：`总览`、`运行日志`、`AI 全权代管`、`设置`）
- **系统代理 vs 虚拟网卡（TUN 模式）**：日常浏览器开「系统代理」免管理员权限最省心；终端、开发工具或游戏不通时再在「总览」开启「虚拟网卡（TUN 模式）」。
- **朋友间 `.zip` 分享包**：在「节点与测速」或「国内提速」可勾选想分享的节点或中转一键打包 `.zip`，发给朋友直接一键导入（自动剥离原订阅链接与本机隐私）。
- **悬浮小窗与关窗省内存**：在「总览」可开悬浮小窗盯网速；平时直接点右上角关窗，软件会缩进系统托盘释放界面内存（后台常驻约 70 MB 内），代理照常稳定运行。

---

## 三、建议的 5 步渐进引导节奏（供 AI 对照状态推进）

1. **状态 1：0 个节点** → 用「车和油」讲清来源，引导去「节点与测速 → 订阅与导入」，只问用户手头是订阅链接、分享包/配置文本还是已有运行软件，只教对应 1 种方法。
2. **状态 2：已有节点，代理未开启** → 引导回「总览」打开主开关与「系统代理」，点「常用网站连通检测 → 测一下」验证海外网页已通。
3. **状态 3：已连上，想挑更稳更快或防 AI 掉线** → 引导去「节点与测速」先跑一次省流快测，再去「智能多选组」勾选未送中且 AI 解锁的节点开启粘性优选。
4. **状态 4：上传卡顿 / 终端或游戏不通** → 按需引导了解「国内提速」或在「总览」开启「虚拟网卡（TUN 模式）」。
5. **状态 5：基础已全通（进阶按需）** → 先恭喜用户基础已全通！随后按兴趣轻推 1 项进阶玩法：自定义智能多选组公式、在「分流与连接」微调规则、打包 `.zip` 分享给朋友，或直接关窗进托盘省内存。
"###;

const ZH_DOC_02_PREACCEL: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 02 · 国内提速从 0 到 1 实战手册（省事路线 + 自建一键脚本 + 全局提速）

> **给本机 AI Agent 的行动建议**：若用户提供了国内云服务器 SSH 信息或中转参数，**在征得用户明确同意后，请尽量全程代办**（检查安全组提示 → 执行服务端部署脚本 → 生成并导入 `mmrelay://v1/...` → 执行 `preaccel test` 与 `config reload` 验收），不要把繁琐命令丢给用户手工敲。

## 一、什么时候需要开启「国内提速」？
- 校园网或部分家用宽带下，非 443 高位端口上传被限速到 **2～4 Mbps**（下载很快，但给 AI 传图、推代码或大文件上传极慢、频繁断流），而标准 **TCP 443** 链路可跑满 **50～250+ Mbps**。
- 若日常上传本来就很快，保持「国内提速」关闭即可，无需折腾。

---

## 二、路线 A · 省事路线（有朋友分享或已有零散参数）

1. **收到朋友的 `mmrelay://v1/...` 导入码或 `mmrelay/v1` JSON**：
   - 打开「国内提速」→ 点击右上角「+ 添加中转」→ 切到「导入码 / JSON」直接粘贴保存即可；
   - CLI：`catcloud preaccel add --uri "mmrelay://v1/..." --json` 或 `catcloud preaccel add --file relay.mmrelay.json --json`。
2. **收到朋友的 `.zip` 分享包**：
   - 直接在「国内提速」或「节点与测速 → 订阅与导入」点「导入分享包」，勾选里面的中转线路一键导入。
3. **手里只有零散参数（IP + 端口 443 + 协议 + 密码）**：
   - 在「国内提速 → + 添加中转 → 手动填写」逐项填入（**SNI 务必留空**、勾选跳过证书校验），或者把零散参数发给 AI，请它按下方 `mmrelay/v1` 格式拼好后导入：

```json
{
  "schema": "mmrelay/v1",
  "role": "domestic_pre_accel",
  "relays": [
    {
      "id": "relay-cn-east-1",
      "name": "华东 443 主线",
      "provider": "国内轻量云",
      "region": "华东",
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
}
```

---

## 三、路线 B · 自建路线（买机 → 放行 443 → 一键部署直接吐 `mmrelay://v1/...`）

### 1. 国内轻量应用服务器选购要点
- **地域**：选离自己物理位置最近且到常用海外节点出口质量好的区域（如华东上海/杭州、华南广州/深圳、华北北京）。
- **带宽与流量**：优先峰值带宽 `>= 30 Mbps`（或 100～200 Mbps 峰值轻量包 / 按量计费不限速），确认月流量包足够日常上传。
- **双活备机（可选）**：对稳定性要求极高时可备 2 台不同机房轻量机，设 `priority: 10` 和 `20`，猫猫云梯会自动双活秒切。

### 2. 云厂商控制台防火墙 / 安全组（最常见踩坑点！）
- 登录云厂商控制台 → 找到实例的**防火墙 / 安全组** → 添加入站放行规则：**协议 TCP，端口 `443`，来源 `0.0.0.0/0`**（未放行 TCP 443 时服务端跑起来客户端也连不上）。
- 如需在同一台服务器上并行部署 **Hysteria2（UDP 443）** 与 `AnyTLS（TCP 443）` 双协议共存（互不冲突、共享同一份纯 IP 自签证书），请同步放行入站 **协议 UDP，端口 `443`，来源 `0.0.0.0/0`**。
- `mmrelay/v1` 的 `protocol` 支持 `anytls` / `hysteria2`（别名 `hy2`）/ `trojan` / `vless`；选择 `hysteria2` 时同样须遵守纯 IP `:443` + 空 `sni` + `skip_cert_verify: true`，客户端编译会自动附带保守带宽提示（`up: 100 Mbps` / `down: 200 Mbps`）防止校园网拥塞抖动。

### 3. 三条硬红线（绝不能违背）
1. **SNI 必须严格留空（`sni: ""` / VLESS `servername: ""`）**：国内云机房网关会直接阻断 TCP 443 上未备案的第三方域名 SNI！必须使用**纯 IP 自签 ECDSA 证书 + 空 SNI + `skip_cert_verify: true`**（只跳过到自己中转机的证书校验，不影响访问海外 HTTPS 网站的端到端加密）。
2. **健康探针必须用国内 204**：保持默认 `http://connectivitycheck.platform.hicloud.com/generate_204` 或 `http://connect.rom.miui.com/generate_204`，严禁改为海外 `gstatic.com`。
3. **严禁把真实中转 IP 与密码发到公开仓库或公开论坛**。

### 4. 服务器一键部署脚本模板（Ubuntu / Debian，支持 `anytls` / `trojan`，跑完直接输出 `mmrelay://v1/...`）

> 将下面脚本保存为 `setup-relay.sh` 后以 `root` 运行（默认部署 `anytls`，如需 Trojan 加 `PROTO=trojan`；如自动取公网 IP 失败可显式传 `SERVER_IP=203.0.113.10`）：

```bash
#!/usr/bin/env bash
set -euo pipefail

PROTO="${PROTO:-anytls}"          # 可选: anytls (推荐) | trojan
RELAY_NAME="${RELAY_NAME:-CN-443-Primary}"
RELAY_REGION="${RELAY_REGION:-CN-East}"
RELAY_PROVIDER="${RELAY_PROVIDER:-domestic-light}"
EXPIRES_AT="${EXPIRES_AT:-2027-08-12}"
SERVER_IP="${SERVER_IP:-$(curl -4s --max-time 6 https://api.ipify.org || hostname -I | awk '{print $1}')}"
PASSWORD="${PASSWORD:-$(openssl rand -hex 16)}"

echo "[1/6] 开启内核 BBR + 在线热切网卡 fq 队列调度（防 pfifo_fast 丢包）..."
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
cat >/etc/sysctl.d/99-catcloud-relay-tune.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
# AnyTLS 官方不兼容 TCP Fast Open，请勿启用 tcp_fastopen
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
SYSCTL
sysctl -p /etc/sysctl.d/99-catcloud-relay-tune.conf >/dev/null || true
if [ -n "${IFACE}" ]; then
  tc qdisc replace dev "${IFACE}" root fq || true
  cat >/etc/systemd/system/catcloud-fq-qdisc.service <<FQUNIT
[Unit]
Description=Apply fq qdisc on ${IFACE} for BBR pacing
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/sbin/tc qdisc replace dev ${IFACE} root fq
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
FQUNIT
  systemctl daemon-reload && systemctl enable catcloud-fq-qdisc.service >/dev/null 2>&1 || true
fi

echo "[2/6] 安装依赖与官方 sing-box（支持 AnyTLS 与 Trojan）..."
apt-get update -qq
apt-get install -y -qq curl openssl jq python3 ca-certificates
if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.app/install.sh | sh
fi

echo "[3/6] 为纯 IP (${SERVER_IP}) 生成自签 ECDSA 证书..."
mkdir -p /etc/catcloud-relay
openssl ecparam -name prime256v1 -genkey -noout -out /etc/catcloud-relay/key.pem
openssl req -new -x509 -days 3650 -key /etc/catcloud-relay/key.pem \
  -out /etc/catcloud-relay/cert.pem \
  -subj "/CN=${SERVER_IP}" \
  -addext "subjectAltName=IP:${SERVER_IP}"
chmod 600 /etc/catcloud-relay/key.pem

echo "[4/6] 写入 /etc/catcloud-relay/config.json (TCP 443, ${PROTO})..."
if [ "${PROTO}" = "trojan" ]; then
  INBOUND_JSON=$(jq -n --arg pw "${PASSWORD}" '{
    type: "trojan", tag: "relay-in", listen: "::", listen_port: 443,
    users: [{name: "catcloud", password: $pw}],
    tls: {enabled: true, certificate_path: "/etc/catcloud-relay/cert.pem", key_path: "/etc/catcloud-relay/key.pem"}
  }')
else
  PROTO="anytls"
  INBOUND_JSON=$(jq -n --arg pw "${PASSWORD}" '{
    type: "anytls", tag: "relay-in", listen: "::", listen_port: 443,
    users: [{name: "catcloud", password: $pw}],
    tls: {enabled: true, certificate_path: "/etc/catcloud-relay/cert.pem", key_path: "/etc/catcloud-relay/key.pem"}
  }')
fi
jq -n --argjson inbound "${INBOUND_JSON}" '{
  log: {level: "warn"},
  inbounds: [$inbound],
  outbounds: [{type: "direct", tag: "direct"}]
}' > /etc/catcloud-relay/config.json

echo "[5/6] 注册并启动 systemd 服务..."
cat >/etc/systemd/system/catcloud-relay.service <<'UNIT'
[Unit]
Description=CatCloud Domestic 443 Relay (sing-box)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/sing-box run -c /etc/catcloud-relay/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now catcloud-relay.service
ss -tlnp | grep ':443 ' || echo "警告：未检测到 443 监听，请运行 journalctl -u catcloud-relay -n 30 检查"

echo "[6/6] 生成猫猫云梯 mmrelay/v1 导入包（仅私用，勿公开分享）..."
MMRELAY_JSON=$(jq -nc \
  --arg id "relay-$(date +%s)" --arg name "${RELAY_NAME}" \
  --arg provider "${RELAY_PROVIDER}" --arg region "${RELAY_REGION}" \
  --arg server "${SERVER_IP}" --arg proto "${PROTO}" \
  --arg pw "${PASSWORD}" --arg exp "${EXPIRES_AT}" '{
    schema: "mmrelay/v1", role: "domestic_pre_accel",
    relays: [{
      id: $id, name: $name, provider: $provider, region: $region,
      server: $server, port: 443, protocol: $proto, password: $pw,
      sni: "", skip_cert_verify: true, priority: 10, expires_at: $exp, enabled: true
    }]
  }')
MMRELAY_URI="mmrelay://v1/$(printf '%s' "${MMRELAY_JSON}" | python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')"
echo "=== 请复制下方单行导入码到猫猫云梯「国内提速 → + 添加中转」 ==="
echo "${MMRELAY_URI}"
```

---

## 四、客户端验收、全局提速与安全回退

1. **导入并验收**：
   - 在「国内提速」导入后，确认开启**「自动跳过原生 443 节点」**（本身已在 443 的高速海外节点不绕路省流量），然后点击「测延迟」或「测上下行」（支持**单条或全部中转真实上下行测速**）验真，或跑一次 443 vs 非 443 体检。
   - CLI 验真：
     ```bash
     catcloud preaccel pool --json
     catcloud preaccel test --json
     catcloud preaccel test --speed --json
     catcloud preaccel test --speed --node-id <id> --json
     catcloud preaccel global-status --json
     catcloud preaccel bind --dispatch-strategy auto --lb-strategy consistent_hashing --json
     catcloud config reload --json
     ```
2. **多云物理机调度与密钥轮换回收**：
   - 接入 2 台及以上不同物理云时，默认 `--dispatch-strategy auto`（或 `load_balance`）搭配 `--lb-strategy consistent_hashing`（同主机长连接稳定锚定同一物理云，跨主机自然聚合带宽，外层 `fallback` 兜底），同机多协议互不抢网卡；也可用 `--dispatch-strategy fallback` 切回纯单线主备，或按需切 `--lb-strategy round_robin`。
   - 内测/朋友分享后需收回访问权时，使用仓库内置脱敏脚本一键安全轮换远端密钥（默认 SSH stdin 传密、自动生成回滚脚本并输出新 `mmrelay://v1/...`，先加 `--dry-run` 离线验证）：
     `node scripts/relay/rotate_relay_secrets.mjs --host <IP> --user root --key <KEY_PATH> --config /etc/catcloud-relay/config.json --service catcloud-relay --dry-run`
3. **全局提速（独立加速其他代理软件或终端工具）**：
   - 即使关闭猫猫云梯主代理，只要开启「国内提速」总开关，Windows 下可按需经签名 WinDivert 驱动透明加速其他代理核心或 `ssh`/`scp`（自动跳过纯国内 80 端口与普通通讯软件，避免误拦截）；若被安全软件拦截会自动优雅降级为本地 `SOCKS5` 入口防断网。
   - 在 macOS / Linux 或非管理员权限下，自动提供独立本地 `SOCKS5` 入口供其他工具填写前置代理。
4. **一键安全回退**：
   - 在「国内提速」关闭总开关，或执行：
     `catcloud preaccel bind --enabled false --json && catcloud config reload --json`

---

## 五、提速性能调优与实测避坑铁律（Agent 排障必查）

1. **首查云服务器主网卡真实 `tc qdisc`（头号隐形大坑）**：
   - 仅在 `/etc/sysctl.d/` 写 `net.core.default_qdisc = fq` **不会**自动套用到开机前已初始化的 `eth0`！若 `tc qdisc show dev eth0` 仍显示 `pfifo_fast`，BBR 会失去 pacing 发包整形导致丢包重传激增、4 并发经常卡死 1～2 条连接。
   - **零断流在线修复**（不踢任何现役连接）：执行 `tc qdisc replace dev <iface> root fq` 并配置上文 `catcloud-fq-qdisc.service` 防止重启后退回 `pfifo_fast`。
2. **协议首选 `AnyTLS`，宽带放行国内 UDP 443 可并挂 `Hysteria2`**：
   - `AnyTLS` 支持高效 TLS 会话复用，比旧 `Trojan` 更抗并发抖动；猫猫云梯编译时默认全量关闭 TFO（`tfo: false`，AnyTLS 官方不兼容 TFO，关闭可消除首包 2 秒卡顿）、设置 `min-idle-session: 0`（防止 NAT 半关闭残留僵尸空闲会话引发连环断流），并配合 `keep-alive-idle: 45`、自适应 `expected-status` 探针、`consistent-hashing` 粘性均衡与 TUN MTU `<= 1400` 抗分片钳降保障长流稳定；
   - 若用户宽带不屏蔽国内 UDP 443，可在同一台云服务器的 `UDP 443` 并行部署 `Hysteria2`（与 TCP 443 互不冲突），彻底消除 TCP-over-TCP 队头阻塞。
3. **搭配轻加密非 443 海外节点，避开双层 TLS**：
   - 外层国内 443 已提供完整 TLS 加密，内层优先搭配 `Shadowsocks` 等轻加密节点（单层 TLS 吞吐显著高于双层 TLS 嵌套且不易触发分片卡死）；原生 443 高速节点保持「自动跳过原生 443」直连。
4. **按云机数量选调度模式**：
   - 2 台及以上独立健康物理云用默认 `auto`/`load_balance` 聚合带宽（同机多协议自动去重，外层 `fallback` 保兜底）；若备机质量显著弱于主机，切 `--dispatch-strategy fallback` 保持主备秒切。

---

## 六、透明网关 / 软路由标准 YAML 导出

若你在 OpenWrt（OpenClash / ShellCrash）或 Linux 旁路由上自维护 Mihomo，可直接导出标准配置（默认强制脱敏，实际部署时加 `--reveal-secrets`）：

```bash
# 仅导出国内 443 中转片段（含防环与 fake-ip-filter；在目标海外节点下挂一行 dialer-proxy 即可接入）
catcloud config export-gateway --profile relay-fragment --reveal-secrets --output relay-fragment.yaml

# 导出完整透明网关配置（自动开启 allow-lan、TPROXY 7893、REDIR 7892、0.0.0.0:1053 DNS 并关闭桌面 TUN）
catcloud config export-gateway --profile transparent-gateway --reveal-secrets --output gateway.yaml

# 导出优选业务节点与国内 443 中转防环片段
catcloud config export-gateway --profile preferred-nodes --reveal-secrets --output preferred.yaml
```
"###;

const ZH_DOC_03_MULTIGROUP: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 03 · 智能多选组与安全评分公式手册

## 一、核心优势与 4 种选路模式
- **跨多家订阅混池**：把不同服务商的好节点装进同一个组统一评测挑优。
- **4 种模式**：
  - `sticky_best`（**粘性优选，默认推荐**）：平时稳稳锁定当前健康第一名，不频繁乱跳 IP，防海外 AI 封号/掉登录；连续达标失败或断流才自动切下一名。
  - `conditional_pool`（**动态条件池**）：按地区、倍率、协议与健康门禁自动纳管符合条件的节点。
  - `load_balance_consistent_hash` / `load_balance_round_robin`（**受控负载均衡**）：按域名哈希或轮询分散并发，同时经硬门禁排除送中/异常节点。

## 二、小白场景预设公式表（直接复制套用）

| 使用场景 | 推荐模式 | 推荐硬门禁 | 推荐安全评分公式 | 推荐兜底与切线策略 |
|---|---|---|---|---|
| **AI 编程防封号（推荐）** | `sticky_best` | `google_clean == 1`、`keepalive_ok == 1` | `(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)` | `cross_pool_escalate` + `force_close_old` |
| **低倍率省流 + 高倍率兜底** | `conditional_pool` | `multiplier <= 1.0`、`google_clean == 1` | `(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08) / max(multiplier, 0.25)` | 主池配 `cross_pool_escalate` 借道高倍率备池，恢复自动滞回回切 |
| **影音流媒体 / 大文件下载** | `sticky_best` | `ok == 1` | `down_mbps * 30 + up_mbps * 5 - ping_ms * 0.15 - jitter_ms * 0.2` | `degrade_best_warn` + `graceful_new_only` |
| **纯极速性能优先（不计倍率）** | `sticky_best` | `google_clean == 1` | `up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1` | `degrade_best_warn` + `force_close_old` |

> **安全公式可用变量与函数**（零 `eval`）：`up_mbps`、`down_mbps`、`ping_ms`（别名 `latency_ms`）、`jitter_ms`、`loss_pct`、`multiplier`、`keepalive_ok`、`google_clean`、`unlocked`、`is_443_native`、`ok`；纯函数 `min(a,b)`、`max(a,b)`、`clamp(x,lo,hi)`、`if(c,t,f)`、`abs(x)`；按探针 ID 寻址 `probe_up("id")`、`probe_down("id")`、`probe_ping("id")`、`probe_ok("id")`、`site_unlocked("name")`。

## 三、GUI 操作与 CLI 精确命令

- **GUI**：打开「智能多选组」→ 新建或编辑组 → 选择模式、成员/筛选条件、评分公式、三选一兜底（`降级最佳并告警` / `跨池借道自动回切` / `严格熔断 REJECT`）及切换策略（`强制断开旧连接` vs `平滑仅新连接`）。
- **CLI 命令（注意 `<group_id>` 为位置参数）**：

```bash
# 查看全部多选组与当前选中节点
catcloud group list --json

# 创建或局部更新智能多选组（已有组未传字段全部安全保留）
catcloud group create --id grp-ai --name "AI 稳定组" --mode sticky_best --fallback cross_pool_escalate --switch-mode force_close_old --json

# 专用成员维护（安全增删/替换成员，零触碰策略与分流规则）
catcloud group members --id grp-ai add --nodes node_1,node_2 --json
catcloud group members --id grp-ai remove --nodes node_2 --json
catcloud group members --id grp-ai set --nodes node_1,node_3 --json

# 试算候选得分排行与仲裁决策（离线只读试算 + 附带守护快照）
catcloud group eval grp-ai --json

# 切换到指定节点或自动轮换下一最佳候选
catcloud group switch grp-ai --json
catcloud group switch grp-ai --node <node_id> --json

# 更新评分公式、兜底、硬门禁与分流规则
catcloud group policy grp-ai --formula "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08) / max(multiplier, 0.25)" --fallback degrade_best_warn --hard-gate "google_clean == 1" --add-match-rule "DOMAIN-SUFFIX,openai.com" --json
catcloud group policy grp-ai --match-rules "DOMAIN-SUFFIX,openai.com;DOMAIN-SUFFIX,claude.ai" --json
catcloud group policy grp-ai --clear-match-rules --json
```

## 四、排障与回退
- 若某组显示「已熔断（REJECT）」：执行 `catcloud group eval <group_id> --json` 查看哪条硬门禁筛空了节点，先跑一次测速或将兜底策略改回 `degrade_best_warn`。
- 若切点后旧对话仍卡死：将该组切换策略设为 `force_close_old` 以主动踢断旧 HTTP/2 长连接。
"###;

const ZH_DOC_04_NODES_PROBES: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 04 · 节点管理、订阅导入、实时捕捉与三档零干扰测速手册

## 一、三档零干扰测速体系（页面：`节点与测速`）

测速运行在独立临时沙箱核心（仅绑定本机回环、关闭虚拟网卡、低内存上限、结束即销毁），**全程不打断当前上网**：
1. **省流快测（L1，推荐首选）**：极低流量一次性测出真实延迟、是否「谷歌送中」（以 Google 侧真值为硬门禁）以及 Claude / ChatGPT / Gemini / Windsurf 解锁状态。
2. **完整测速（L2，按需跑）**：在 L1 基础上实测真实上传（512 KB 快切防卡死）与下载带宽，为「智能多选组」提供排序依据。
3. **60 秒静默保活（Keep-Alive）**：排查「能 ping 通但静默 20～60 秒就黑洞断流」的假活线路。
- **黄金节点智能降级**：若刚跑完省流快测还没有上下行速度数据，列表会自动降级按「未送中 + AI 解锁 + 有效延迟升序」排优，并提示一键为黄金节点补测上下行。

## 二、节点获取、实时捕捉与订阅组管理（页面：`节点与测速 → 订阅与导入`）

- **订阅链接导入与代理回退**：支持 Clash/Mihomo YAML（上限 16 MiB）、sing-box JSON、Base64 与明文 URI 列表；直连拉取失败时自动尝试借本机已有代理回退拉取；遇到 HTTP 500、畸形内容或 0 节点时原子拒载，**绝不清空已有节点**。
- **只读迁移已有开源客户端**：扫描并只读导入本机开源代理软件明文配置，绝不修改第三方目录。
- **`1→2→3` 实时捕捉与已有组更新**：捕捉运行中代理软件刷新或连接时产生的明文配置；确认页支持改组名、勾选剔除假节点，也支持**「作为已有组结果更新」**（失败保留原组，成功可三选一：**保留最新 / 整合去重 / 取消更新**）。
- **订阅组改名与双组整合合并**：已导入组支持原地改名；两个已有组可在同事务中整合合并，自动去重并保留节点历史测速与多选组引用。
- **开放外部脚本适配器（`catcloud-adapter/v1`）**：支持用户自维护脚本通过 `stdin`/`stdout` JSON 动态刷新节点（内置 `>= 60s` 防风暴冷却与 0 节点保护）。

## 三、CLI 精确命令（默认脱敏）

```bash
# 订阅组查询、刷新、改名、合并与删除
catcloud sub list --json
catcloud sub refresh <sub_id> --json
catcloud sub rename <id> --name <new_name> --json
catcloud sub merge --source <src_id> --target <dst_id> --json
catcloud sub remove <sub_id> --json

# 节点多维筛选、导入、只读迁移与进程探查
catcloud node list --region TW --max-multiplier 1.0 --json
catcloud node import --file sub.yaml --json
catcloud node import --url "https://example.invalid/sub" --name "主订阅" --json
catcloud node migrate --scan --json
catcloud node attach-process --list --json

# 探针管理与三档测速（注意 probe add 必填 --id --name --kind --url）
catcloud probe list --json
catcloud probe run --tier l1 --json
catcloud probe run --tier l2 --node <node_id> --json
catcloud probe add --id custom_api --name "Custom API Upload" --kind upload --url https://example.com/up --json
catcloud probe remove --id custom_api --json
```

> 若缺失本机 Mihomo 核心，CLI 会诚实返回 `executed: false` 与官方校验下载指引；所有临时测速核心结束后立即回收，零僵尸残留。

## 四、专用客户端实时捕捉结果为空：4 条高频排查

当通过「节点与测速 → 订阅与导入」或 `catcloud node attach-process` 从运行中的专用客户端实时捕捉节点却返回 0 节点时，按以下 4 点逐一核查：
1. **仅点了「更新订阅」未点「连接/开启代理」**：多数专用客户端只在真正开启连接时才会把运行时明文配置落盘或启动本地控制口，请先在原客户端点击一次连接再执行捕捉。
2. **选错了前端外壳进程而非底层代理内核进程**：桌面客户端常拆分为 Electron/UI 外壳进程与底层 `mihomo` / `sing-box` / `xray` 代理内核进程，请在进程列表中选择实际携带配置参数或监听本地端口的底层代理内核进程。
3. **目标客户端以管理员权限运行导致普通权限跨权读取受限**：在 Windows 上，普通权限的猫猫云梯无法读取高完整性（管理员权限）进程的完整命令行与工作目录；请以同级权限运行（或在普通权限下启动目标客户端）后重试。
4. **遇到双层加密闭源客户端时的兜底路径**：若原客户端全程内存/本地双层加密且未暴露明文配置或标准控制口，可先借原软件保持联网，直接打开对应服务商官网用户中心复制通用订阅链接，再粘贴到猫猫云梯「节点与测速 → 订阅与导入」导入。
"###;

const ZH_DOC_05_ROUTING_CONNS: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 05 · 分流规则、QUIC 策略与实时连接排障手册

## 一、三种全局分流模式（页面：`总览` / `分流与连接`）
- **规则分流（推荐默认）**：国内直连、海外走代理、AI 服务按需走专属稳定组。
- **全局代理**：除防环与本机回环外所有流量走代理（排查规则误判时可临时切换；切回规则分流后若内核内存偏高，后台会安全评估并自动回收多余内存）。
- **直连模式**：所有流量直连不经过海外节点。

## 二、国内直连、AI 域分流、纯自写规则与 `rule-providers`
- **国内直连**：基于 `Country.mmdb`（及可选 `geosite.dat`）将国内域名与国内 IP 直接放行 `DIRECT`。可在「设置」一键刷新地区数据库。
- **内置 AI 域名分流**：内置覆盖 OpenAI / ChatGPT / Anthropic / Claude / Gemini / Google AI / Antigravity / Windsurf / Codeium / Cursor / Copilot 等主流域名；在「智能多选组」开启某组的「独立分流」后，该组的匹配规则会自动生效并锁定对应稳线，不干扰其他网页流量。
- **自定义前置/后置规则与批量粘贴**：在「分流与连接」添加或批量粘贴 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`RULE-SET`、`AND`/`OR`/`NOT`、`MATCH` 等规则（自动剥离 YAML `- `、引号与注释）。
- **纯自写规则模式与内联 YAML 覆写**：高阶用户可在「分流与连接」开启「纯自写规则模式（`custom_rules_only`）」跳过内置国内直连/QUIC/组自动规则与 AI DNS 覆写（仅保留中转/局域网防环，自写 `MATCH` 时不覆盖），并通过「内联 YAML 覆写（`inline_override_yaml`，上限 1 MiB）」直接粘贴 `rule-providers:` / `rules:` / `dns:` 片段生效。

## 三、QUIC（UDP 443）双层策略与腾讯系防 Fake-IP
- **国内 QUIC 放行 + 海外 QUIC 拦截**：开启「阻止海外 QUIC」时，猫猫云梯会在拦截规则**紧前面**自动插入国内 UDP 443 直连放行（`GEOSITE,cn` / `GEOIP,CN` 及国内核心域），既让海外网页/AI 稳走 TCP 避免 UDP 丢包断流，又保证 QQ、微信、国内影音的直连 QUIC 流畅不卡。
- **QQ / 微信防 Fake-IP 兜底**：自动将 `*.qq.com`、`*.qpic.cn`、`*.qlogo.cn`、`*.gtimg.cn`、`*.nt.qq.com.cn`、`*.weixin.qq.com`、`*.tencent.com` 等加入 `fake-ip-filter`，防止语音、扫码或图片加载异常。

## 四、实时连接排查（GUI + 听诊 CLI）
- **GUI**：打开「分流与连接」查看当前活跃连接（目标域名、命中规则、所走节点、上下行流量），支持按关键字搜索或一键断开卡住的旧连接。
- **CLI 听诊命令**：

```bash
# 查看活跃连接摘要（默认脱敏）
catcloud net connections --json

# 模拟测试某域名会命中哪条规则与目标组
catcloud net match chatgpt.com --json
catcloud net match qq.com --json
```
"###;

const ZH_DOC_06_NETWORK_LIFECYCLE: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 06 · 网络设置、热加载、无窗省内存与安全更新手册

## 一、系统代理、代理守护、虚拟网卡（TUN）与 DNS（页面：`总览`、`设置`）
- **系统代理与代理守护（Proxy Guard）**：自动接管浏览器与常规软件流量；开启代理守护后，可防止其他软件偷偷改写系统代理设置。
- **虚拟网卡（TUN 模式）**：接管整机包括命令行、开发工具与游戏流量（Windows 首次开启会请求管理员权限，支持 `mixed` / `system` / `gvisor` 协议栈）。
- **高级 DNS 与独立 IPv6**：支持 `fake-ip` / `redir-host`、国内加密 DoH 上游与海外 Fallback-filter，并独立控制代理核 IPv6 与 DNS IPv6；在「设置」可一键复制 PowerShell / CMD / Bash / Fish 终端代理环境变量。

## 二、三级零断流热加载
- **L1（毫秒级生效）**：切换分流模式、切节点、断开旧连接，直接与控制面通信，零断流。
- **L2（校验后热应用）**：修改规则、DNS、多选组、订阅或国内提速配置后，先做语法、防环与内核预检；无效配置原子拒载绝不断网，通过后无缝热应用并恢复选组状态。
- **L3（核心轻量重启）**：仅在变更端口、TUN 栈或更换内核二进制时重启转发核心进程，界面与数据保持不变；端口冲突时支持 TCP/UDP 自动顺延。

## 三、无窗托盘省内存、便携隔离与后台预下载安全更新
- **关窗进托盘省内存**：点击主窗口右上角关闭时彻底销毁界面渲染进程，转入纯无窗托盘态（后台常驻目标 `<= 70 MB`）；点击托盘图标或快捷键瞬间重建窗口。
- **数据隔离与便携 CLI**：支持 `--data-dir <PATH>`、`CATCLOUD_DATA_DIR` 与绿色便携版 `portable.flag`；便携版 `cli/catcloud(.exe)` 会自动向上识别同包根目录 `../portable.flag` 并复用同一份 `data/` 与随包内核，且不影响主程序便携自更新判定。
- **安全后台预下载与询问更新（`JuryBu/CatCloud`）**：仅允许 HTTPS 443 访问 GitHub 官方域名，强制核验 `latest.json` 与 `SHA256SUMS.txt` 后流式预下载至 `.update_staging/`（支持绿色便携版与系统安装版）。每次打开主窗口或后台校验就绪时弹窗询问：用户可点击「立即重启并更新」（便携版无感热换轨、安装版拉起已校验安装向导）、点击「稍后提醒」（保留预下载包下次打开再问），或点击「跳过此版本」（记录跳过版本并立即删除预下载包释放磁盘，该版本不再提醒）；更新全程绝对保留 `data/`、`portable.flag` 与数据库文件，任意失败自动全量回滚。

## 四、配置校验、备份恢复与更新 CLI 命令

```bash
# 校验配置、编译预览与零断流热载
catcloud config validate --json
catcloud config compile --json
catcloud config reload --json
catcloud config export-env --shell powershell --json

# 完整性校验的配置备份与恢复
catcloud config backup --output catcloud-backup.json --json
catcloud config restore --file catcloud-backup.json --json

# 在线/离线检查更新与本地校验暂存
catcloud update check --json
catcloud update check --offline --json
catcloud update stage --manifest latest.json --archive CatCloud-0.2.0-windows-x64-portable.zip --checksums SHA256SUMS.txt --json

# 导出或同步多语言随装权威手册树
catcloud docs export --lang zh-CN --sync-dir <dir> --json
```
"###;

const ZH_DOC_07_SHARE_BUNDLE: &str = r###"> 【语言锁定】请全程使用简体中文回复用户，并严格使用猫猫云梯真实中文界面名称（总览 / 智能多选组 / 节点与测速 / 分流与连接 / 国内提速 / 运行日志 / AI 全权代管 / 设置）。

# 07 · 朋友间可勾选 `.zip` 分享包使用与安全红线手册

## 一、什么是猫猫云梯 `.zip` 分享包（`catcloud-share/v1`）？
当你想把几条好用的海外节点，或自建的国内 443 提速中转分享给朋友时，无需手动复制零散密码或暴露整个订阅链接：
- **精确勾选打包**：可自由勾选指定订阅组/地区的若干节点，并可同步勾选国内提速中转线路，打成一份干净的 `.zip` 压缩包。
- **自动剥离个人隐私**：导出时自动剔除原订阅 URL、本机绝对路径、控制口密钥、运行日志、节点本地 `dialer-proxy` 绑定与中转测速缓存。
- **人机双读结构**：包内包含 `manifest.json`、`nodes.yaml`（标准 Clash 格式）、`relays.mmrelay.json`（标准 `mmrelay/v1`）及 `README.md`（附猫猫云梯一键导入指引与 CLI 命令）。

## 二、软件内三处快捷入口与一键导入
- **导出入口**：
  1. 「国内提速」→ 中转线路卡片右上角「分享包」；
  2. 「节点与测速」→ 多选节点后，底部操作栏右侧「导出已选分享包」；
  3. 「节点与测速 → 订阅与导入」→ 已导入订阅顶栏「导入 / 导出分享包」。
- **导入流程**：点击「导入分享包」选定 `.zip` → 先看脱敏预览并可勾选需要的子集 → 选择「作为新订阅组导入」或「更新已有订阅组（保留最新 / 整合去重）」。导入内置防路径穿越、拒绝符号链接、单包 `<= 32` 文件 / `<= 4000` 节点 / `<= 16 MiB` 真实解压上限护栏。

## 三、CLI 导出与导入命令

```bash
# 导出指定节点与中转线路到 .zip 分享包
catcloud share export --output friend-pack.zip --name "朋友分享包" --nodes node_1,node_2 --relays relay_1 --json

# 只读脱敏预览分享包内容（不写入数据库，默认掩码全部密钥与服务器地址）
catcloud share inspect friend-pack.zip --json
catcloud share import --file friend-pack.zip --dry-run --json

# 确认无误后导入（可选 --target-sub <sub_id> --mode merge_dedup|replace_latest）
catcloud share import --file friend-pack.zip --apply --json
```

## 四、绝对安全红线（用户与 AI Agent 必读）
1. **仅限私对私发送**：`.zip` 分享包内含可直接连通的节点与中转凭据，**严禁上传至公开 GitHub 仓库、Issue、公开网盘或公共群聊**。
2. **严禁 AI 复述明文密钥**：AI Agent 处理或协助导入/导出分享包时，**严禁在对话、日志或摘要中打印、复述或泄露包内的明文密码、UUID、Token、私钥或未脱敏中转 IP**；查看内容应始终使用默认的脱敏预览模式。
"###;

// ============================================================================
// Refined Complete English Baseline Manuals (8 Chapters)
// ============================================================================

const EN_DOC_00_TROUBLESHOOTING: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 00 · General Network Troubleshooting (6-Layer Guide & GitHub Issue Template)

> Need AI help before proxy access works? Paste your sanitized diagnostic summary into directly reachable Web AIs first (**DeepSeek, Doubao, Qwen, Kimi**), or use ChatGPT / Claude / Gemini once online, or ask a local CLI Agent.

> **Locate local `catcloud.exe` (installed builds are not on `PATH` by default)**:
> - PowerShell: `$CATCLOUD = @("$env:LOCALAPPDATA\CatCloud\resources\cli\catcloud.exe", ".\cli\catcloud.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1`
> - Bash: `CATCLOUD=$(command -v catcloud || ([ -x "./cli/catcloud.exe" ] && echo "./cli/catcloud.exe") || echo "$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe")`

## 1. 6-Layer Bottom-Up Diagnostic Order
1. **Layer 1 — Physical Network & Captive Portal**: Confirm direct domestic sites load with proxy off. On campus/hotel Wi-Fi returning HTTP 302 login portals, authenticate first (`catcloud preaccel test --campus --json`).
2. **Layer 2 — Conflicting Proxy Apps & Residual Services**: Check for other running proxy clients, leftover system proxy entries, `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` env vars, or security software blocking core/driver binaries (`catcloud net doctor --json`).
3. **Layer 3 — CatCloud Core, Ports & TUN Mode**: If browsers work but terminals/IDEs/games fail, enable **TUN Mode** on **Overview** (requires admin elevation on Windows). If CatCloud was started without Windows elevation while TUN was configured, the UI honestly shows **TUN · Admin Required** (only System Proxy is active, so browsers work while desktop apps/terminals may time out); click it for one-click admin relaunch, or choose to turn TUN off. Check port auto-shift in **Settings → Network & DNS**, and verify config with `catcloud status --json` and `catcloud config validate --json`.
4. **Layer 4 — Routing Rules, DNS & QUIC Policy**: Ensure domestic direct routing and `Country.mmdb` are present (**Rules & Conns** / **Settings → Network & DNS**). On campus/enterprise networks blocking outbound plaintext UDP 53, direct or proxy-node DNS can time out; CatCloud now defaults to pure-IP DoH 443 (`223.5.5.5` / `1.12.12.12`) while keeping `system` resolution in `nameserver-policy` for `+.edu.cn`/LAN suffixes and configured campus direct domains—switch back to pure-IP DoH 443 if you manually set plaintext UDP 53. CatCloud allows domestic QUIC (UDP 443) before overseas QUIC blocking and bypasses Fake-IP for major domestic IM domains. Inspect with `catcloud net match <domain> --json` and `catcloud net connections --json`.
5. **Layer 5 — Domestic Boost**: Verify relay expiry, cloud firewall TCP 443 inbound allow rule, strictly EMPTY `sni`, domestic 204 health probe, real relay speeds, and standalone global tunnel status (`catcloud preaccel pool --json`, `catcloud preaccel test --json`, `catcloud preaccel test --speed --json`, `catcloud preaccel global-status --json`). Quick rollback: `catcloud preaccel bind --enabled false --json && catcloud config reload --json`.
6. **Layer 6 — Overseas Nodes, Subscriptions & AI Unlock**: Run **Lite Test (L1)** on **Nodes & Speed** to check Google region cleanliness & AI unlocks, plus **60s Keep-Alive** for silent blackholes; use sticky mode in **Smart Groups**.

## 2. Read-Only Stethoscope CLI (Sanitized by Default)
```bash
catcloud status --json
catcloud net doctor --json
catcloud net connections --json
catcloud net match api.openai.com --json
catcloud logs tail --lines 80 --level warning --json
catcloud logs tail --since 30m --level warning --json
catcloud logs tail --since "2026-11-26 03:40" --until "2026-11-26 03:50" --json
catcloud config diag --json
```

## 3. Still Stuck? Report an Issue to `JuryBu/CatCloud`
- Click **Report Issue on GitHub** in **AI Autopilot**, **Logs**, or **Settings → About & Updates** to copy a sanitized diagnostic summary and open `https://github.com/JuryBu/CatCloud/issues/new`.
- Never paste plaintext passwords, UUIDs, tokens, subscription URLs, or unmasked relay IPs.

```markdown
### Environment
- CatCloud version: v0.1.0 (Portable / Installed)
- OS: Windows / macOS / Linux
- Mode: System Proxy / TUN Mode / Domestic Boost (On/Off)

### Steps to Reproduce
1. In `<Page>`, I did `<Action>`
2. Expected: ...
3. Actual: ...

### Sanitized Diagnostics
Paste output from "Copy Diagnostic Summary" or `catcloud net doctor --json` (confirm zero secrets/raw IPs).
```
"###;

const EN_DOC_01_ONBOARDING: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 01 · CatCloud Beginner Onboarding Guide (For AI Mentors)

> **Mentor Rules:**
> 1. Inspect the user's sanitized status snapshot first and summarize their exact step in 1-2 plain sentences; resolve errors/blocks first.
> 2. Teach **only ONE small actionable step at a time** — never dump long manuals at once.
> 3. Use exact CatCloud UI page names (**Overview / Smart Groups / Nodes & Speed / Rules & Conns / Domestic Boost / Logs / AI Autopilot / Settings**); avoid internal jargon or CLI commands unless asked.
> 4. If offline, remind the user they can paste prompts into directly accessible Web AIs (**DeepSeek, Doubao, Qwen, Kimi**) first.

## 1. Zero-Node Cold Start: "CatCloud Is the Car, Subscriptions/Nodes Are the Fuel"
1. CatCloud does not bundle or sell proxy nodes; bring your own subscription URL, a friend's `.zip` Share Pack / node text, or migrate from an existing proxy app.
2. Go to **Nodes & Speed → Subs & Import** to add nodes.
3. Anytime you feel stuck, open **AI Autopilot** to copy a sanitized status prompt for Web AI or a local Agent.

## 2. Six Core Workflows
1. **Import, Migrate & `1→2→3` Live Capture (`Nodes & Speed → Subs & Import`)**: Paste subscription URLs (auto proxy-fallback on direct failure), paste configs/scan existing open-source clients read-only, or run the `1→2→3` live capture wizard (supports updating existing groups).
2. **Routing Selection (`Smart Groups` / `Overview`)**: Cross-provider pools, low-multiplier priority with automatic escalation, and sticky-best locking to prevent AI account lockouts; or single-node selection.
3. **Zero-Interference Speed Testing (`Nodes & Speed`)**: Isolated ephemeral sandbox core — Lite Test (latency, Google cleanliness, AI unlocks), Full Test (upload/download throughput), and 60s Keep-Alive without interrupting active sessions.
4. **Routing & Live Connections (`Rules & Conns`)**: Domestic direct routing, built-in AI domain split routing, domestic QUIC allow + overseas QUIC block, and live connection/rule inspection.
5. **Domestic Boost (`Domestic Boost`)**: Pure-IP TCP `:443` relay chain for upload-throttled campus/broadband networks (auto-skips native 443 nodes, supports single/all relay real upload/download speed testing, optional standalone global boost). Leave off if upload is already fast.
6. **Daily Controls, `.zip` Share Packs & Tray Memory Saver (`Overview`, `Logs`, `AI Autopilot`, `Settings`)**: System Proxy for browsers (no admin needed), **TUN Mode** for terminals/games, selective `.zip` Share Packs for friends, **Mini Capsule**, and closing the main window to destroy WebView2 (`<= 70 MB` background tray footprint).

## 3. Five-Step Mentor Progression
1. **State 1 (0 nodes)** → Explain car-vs-fuel; ask which source they have and guide only that 1 import path.
2. **State 2 (Nodes ready, proxy off)** → Back to **Overview**, turn on main switch + System Proxy, click **Quick Connectivity Check**.
3. **State 3 (Connected, optimizing for stability/AI)** → Run Lite Test in **Nodes & Speed**, then configure sticky selection in **Smart Groups**.
4. **State 4 (Slow upload or terminal/game bypass)** → Introduce **Domestic Boost** or **TUN Mode** as needed.
5. **State 5 (All basics working)** → Congratulate the user, then optionally suggest one next step: custom group formula, rule tweaks, friend `.zip` Share Pack, or closing to tray to save RAM.
"###;

const EN_DOC_02_PREACCEL: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 02 · Domestic Boost (TCP :443 Pre-Acceleration) Field Manual

> **For Local AI Agents**: If the user shares domestic VPS SSH access or relay parameters, ask confirmation and handle the entire workflow end-to-end (firewall check → run server script → import `mmrelay://v1/...` → run `preaccel test` + `config reload`).

## 1. When to Enable
- Non-443 proxy ports suffer 2-4 Mbps upload throttling or stalls while domestic TCP `:443` sustains 50-250+ Mbps (common on campus/broadband links). Keep disabled if upload is already fast.

## 2. Route A — Easy Setup (Friend Share or Raw Parameters)
- Paste a friend's `mmrelay://v1/...` URI or `mmrelay/v1` JSON in **Domestic Boost → + Add Relay**, or click **Import Share Pack** for their `.zip` bundle.
- CLI: `catcloud preaccel add --uri "mmrelay://v1/..." --json` or `catcloud preaccel add --file relay.mmrelay.json --json`.
- If you only have raw IP + port 443 + protocol + password, enter them manually (**keep `sni` strictly empty**, `skip_cert_verify: true`) or wrap them in `mmrelay/v1`:

```json
{
  "schema": "mmrelay/v1",
  "role": "domestic_pre_accel",
  "relays": [
    {
      "id": "relay-cn-east-1",
      "name": "CN-East-443 Primary",
      "provider": "cloud-light",
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
}
```

## 3. Route B — Self-Hosting a Domestic Pure-IP :443 Relay
1. **Pick a nearby domestic lightweight cloud server** with `>= 30 Mbps` peak bandwidth and sufficient monthly traffic (optionally 2 instances with `priority: 10` and `20` for active-standby failover).
2. **Open TCP `443` inbound** in the cloud provider's Firewall / Security Group; to co-host **AnyTLS (TCP 443) + Hysteria2 (UDP 443)** on the same relay (sharing the same pure-IP self-signed cert with zero port conflict), also allow **UDP `443`** inbound. `mmrelay/v1` `protocol` supports `anytls`, `hysteria2` (alias `hy2`), `trojan`, and `vless` (pure-IP `:443`, empty `sni`, `skip_cert_verify: true`; CatCloud compiles `hysteria2` with conservative `up: "100 Mbps"` / `down: "200 Mbps"` limits to prevent campus Brutal congestion jitter).
3. **Hard Compliance & Stability Rules**:
   - Keep `sni` (and VLESS `servername`) **strictly empty (`""`)** with a self-signed IP-SAN ECDSA certificate and `skip_cert_verify: true`; unfiled third-party SNIs on domestic `:443` are blocked by cloud gateways.
   - Keep health probes domestic (`http://connectivitycheck.platform.hicloud.com/generate_204` or `http://connect.rom.miui.com/generate_204`); overseas `gstatic` URLs are rejected.
4. **One-Shot Ubuntu/Debian Deployment Script (`anytls` default or `PROTO=trojan`, outputs `mmrelay://v1/...`)**:

```bash
#!/usr/bin/env bash
set -euo pipefail
PROTO="${PROTO:-anytls}"
RELAY_NAME="${RELAY_NAME:-CN-443-Primary}"
SERVER_IP="${SERVER_IP:-$(curl -4s --max-time 6 https://api.ipify.org || hostname -I | awk '{print $1}')}"
PASSWORD="${PASSWORD:-$(openssl rand -hex 16)}"
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\nnet.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216\nnet.ipv4.tcp_rmem = 4096 131072 16777216\nnet.ipv4.tcp_wmem = 4096 131072 16777216\nnet.core.netdev_max_backlog = 8192\nnet.ipv4.tcp_max_syn_backlog = 4096\nnet.core.somaxconn = 4096\nnet.ipv4.tcp_slow_start_after_idle = 0\nnet.ipv4.tcp_mtu_probing = 1\nnet.ipv4.tcp_notsent_lowat = 16384\n' >/etc/sysctl.d/99-catcloud-relay-tune.conf
sysctl -p /etc/sysctl.d/99-catcloud-relay-tune.conf >/dev/null || true
[ -n "${IFACE}" ] && tc qdisc replace dev "${IFACE}" root fq || true
apt-get update -qq && apt-get install -y -qq curl openssl jq python3 ca-certificates
command -v sing-box >/dev/null 2>&1 || curl -fsSL https://sing-box.app/install.sh | sh
mkdir -p /etc/catcloud-relay
openssl ecparam -name prime256v1 -genkey -noout -out /etc/catcloud-relay/key.pem
openssl req -new -x509 -days 3650 -key /etc/catcloud-relay/key.pem -out /etc/catcloud-relay/cert.pem \
  -subj "/CN=${SERVER_IP}" -addext "subjectAltName=IP:${SERVER_IP}"
chmod 600 /etc/catcloud-relay/key.pem
[ "${PROTO}" = "trojan" ] || PROTO="anytls"
jq -n --arg proto "${PROTO}" --arg pw "${PASSWORD}" '{
  log:{level:"warn"},
  inbounds:[{type:$proto,tag:"relay-in",listen:"::",listen_port:443,
    users:[{name:"catcloud",password:$pw}],
    tls:{enabled:true,certificate_path:"/etc/catcloud-relay/cert.pem",key_path:"/etc/catcloud-relay/key.pem"}}],
  outbounds:[{type:"direct",tag:"direct"}]
}' > /etc/catcloud-relay/config.json
printf '[Unit]\nDescription=CatCloud Relay\nAfter=network-online.target\n[Service]\nExecStart=/usr/bin/sing-box run -c /etc/catcloud-relay/config.json\nRestart=on-failure\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/catcloud-relay.service
systemctl daemon-reload && systemctl enable --now catcloud-relay.service
MMJSON=$(jq -nc --arg id "relay-$(date +%s)" --arg name "${RELAY_NAME}" --arg srv "${SERVER_IP}" --arg proto "${PROTO}" --arg pw "${PASSWORD}" '{schema:"mmrelay/v1",role:"domestic_pre_accel",relays:[{id:$id,name:$name,provider:"cloud-light",region:"CN",server:$srv,port:443,protocol:$proto,password:$pw,sni:"",skip_cert_verify:true,priority:10,enabled:true}]}')
echo "mmrelay://v1/$(printf '%s' "${MMJSON}" | python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')"
```

## 4. Verification, Real Relay Speed Testing, Standalone Global Boost & Rollback
- Keep **Auto-skip native 443 nodes** enabled so native 443 nodes stay direct.
- **Real Relay Upload/Download Speed Test**: In **Domestic Boost**, you can test real upload and download throughput for either a single relay or all relays (chained via a reference overseas node or direct).
- **Standalone Global Boost**: Even with CatCloud's main proxy off, enabling **Domestic Boost** can transparently accelerate other proxy cores or `ssh`/`scp` via signed WinDivert on Windows (auto-bypassing domestic port 80 and regular chat apps, with automatic SOCKS5 fallback if blocked by local firewall) or local SOCKS5 on macOS/Linux.
- **Performance Tuning Checklist (for Agents)**:
  - Always check `tc qdisc show dev <iface>` on Linux relays: `sysctl` `default_qdisc=fq` does NOT retroactively replace `pfifo_fast` on an already-booted NIC. Run `tc qdisc replace dev <iface> root fq` (zero-downtime) and persist it via systemd so BBR pacing actually engages.
  - Prefer `anytls` over legacy per-connection `trojan` (CatCloud defaults to `tfo: false` because AnyTLS is incompatible with TCP Fast Open, `min-idle-session: 0` to prevent stale NAT-closed idle sessions, `keep-alive-idle: 45`, adaptive `expected-status` probes, `consistent-hashing` stickiness, and TUN MTU `<= 1400` clamping); if domestic UDP 443 is open, co-hosting `hysteria2` on UDP 443 eliminates TCP-over-TCP congestion without conflicting with TCP 443.
  - Pair domestic `:443` relays with lightweight non-443 overseas nodes (e.g. `ss`) to avoid TLS-in-TLS overhead. With 2+ distinct physical cloud relays, `auto` / `load_balance` aggregates bandwidth via nested `load-balance` inside outer `fallback` (deduplicating same-host protocols); switch to `--dispatch-strategy fallback` if a backup VPS has weaker quality.
- **Secret Rotation & Revocation**: After private testing or sharing, rotate relay credentials cleanly via SSH stdin (auto backup + rollback script + fresh `mmrelay://v1/...`, preview with `--dry-run`):
  `node scripts/relay/rotate_relay_secrets.mjs --host <IP> --user root --key <KEY_PATH> --config /etc/catcloud-relay/config.json --service catcloud-relay --dry-run`
- CLI verification, strategy & rollback:
```bash
catcloud preaccel pool --json
catcloud preaccel test --json
catcloud preaccel test --speed --json
catcloud preaccel test --speed --node-id <id> --json
catcloud preaccel global-status --json
catcloud preaccel bind --dispatch-strategy auto --lb-strategy consistent_hashing --json
catcloud preaccel bind --enabled false --json && catcloud config reload --json
# Export Mihomo YAML for transparent gateway / soft-router (redacted by default; add --reveal-secrets to deploy)
catcloud config export-gateway --profile relay-fragment --reveal-secrets --output relay-fragment.yaml
catcloud config export-gateway --profile transparent-gateway --reveal-secrets --output gateway.yaml
catcloud config export-gateway --profile preferred-nodes --reveal-secrets --output preferred.yaml
```
"###;

const EN_DOC_03_MULTIGROUP: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 03 · Smart Groups & Safe Scoring Formula Guide

## 1. Selection Modes
- `sticky_best` (default): Locks onto the healthiest top-ranked node to avoid IP churn on AI/coding tools; switches only on sustained failure.
- `conditional_pool`: Dynamic membership by region, multiplier, protocol, and health gates.
- `load_balance_consistent_hash` / `load_balance_round_robin`: Controlled balancing after hard-gate filtering.

## 2. Beginner Scenario Formula Presets

| Scenario | Mode | Hard Gates | Safe AST Formula | Fallback & Switch |
|---|---|---|---|---|
| **AI Coding & Anti-Ban** | `sticky_best` | `google_clean == 1`, `keepalive_ok == 1` | `(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)` | `cross_pool_escalate` + `force_close_old` |
| **Low-Multiplier + Backup Escalation** | `conditional_pool` | `multiplier <= 1.0`, `google_clean == 1` | `(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08) / max(multiplier, 0.25)` | `cross_pool_escalate` (auto hysteresis return) |
| **Streaming & Downloads** | `sticky_best` | `ok == 1` | `down_mbps * 30 + up_mbps * 5 - ping_ms * 0.15 - jitter_ms * 0.2` | `degrade_best_warn` + `graceful_new_only` |
| **Max Raw Speed** | `sticky_best` | `google_clean == 1` | `up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1` | `degrade_best_warn` + `force_close_old` |

- Available scalars/functions (zero `eval`): `up_mbps`, `down_mbps`, `ping_ms`, `jitter_ms`, `loss_pct`, `multiplier`, `keepalive_ok`, `google_clean`, `unlocked`, `is_443_native`, `ok`, `min`, `max`, `clamp`, `if`, `abs`, `probe_up("id")`, `probe_down("id")`, `probe_ping("id")`, `probe_ok("id")`, `site_unlocked("name")`.

## 3. CLI Reference (`<group_id>` Is Positional)
```bash
catcloud group list --json
catcloud group create --id grp-ai --name "AI Sticky" --mode sticky_best --fallback cross_pool_escalate --switch-mode force_close_old --json
catcloud group members --id grp-ai add --nodes node_1,node_2 --json
catcloud group members --id grp-ai remove --nodes node_2 --json
catcloud group members --id grp-ai set --nodes node_1,node_3 --json
catcloud group eval grp-ai --json
catcloud group switch grp-ai --json
catcloud group switch grp-ai --node <node_id> --json
catcloud group policy grp-ai --formula "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08) / max(multiplier, 0.25)" --fallback degrade_best_warn --add-match-rule "DOMAIN-SUFFIX,openai.com" --json
```

## 4. Rollback & Troubleshooting
- If a group enters `circuit_open` (`REJECT`), run `catcloud group eval <group_id> --json` to inspect failing hard gates or switch fallback to `degrade_best_warn`.
- Set `switch_mode` to `force_close_old` when stale HTTP/2 streams stay pinned after switching.
"###;

const EN_DOC_04_NODES_PROBES: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 04 · Nodes, Subscriptions, Live Capture & 3-Tier Speed Testing

## 1. Zero-Interference 3-Tier Speed Testing (`Nodes & Speed`)
Tests execute in an ephemeral loopback-only sandbox core (no TUN, low memory cap, immediate teardown) with zero interruption to active traffic:
- **Lite Test (L1, recommended first)**: Minimal bandwidth; measures latency, Google region truth (hard gate), and AI service unlocks (Claude / ChatGPT / Gemini / Windsurf).
- **Full Test (L2)**: Measures upload (512 KB fast-cut) and download throughput for **Smart Groups** scoring.
- **60s Silent Keep-Alive**: Filters out nodes that answer pings yet blackhole idle streams after 20-60s.
- **Golden Nodes Fallback**: When throughput has not been measured yet, **Golden Nodes** gracefully rank by Clean Google + AI Unlock + lowest latency, with a one-click throughput top-up button.

## 2. Subscriptions, Migration, `1→2→3` Live Capture & Group Management (`Nodes & Speed → Subs & Import`)
- **Subscriptions**: Supports Clash/Mihomo YAML (`<= 16 MiB`), sing-box JSON, Base64/plain URIs, auto proxy-fallback refresh, and atomic zero-node/error protection.
- **Read-Only Migration & `1→2→3` Live Capture**: Never alters third-party files; capture confirmation supports renaming, filtering, and updating an existing group (**Keep Latest (Replace) / Merge & Deduplicate / Cancel Update**).
- **Rename & Merge Groups**: Inline group rename and transactional two-group merge preserving probe history and group references.
- **Open External Adapter (`catcloud-adapter/v1`)**: `stdin`/`stdout` JSON contract with `>= 60s` cooldown and zero-node protection.

## 3. CLI Reference (Sanitized by Default)
```bash
catcloud sub list --json
catcloud sub refresh <sub_id> --json
catcloud sub rename <id> --name <new_name> --json
catcloud sub merge --source <src_id> --target <dst_id> --json
catcloud sub remove <sub_id> --json
catcloud node list --region TW --max-multiplier 1.0 --json
catcloud node import --file sub.yaml --json
catcloud node migrate --scan --json
catcloud node attach-process --list --json
catcloud probe list --json
catcloud probe run --tier l1 --json
catcloud probe add --id custom_api --name "Custom API Upload" --kind upload --url https://example.com/up --json
catcloud probe remove --id custom_api --json
```

## 4. Live Capture Returned 0 Nodes: 4 High-Frequency Checks
When live capture from a dedicated third-party client under `Nodes & Speed → Subs & Import` (or `catcloud node attach-process`) returns empty results, check these 4 causes first:
1. **Updated subscription without clicking Connect**: Many dedicated clients only materialize their runtime config file or local controller when you actually toggle Connect/Start Proxy—click Connect once before capturing.
2. **Selected the UI shell process instead of the underlying proxy core**: Desktop apps often split into a frontend Electron/GUI shell and a child proxy core (`mihomo` / `sing-box` / `xray`); attach to the core process carrying config flags or listening on local ports.
3. **Cross-privilege block when the target client runs as Administrator**: On Windows, a standard-privilege CatCloud process cannot read full command lines or working directories of an elevated target process; match privilege levels (or run the target client without elevation) and retry.
4. **Fallback for double-encrypted closed clients**: If the vendor app encrypts both disk and memory payloads without exposing plaintext YAML or a standard controller API, stay connected with that app briefly, open your provider's web dashboard to copy the standard subscription URL, and import it directly in `Nodes & Speed → Subs & Import`.
"###;

const EN_DOC_05_ROUTING_CONNS: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 05 · Routing Rules, QUIC Policy & Live Connection Diagnostics

## 1. Proxy Modes & Split Routing (`Rules & Conns`)
- **Rule Mode (default)**: Domestic direct (`Country.mmdb` / `geosite.dat`), overseas via proxy, plus per-group independent routing when enabled in **Smart Groups**.
- **Global Mode**: Routes non-exempt traffic through proxy; returning from Global to Rule automatically checks and reclaims excess core memory safely.
- **Direct Mode**: Sends all traffic directly without overseas proxies.

## 2. Built-In AI Domains, Custom Rules & `rule-providers`
- Built-in AI routing covers OpenAI, ChatGPT, Anthropic, Claude, Google AI / Gemini / Antigravity, Windsurf, Codeium, Cursor, and GitHub Copilot.
- Add or bulk-paste custom prepend/append rules in **Rules & Conns** (`DOMAIN`, `DOMAIN-SUFFIX`, `IP-CIDR`, `RULE-SET`, `AND`/`OR`/`NOT`, `MATCH`; YAML `- `, quotes, and comments are stripped automatically).
- Enable **Pure Custom-Rules Mode (`custom_rules_only`)** to skip built-in domestic/QUIC/group/AI-DNS overrides while keeping anti-loop guards (user `MATCH` rules are respected verbatim), and paste `rule-providers:` / `rules:` / `dns:` YAML into **Inline YAML Override (`inline_override_yaml`, <= 1 MiB)**.

## 3. Dual-Layer QUIC (UDP 443) & Domestic IM Protection
- Domestic QUIC (`GEOSITE,cn` / `GEOIP,CN` and core domestic domains) is explicitly allowed **right before** overseas UDP 443 rejection, keeping QQ/WeChat/domestic media smooth while stabilizing overseas TCP streams.
- Core QQ/WeChat/Tencent domains are unconditionally included in `fake-ip-filter`.

## 4. Inspection Commands
```bash
catcloud net connections --json
catcloud net match chatgpt.com --json
catcloud net match qq.com --json
```
"###;

const EN_DOC_06_NETWORK_LIFECYCLE: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 06 · Network, Three-Level Hot Reload, Tray Memory Saver & Safe Updates

## 1. Network Stack (`Overview` & `Settings → Network & DNS`)
- **System Proxy & Proxy Guard**: Auto-configures OS proxy and defends against third-party hijacking; copy PowerShell/CMD/Bash/Fish env snippets from **Settings → General & Proxy**.
- **TUN Mode**: Full-machine routing (`mixed` / `system` / `gvisor`), split core/DNS IPv6, Fake-IP/Redir-Host DNS, and 4-item GeoData refresh (`Country.mmdb` / `geosite.dat` / `geoip.dat` / `GeoLite2-ASN.mmdb`) in **Settings → Network & DNS**.

## 2. Three-Level Zero-Downtime Hot Reload
- **L1 (REST API)**: Instant mode change, node switch, or connection close with zero disconnect.
- **L2 (Validated Hot Apply)**: Syntax, anti-loop, and core verification before applying; invalid configs are atomically rejected with zero traffic drop, and active group selections are replayed.
- **L3 (Core Lightweight Restart)**: Restarts only the forwarding core on port/TUN/binary changes with TCP+UDP port conflict auto-shift.

## 3. Windowless Tray Mode, Portable CLI & Safe Updates (`Settings → About & Updates`)
- Closing the main window destroys WebView2 (`<= 70 MB` background tray target) and rebuilds smoothly on click/hotkey.
- Portable `cli/catcloud(.exe)` detects `../portable.flag` automatically to share the same `data/` and bundled core without breaking desktop self-update checks.
- Background pre-download updater (`JuryBu/CatCloud`) enforces GitHub HTTPS `:443` allowlist + `latest.json` + `SHA256SUMS.txt` verification into `.update_staging/` (supporting both portable ZIP and platform installers), prompts on launch/ready to restart & apply, remind later, or skip version (purging the staged package), preserves `data/`, `portable.flag`, and databases, and rolls back atomically on error.

## 4. CLI Reference
```bash
catcloud config validate --json
catcloud config compile --json
catcloud config reload --json
catcloud config export-env --shell bash --json
catcloud config backup --output catcloud-backup.json --json
catcloud config restore --file catcloud-backup.json --json
catcloud update check --json
catcloud update check --offline --json
catcloud update stage --manifest latest.json --archive CatCloud-0.2.0-windows-x64-portable.zip --checksums SHA256SUMS.txt --json
catcloud docs export --lang en --sync-dir <dir> --json
```
"###;

const EN_DOC_07_SHARE_BUNDLE: &str = r###"> [LANGUAGE LOCK] Reply strictly in English throughout this conversation and use CatCloud's exact UI page/button names.

# 07 · Selective `.zip` Share Packs (`catcloud-share/v1`) & Secret Redline

## 1. Overview
Export selected nodes (by group/region) and/or domestic `:443` relays into one clean `.zip` (`manifest.json`, `nodes.yaml`, `relays.mmrelay.json`, `README.md`) for private sharing with friends.
- Automatically strips subscription source URLs, local file paths, controller secrets, logs, local `dialer-proxy` bindings, and relay probe caches.
- Safe import validates zip paths (anti Zip-Slip), rejects symlinks, and caps `<= 32` entries, `<= 4000` nodes, and `<= 16 MiB` uncompressed bytes.

## 2. GUI & CLI Usage
- **GUI Entry Points**: **Domestic Boost** (**Share Pack**), **Nodes & Speed** (multi-select bar), and **Nodes & Speed → Subs & Import** (**Import Share Pack** / **Export Share Pack**). Import offers sanitized preview, subset checkboxes, and **Save as New Group** vs **Update Existing Group** (**Keep Latest (Replace)** / **Merge & Deduplicate**).
- **CLI**:
```bash
catcloud share export --output friend-pack.zip --name "Friend Pack" --nodes node_1,node_2 --relays relay_1 --json
catcloud share inspect friend-pack.zip --json
catcloud share import --file friend-pack.zip --dry-run --json
catcloud share import --file friend-pack.zip --apply --json
```

## 3. Strict Security Redline
1. Share `.zip` files **privately only** — never upload to public repos, forums, or GitHub Issues.
2. **AI Agents MUST NEVER echo, print, or quote plaintext passwords, UUIDs, tokens, private keys, or unmasked relay IPs** from a share bundle; always inspect with `share inspect` or default sanitized preview (`--dry-run`).
"###;

// ============================================================================
// Localized JA & RU Guidance Headers + Exact UI Term Bindings
// ============================================================================

const JA_UI_GLOSSARY: &str = r###"> 【言語固定】以降の回答はすべて自然な日本語で行い、CatCloud の日本語 UI 名称を正確に使ってください。
> オフライン／プロキシ未接続時は、中国本土から直接利用できる Web AI（DeepSeek / Doubao / Qwen / Kimi）または接続後の ChatGPT / Claude / Gemini、ローカル CLI Agent にそのまま貼り付けて使えます。

### CatCloud 日本語 UI 名称対応表（案内時は必ずこの名称を使用）
| 画面 ID | 日本語 UI 名 | 主な用途 |
|---|---|---|
| `home` | 概要 | 電源スイッチ・システムプロキシ・仮想 NIC (TUN)・疎通確認 |
| `multigroup` | スマートグループ | 複数プロバイダ統合・粘着最適選択・安全スコア式 |
| `nodes` / `speedtest` | ノードと速度 | 購読インポート・1→2→3 捕捉・省通信/完全/60秒キープアライブ測定 |
| `routing` | ルールと接続 | 国内直接・AI ドメイン分流・QUIC 制御・リアルタイム接続確認 |
| `preaccel` | 国内高速化 | 純 IP TCP 443 中継・単体/全中継の実上下り速度テスト・グローバル高速化 |
| `logs` | 実行ログ | 脱敏済みログ閲覧・`GitHub で不具合報告` |
| `ai` | AI 自動設定 | Web AI 向けガイドコピー・ローカル Agent 起動プロンプト・`GitHub で Issue 作成` |
| `settings` | 設定 | `一般・プロキシ` / `外観と言語` / `ネットワーク・DNS` / `コアと保守` / `情報と更新` |
"###;

const RU_UI_GLOSSARY: &str = r###"> [ЯЗЫК ОТВЕТА] Отвечайте строго на русском языке и используйте точные названия разделов интерфейса CatCloud.
> Если доступ к зарубежным AI ещё не настроен, вставьте очищенный отчёт в доступные напрямую веб-AI (DeepSeek, Doubao, Qwen, Kimi) либо в локального CLI-агента.

### Точные названия разделов интерфейса CatCloud (RU)
| Раздел | Название в UI | Назначение |
|---|---|---|
| `home` | Обзор | Главный переключатель, Системный прокси, TUN-адаптер, проверка доступности |
| `multigroup` | Умные группы | Объединение провайдеров, липкий выбор (sticky), безопасные формулы |
| `nodes` / `speedtest` | Узлы и тест | Импорт подписок, захват 1→2→3, тест L1/L2 и 60s Keep-Alive |
| `routing` | Правила и сети | Прямой трафик CN, правила AI-доменов, QUIC, активные соединения |
| `preaccel` | Ускорение 443 | Чистый IP TCP 443, тест реальной скорости одного/всех релеев, глобальное ускорение |
| `logs` | Журнал | Очищенные логи, кнопка «Сообщить на GitHub» |
| `ai` | ИИ-автопилот | Промпты для веб-ИИ и локальных CLI-агентов, кнопка «Создать Issue на GitHub» |
| `settings` | Настройки | «Общие и прокси» / «Внешний вид и язык» / «Сеть и DNS» / «Ядро и утилиты» / «О программе» |
"###;

fn ja_chapter_intro(canonical_id: &str) -> &'static str {
    match canonical_id {
        TROUBLESHOOTING_DOC_ID => {
            "# 00 · ネットワーク総合トラブルシューティング（6 層診断 & GitHub Issue）\n\n\
             > ローカル `catcloud.exe` 探索（インストール版は PATH 未登録）：PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` ／ Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\n\
             物理回線・キャンパス認証 → 競合プロキシ/残留環境変数 → コア/仮想 NIC (TUN)（「設定 → ネットワーク・DNS」）→ ルールと接続/DNS/QUIC（`logs tail --since/--until`、DNS 証明書診断対応）→ 国内高速化 → 海外ノード/AI 解除の 6 層で順に切り分けます。解決しない場合は「AI 自動設定」（「GitHub で Issue 作成」）、「実行ログ」または「設定 → 情報と更新」（「GitHub で不具合報告」）から `JuryBu/CatCloud` へ脱敏済み Issue を送信してください（秘密情報・生 IP は絶対に含めないこと）。"
        }
        ONBOARDING_DOC_ID => {
            "# 01 · 初心者向けオンボーディング総綱（AI メンター用）\n\n\
             「CatCloud は車、購読/ノードは燃料」を前提に、現在の状態スナップショットから毎回 1 ステップだけ案内してください。6 大機能（ノードと速度・スマートグループ・3 段階速度テスト・ルールと接続・国内高速化・共有パック `.zip` とトレイ省メモリ）と 5 段階の進行（状態 5：基本疎通完了を含む）を網羅します。"
        }
        PREACCEL_DOC_ID => {
            "# 02 · 国内高速化（TCP 443 純 IP 中継）実践マニュアル\n\n\
             非 443 ポートの上り制限を突破するため、① 友人共有（`mmrelay://v1/...` / `.zip` 共有パック / 手動入力）と ② 自前構築（国内軽量 VPS・ファイアウォール TCP 443 開放・SNI 厳格空欄・AnyTLS/Trojan ワンショット導入スクリプト）、複数物理クラウド自動均衡（`preaccel bind --dispatch-strategy auto|load_balance|fallback --lb-strategy consistent_hashing|round_robin`）、鍵ローテーション（`scripts/relay/rotate_relay_secrets.mjs`）、単体/全中継の実上下り速度テスト（`catcloud preaccel test --speed [--node-id <id>]`）、透明ゲートウェイ / ソフトルーター向け Mihomo YAML 出力（`catcloud config export-gateway --profile relay-fragment|transparent-gateway|preferred-nodes`）、およびグローバル高速化・`catcloud preaccel global-status --json` 検証手順を提供します。ローカル Agent はユーザー同意後に全工程を代行してください。"
        }
        MULTIGROUP_DOC_ID => {
            "# 03 · スマートグループ & 安全スコア式ガイド\n\n\
             AI コーディング向け粘着ロック（IP 変動防止）、低倍率優先＋高倍率フェイルオーバー、動画向けプリセット式と、`catcloud group create / members --id <id> <add|remove|set> --nodes <csv> / eval / switch <group_id> / policy` の正確なコマンド契約を定義します。"
        }
        NODES_PROBES_DOC_ID => {
            "# 04 · ノードと速度・購読・1→2→3 捕捉 & 3 段階速度テスト\n\n\
             省通信 L1・完全 L2・60 秒キープアライブの 3 段階分離テスト、既存グループ更新/名前変更/統合マージ、`sub list/refresh/rename/merge/remove`、`probe add --name` 必須引数を解説します。\n\n\
             ## 専用クライアントのリアルタイム捕捉が空になる場合の 4 つの頻出確認点\n\
             1. **購読更新のみで「接続」を押していない**：多くの専用クライアントは実際に接続開始するまで実行時設定をディスクへ書き出しません。一度接続してから捕捉してください。\n\
             2. **フロントエンド UI プロセスではなく基盤プロキシコアを選択する**：デスクトップアプリは GUI 外殻プロセスと基盤コア（`mihomo` / `sing-box` / `xray`）が分離しているため、設定引数を持つコア側を選んでください。\n\
             3. **管理者権限で起動された対象クライアントによるクロス権限制限**：通常権限の CatCloud は昇格済みプロセスのコマンドラインを読み取れません。権限レベルを揃えて再試行してください。\n\
             4. **二重暗号化クライアント時のフォールバック経路**：平文設定や標準コントローラを公開しない専用アプリの場合は、元のソフトで接続したまま公式サイトのマイページを開き、標準購読リンクをコピーして「ノードと速度 → 購読とインポート」へ直接取り込んでください。"
        }
        ROUTING_CONNS_DOC_ID => {
            "# 05 · ルールと接続・QUIC 制御 & リアルタイム接続診断\n\n\
             国内直接、内蔵 AI ドメイン分流、国内 QUIC 優先許可＋海外 QUIC ブロック、`fake-ip-filter` 保護、純自記ルールモード（`custom_rules_only`：内蔵国内直結/QUIC/AI DNS 上書きを無効化しつつ防環・LAN 安全基盤を保持）、一括ルール貼付とインライン YAML 上書き（`inline_override_yaml`、上限 1 MiB、`rule-providers:` / `rules:` / `dns:` 記述対応）、および `catcloud net connections` / `net match` の使い方を解説します。"
        }
        NETWORK_LIFECYCLE_DOC_ID => {
            "# 06 · ネットワーク・DNS・3 段階ホットリロード・省メモリ & 自動更新\n\n\
             システムプロキシ/Proxy Guard/仮想 NIC (TUN)/「設定 → ネットワーク・DNS」、L1〜L3 無断線リロード、ウィンドウ破棄トレイ省メモリ（`<= 70 MB`）、`config backup/restore`、`docs export --lang <lang> --sync-dir <dir>`、「設定 → 情報と更新」と `update stage --manifest --archive --checksums` を解説します。"
        }
        _ => {
            "# 07 · 選択式 `.zip` 共有パック（`catcloud-share/v1`）と秘密保持ルール\n\n\
             選択したノードや国内中継だけをプライバシー除去済み `.zip` にまとめて友人へ共有し、GUI（「共有パック出力」/「共有パック取込」）または `catcloud share export/inspect/import` で安全に取り込めます。平文パスワード・UUID・未マスク IP をチャットや公開場に絶対出力しないでください。"
        }
    }
}

fn ru_chapter_intro(canonical_id: &str) -> &'static str {
    match canonical_id {
        TROUBLESHOOTING_DOC_ID => {
            "# 00 · Универсальная 6-уровневая диагностика сети и GitHub Issue\n\n\
             > Поиск локального `catcloud.exe` (установленная сборка не в PATH): PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` | Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\n\
             Последовательно проверьте 6 слоёв: физическая сеть/портал → конфликтующие прокси/переменные → ядро/TUN-адаптер («Настройки → Сеть и DNS») → Правила и сети/DNS/QUIC (`logs tail --since/--until`, диагностика TLS DNS) → Ускорение 443 → зарубежные узлы/AI. Если проблема осталась, откройте форму Issue в `JuryBu/CatCloud` через «ИИ-автопилот» («Создать Issue на GitHub»), «Журнал» или «Настройки → О программе» («Сообщить на GitHub») — только очищенные данные без секретов."
        }
        ONBOARDING_DOC_ID => {
            "# 01 · Руководство для новичков (для AI-наставника)\n\n\
             Объясняйте по одному простому шагу с опорой на снимок состояния («CatCloud — автомобиль, подписки/узлы — топливо»). Охватывает 6 ключевых сценариев («Узлы и тест», «Умные группы», «Правила и сети», «Ускорение 443», «Пакет обмена» и трей) и 5 этапов прогресса, включая состояние 5 (базовая сеть полностью работает)."
        }
        PREACCEL_DOC_ID => {
            "# 02 · Практическое руководство по «Ускорение 443» (TCP :443 без SNI)\n\n\
             Включает простой путь (`mmrelay://v1/...`, «Пакет обмена» `.zip`, ручной ввод), самостоятельное развёртывание на сервере (открытие TCP 443 в фаерволе, строго пустой SNI, готовый bash-скрипт AnyTLS/Trojan с выводом `mmrelay://v1/...`), мульти-облачную балансировку (`preaccel bind --dispatch-strategy auto|load_balance|fallback --lb-strategy consistent_hashing|round_robin`), ротацию секретов (`scripts/relay/rotate_relay_secrets.mjs`), тест реальной скорости аплоада/даунлоада одного или всех релеев (`catcloud preaccel test --speed [--node-id <id>]`), экспорт Mihomo YAML для прозрачного шлюза и роутеров (`catcloud config export-gateway --profile relay-fragment|transparent-gateway|preferred-nodes`), глобальное ускорение и проверку `catcloud preaccel global-status --json`. Локальный агент должен выполнять шаги целиком после согласия пользователя."
        }
        MULTIGROUP_DOC_ID => {
            "# 03 · «Умные группы» и безопасные формулы оценки\n\n\
             Готовые формулы для AI-кодинга (липкий выбор без скачков IP), экономии трафика с резервным пулом и стриминга, а также точные команды `catcloud group create / members --id <id> <add|remove|set> --nodes <csv> / eval / switch <group_id> / policy`."
        }
        NODES_PROBES_DOC_ID => {
            "# 04 · «Узлы и тест», подписки, захват 1→2→3 и 3-уровневый тест скорости\n\n\
             Изолированные тесты L1/L2/60s Keep-Alive, обновление/переименование/слияние групп подписок, `sub list/refresh/rename/merge/remove` и обязательный параметр `--name` у `probe add`.\n\n\
             ## 4 частые причины пустого захвата (0 узлов) из стороннего клиента\n\
             1. **Нажали только «Обновить подписку», но не «Подключиться»**: многие клиенты записывают рабочий конфиг на диск или открывают локальный контроллер только после фактического подключения — сначала нажмите подключение.\n\
             2. **Выбрана оболочка GUI вместо процесса ядра прокси**: настольные клиенты часто разделены на фронтенд-оболочку и дочернее ядро (`mihomo` / `sing-box` / `xray`) — выбирайте именно процесс ядра с параметрами конфигурации.\n\
             3. **Целевой клиент запущен от имени администратора**: при обычных правах Windows ограничивает чтение командной строки и каталога повышенного процесса — уравняйте права и повторите попытку.\n\
             4. **Резервный путь для клиентов с двойным шифрованием**: если приложение шифрует конфиг без открытого YAML и стандартного контроллера, оставайтесь в сети через него, откройте личный кабинет провайдера на сайте, скопируйте обычную ссылку подписки и импортируйте её в «Узлы и тест → Подписки и импорт»."
        }
        ROUTING_CONNS_DOC_ID => {
            "# 05 · «Правила и сети», политика QUIC и диагностика соединений\n\n\
             Прямой CN-трафик, встроенные AI-домены, разрешение локального QUIC перед блокировкой зарубежного UDP 443, защита `fake-ip-filter`, режим чистых пользовательских правил (`custom_rules_only` с сохранением защиты от петель и локальных сетей), массовая вставка правил и встроенное YAML-переопределение (`inline_override_yaml`, до 1 MiB, поддержка `rule-providers:` / `rules:` / `dns:`), а также `catcloud net connections` и `net match`."
        }
        NETWORK_LIFECYCLE_DOC_ID => {
            "# 06 · «Сеть и DNS», 3-уровневая горячая перезагрузка, экономия ОЗУ и обновления\n\n\
             Системный прокси, Proxy Guard, TUN-адаптер, «Настройки → Сеть и DNS», уровни L1–L3, режим без окна в трее (`<= 70 MB`), `config backup/restore`, `docs export --lang <lang> --sync-dir <dir>` и «Настройки → О программе» (`update stage --manifest --archive --checksums`)."
        }
        _ => {
            "# 07 · Выборочный «Пакет обмена» `.zip` (`catcloud-share/v1`) и правила безопасности\n\n\
             Упаковка выбранных узлов и релеев без личных ссылок/путей, импорт в 1 клик через GUI («Экспорт пакета» / «Импорт пакета») или `catcloud share export/inspect/import`. AI-агентам строго запрещено повторять открытые пароли, UUID, токены и немаскированные IP."
        }
    }
}

fn zh_markdown_for_canonical(canonical_id: &str) -> &'static str {
    match canonical_id {
        TROUBLESHOOTING_DOC_ID => ZH_DOC_00_TROUBLESHOOTING,
        ONBOARDING_DOC_ID => ZH_DOC_01_ONBOARDING,
        PREACCEL_DOC_ID => ZH_DOC_02_PREACCEL,
        MULTIGROUP_DOC_ID => ZH_DOC_03_MULTIGROUP,
        NODES_PROBES_DOC_ID => ZH_DOC_04_NODES_PROBES,
        ROUTING_CONNS_DOC_ID => ZH_DOC_05_ROUTING_CONNS,
        NETWORK_LIFECYCLE_DOC_ID => ZH_DOC_06_NETWORK_LIFECYCLE,
        _ => ZH_DOC_07_SHARE_BUNDLE,
    }
}

fn en_markdown_for_canonical(canonical_id: &str) -> &'static str {
    match canonical_id {
        TROUBLESHOOTING_DOC_ID => EN_DOC_00_TROUBLESHOOTING,
        ONBOARDING_DOC_ID => EN_DOC_01_ONBOARDING,
        PREACCEL_DOC_ID => EN_DOC_02_PREACCEL,
        MULTIGROUP_DOC_ID => EN_DOC_03_MULTIGROUP,
        NODES_PROBES_DOC_ID => EN_DOC_04_NODES_PROBES,
        ROUTING_CONNS_DOC_ID => EN_DOC_05_ROUTING_CONNS,
        NETWORK_LIFECYCLE_DOC_ID => EN_DOC_06_NETWORK_LIFECYCLE,
        _ => EN_DOC_07_SHARE_BUNDLE,
    }
}

fn strip_leading_lock_line(md: &str) -> &str {
    if let Some((_, rest)) = md.split_once("\n\n") {
        if md.starts_with("> [LANGUAGE LOCK]") || md.starts_with("> 【") {
            return rest;
        }
    }
    md
}

fn render_doc_markdown_for_lang(canonical_id: &str, lang: &str) -> String {
    match normalize_doc_lang(Some(lang)) {
        "zh-CN" => zh_markdown_for_canonical(canonical_id).to_string(),
        "en" => en_markdown_for_canonical(canonical_id).to_string(),
        "ja" => format!(
            "{}\n\n{}\n\n---\n\n## 詳細技術リファレンス（English Reference — 必ず日本語で噛み砕いて説明してください）\n\n{}",
            JA_UI_GLOSSARY.trim(),
            ja_chapter_intro(canonical_id),
            strip_leading_lock_line(en_markdown_for_canonical(canonical_id))
        ),
        _ => format!(
            "{}\n\n{}\n\n---\n\n## Подробный технический справочник (English Reference — объясняйте пользователю строго на русском)\n\n{}",
            RU_UI_GLOSSARY.trim(),
            ru_chapter_intro(canonical_id),
            strip_leading_lock_line(en_markdown_for_canonical(canonical_id))
        ),
    }
}

/// Return the authoritative pure-Chinese beginner AI onboarding guide.
pub fn render_zh_onboarding_guide() -> &'static str {
    ZH_DOC_01_ONBOARDING
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
    /// Render a structured four-section Markdown guide.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# CatCloud Agent Guide: {} (`{}`)\n\n",
            self.title, self.module_id
        ));
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

fn svec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn build_zh_docs() -> Vec<AgentModuleDoc> {
    vec![
        AgentModuleDoc {
            module_id: TROUBLESHOOTING_DOC_ID.into(),
            title: "通用网络疑难杂症 6 层排障总纲".into(),
            summary: "从物理网/校园网、冲突代理服务、核心/TUN、分流/DNS/QUIC、国内提速到海外节点的 6 层排障法，附听诊 CLI 与 JuryBu/CatCloud 脱敏 Issue 反馈模板。".into(),
            when_to_use_and_signals: svec(&[
                "网页打不开、终端/开发工具连不上外网、国内网站变慢或启动报端口/权限异常时。",
                "排查后仍未解决，需要生成脱敏诊断并向 GitHub 仓库 JuryBu/CatCloud 反馈 Issue 时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "未翻墙前即可直接把脱敏诊断发给 DeepSeek、豆包、通义千问、Kimi 等国内直连网页 AI。",
                "所有只读听诊 CLI 默认自动掩码密码、UUID、Token、本机路径与公私网 IP 末段。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：打开「AI 全权代管」「运行日志」或「设置 → 关于与更新」，点击「反馈问题到 GitHub」或复制脱敏摘要。",
                "CLI：`catcloud net doctor --json`、`catcloud net connections --json`、`catcloud net match <domain> --json`、`catcloud logs tail --lines 80 --since 30m --json`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "优先按 1→6 层定位：先查物理网/校园网认证与冲突代理软件，再查核心/TUN（「设置 → 网络与 DNS」）、分流、国内提速与海外节点。",
                "紧急恢复直连：在「总览」关闭代理开关，或执行 `catcloud preaccel bind --enabled false --json && catcloud config reload --json`。",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: ONBOARDING_DOC_ID.into(),
            title: "新手全中文上手总纲（给 AI 导师）".into(),
            summary: "覆盖 0 节点「猫云是车、订阅是油」三要素、6 大核心玩法与 5 步渐进引导节奏（含基础已全通进阶引导），确保 AI 每次只教下一小步。".into(),
            when_to_use_and_signals: svec(&[
                "首次安装或 0 节点冷启动，不知道如何导入节点、测速、建智能多选组或开关代理时。",
                "准备在「AI 全权代管」页复制状态发给 DeepSeek / 豆包等网页 AI 手把手带路时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "只需准备至少一份订阅链接、朋友的 .zip 分享包 / 配置文本，或电脑上已有代理软件即可开始。",
                "严禁向新手倾倒底层源码或未要求的命令行；严格使用真实中文界面名指路。",
            ]),
            gui_and_cli_verification: svec(&[
                "导入与测速：「节点与测速 → 订阅与导入」导入/捕捉节点，并在「节点与测速」跑省流快测或完整测速。",
                "选路与分流：「智能多选组」配粘性优选，「分流与连接」查规则与实时连接，「国内提速」按需破上传限速，「总览」一键开关与悬浮小窗。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "浏览器正常但终端/游戏不通：在「总览」开启「虚拟网卡（TUN 模式）」，随时可一键关闭。",
                "点击「AI 全权代管」即可一键复制脱敏诊断或点击「反馈问题到 GitHub」。",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: PREACCEL_DOC_ID.into(),
            title: "国内提速实战手册（纯 IP 443 中转与全局提速）".into(),
            summary: "包含省事路线（mmrelay/v1、分享包、零散参数拼装）、自建路线（买机、安全组放 443、SNI 留空红线、一键部署脚本直出 mmrelay://v1）、单条/全部中转真实上下行测速及全局提速验收。".into(),
            when_to_use_and_signals: svec(&[
                "非 443 代理端口单流上传被限速到 2～4 Mbps，而国内 TCP 443 链路可达 50～250+ Mbps。",
                "AI 传图、推代码或校园网高位端口频繁卡顿断流时；日常上传已很快则保持关闭。",
            ]),
            external_prereqs_and_schema: svec(&[
                "国内轻量云服务器放行安全组入站 TCP 443（并挂 Hysteria2 需同时放行 UDP 443），监听 AnyTLS / Hysteria2 / Trojan / VLESS 并使用纯 IP 自签 ECDSA 证书。",
                "硬红线：sni / servername 严格留空（\"\"）+ skip_cert_verify: true；健康探针必须保持国内 204（hicloud.com / miui.com）。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「国内提速 → + 添加中转」导入 mmrelay://v1 或 JSON，确认开启「自动跳过原生 443 节点」，并可一键执行单条/全部中转真实上下行测速。",
                "CLI：`catcloud preaccel add --uri ... --json`、`catcloud preaccel pool --json`、`catcloud preaccel bind --dispatch-strategy auto --lb-strategy consistent_hashing --json`、`catcloud preaccel test --speed [--node-id <id>] --json`、`catcloud preaccel global-status --json`、`catcloud config export-gateway --profile relay-fragment|transparent-gateway|preferred-nodes --json`；轮换回收密钥用 `scripts/relay/rotate_relay_secrets.mjs`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "一键关闭：「国内提速」关总开关或执行 `catcloud preaccel bind --enabled false --json && catcloud config reload --json`。",
                "若开启全局提速后被安全软件拦截，系统会自动卸载底层拦截并优雅降级至本地 SOCKS5 防断网。",
            ]),
            contract_example: r#"{"schema":"mmrelay/v1","role":"domestic_pre_accel","relays":[{"id":"relay-cn-east-1","name":"华东 443 主线","provider":"国内轻量云","region":"华东","server":"203.0.113.10","port":443,"protocol":"anytls","password":"<YOUR_GENERATED_SECRET>","sni":"","skip_cert_verify":true,"priority":10,"expires_at":"2027-08-12","enabled":true}]}"#.into(),
        },
        AgentModuleDoc {
            module_id: MULTIGROUP_DOC_ID.into(),
            title: "智能多选组与安全评分公式".into(),
            summary: "支持跨服务商混池、粘性优选防 AI 封号、低倍率优先+高倍率跨池兜底与安全无 eval 评分公式，附小白场景公式表与精确 CLI 参数。".into(),
            when_to_use_and_signals: svec(&[
                "AI 网页与编程工具因 IP 频繁轮换触发风控、掉登录或误走地区受限节点时。",
                "需要平时优先省流低倍率节点、异常时自动借道高倍率备池并在恢复后自动回切时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "节点库至少有 2 个启用节点，建议先在「节点与测速」跑过省流快测或完整测速。",
                "支持 sticky_best / conditional_pool / load_balance_*，兜底策略支持 degrade_best_warn / cross_pool_escalate / strict_circuit_break。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「智能多选组」配置成员、硬门禁（如 google_clean == 1）、安全评分公式与切换模式。",
                "CLI：`catcloud group list --json`、`catcloud group create --id grp-ai --name AI --mode sticky_best --json`、`catcloud group members --id grp-ai add|remove|set --nodes <csv> --json`、`catcloud group eval <group_id> --json`、`catcloud group switch <group_id> --json`、`catcloud group policy <group_id> --formula \"...\" --match-rules \"...\" --json`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "组触发熔断（REJECT）时，用 `catcloud group eval <group_id> --json` 排查硬门禁或将兜底改回 degrade_best_warn。",
                "切点后旧连接仍卡住时，把切换模式设为 force_close_old 主动断开旧流。",
            ]),
            contract_example: r#"{"id":"grp-ai-core","name":"AI 稳定组","mode":"sticky_best","hard_gates":["google_clean == 1","keepalive_ok == 1"],"formula_expr":"(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)","fallback_policy":"cross_pool_escalate","switch_mode":"force_close_old"}"#.into(),
        },
        AgentModuleDoc {
            module_id: NODES_PROBES_DOC_ID.into(),
            title: "节点管理、订阅捕捉与三档零干扰测速".into(),
            summary: "整合订阅导入、只读搬家、1→2→3 实时捕捉、订阅组更新/改名/整合合并、开放适配器，以及省流/完整/60s 保活三档沙箱测速。".into(),
            when_to_use_and_signals: svec(&[
                "汇总多家订阅、搬家本地开源软件、从运行中软件捕捉节点或合并整理多个订阅组时。",
                "排查「能 ping 通但传图极慢、谷歌送中或 20 秒静默卡死」的假活节点时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "支持 Clash/Mihomo YAML（<= 16 MiB）、sing-box JSON、Base64/明文 URI 及 catcloud-adapter/v1 外部脚本（>= 60s 冷却）。",
                "临时沙箱测速核仅监听 127.0.0.1、无 TUN、测完即销毁；无上下行数据时黄金节点自动按未送中+AI 解锁+延迟降级排序。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「节点与测速」跑省流/完整/60s 保活测速；「节点与测速 → 订阅与导入」导入订阅、1→2→3 捕捉、改组名或双组合并。",
                "CLI：`catcloud sub list|refresh|remove`、`catcloud sub rename <id> --name <new_name> --json`、`catcloud sub merge --source <src_id> --target <dst_id> --json`、`catcloud node list|import|migrate|attach-process`、`catcloud probe list|run --tier l1`、`catcloud probe add --id custom_api --name \"Custom API\" --kind upload --url https://example.com/up --json`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "订阅拉取异常或解析出 0 节点时原子拒载，原节点与分组保持不变；1→2→3 捕捉更新已有组支持保留最新、整合去重或取消。",
                "专用客户端实时捕捉为空时重点排查：① 是否仅更新订阅未点击连接；② 是否误选前端外壳而非底层代理内核进程；③ 目标客户端是否以管理员权限运行致跨权读取受限；④ 双层加密客户端可借原软件联网去官网复制订阅链接导入。",
                "要清理某个订阅来源，直接在「订阅与导入」删除对应组或运行 `catcloud sub remove <sub_id> --json`。",
            ]),
            contract_example: r#"{"schema":"catcloud-adapter/v1","nodes":[{"name":"Example-SG-01 1x","type":"trojan","server":"198.51.100.20","port":443,"password":"<PLACEHOLDER>"}]}"#.into(),
        },
        AgentModuleDoc {
            module_id: ROUTING_CONNS_DOC_ID.into(),
            title: "分流规则、QUIC 策略与实时连接排查".into(),
            summary: "覆盖规则/全局/直连模式、国内直连、AI 域独立分流、国内 QUIC 放行 + 海外 QUIC 拦截、QQ/微信防 Fake-IP 兜底与实时连接听诊。".into(),
            when_to_use_and_signals: svec(&[
                "想确认某个网站到底走了国内直连还是海外节点、为什么 QQ/微信卡顿，或为 AI 工具单独分流时。",
                "需要自定义前置/后置分流规则或实时踢断异常长连接时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "国内直连依赖 Country.mmdb（及可选 geosite.dat），可在「设置 → 网络与 DNS」一键更新地区数据库。",
                "国内 QUIC 放行自动位于海外 UDP 443 拦截规则紧前面；腾讯/QQ/微信核心域自动加入 fake-ip-filter。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「分流与连接」查看实时活跃连接、命中规则与开关国内直连/QUIC 策略。",
                "CLI：`catcloud net connections --json`、`catcloud net match <domain> --json`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "误配自定义规则导致某站不通时，用 `catcloud net match <domain> --json` 核查命中条目并移除错误前置规则后重载。",
                "从全局模式切回规则模式后，若内核内存偏高系统会自动安全回收多余内存。",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: NETWORK_LIFECYCLE_DOC_ID.into(),
            title: "网络设置、三级热加载、省内存与安全更新".into(),
            summary: "涵盖系统代理、Proxy Guard、TUN、高级 DNS、L1/L2/L3 零断流热载、无窗托盘省内存（<= 70 MB）、便携 CLI 与 JuryBu/CatCloud 后台预下载安全更新。".into(),
            when_to_use_and_signals: svec(&[
                "外部工具或 AI Agent 编辑配置后需要预检与零断流热载，或配置备份恢复、终端环境变量导出时。",
                "希望长期低内存后台常驻，或从 GitHub Releases 检查与校验暂存新版本时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "更新器仅放行 GitHub 官方域名 HTTPS 443，强制校验 latest.json 与 SHA256SUMS.txt，绝不动 data/、portable.flag 与数据库。",
                "便携版 cli/catcloud(.exe) 自动向上识别 ../portable.flag 共享 data/ 与随包内核。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「设置 → 网络与 DNS」调整端口/DNS/GeoData、「设置 → 关于与更新」检查更新与反馈问题；关窗自动进托盘释放界面内存。",
                "CLI：`catcloud config validate|reload|compile|backup|restore|export-env|diag --json`、`catcloud update check --json`、`catcloud update stage --manifest latest.json --archive <zip> --checksums SHA256SUMS.txt --json`、`catcloud docs export --lang <lang> --sync-dir <dir>`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "配置异常时先运行 `catcloud config validate --json`，必要时用 `catcloud config restore --file <backup.json> --json` 回滚。",
                "更新换轨遇任意错误会自动从备份目录完整回滚并保持用户数据完好。",
            ]),
            contract_example: r#"{"repo":"JuryBu/CatCloud","mode":"next_launch","preserved_paths":["data/","portable.flag","*.sqlite*"]}"#.into(),
        },
        AgentModuleDoc {
            module_id: SHARE_BUNDLE_DOC_ID.into(),
            title: "朋友间可勾选 .zip 分享包与密钥红线".into(),
            summary: "支持按组/地区勾选节点与国内提速中转打成一个干净的 catcloud-share/v1 .zip 包，自动剥离隐私并支持一键预览导入，附严禁 AI 复述明文密钥红线。".into(),
            when_to_use_and_signals: svec(&[
                "想把自己测好的若干节点或自建 443 中转轻松分享给朋友，又不想暴露整条订阅链接或本机配置时。",
                "收到朋友发来的猫猫云梯 .zip 分享包，想先安全预览再勾选导入时。",
            ]),
            external_prereqs_and_schema: svec(&[
                "包结构 catcloud-share/v1：manifest.json + nodes.yaml + relays.mmrelay.json + README.md；导入严格防路径穿越、拒符号链接、<= 32 文件、<= 4000 节点、<= 16 MiB 解压上限。",
                "安全红线：仅限私对私发送；AI Agent 严禁在对话、日志或 Issue 中复述或打印明文密码、UUID、Token、私钥或未脱敏中转 IP。",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI：「国内提速」「节点与测速」「节点与测速 → 订阅与导入」三处均提供轻量分享包导入/导出入口。",
                "CLI：`catcloud share export --output friend.zip --name \"朋友分享包\" --nodes <ids> --relays <ids> --json`、`catcloud share inspect <file.zip> --json`、`catcloud share import --file friend.zip --dry-run --json`、`catcloud share import --file friend.zip --apply --json`。",
            ]),
            rollback_and_troubleshooting: svec(&[
                "导入前务必先走默认脱敏预览（GUI 预览弹窗、`share inspect` 或 `--dry-run`），再决定新增订阅组或更新已有组。",
                "如误分享给非预期人员，请立即在原中转机或订阅后台轮换密码/重置订阅链接。",
            ]),
            contract_example: r#"{"schema":"catcloud-share/v1","files":["manifest.json","nodes.yaml","relays.mmrelay.json","README.md"]}"#.into(),
        },
    ]
}

fn build_en_docs() -> Vec<AgentModuleDoc> {
    vec![
        AgentModuleDoc {
            module_id: TROUBLESHOOTING_DOC_ID.into(),
            title: "General Network Troubleshooting (6-Layer Guide)".into(),
            summary: "Six-layer diagnostic workflow from physical/campus network and proxy conflicts up to nodes/AI unlock, with read-only stethoscope CLI and sanitized JuryBu/CatCloud Issue template.".into(),
            when_to_use_and_signals: svec(&[
                "Websites fail to load, terminals/IDEs bypass proxy, domestic apps lag, or startup reports port/permission errors.",
                "Issue persists after local checks and needs a sanitized report for GitHub repo JuryBu/CatCloud.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Before proxy access works, paste sanitized summaries into directly reachable Web AIs (DeepSeek, Doubao, Qwen, Kimi) or run a local Agent.",
                "All read-only stethoscope commands sanitize secrets, paths, and non-allowlist IPs by default.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: Open 'AI Autopilot', 'Logs', or 'Settings -> About & Updates' and click 'Report Issue on GitHub' or copy sanitized diagnostics.",
                "CLI: `catcloud net doctor --json`, `catcloud net connections --json`, `catcloud net match <domain> --json`, `catcloud logs tail --lines 80 --since 30m --json`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Check bottom-up: Layer 1 physical/portal -> Layer 2 conflicting proxies -> Layer 3 core/TUN ('Settings -> Network & DNS') -> Layer 4 routing/DNS/QUIC -> Layer 5 Domestic Boost -> Layer 6 nodes/AI unlock.",
                "Quick recovery: switch proxy off in 'Overview' or run `catcloud preaccel bind --enabled false --json && catcloud config reload --json`.",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: ONBOARDING_DOC_ID.into(),
            title: "Beginner Onboarding Guide (For AI Mentors)".into(),
            summary: "Car-vs-fuel zero-node cold start, all 6 core workflows, exact UI names, and 5-step mentor pacing (including State 5 all-working next steps).".into(),
            when_to_use_and_signals: svec(&[
                "First launch or 0-node cold start needing plain-language, one-step-at-a-time AI mentoring.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Bring at least one subscription URL, friend .zip Share Pack / config text, or existing proxy client.",
                "Teach one small UI action per turn; never dump walls of text or unrequested CLI commands.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: 'Nodes & Speed -> Subs & Import' -> 'Overview' switch -> 'Nodes & Speed' Lite Test -> 'Smart Groups' -> 'Rules & Conns'.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Enable 'TUN Mode' on 'Overview' if terminals/games do not follow System Proxy.",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: PREACCEL_DOC_ID.into(),
            title: "Domestic Boost (TCP :443 Pure-IP Pre-Acceleration)".into(),
            summary: "Easy friend import, self-hosted domestic VPS guide with TCP 443 firewall & empty-SNI rules, one-shot AnyTLS/Trojan deployment script emitting mmrelay://v1, single/all relay real upload/download speed tests, and standalone global boost.".into(),
            when_to_use_and_signals: svec(&[
                "Non-443 upload throttled around 2-4 Mbps while domestic TCP :443 sustains 50-250+ Mbps.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Open TCP :443 inbound on domestic cloud firewall; use self-signed IP-SAN ECDSA cert with strictly EMPTY sni/servername and skip_cert_verify: true.",
                "Health probe URL must remain domestic (hicloud.com / miui.com); overseas gstatic URLs are rejected.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: Open 'Domestic Boost' -> '+ Add Relay' -> verify 'Auto-skip native 443 nodes', and run single/all relay real upload/download speed tests.",
                "CLI: `catcloud preaccel add --uri ... --json`, `catcloud preaccel pool --json`, `catcloud preaccel bind --dispatch-strategy auto --lb-strategy consistent_hashing --json`, `catcloud preaccel test --speed [--node-id <id>] --json`, `catcloud preaccel global-status --json`, `catcloud config export-gateway --profile relay-fragment|transparent-gateway|preferred-nodes --json`; rotate secrets via `scripts/relay/rotate_relay_secrets.mjs`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Disable via GUI switch or `catcloud preaccel bind --enabled false --json && catcloud config reload --json`.",
            ]),
            contract_example: r#"{"schema":"mmrelay/v1","role":"domestic_pre_accel","relays":[{"id":"relay-cn-east-1","name":"CN-East-443 Primary","provider":"cloud-light","region":"CN-East","server":"203.0.113.10","port":443,"protocol":"anytls","password":"<YOUR_GENERATED_SECRET>","sni":"","skip_cert_verify":true,"priority":10,"expires_at":"2027-08-12","enabled":true}]}"#.into(),
        },
        AgentModuleDoc {
            module_id: MULTIGROUP_DOC_ID.into(),
            title: "Smart Groups & Safe Scoring Formula".into(),
            summary: "Cross-provider sticky-best pools, scenario formula presets, three-way fallbacks, and positional CLI controls.".into(),
            when_to_use_and_signals: svec(&[
                "AI/coding tools break on IP rotation or region-restricted exits, or need low-multiplier primary + backup escalation.",
            ]),
            external_prereqs_and_schema: svec(&[
                "At least 2 enabled nodes plus recent speed test results; safe zero-eval AST formulas.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: 'Smart Groups' -> mode, hard gates, formula, fallback, switch mode.",
                "CLI: `catcloud group list --json`, `catcloud group create --id grp-ai --name AI --mode sticky_best --json`, `catcloud group members --id grp-ai add|remove|set --nodes <csv> --json`, `catcloud group eval <group_id> --json`, `catcloud group switch <group_id> --json`, `catcloud group policy <group_id> --formula \"...\" --match-rules \"...\" --json`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Inspect `circuit_open` via `catcloud group eval <group_id> --json` or set fallback to `degrade_best_warn`.",
            ]),
            contract_example: r#"{"id":"grp-ai-core","name":"AI Primary Sticky Pool","mode":"sticky_best","hard_gates":["google_clean == 1","keepalive_ok == 1"],"formula_expr":"(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)","fallback_policy":"cross_pool_escalate","switch_mode":"force_close_old"}"#.into(),
        },
        AgentModuleDoc {
            module_id: NODES_PROBES_DOC_ID.into(),
            title: "Nodes, Subscriptions, Live Capture & 3-Tier Probes".into(),
            summary: "Unified subscriptions, read-only migration, 1->2->3 capture, group rename/merge, catcloud-adapter/v1, and isolated L1/L2/60s keep-alive probes.".into(),
            when_to_use_and_signals: svec(&[
                "Consolidating multi-provider nodes, capturing running clients, or detecting Google-CN/silent-blackhole nodes without interrupting live traffic.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Supports Clash YAML (<= 16 MiB), sing-box JSON, URI lists, and catcloud-adapter/v1 (>= 60s cooldown); ephemeral loopback probe core tears down immediately.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: 'Nodes & Speed' (Lite/Full/60s tests, Golden Nodes fallback) and 'Subs & Import'.",
                "CLI: `catcloud sub list|refresh|remove`, `catcloud sub rename <id> --name <new_name> --json`, `catcloud sub merge --source <src_id> --target <dst_id> --json`, `catcloud node list|import|migrate|attach-process`, `catcloud probe list|run --tier l1`, `catcloud probe add --id custom_api --name \"Custom API\" --kind upload --url https://example.com/up --json`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Failed refreshes or 0-node payloads are atomically rejected without touching existing nodes.",
                "If live capture from a dedicated client returns 0 nodes: (1) click Connect, not just Update Subscription; (2) pick the underlying proxy core process rather than the UI shell; (3) match elevation if the target client runs as Administrator; (4) for double-encrypted closed clients, stay connected via that app to copy the subscription URL from the provider dashboard.",
            ]),
            contract_example: r#"{"schema":"catcloud-adapter/v1","nodes":[{"name":"Example-SG-01 1x","type":"trojan","server":"198.51.100.20","port":443,"password":"<PLACEHOLDER>"}]}"#.into(),
        },
        AgentModuleDoc {
            module_id: ROUTING_CONNS_DOC_ID.into(),
            title: "Rules & Conns, QUIC Policy & Connections".into(),
            summary: "Rule/Global/Direct modes, domestic direct, built-in AI split routing, domestic QUIC allow before overseas QUIC reject, and live connection diagnostics.".into(),
            when_to_use_and_signals: svec(&[
                "Verifying domain rule matches, splitting AI domains, or diagnosing domestic IM media/QUIC behavior.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Uses Country.mmdb (and optional geosite.dat); domestic UDP 443 allow precedes overseas QUIC block; QQ/WeChat domains added to fake-ip-filter.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: 'Rules & Conns'. CLI: `catcloud net connections --json`, `catcloud net match <domain> --json`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Remove misbehaving custom prepend rules after checking `catcloud net match <domain> --json`.",
            ]),
            contract_example: String::new(),
        },
        AgentModuleDoc {
            module_id: NETWORK_LIFECYCLE_DOC_ID.into(),
            title: "Network, Hot Reload, Tray Memory Saver & Updates".into(),
            summary: "System Proxy, Proxy Guard, TUN Mode, Network & DNS, L1/L2/L3 zero-downtime reload, windowless tray (<= 70 MB), portable cli/ detection, config backup/restore, and JuryBu/CatCloud safe updater.".into(),
            when_to_use_and_signals: svec(&[
                "Validating/hot-reloading config edits, backing up or restoring settings, or staging verified GitHub Releases updates.",
            ]),
            external_prereqs_and_schema: svec(&[
                "Updater allows GitHub HTTPS :443 only with latest.json + SHA256SUMS.txt verification and preserves data/, portable.flag, and databases.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: 'Settings -> Network & DNS' and 'Settings -> About & Updates'; close main window for windowless tray mode.",
                "CLI: `catcloud config validate|reload|compile|backup|restore|export-env|diag --json`, `catcloud update check --json`, `catcloud update stage --manifest latest.json --archive <zip> --checksums SHA256SUMS.txt --json`, `catcloud docs export --lang <lang> --sync-dir <dir>`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Restore verified snapshots with `catcloud config restore --file <backup.json> --json`; portable updates roll back atomically on failure.",
            ]),
            contract_example: r#"{"repo":"JuryBu/CatCloud","mode":"next_launch","preserved_paths":["data/","portable.flag","*.sqlite*"]}"#.into(),
        },
        AgentModuleDoc {
            module_id: SHARE_BUNDLE_DOC_ID.into(),
            title: "Selective .zip Share Packs & Secret Redline".into(),
            summary: "Pack selected nodes and domestic relays into catcloud-share/v1 .zip with automatic privacy stripping, preview-before-import, and strict no-secret-echo rules for Agents.".into(),
            when_to_use_and_signals: svec(&[
                "Sharing vetted nodes or domestic :443 relays privately with friends without exposing subscription URLs or local machine data.",
            ]),
            external_prereqs_and_schema: svec(&[
                "catcloud-share/v1 zip (<= 32 files, <= 4000 nodes, <= 16 MiB uncompressed, anti Zip-Slip & symlink rejection).",
                "Redline: private sharing only; AI Agents must never echo plaintext passwords, UUIDs, tokens, keys, or unmasked relay IPs.",
            ]),
            gui_and_cli_verification: svec(&[
                "GUI: Entry points in 'Domestic Boost', 'Nodes & Speed', and 'Subs & Import'.",
                "CLI: `catcloud share export --output friend.zip --name \"Friend Pack\" --nodes <ids> --relays <ids> --json`, `catcloud share inspect <file.zip> --json`, `catcloud share import --file friend.zip --dry-run|--apply --json`.",
            ]),
            rollback_and_troubleshooting: svec(&[
                "Always preview with `share inspect` or `--dry-run` first; rotate relay passwords immediately if a bundle is ever shared outside trusted recipients.",
            ]),
            contract_example: r#"{"schema":"catcloud-share/v1","files":["manifest.json","nodes.yaml","relays.mmrelay.json","README.md"]}"#.into(),
        },
    ]
}

fn localized_title_and_summary(canonical_id: &str, lang: &str) -> (&'static str, &'static str) {
    match normalize_doc_lang(Some(lang)) {
        "ja" => match canonical_id {
            TROUBLESHOOTING_DOC_ID => (
                "汎用ネットワーク 6 層トラブルシューティング総綱",
                "物理回線から競合プロキシ、仮想 NIC (TUN)、ルールと接続/QUIC、国内高速化、海外ノードまで 6 層で診断し、脱敏済み GitHub Issue テンプレートを提供します。",
            ),
            ONBOARDING_DOC_ID => (
                "初心者オンボーディング総綱（AI メンター用）",
                "6 大機能・5 段階ガイド（状態 5 完了含む）・「車は CatCloud、燃料は購読」の説明と日本語 UI 名称を収録。",
            ),
            PREACCEL_DOC_ID => (
                "国内高速化（TCP 443 純 IP 中継）実践マニュアル",
                "友人共有・自前構築（安全組 TCP 443 開放・空 SNI・ワンショット導入スクリプト）・単体/全中継の実上下り速度テスト・グローバル高速化検証を網羅。",
            ),
            MULTIGROUP_DOC_ID => (
                "スマートグループ & 安全スコア式",
                "AI 向け粘着ロック・低倍率優先＋高倍率兜底のプリセット式と正確な CLI 引数を収録。",
            ),
            NODES_PROBES_DOC_ID => (
                "ノードと速度・1→2→3 捕捉 & 3 段階速度テスト",
                "L1/L2/60 秒キープアライブ、購読グループ更新・名前変更・統合マージ、sub/probe CLI を収録。",
            ),
            ROUTING_CONNS_DOC_ID => (
                "ルールと接続・QUIC 制御 & リアルタイム接続診断",
                "国内直接・AI ドメイン分流・国内 QUIC 優先許可＋海外 QUIC ブロック・接続診断を収録。",
            ),
            NETWORK_LIFECYCLE_DOC_ID => (
                "ネットワーク・DNS・3 段階熱再読込・省メモリ & 安全更新",
                "システムプロキシ/仮想 NIC (TUN)/ネットワーク・DNS・トレイ省メモリ・config backup/restore・docs export・update stage 手順を収録。",
            ),
            _ => (
                "選択式 .zip 共有パック & 秘密保護ルール",
                "選択ノードと国内中継の安全な共有・プレビュー取込（share inspect/import）と、AI の平文秘密出力禁止ルールを定義。",
            ),
        },
        _ => match canonical_id {
            TROUBLESHOOTING_DOC_ID => (
                "6-уровневая диагностика сети и GitHub Issue",
                "Пошаговая диагностика от физической сети и конфликтов прокси до узлов AI, CLI-стетоскоп и шаблон Issue для JuryBu/CatCloud.",
            ),
            ONBOARDING_DOC_ID => (
                "Руководство для новичков (для AI-наставника)",
                "6 ключевых сценариев, 5 шагов прогресса (включая этап 5) и точные названия интерфейса для пошагового обучения.",
            ),
            PREACCEL_DOC_ID => (
                "Ускорение 443 (TCP :443 без SNI) и глобальный режим",
                "Импорт от друзей, самостоятельный запуск на VPS (TCP 443, пустой SNI, скрипт AnyTLS/Trojan), тест реальной скорости одного/всех релеев и проверка global-status.",
            ),
            MULTIGROUP_DOC_ID => (
                "Умные группы и безопасные формулы",
                "Пресеты формул для AI-кодинга, экономии трафика и стриминга, а также команды group create/eval/switch/policy.",
            ),
            NODES_PROBES_DOC_ID => (
                "Узлы и тест, подписки, захват 1→2→3 и 3-уровневый тест",
                "Изолированные тесты L1/L2/60s Keep-Alive, обновление/переименование/слияние групп подписок и команды sub/probe.",
            ),
            ROUTING_CONNS_DOC_ID => (
                "Правила и сети, QUIC и диагностика соединений",
                "Прямой CN-трафик, AI-домены, разрешение локального QUIC перед блокировкой зарубежного UDP 443 и net connections/match.",
            ),
            NETWORK_LIFECYCLE_DOC_ID => (
                "Сеть и DNS, горячая перезагрузка, экономия ОЗУ и обновления",
                "Системный прокси, TUN-адаптер, Сеть и DNS, режим трея (<= 70 MB), config backup/restore, docs export и безопасный update stage.",
            ),
            _ => (
                "Выборочный Пакет обмена .zip и защита секретов",
                "Экспорт и предпросмотр .zip пакетов catcloud-share/v1 (share inspect/import) без личных данных и строгий запрет вывода открытых ключей для AI.",
            ),
        },
    }
}

/// Return all 8 authoritative Agent module guides for the requested language
/// (`"zh-CN" | "en" | "ja" | "ru"`, defaulting to `"zh-CN"`).
pub fn list_agent_docs_for_lang(lang: &str) -> Vec<AgentModuleDoc> {
    let norm = normalize_doc_lang(Some(lang));
    match norm {
        "zh-CN" => build_zh_docs(),
        "en" => build_en_docs(),
        "ja" | "ru" => build_en_docs()
            .into_iter()
            .map(|mut doc| {
                let (title, summary) = localized_title_and_summary(&doc.module_id, norm);
                doc.title = title.to_string();
                doc.summary = summary.to_string();
                doc
            })
            .collect(),
        _ => build_zh_docs(),
    }
}

/// Return all 8 authoritative built-in Agent module guides in default Simplified Chinese.
pub fn list_agent_docs() -> Vec<AgentModuleDoc> {
    list_agent_docs_for_lang("zh-CN")
}

/// Look up a single module's guide by canonical ID or legacy alias (case-insensitive).
pub fn get_agent_doc(module_id: &str) -> CatResult<AgentModuleDoc> {
    get_agent_doc_for_lang(module_id, "zh-CN")
}

/// Look up a single module's guide in a specific language by canonical ID or legacy alias.
pub fn get_agent_doc_for_lang(module_id: &str, lang: &str) -> CatResult<AgentModuleDoc> {
    let canonical = resolve_canonical_doc_id(module_id).ok_or_else(|| {
        CatError::NotFound(format!("未找到指定的助手指南模块「{module_id}」"))
    })?;
    list_agent_docs_for_lang(lang)
        .into_iter()
        .find(|d| d.module_id == canonical)
        .ok_or_else(|| CatError::NotFound(format!("未找到指定的助手指南模块「{module_id}」")))
}

/// Export either one module (canonical ID or legacy alias) or `"all"` in Markdown or JSON
/// for the specified language (`"zh-CN" | "en" | "ja" | "ru"`).
pub fn export_agent_docs_with_lang(
    module_id: &str,
    as_json: bool,
    lang: &str,
) -> CatResult<String> {
    let norm = normalize_doc_lang(Some(lang));
    let needle = module_id.trim().to_ascii_lowercase();
    if needle.is_empty() || needle == "all" {
        if as_json {
            Ok(serde_json::to_string_pretty(&list_agent_docs_for_lang(norm))?)
        } else {
            let rendered: Vec<String> = DOC_CATALOG
                .iter()
                .map(|entry| render_doc_markdown_for_lang(entry.id, norm))
                .collect();
            Ok(rendered.join("\n\n---\n\n"))
        }
    } else {
        let canonical = resolve_canonical_doc_id(&needle).ok_or_else(|| {
            CatError::NotFound(format!("未找到指定的助手指南模块「{module_id}」"))
        })?;
        if as_json {
            let doc = get_agent_doc_for_lang(canonical, norm)?;
            Ok(serde_json::to_string_pretty(&doc)?)
        } else {
            Ok(render_doc_markdown_for_lang(canonical, norm))
        }
    }
}

/// Export either one module or `"all"` modules as Markdown or JSON in default Simplified Chinese.
pub fn export_agent_docs(module_id: &str, as_json: bool) -> CatResult<String> {
    export_agent_docs_with_lang(module_id, as_json, "zh-CN")
}

/// Render a self-contained Web-AI-ready Markdown guide (for pasting or dragging into
/// directly reachable domestic Web AIs like DeepSeek / Doubao / Qwen / Kimi, or overseas Web AIs).
pub fn render_web_ai_guide(module_id: &str, lang: &str) -> CatResult<String> {
    let norm = normalize_doc_lang(Some(lang));
    let body = export_agent_docs_with_lang(module_id, false, norm)?;
    let body_clean = strip_leading_lock_line(&body);
    let header = match norm {
        "en" => format!(
            "{}\n\n\
             ## Web AI Assistant Instructions\n\
             - Recommended Web AIs (directly reachable even before proxy is connected): **DeepSeek**, **Doubao**, **Qwen**, **Kimi** (and ChatGPT / Claude / Gemini once online).\n\
             - Guide the user with **one concrete GUI step at a time** using exact CatCloud page/button names; avoid CLI commands unless asked.\n\
             - Never ask for or repeat plaintext passwords, UUIDs, tokens, private keys, or unmasked relay IPs.\n\n---\n\n",
            lang_lock_line(norm)
        ),
        "ja" => format!(
            "{}\n\n\
             ## Web AI アシスタント向け案内ルール\n\
             - プロキシ未接続でも直接使える推奨 Web AI：**DeepSeek**・**豆包 (Doubao)**・**通義千問 (Qwen)**・**Kimi**（接続後は ChatGPT / Claude / Gemini も利用可能）。\n\
             - 毎回「今すぐ押せる 1 ステップ」だけを正確な画面名で案内し、平文パスワード・UUID・生 IP を要求・復唱しないでください。\n\n---\n\n",
            lang_lock_line(norm)
        ),
        "ru" => format!(
            "{}\n\n\
             ## Инструкция для веб-AI ассистента\n\
             - Рекомендуемые веб-AI (доступны напрямую ещё до подключения прокси): **DeepSeek**, **Doubao**, **Qwen**, **Kimi** (а после подключения — ChatGPT / Claude / Gemini).\n\
             - Давайте по одному конкретному шагу в интерфейсе CatCloud; никогда не запрашивайте и не повторяйте открытые пароли, UUID, токены и немаскированные IP.\n\n---\n\n",
            lang_lock_line(norm)
        ),
        _ => format!(
            "{}\n\n\
             ## 给网页 AI 助手的对话说明\n\
             - **国内直连推荐**（还没连上外网也能直接打开）：**DeepSeek（deepseek.com）**、**豆包（doubao.com）**、**通义千问（tongyi.aliyun.com）**、**Kimi（kimi.moonshot.cn）**；已联网后也可用 ChatGPT / Claude / Gemini。\n\
             - 请用亲切大白话、**每次只教当下最该做的下一小步**，严格使用猫猫云梯真实中文界面名；除非用户主动追问，不要甩源码或命令行。\n\
             - **安全红线**：不要索要或复述任何明文密码、UUID、Token、订阅链接密钥或未脱敏中转 IP。\n\n---\n\n",
            lang_lock_line(norm)
        ),
    };
    Ok(format!("{header}{body_clean}"))
}

fn describe_current_page(current_page: &str, lang: &str) -> (String, &'static str) {
    let raw = current_page.trim();
    let lower = raw.to_ascii_lowercase();
    let norm = normalize_doc_lang(Some(lang));

    let (zh, en, ja, ru, doc_file) = match lower.as_str() {
        "" | "home" | "overview" | "总览" => (
            "总览",
            "Overview",
            "概要",
            "Обзор",
            "01-onboarding.md",
        ),
        "preaccel" | "domestic" | "国内提速" => (
            "国内提速",
            "Domestic Boost",
            "国内高速化",
            "Ускорение 443",
            "02-domestic-preaccel.md",
        ),
        "multigroup" | "groups" | "智能多选组" => (
            "智能多选组",
            "Smart Groups",
            "スマートグループ",
            "Умные группы",
            "03-multigroup.md",
        ),
        "nodes" | "speedtest" | "nodes_probes" | "subs" | "节点与测速" => (
            "节点与测速",
            "Nodes & Speed",
            "ノードと速度",
            "Узлы и тест",
            "04-nodes-and-probes.md",
        ),
        "routing" | "connections" | "routing_conns" | "分流与连接" => (
            "分流与连接",
            "Rules & Conns",
            "ルールと接続",
            "Правила и сети",
            "05-routing-and-connections.md",
        ),
        "logs" | "troubleshooting" | "运行日志" => (
            "运行日志",
            "Logs",
            "実行ログ",
            "Журнал",
            "00-general-troubleshooting.md",
        ),
        "settings" | "network_lifecycle" | "设置" => (
            "设置",
            "Settings",
            "設定",
            "Настройки",
            "06-network-and-lifecycle.md",
        ),
        "share" | "share_bundle" => (
            "分享包",
            "Share Pack",
            "共有パック",
            "Пакет обмена",
            "07-share-bundle.md",
        ),
        "ai" | "assistant" | "ai_assistant" | "autopilot" | "ai_autopilot" | "ai 助手" | "ai 全权代管" => (
            "AI 全权代管",
            "AI Autopilot",
            "AI 自動設定",
            "ИИ-автопилот",
            "00-general-troubleshooting.md",
        ),
        _ => return (raw.to_string(), "00-general-troubleshooting.md"),
    };

    let label = match norm {
        "en" => en,
        "ja" => ja,
        "ru" => ru,
        _ => zh,
    };
    (label.to_string(), doc_file)
}

/// Authorization mode for the local AI Agent bootstrap prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPromptMode {
    Autopilot,
    Readonly,
    TroubleshootIssue,
}

impl AgentPromptMode {
    pub fn from_opt_str(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("readonly" | "read_only" | "inspect" | "check") => Self::Readonly,
            Some("issue" | "troubleshoot" | "troubleshoot_issue" | "feedback" | "report") => {
                Self::TroubleshootIssue
            }
            _ => Self::Autopilot,
        }
    }
}

/// Render a clean, lightweight Bootstrap Prompt for local CLI/coding AI Agents
/// (e.g. Codex, Claude Code, Antigravity) with explicit authorization mode:
/// - `AgentPromptMode::Autopilot`: directly authorizes end-to-end setup, speed testing,
///   smart group creation, domestic boost configuration, and hot-reload verification
///   (confirming only before destructive deletions or remote SSH deployments).
/// - `AgentPromptMode::Readonly`: read-only inspection first; ask confirmation before any write.
pub fn render_agent_bootstrap_prompt_with_mode(
    cli_path: &str,
    data_dir: &str,
    docs_index_path: &str,
    current_page: &str,
    lang: &str,
    mode: AgentPromptMode,
) -> String {
    let norm = normalize_doc_lang(Some(lang));
    let cli = if cli_path.trim().is_empty() {
        "catcloud"
    } else {
        cli_path.trim()
    };
    let data = data_dir.trim();
    let index = docs_index_path.trim();
    let (page_label, suggested_doc) = describe_current_page(current_page, norm);

    match (norm, mode) {
        ("en", AgentPromptMode::Autopilot) => format!(
            "{}\n\n\
             You are my local CatCloud AI Agent (Codex / Claude Code / Antigravity). I authorize you to configure and optimize this exact running instance end-to-end:\n\
             - CLI executable: `{cli}`\n\
             - Data directory flag: `--data-dir \"{data}\"` (always pass `--json`)\n\
             - Authoritative local docs index: `{index}` (start with `{suggested_doc}` for current page: **{page_label}**)\n\n\
             Autopilot Authorization:\n\
             1. **Inspect automatically first**: Read `{index}` (and `{suggested_doc}`) as needed, then run read-only diagnostics (`status --json`, `net doctor --json`, `config validate --json`, `logs tail --lines 50 --json`) using the exact CLI path above.\n\
             2. **Execute end-to-end directly**: You are pre-authorized to import subscriptions/nodes I provide (or migrate existing local clients), run zero-interference speed tests to pick the fastest golden nodes, build/tune Smart Groups, repair dangling rules (`config repair-rules`), configure Domestic Boost, and run `config reload --json` to make changes live without pausing on routine steps.\n\
             3. **Troubleshoot & Report Real Bugs**: If you hit a genuine CatCloud software bug that cannot be solved by config repair, draft a strictly sanitized reproduction report and (after my confirmation) help me file a GitHub Issue on `JuryBu/CatCloud` (via `gh` if available, or provide a ready-to-paste summary).\n\
             4. **Confirm only high-risk actions & strict secret redline**: Ask before destructive deletions, remote SSH deployment, or publishing a GitHub Issue; NEVER echo, print, or leak plaintext passwords, UUIDs, tokens, private keys, subscription URLs, or unmasked relay IPs.\n\n\
             Start immediately by checking my current state, carry out the needed setup, and report a concise plain-language verification summary.",
            lang_lock_line(norm)
        ),
        ("en", AgentPromptMode::TroubleshootIssue) => format!(
            "{}\n\n\
             You are my local CatCloud troubleshooting & feedback AI Agent (Codex / Claude Code / Antigravity). Please diagnose what went wrong in this running instance, fix safe configuration issues if possible, or prepare a sanitized GitHub Issue for `JuryBu/CatCloud`:\n\
             - CLI executable: `{cli}`\n\
             - Data directory flag: `--data-dir \"{data}\"` (always pass `--json`)\n\
             - Troubleshooting manual: `{index}` (start with `00-general-troubleshooting.md`; current page: **{page_label}**)\n\n\
             Workflow:\n\
             1. **Read-only diagnosis first**: Run `status --json`, `config validate --json`, `net doctor --json`, and `logs tail --lines 80 --since 30m --json`.\n\
             2. **Auto-fix safe config issues**: If you find dangling migrated rules (`unknown_rule_target`) or simple config mismatches, explain clearly and fix them with `config repair-rules` + `config reload --json`.\n\
             3. **File a sanitized GitHub Issue for real bugs**: If it is a CatCloud software defect, compile a concise, zero-secret reproduction report (version, OS, exact steps, expected vs actual, sanitized diagnostic summary). Ask my confirmation before submitting via `gh issue create --repo JuryBu/CatCloud` (or give me the ready-to-paste markdown).\n\
             4. **Zero-secret redline**: NEVER include plaintext passwords, UUIDs, tokens, private keys, subscription URLs, or unmasked relay IPs.\n\n\
             Start diagnosing immediately and explain what you found in plain language.",
            lang_lock_line(norm)
        ),
        ("en", AgentPromptMode::Readonly) => format!(
            "{}\n\n\
             You are my local CatCloud AI Agent assistant. Work against this exact running instance:\n\
             - CLI executable: `{cli}`\n\
             - Data directory flag: `--data-dir \"{data}\"` (always pass `--json` for machine output)\n\
             - Authoritative local docs index: `{index}` (start with `{suggested_doc}` for current page: **{page_label}**)\n\n\
             Operating Contract:\n\
             1. **Read-only self-check first**: Read `{index}` (and the matching chapter) on demand, then inspect via read-only CLI (`status --json`, `net doctor --json`, `logs tail --lines 50 --json`) instead of guessing flags or UI labels.\n\
             2. **Confirm before changes**: Ask my explicit permission before any write, import, reload, delete, or remote server deployment.\n\
             3. **Handle end-to-end when approved**: Once approved, run the full workflow for me (imports, speed tests, multi-group setup, domestic :443 relay deployment, share bundles, troubleshooting) and verify results.\n\
             4. **Strict secret redline**: Default CLI outputs are already sanitized; NEVER echo, print, or leak plaintext passwords, UUIDs, tokens, private keys, subscription URLs, or unmasked relay IPs.\n\n\
             Start by inspecting my current status read-only and tell me what you see and how you can help.",
            lang_lock_line(norm)
        ),
        ("ja", AgentPromptMode::Autopilot) => format!(
            "{}\n\n\
             あなたは私のローカル CatCloud AI エージェント（Codex / Claude Code / Antigravity）です。以下の実インスタンスの設定・最適化を一貫代行することを承認します：\n\
             - CLI 実行ファイル：`{cli}`\n\
             - データディレクトリ引数：`--data-dir \"{data}\"`（常に `--json` を付与）\n\
             - ローカル権威マニュアル目次：`{index}`（現在画面「**{page_label}**」向け推奨章：`{suggested_doc}`）\n\n\
             全自動代行ルール：\n\
             1. **まず自動で現状診断**：`{index}` と `{suggested_doc}` を必要時に読み、上記 CLI で `status --json` / `config validate --json` / `net doctor --json` / `logs tail --lines 50 --json` を実行して現状を把握すること。\n\
             2. **そのまま一気通貫で設定・反映**：購読/ノード取り込み、速度テスト、スマートグループ構築、残留ルール修復（`config repair-rules`）、国内高速化設定、`config reload --json` 反映まで自律完了してよい。\n\
             3. **不具合なら脱敏 Issue 作成を支援**：ソフトウェア側の不具合と判断した場合は脱敏済みの再現報告を作成し、確認のうえで `JuryBu/CatCloud` への GitHub Issue 提出を支援すること。\n\
             4. **高リスク操作の事前確認と秘密保護**：破壊的削除・SSH 構築・Issue 公開送信前は確認し、平文パスワード・UUID・トークン・秘密鍵・購読 URL・未マスク中継 IP は絶対に出力しないこと。\n\n\
             すぐ現状診断から始め、必要な設定と反映を完了したうえで分かりやすい日本語で検証結果を報告してください。",
            lang_lock_line(norm)
        ),
        ("ja", AgentPromptMode::TroubleshootIssue) => format!(
            "{}\n\n\
             あなたは私のローカル CatCloud 障害診断・フィードバック支援 AI エージェントです。以下の実インスタンスで発生した問題を調査し、設定起因なら修復、ソフト不具合なら `JuryBu/CatCloud` 向け脱敏 Issue を作成してください：\n\
             - CLI 実行ファイル：`{cli}`\n\
             - データディレクトリ引数：`--data-dir \"{data}\"`（常に `--json` を付与）\n\
             - マニュアル目次：`{index}`（`00-general-troubleshooting.md` を参照、現在画面：**{page_label}**）\n\n\
             手順：\n\
             1. `status --json`、`config validate --json`、`net doctor --json`、`logs tail --lines 80 --since 30m --json` で読み取り専用診断を行う。\n\
             2. 残留ルール（`unknown_rule_target`）等の設定起因なら `config repair-rules` と `config reload --json` で修復して検証する。\n\
             3. ソフト不具合なら秘密情報を完全除去した再現手順・診断要約を作成し、同意を得たうえで `gh issue create --repo JuryBu/CatCloud` または貼付用 Markdown を提示する。\n\
             4. 平文パスワード・UUID・トークン・秘密鍵・購読 URL・未マスク IP は絶対に含めないこと。\n\n\
             すぐ診断を開始し、原因と対処を分かりやすく報告してください。",
            lang_lock_line(norm)
        ),
        ("ja", AgentPromptMode::Readonly) => format!(
            "{}\n\n\
             あなたは私のローカル CatCloud AI エージェントです。以下の実インスタンス環境を操作対象にしてください：\n\
             - CLI 実行ファイル：`{cli}`\n\
             - データディレクトリ引数：`--data-dir \"{data}\"`（機械読取には常に `--json` を付与）\n\
             - ローカル権威マニュアル目次：`{index}`（現在画面「**{page_label}**」向け推奨章：`{suggested_doc}`）\n\n\
             行動契約：\n\
             1. **まず読み取り専用で自己診断**：`{index}` と該当章を必要時に読み、`status --json` / `net doctor --json` / `logs tail --lines 50 --json` で現状確認すること（フラグや UI 名を推測しない）。\n\
             2. **変更前は必ず同意確認**：設定変更・インポート・リロード・削除・サーバー構築の前に必ず確認を取ること。\n\
             3. **同意後は全工程を代行**：承認後はインポート・速度テスト・グループ構築・国内 443 中継導入・共有パッケージ・障害復旧まで一貫して代行・検証すること。\n\
             4. **秘密保護レッドライン**：平文パスワード・UUID・トークン・秘密鍵・購読 URL・未マスク中継 IP を絶対に出力・復唱しないこと。\n\n\
             まず読み取り専用で現在状態を確認し、状況と手伝える内容を簡潔に教えてください。",
            lang_lock_line(norm)
        ),
        ("ru", AgentPromptMode::Autopilot) => format!(
            "{}\n\n\
             Ты мой локальный AI-агент CatCloud (Codex / Claude Code / Antigravity). Я заранее разрешаю тебе настроить и оптимизировать этот экземпляр под ключ:\n\
             - Исполняемый CLI: `{cli}`\n\
             - Флаг каталога данных: `--data-dir \"{data}\"` (всегда добавляй `--json`)\n\
             - Индекс локальной документации: `{index}` (текущий экран: **{page_label}**, рекомендуемая глава: `{suggested_doc}`)\n\n\
             Полномочия автонастройки:\n\
             1. **Автодиагностика**: прочитай `{index}` и `{suggested_doc}`, затем проверь состояние через `status --json`, `config validate --json`, `net doctor --json`, `logs tail --lines 50 --json`.\n\
             2. **Выполнение под ключ**: импортируй подписки/узлы, отбирай золотые узлы, настраивай «Умные группы», очищай битые правила (`config repair-rules`), подключай «Ускорение 443» и применяй через `config reload --json`.\n\
             3. **Диагностика и помощь с Issue**: если обнаружена реальная ошибка самого CatCloud, подготовь очищенный от секретов отчёт и (с моего согласия) помоги создать GitHub Issue в `JuryBu/CatCloud`.\n\
             4. **Риски и запрет утечки секретов**: спрашивай перед удалением подписок, SSH-деплоем или публикацией Issue; никогда не выводи пароли, UUID, токены, ключи, ссылки подписок и немаскированные IP.\n\n\
             Сразу начни с диагностики, выполни настройку и дай краткий понятный отчёт о проверке.",
            lang_lock_line(norm)
        ),
        ("ru", AgentPromptMode::TroubleshootIssue) => format!(
            "{}\n\n\
             Ты мой локальный AI-агент диагностики и обратной связи CatCloud. Проверь сбой в этом экземпляре, почини безопасные ошибки конфигурации или подготовь очищенный GitHub Issue для `JuryBu/CatCloud`:\n\
             - Исполняемый CLI: `{cli}`\n\
             - Флаг каталога данных: `--data-dir \"{data}\"` (всегда с `--json`)\n\
             - Документация: `{index}` (начни с `00-general-troubleshooting.md`; экран: **{page_label}**)\n\n\
             Порядок действий:\n\
             1. Выполни `status --json`, `config validate --json`, `net doctor --json`, `logs tail --lines 80 --since 30m --json`.\n\
             2. Если найдены висячие правила (`unknown_rule_target`) или простая ошибка конфигурации — исправь через `config repair-rules` и `config reload --json`.\n\
             3. Если это баг CatCloud — составь краткий отчёт без секретов и после моего согласия отправь через `gh issue create --repo JuryBu/CatCloud` (или дай готовый Markdown).\n\
             4. Строго без паролей, UUID, токенов, ключей, ссылок подписок и немаскированных IP.\n\n\
             Начинай диагностику и коротко объясни причину.",
            lang_lock_line(norm)
        ),
        ("ru", AgentPromptMode::Readonly) => format!(
            "{}\n\n\
             Ты мой локальный AI-агент для CatCloud. Работай строго с этим экземпляром:\n\
             - Исполняемый CLI: `{cli}`\n\
             - Флаг каталога данных: `--data-dir \"{data}\"` (всегда добавляй `--json`)\n\
             - Индекс локальной документации: `{index}` (текущий экран: **{page_label}**, рекомендуемая глава: `{suggested_doc}`)\n\n\
             Правила работы:\n\
             1. **Сначала только чтение**: прочитай `{index}` и нужную главу, затем проверь состояние через `status --json`, `net doctor --json`, `logs tail --lines 50 --json` (не угадывай флаги и названия UI).\n\
             2. **Согласие перед изменениями**: перед записью, импортом, перезагрузкой, удалением или настройкой сервера спроси подтверждение.\n\
             3. **Выполняй процесс целиком**: после одобрения бери на себя весь цикл (импорт, тесты, мультигруппы, деплой релея :443, пакеты обмена, диагностику) с проверкой результата.\n\
             4. **Запрет утечки секретов**: никогда не выводи и не повторяй открытые пароли, UUID, токены, приватные ключи, ссылки подписок и немаскированные IP.\n\n\
             Начни с диагностики только для чтения и коротко расскажи о текущем состоянии.",
            lang_lock_line(norm)
        ),
        (_, AgentPromptMode::Autopilot) => format!(
            "{}\n\n\
             请你作为我的本机猫猫云梯（CatCloud）全权代管 AI 助手（Codex / Claude Code / Antigravity），我正式授权你直接端到端替我配好这个真实实例：\n\
             - CLI 绝对路径：`{cli}`\n\
             - 实例数据目录参数：`--data-dir \"{data}\"`（所有命令统一加 `--json`）\n\
             - 随装权威手册总目录：`{index}`（当前所在页面：**{page_label}**，推荐优先读 `{suggested_doc}`）\n\n\
             全权代办授权：\n\
             1. **自动先体检现状**：按需读取 `{index}` 与 `{suggested_doc}`，立即使用上面的精确 CLI 路径和 `--data-dir` 跑 `status --json`、`config validate --json`、`net doctor --json`、`logs tail --lines 50 --json` 摸清现状。\n\
             2. **直接端到端帮我配好并热载生效**：无需每一步都反复打断问我——可直接帮我导入提供的订阅/节点（或只读迁移本机已有软件）、跑零干扰测速挑出最快黄金节点、建好并调优「智能多选组」、修复悬空失效分流规则（`config repair-rules`）、按需配置「国内提速」，并执行 `config reload --json` 免重启热切验收。\n\
             3. **排查异常并协助反馈软件 Bug**：如果发现是猫猫云梯软件本身的缺陷，请整理一份完全脱敏的复现步骤与诊断摘要，经我确认后可用本机 `gh` 直接帮我向 `JuryBu/CatCloud` 提交 GitHub Issue（或给出可直接粘贴的反馈稿）。\n\
             4. **仅高风险操作前再确认 & 严守脱敏红线**：只有涉及不可逆删除、远程 SSH 部署/改密、或对外公开发布 GitHub Issue 前才向我确认；严禁在对话、摘要或 Issue 中打印、复述任何明文密码、UUID、Token、私钥、订阅原链接或未脱敏中转 IP。\n\n\
             请直接开始体检现状并替我推进配置，完成后用简洁大白话告诉我验收结果和还缺什么资料。",
            lang_lock_line(norm)
        ),
        (_, AgentPromptMode::TroubleshootIssue) => format!(
            "{}\n\n\
             请你作为我的本机猫猫云梯（CatCloud）排障与反馈 AI 助手（Codex / Claude Code / Antigravity），帮我查清当前实例遇到的问题——能直接修好的配置问题直接帮我修好，如果是软件本身的 Bug 请直接帮我整理并提交脱敏 GitHub Issue：\n\
             - CLI 绝对路径：`{cli}`\n\
             - 实例数据目录参数：`--data-dir \"{data}\"`（所有命令统一加 `--json`）\n\
             - 排障权威手册：`{index}`（优先读 `00-general-troubleshooting.md`；当前页面：**{page_label}**）\n\n\
             排障与反馈步骤：\n\
             1. **先做只读听诊**：立刻运行 `status --json`、`config validate --json`、`net doctor --json` 和 `logs tail --lines 80 --since 30m --json` 定位具体报错与根因。\n\
             2. **常见配置异常直接自愈**：若发现悬空分流规则（`unknown_rule_target`）等可安全修复的配置问题，请先说明原因并用 `config repair-rules --mode remove --json`（或 `--mode rewrite`）+ `config reload --json` 帮我直接修好验证。\n\
             3. **确认是软件 Bug 则帮提脱敏 Issue**：若排查后确属猫猫云梯软件缺陷，请整理结构化、零隐私泄露的复现步骤、环境信息与关键日志摘要；经我确认后，若本机已登录 `gh` 可直接执行 `gh issue create --repo JuryBu/CatCloud` 代为提交，否则给我可直接粘贴的 Markdown 与预填链接。\n\
             4. **严守脱敏红线**：绝不在对话或 Issue 中包含任何明文密码、UUID、Token、私钥、订阅链接或未脱敏中转 IP。\n\n\
             请立即开始排查，并用大白话告诉我问题出在哪、怎么修或是否需要提交 Issue。",
            lang_lock_line(norm)
        ),
        (_, AgentPromptMode::Readonly) => format!(
            "{}\n\n\
             请作为我的本机猫猫云梯（CatCloud）AI 助手，围绕下面这个真实实例协作：\n\
             - CLI 绝对路径：`{cli}`\n\
             - 实例数据目录参数：`--data-dir \"{data}\"`（所有命令统一加 `--json`）\n\
             - 随装权威手册总目录：`{index}`（当前所在页面：**{page_label}**，推荐优先读 `{suggested_doc}`）\n\n\
             协作契约：\n\
             1. **先只读自查**：按需读取 `{index}` 与对应章节，并用只读命令（`status --json`、`net doctor --json`、`logs tail --lines 50 --json`）摸清现状，严禁凭空猜测命令参数或界面名称。\n\
             2. **修改前征求同意**：任何写入配置、导入/删除、热重载或远程服务器部署操作，必须先征得我明确同意。\n\
             3. **获准后尽量全程代办**：同意后请尽量替我跑完整个闭环（导入节点、测速、配智能多选组、部署国内 443 中转、导出/导入分享包、排障验真），减少我手动折腾。\n\
             4. **严禁泄露明文密钥**：默认只读输出已自动脱敏；严禁在对话、摘要或 Issue 中复述、打印任何明文密码、UUID、Token、私钥、订阅原链接或未脱敏中转 IP。\n\n\
             请先做一次只读状态检查，用简短大白话告诉我你看到的情况，以及接下来可以帮我做什么。",
            lang_lock_line(norm)
        ),
    }
}

/// Render a clean, lightweight (~15-line) Bootstrap Prompt for local CLI/coding AI Agents.
/// Preserved for 100% backward compatibility (delegates to [`AgentPromptMode::Readonly`]).
pub fn render_agent_bootstrap_prompt(
    cli_path: &str,
    data_dir: &str,
    docs_index_path: &str,
    current_page: &str,
    lang: &str,
) -> String {
    render_agent_bootstrap_prompt_with_mode(
        cli_path,
        data_dir,
        docs_index_path,
        current_page,
        lang,
        AgentPromptMode::Readonly,
    )
}

fn render_root_index_markdown() -> String {
    r###"# CatCloud Local Authoritative Agent Docs (`agent_docs/`)

This directory is automatically synchronized by CatCloud on startup.
Select the subdirectory matching the user's preferred language, then read only the needed chapter(s):

- Locate local `catcloud.exe` (installed builds are not on `PATH` by default):
  - PowerShell: `$CATCLOUD = @("$env:LOCALAPPDATA\CatCloud\resources\cli\catcloud.exe", ".\cli\catcloud.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1`
  - Bash: `CATCLOUD=$(command -v catcloud || ([ -x "./cli/catcloud.exe" ] && echo "./cli/catcloud.exe") || echo "$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe")`

- Simplified Chinese (Primary Authoritative Source): `zh-CN/INDEX.md`
- English (Complete Baseline): `en/INDEX.md`
- Japanese (UI-Bound Localized Guide): `ja/INDEX.md`
- Russian (UI-Bound Localized Guide): `ru/INDEX.md`

## 8-Chapter Map (Identical Filenames Across All Languages)
| File | Module ID | Scope |
|---|---|---|
| `00-general-troubleshooting.md` | `troubleshooting` | 6-layer network diagnosis, stethoscope CLI & `JuryBu/CatCloud` Issue template |
| `01-onboarding.md` | `onboarding` | Beginner mentor guide, 6 workflows, 5-step pacing & car-vs-fuel cold start |
| `02-domestic-preaccel.md` | `preaccel` | Domestic TCP :443 boost: friend import, self-host bash script (`mmrelay://v1`), global boost |
| `03-multigroup.md` | `multigroup` | Smart Multi-Groups, beginner formula presets & `group create/members/eval/switch/policy` |
| `04-nodes-and-probes.md` | `nodes_probes` | 3-tier speed tests, subscriptions, `1->2->3` capture, group rename/merge (`sub`/`probe` CLI) |
| `05-routing-and-connections.md` | `routing_conns` | Routing modes, domestic direct, AI split, domestic QUIC allow & `net connections/match` |
| `06-network-and-lifecycle.md` | `network_lifecycle` | System proxy, TUN, DNS, 3-level hot reload, tray memory saver, `config backup/restore`, `update stage` |
| `07-share-bundle.md` | `share_bundle` | Selective `.zip` share bundles (`catcloud-share/v1`), `share export/import` & secret redline |
"###
    .to_string()
}

fn render_lang_index_markdown(lang: &str) -> String {
    let norm = normalize_doc_lang(Some(lang));
    let docs = list_agent_docs_for_lang(norm);
    let heading = match norm {
        "en" => "# CatCloud Authoritative Agent Manuals (`en`)\n\n> Locate `catcloud.exe` (installed builds are not on `PATH`): PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` | Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\nRead only the chapter relevant to the user's current task:\n",
        "ja" => "# CatCloud 公式エージェントマニュアル一覧 (`ja`)\n\n> `catcloud.exe` 探索（インストール版は PATH 未登録）：PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` ／ Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\n現在のタスクに該当する章だけを選んで参照してください：\n",
        "ru" => "# Справочник локальной документации CatCloud (`ru`)\n\n> Поиск `catcloud.exe` (установленная сборка не в PATH): PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` | Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\nОткрывайте только главы, нужные для текущей задачи пользователя:\n",
        _ => "# 猫猫云梯（CatCloud）随装权威手册总目录（`zh-CN`）\n\n> 定位本机 `catcloud.exe`（安装版不在 PATH）：PowerShell `$CATCLOUD = @(\"$env:LOCALAPPDATA\\CatCloud\\resources\\cli\\catcloud.exe\", \".\\cli\\catcloud.exe\") | Where-Object { Test-Path $_ } | Select-Object -First 1` ｜ Bash `CATCLOUD=$(command -v catcloud || ([ -x \"./cli/catcloud.exe\" ] && echo \"./cli/catcloud.exe\") || echo \"$LOCALAPPDATA/CatCloud/resources/cli/catcloud.exe\")`\n\n按需只读与当前任务相关的章节即可，严禁凭空猜测界面名称或命令参数：\n",
    };

    let mut out = String::new();
    out.push_str(lang_lock_line(norm));
    out.push_str("\n\n");
    out.push_str(heading);
    out.push('\n');
    for (entry, doc) in DOC_CATALOG.iter().zip(docs.iter()) {
        out.push_str(&format!(
            "- `{}` (`{}`) — **{}**：{}\n",
            entry.filename, entry.id, doc.title, doc.summary
        ));
    }
    out
}

/// Synchronize the complete multi-language documentation tree into `<root_data_dir>/agent_docs/`.
/// Uses `.manifest_hash` (SHA-256 over all filenames and contents) to short-circuit with
/// **zero disk writes** whenever the on-disk tree is already intact and up to date.
pub fn sync_agent_docs_to_disk(root_data_dir: &Path) -> CatResult<PathBuf> {
    let docs_root = root_data_dir.join("agent_docs");
    let mut files: Vec<(PathBuf, String)> =
        Vec::with_capacity(1 + SUPPORTED_DOC_LANGS.len() * (1 + DOC_CATALOG.len()));

    files.push((PathBuf::from("INDEX.md"), render_root_index_markdown()));
    for &lang in SUPPORTED_DOC_LANGS {
        files.push((
            PathBuf::from(lang).join("INDEX.md"),
            render_lang_index_markdown(lang),
        ));
        for entry in DOC_CATALOG {
            files.push((
                PathBuf::from(lang).join(entry.filename),
                render_doc_markdown_for_lang(entry.id, lang),
            ));
        }
    }

    let mut hasher = Sha256::new();
    for (rel, content) in &files {
        let rel_norm = rel.to_string_lossy().replace('\\', "/");
        hasher.update(rel_norm.as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    let expected_hash = hex::encode(hasher.finalize());

    let hash_path = docs_root.join(".manifest_hash");
    if let Ok(existing_hash) = std::fs::read_to_string(&hash_path) {
        if existing_hash.trim() == expected_hash
            && files.iter().all(|(rel, _)| docs_root.join(rel).is_file())
        {
            return Ok(docs_root);
        }
    }

    std::fs::create_dir_all(&docs_root)?;
    for &lang in SUPPORTED_DOC_LANGS {
        std::fs::create_dir_all(docs_root.join(lang))?;
    }
    for (rel, content) in &files {
        AppPaths::atomic_write(&docs_root.join(rel), content.as_bytes())?;
    }
    AppPaths::atomic_write(&hash_path, expected_hash.as_bytes())?;

    Ok(docs_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_static_docs_stay_strictly_within_160kb_budget() {
        let static_bytes: usize = ZH_DOC_00_TROUBLESHOOTING.len()
            + ZH_DOC_01_ONBOARDING.len()
            + ZH_DOC_02_PREACCEL.len()
            + ZH_DOC_03_MULTIGROUP.len()
            + ZH_DOC_04_NODES_PROBES.len()
            + ZH_DOC_05_ROUTING_CONNS.len()
            + ZH_DOC_06_NETWORK_LIFECYCLE.len()
            + ZH_DOC_07_SHARE_BUNDLE.len()
            + EN_DOC_00_TROUBLESHOOTING.len()
            + EN_DOC_01_ONBOARDING.len()
            + EN_DOC_02_PREACCEL.len()
            + EN_DOC_03_MULTIGROUP.len()
            + EN_DOC_04_NODES_PROBES.len()
            + EN_DOC_05_ROUTING_CONNS.len()
            + EN_DOC_06_NETWORK_LIFECYCLE.len()
            + EN_DOC_07_SHARE_BUNDLE.len()
            + JA_UI_GLOSSARY.len()
            + RU_UI_GLOSSARY.len();
        assert!(
            static_bytes <= 150 * 1024,
            "embedded agent_docs static payload ({static_bytes} bytes) exceeded 150 KiB target"
        );
    }

    #[test]
    fn registry_contains_all_eight_modules_across_four_languages_with_clean_terminology() {
        for &lang in SUPPORTED_DOC_LANGS {
            let docs = list_agent_docs_for_lang(lang);
            assert_eq!(docs.len(), 8, "lang `{lang}` must have 8 modules");
            assert!(docs.iter().any(|d| d.module_id == TROUBLESHOOTING_DOC_ID));
            assert!(docs.iter().any(|d| d.module_id == ONBOARDING_DOC_ID));
            assert!(docs.iter().any(|d| d.module_id == SHARE_BUNDLE_DOC_ID));

            for doc in &docs {
                assert!(!doc.when_to_use_and_signals.is_empty(), "{}", doc.module_id);
                assert!(!doc.external_prereqs_and_schema.is_empty(), "{}", doc.module_id);
                assert!(!doc.gui_and_cli_verification.is_empty(), "{}", doc.module_id);
                assert!(!doc.rollback_and_troubleshooting.is_empty(), "{}", doc.module_id);

                let md = export_agent_docs_with_lang(&doc.module_id, false, lang)
                    .expect("export md");
                assert!(
                    md.starts_with(lang_lock_line(lang)),
                    "module `{}` lang `{lang}` must start with language lock",
                    doc.module_id
                );

                // Outdated Chinese UI terms & internal Rust/SQLite jargon must never regress.
                for forbidden in [
                    "国内预加速",
                    "隔离测速",
                    "节点与订阅",
                    "设置与 CLI",
                    "config::export_backup",
                    "config::import_backup",
                    "SQLite cascade",
                ] {
                    assert!(
                        !md.contains(forbidden) && !doc.to_markdown().contains(forbidden),
                        "module `{}` lang `{lang}` leaked forbidden term `{forbidden}`",
                        doc.module_id
                    );
                }
            }
        }

        for lang in ["ja", "ru"] {
            let preaccel_md =
                export_agent_docs_with_lang(PREACCEL_DOC_ID, false, lang).expect("export 02");
            assert!(
                preaccel_md.contains("config export-gateway"),
                "lang `{lang}` doc 02 must document config export-gateway"
            );
            assert!(
                preaccel_md.contains("--lb-strategy consistent_hashing|round_robin"),
                "lang `{lang}` doc 02 must order --lb-strategy consistent_hashing|round_robin"
            );
            assert!(
                !preaccel_md.contains("--lb-strategy round_robin|consistent_hashing"),
                "lang `{lang}` doc 02 must not keep old round_robin|consistent_hashing order"
            );

            let routing_md =
                export_agent_docs_with_lang(ROUTING_CONNS_DOC_ID, false, lang).expect("export 05");
            assert!(
                routing_md.contains("custom_rules_only"),
                "lang `{lang}` doc 05 must document custom_rules_only"
            );
            assert!(
                routing_md.contains("inline_override_yaml"),
                "lang `{lang}` doc 05 must document inline_override_yaml"
            );
        }
    }

    #[test]
    fn legacy_aliases_and_zh_onboarding_guide_remain_fully_compatible() {
        let guide = render_zh_onboarding_guide();
        assert!(guide.contains("每次只教当下最需要做的下一小步"));
        assert!(guide.contains("猫猫云梯是车"));
        assert!(guide.contains("DeepSeek"));
        assert!(guide.contains("豆包"));
        assert!(guide.contains("节点与测速 → 订阅与导入"));
        assert!(guide.contains("分流与连接"));
        assert!(guide.contains("状态 5：基础已全通"));
        assert!(guide.contains(".zip"));

        let exported_onboarding = export_agent_docs(ONBOARDING_DOC_ID, false).unwrap();
        assert_eq!(exported_onboarding, guide);

        // Legacy module_id aliases must still resolve cleanly.
        assert_eq!(get_agent_doc("probes").unwrap().module_id, NODES_PROBES_DOC_ID);
        assert_eq!(
            get_agent_doc("nodes_ingest").unwrap().module_id,
            NODES_PROBES_DOC_ID
        );
        assert_eq!(
            get_agent_doc("network_reload").unwrap().module_id,
            NETWORK_LIFECYCLE_DOC_ID
        );
        assert_eq!(
            get_agent_doc("updater_lifecycle").unwrap().module_id,
            NETWORK_LIFECYCLE_DOC_ID
        );
        assert!(export_agent_docs("nonexistent_module", false).is_err());

        // Verify required chapters include key Stage 14 contracts and R11 updates.
        let preaccel_md = export_agent_docs(PREACCEL_DOC_ID, false).unwrap();
        assert!(preaccel_md.contains("mmrelay://v1/"));
        assert!(preaccel_md.contains("preaccel global-status --json"));
        assert!(preaccel_md.contains("catcloud preaccel test --speed --json"));
        assert!(preaccel_md.contains("catcloud preaccel test --speed --node-id <id> --json"));
        assert!(preaccel_md.contains("单条或全部中转真实上下行测速"));
        assert!(preaccel_md.contains("hicloud.com"));
        assert!(preaccel_md.contains("203.0.113.10"));

        let trouble_md = export_agent_docs(TROUBLESHOOTING_DOC_ID, false).unwrap();
        assert!(trouble_md.contains("JuryBu/CatCloud"));
        assert!(trouble_md.contains("catcloud net doctor --json"));
        assert!(trouble_md.contains("设置 → 网络与 DNS"));
        assert!(trouble_md.contains("设置 → 关于与更新"));
        assert!(trouble_md.contains("反馈问题到 GitHub"));
        assert!(!trouble_md.contains("设置 → 网络」"));
        assert!(!trouble_md.contains("设置 → 关于」"));
        assert!(!trouble_md.contains("反馈问题（GitHub Issue）"));

        let nodes_md = export_agent_docs(NODES_PROBES_DOC_ID, false).unwrap();
        assert!(nodes_md.contains("probe add --id custom_api --name"));
        assert!(nodes_md.contains("catcloud sub list --json"));
        assert!(nodes_md.contains("catcloud sub rename <id> --name <new_name> --json"));
        assert!(nodes_md.contains("catcloud sub merge --source <src_id> --target <dst_id> --json"));
        assert!(nodes_md.contains("专用客户端实时捕捉结果为空：4 条高频排查"));
        assert!(nodes_md.contains("双层加密"));

        let en_nodes = export_agent_docs_with_lang(NODES_PROBES_DOC_ID, false, "en").unwrap();
        assert!(en_nodes.contains("Live Capture Returned 0 Nodes: 4 High-Frequency Checks"));
        assert!(en_nodes.contains("double-encrypted"));

        let ja_nodes = export_agent_docs_with_lang(NODES_PROBES_DOC_ID, false, "ja").unwrap();
        assert!(ja_nodes.contains("専用クライアントのリアルタイム捕捉が空になる場合の 4 つの頻出確認点"));
        assert!(ja_nodes.contains("二重暗号化"));

        let ru_nodes = export_agent_docs_with_lang(NODES_PROBES_DOC_ID, false, "ru").unwrap();
        assert!(ru_nodes.contains("4 частые причины пустого захвата (0 узлов) из стороннего клиента"));
        assert!(ru_nodes.contains("двойным шифрованием"));

        let net_md = export_agent_docs(NETWORK_LIFECYCLE_DOC_ID, false).unwrap();
        assert!(net_md.contains("catcloud config backup"));
        assert!(net_md.contains("catcloud update stage --manifest"));
        assert!(net_md.contains("catcloud docs export --lang zh-CN --sync-dir <dir> --json"));

        let share_md = export_agent_docs(SHARE_BUNDLE_DOC_ID, false).unwrap();
        assert!(share_md.contains("catcloud share inspect friend-pack.zip --json"));

        // Verify EN / JA / RU UI labels align verbatim with ui/src/i18n/locales/*.ts.
        assert!(trouble_md.contains("AI 全权代管"));
        let en_trouble = export_agent_docs_with_lang(TROUBLESHOOTING_DOC_ID, false, "en").unwrap();
        assert!(en_trouble.contains("Settings → Network & DNS"));
        assert!(en_trouble.contains("Settings → About & Updates"));
        assert!(en_trouble.contains("Report Issue on GitHub"));
        assert!(en_trouble.contains("Nodes & Speed"));
        assert!(en_trouble.contains("Smart Groups"));
        assert!(en_trouble.contains("Rules & Conns"));
        assert!(en_trouble.contains("AI Autopilot"));

        let ja_trouble = export_agent_docs_with_lang(TROUBLESHOOTING_DOC_ID, false, "ja").unwrap();
        assert!(ja_trouble.contains("スマートグループ"));
        assert!(ja_trouble.contains("ノードと速度"));
        assert!(ja_trouble.contains("ルールと接続"));
        assert!(ja_trouble.contains("AI 自動設定"));
        assert!(ja_trouble.contains("GitHub で不具合報告"));
        assert!(ja_trouble.contains("GitHub で Issue 作成"));
        assert!(ja_trouble.contains("ネットワーク・DNS"));
        assert!(ja_trouble.contains("情報と更新"));

        let ru_trouble = export_agent_docs_with_lang(TROUBLESHOOTING_DOC_ID, false, "ru").unwrap();
        assert!(ru_trouble.contains("Умные группы"));
        assert!(ru_trouble.contains("Узлы и тест"));
        assert!(ru_trouble.contains("Правила и сети"));
        assert!(ru_trouble.contains("Ускорение 443"));
        assert!(ru_trouble.contains("ИИ-автопилот"));
        assert!(ru_trouble.contains("Сообщить на GitHub"));
        assert!(ru_trouble.contains("Создать Issue на GitHub"));
        assert!(ru_trouble.contains("Сеть и DNS"));
        assert!(ru_trouble.contains("О программе"));

        assert_eq!(describe_current_page("ai", "zh-CN").0, "AI 全权代管");
        assert_eq!(describe_current_page("ai", "en").0, "AI Autopilot");
        assert_eq!(describe_current_page("ai", "ja").0, "AI 自動設定");
        assert_eq!(describe_current_page("ai", "ru").0, "ИИ-автопилот");
    }

    #[test]
    fn web_ai_guide_and_bootstrap_prompt_lock_language_and_paths() {
        assert_eq!(normalize_doc_lang(None), "zh-CN");
        assert_eq!(normalize_doc_lang(Some("en-US")), "en");
        assert_eq!(normalize_doc_lang(Some("ja-JP")), "ja");
        assert_eq!(normalize_doc_lang(Some("ru-RU")), "ru");

        let web_zh = render_web_ai_guide(PREACCEL_DOC_ID, "zh-CN").unwrap();
        assert!(web_zh.starts_with(lang_lock_line("zh-CN")));
        let ds_pos = web_zh.find("DeepSeek").expect("DeepSeek listed");
        let gpt_pos = web_zh.find("ChatGPT").expect("ChatGPT listed");
        assert!(ds_pos < gpt_pos, "domestic Web AI must appear before overseas Web AI");

        let prompt_en = render_agent_bootstrap_prompt(
            r"C:\CatCloud\cli\catcloud.exe",
            r"C:\CatCloud\data",
            r"C:\CatCloud\data\agent_docs\en\INDEX.md",
            "preaccel",
            "en",
        );
        assert!(prompt_en.starts_with(lang_lock_line("en")));
        assert!(prompt_en.contains(r"C:\CatCloud\cli\catcloud.exe"));
        assert!(prompt_en.contains(r"C:\CatCloud\data"));
        assert!(prompt_en.contains("02-domestic-preaccel.md"));
        assert!(prompt_en.contains("Domestic Boost"));

        // Verify AgentPromptMode::from_opt_str parsing and Autopilot vs Readonly across all 4 langs.
        assert_eq!(AgentPromptMode::from_opt_str(None), AgentPromptMode::Autopilot);
        assert_eq!(
            AgentPromptMode::from_opt_str(Some("autopilot")),
            AgentPromptMode::Autopilot
        );
        assert_eq!(
            AgentPromptMode::from_opt_str(Some("readonly")),
            AgentPromptMode::Readonly
        );
        assert_eq!(
            AgentPromptMode::from_opt_str(Some("read_only")),
            AgentPromptMode::Readonly
        );
        assert_eq!(
            AgentPromptMode::from_opt_str(Some("inspect")),
            AgentPromptMode::Readonly
        );
        assert_eq!(
            AgentPromptMode::from_opt_str(Some("check")),
            AgentPromptMode::Readonly
        );

        for &lang in SUPPORTED_DOC_LANGS {
            let ro_compat = render_agent_bootstrap_prompt(
                r"C:\CatCloud\cli\catcloud.exe",
                r"C:\CatCloud\data",
                r"C:\CatCloud\data\agent_docs\INDEX.md",
                "home",
                lang,
            );
            let ro_explicit = render_agent_bootstrap_prompt_with_mode(
                r"C:\CatCloud\cli\catcloud.exe",
                r"C:\CatCloud\data",
                r"C:\CatCloud\data\agent_docs\INDEX.md",
                "home",
                lang,
                AgentPromptMode::Readonly,
            );
            assert_eq!(ro_compat, ro_explicit);

            let auto_prompt = render_agent_bootstrap_prompt_with_mode(
                r"C:\CatCloud\cli\catcloud.exe",
                r"C:\CatCloud\data",
                r"C:\CatCloud\data\agent_docs\INDEX.md",
                "home",
                lang,
                AgentPromptMode::Autopilot,
            );
            assert!(auto_prompt.starts_with(lang_lock_line(lang)));
            assert!(auto_prompt.contains("Codex / Claude Code / Antigravity"));
            assert!(auto_prompt.contains("config reload --json"));
            assert_ne!(auto_prompt, ro_explicit);

            // Both INDEX.md and 00-general-troubleshooting.md must include the local CLI locator snippet.
            let idx_md = render_lang_index_markdown(lang);
            assert!(idx_md.contains(r"CatCloud\resources\cli\catcloud.exe"));
            assert!(idx_md.contains(r".\cli\catcloud.exe"));
            let trouble_md = export_agent_docs_with_lang(TROUBLESHOOTING_DOC_ID, false, lang).unwrap();
            assert!(trouble_md.contains(r"CatCloud\resources\cli\catcloud.exe"));
            assert!(trouble_md.contains("logs tail --since"));
            let preaccel_md = export_agent_docs_with_lang(PREACCEL_DOC_ID, false, lang).unwrap();
            assert!(preaccel_md.contains("rotate_relay_secrets.mjs"));
            assert!(preaccel_md.contains("--dispatch-strategy"));
            let mg_md = export_agent_docs_with_lang(MULTIGROUP_DOC_ID, false, lang).unwrap();
            assert!(mg_md.contains("group members --id"));
        }
    }

    #[test]
    fn sync_agent_docs_to_disk_writes_tree_and_short_circuits_idempotently() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud-agent-docs-sync-{}",
            uuid::Uuid::new_v4()
        ));
        let docs_root = sync_agent_docs_to_disk(&tmp).expect("initial sync");
        assert_eq!(docs_root, tmp.join("agent_docs"));
        assert!(docs_root.join(".manifest_hash").is_file());
        assert!(docs_root.join("INDEX.md").is_file());

        for &lang in SUPPORTED_DOC_LANGS {
            assert!(docs_root.join(lang).join("INDEX.md").is_file());
            for entry in DOC_CATALOG {
                let path = docs_root.join(lang).join(entry.filename);
                assert!(path.is_file(), "missing synced doc {}", path.display());
            }
        }

        // Second sync with unchanged hash must perform 0 writes (preserve mtime on INDEX.md).
        let index_path = docs_root.join("INDEX.md");
        let mtime_before = std::fs::metadata(&index_path).unwrap().modified().unwrap();
        let hash_mtime_before = std::fs::metadata(docs_root.join(".manifest_hash"))
            .unwrap()
            .modified()
            .unwrap();
        let docs_root_2 = sync_agent_docs_to_disk(&tmp).expect("idempotent sync");
        assert_eq!(docs_root_2, docs_root);
        assert_eq!(
            std::fs::metadata(&index_path).unwrap().modified().unwrap(),
            mtime_before
        );
        assert_eq!(
            std::fs::metadata(docs_root.join(".manifest_hash"))
                .unwrap()
                .modified()
                .unwrap(),
            hash_mtime_before
        );

        // Deleting a synced file must be detected and healed on next sync.
        let target_doc = docs_root.join("zh-CN").join("02-domestic-preaccel.md");
        std::fs::remove_file(&target_doc).unwrap();
        sync_agent_docs_to_disk(&tmp).expect("healing sync");
        assert!(target_doc.is_file());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
