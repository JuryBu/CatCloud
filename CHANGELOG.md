# Changelog

All notable changes to **CatCloud** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Future post-beta iterations will be tracked here.

## [0.1.2] - 2026-11-28

> **快速选包指引（大多数 Windows 电脑请认准 `x64`，切勿误下 `arm64`）**
> - **普通 Windows 电脑（Intel / AMD，64 位）**：优先下载 `CatCloud_0.1.2_x64-setup.exe`（安装版）或 `CatCloud_0.1.2_windows-x64_portable.zip`（绿色便携版，解压即用）
> - **ARM 架构 Windows 笔记本（骁龙等）**：下载 `CatCloud_0.1.2_arm64-setup.exe` 或 `windows-arm64_portable.zip`
> - **macOS（Apple Silicon M1–M4）**：下载 `CatCloud_0.1.2_aarch64.dmg`；**Intel Mac**：下载 `CatCloud_0.1.2_x64.dmg`
> - **Linux（x86_64）**：下载 `.AppImage` / `.deb` / `.rpm`；纯终端/软路由环境可下 `catcloud-cli-*` 无头版

### 规则残留全链路根治、旧配置一键自救与静态校验聚合（修复 Issue #4）
- **导入与删除订阅全链路收口至后端事务**：统一由后端处理搬家迁移规则，导入时自动滤除指向不存在外部代理组的悬空规则并绑定订阅归属；删除订阅时自动级联清理该订阅导入的专属规则，同时完好保留用户手写规则及其他订阅共用规则；合并订阅、删改多选组与订阅刷新同步级联维护规则引用、备选池与失效节点。
- **首页聚合自救条与 `catcloud config repair-rules` 命令**：针对从旧版本遗留的失效分流规则或启动阻断报错，总览页自动弹出简洁的一键修复条（正常状态不占任何空间），支持「一键清理失效规则」「全部改为当前默认组」或交由 AI 排障；同步新增命令行 `catcloud config repair-rules --mode remove|rewrite` 并自动触发免重启热切。
- **消除误报与刷屏**：修复未开启国内提速时 `config validate` 误报 `missing_relay_direct_rule` 的问题；全站静态预检报错按类别与分组名聚合成一句中文说明，不再刷屏展示上百行重复错误。

### 跨进程免重启零断流动态配置热切（Live Hot-Swap）
- **命令行改动实时生效、不断现有连接**：新增 Windows 跨完整性级别命名事件与 Unix 文件锁跨进程热切通道，CLI 修改节点、订阅、规则或执行 `catcloud reload` 后自动通知运行中的桌面端在百毫秒级免重启平滑生效，默认保持活跃长连接不断流并写回原子确认回执；同时补强跨平台热重载回执与请求清理先后顺序。
- **手动覆盖安装自动优雅关闭旧版**：Windows 安装包升级前自动通知旧版优雅退出并回收核心进程，避免覆盖失败或残留孤儿核心；同步修复后台测速延迟顶包与单节点/多选组边界切换问题。

### 一眼会用的清爽界面与 AI 全能代办 / 提反馈体验升级
- **首开 2+1 欢迎窗与全站防晕字零阉割减法**：首次启动直接展示「继续用原梯子，只开国内提速 / 直接用猫猫云梯当主力 / 交给 AI 全程代办（配好一切 · 排障 · 提反馈）」三条清晰入口；总览页提供独立国内提速开关与一行齐平速览条，侧栏与国内提速/多选组/测速页去除工程术语噪音，高阶选项全部保留在默认折叠区。
- **AI 帮手与报错现场一键排障提 Issue**：侧栏明确展示 AI 全能代管、排障与提反馈能力；AI 帮手页顶部常驻「复制『AI 排障 + 帮提 Issue』指令」与「复制脱敏摘要并打开 GitHub Issue」卡片，新增四语排障提反馈专用提示词模板。
- **常用动线稳健性加固**：修复隐藏到托盘误销托盘热键、删光订阅重导后未自动填默认组、首页总开关记忆恢复与独立提权、0 中转状态误报、非管理员本地 SOCKS5 端口展示及设置页/校园网配置偶发覆写问题。

## [0.1.1] - 2026-11-27

> **快速选包指引（大多数 Windows 电脑请认准 `x64`，切勿误下 `arm64`）**
> - **普通 Windows 电脑（Intel / AMD，64 位）**：优先下载 `CatCloud_0.1.1_x64-setup.exe`（安装版）或 `CatCloud_0.1.1_windows-x64_portable.zip`（绿色便携版，解压即用）
> - **ARM 架构 Windows 笔记本（骁龙等）**：下载 `CatCloud_0.1.1_arm64-setup.exe` 或 `windows-arm64_portable.zip`
> - **macOS（Apple Silicon M1–M4）**：下载 `CatCloud_0.1.1_aarch64.dmg`；**Intel Mac**：下载 `CatCloud_0.1.1_x64.dmg`
> - **Linux（x86_64）**：下载 `.AppImage` / `.deb` / `.rpm`；纯终端/软路由环境可下 `catcloud-cli-*` 无头版

### 国内 `:443` 提速断流彻底根治与多云聚合升级
- **内置核心升级至官方 `Mihomo v1.19.34`**：合入上游 AnyTLS 稳定性关键修复（解决大块写入超 64 KiB 截断帧流、异常关闭竞态与关闭未中断阻塞读写等问题），发布流水线六平台校验和统一自动对齐。
- **彻底解决开启国内提速后长对话定时断流**：默认关闭中转 `tfo`（消除冷建连 2 秒级卡顿）、AnyTLS 空闲保留会话改回官方建议的 `0`（根除半开死会话复用引发的连续断流黑洞）、长连接空闲保活放宽至 `45s`、开启提速且实际套用中转时虚拟网卡 MTU 自适应收紧至 `1400`（关闭自动恢复 `1500`）、健康检查按地址自适应严格校验 `204` / `200` 状态码。
- **跨云物理机多云聚合与默认一致哈希**：自动按物理云主机去重构建多云负载均衡池，默认采用「同站一致哈希」（稳定保活 AI 长连接、跨站自动叠加多云带宽，仍支持一键切换轮询）；底层 WinDivert 改按运行指纹去重保活、多地址严格 204 轮询防误熔断；后台堆回收增加活跃代理流零打扰守卫与有界阶梯重试。
- **CLI 与桌面诊断增强**：`catcloud status --json`、`net doctor` 与桌面端 AI 诊断包增补脱敏传输参数与运行期实际命中中转/出口摘要，并新增一键轮换云端中转密钥运维脚本 `scripts/relay/rotate_relay_secrets.mjs`。

### 全站特殊窗口零重叠重塑、首启 AI 全权托管与开屏预下载更新体验
- **全站 `920×620`～`1280×800` 响应式零重叠重塑**：重构首页「组内快选」为浮层防挤压双行布局，彻底解决窄窗下节点名被挤没问题；精算「节点与测速」「节点管理」主表列宽，消灭窄窗表头/单元格文字重影叠压且保证默认 `1200×780` 窗口零横滚全列可点；智能多选组非成员卡内联化与 `<1280px` 标题栏下方右侧滑出抽屉；全站叠层统一与底中轻提示、极窄悬浮胶囊保留核心状态、全部弹窗 `620px` 矮窗完整可滚。
- **首次启动 AI 全权代管引导（仅首启触发）**：新安装首次打开自动展示醒目引导弹窗，一键复制脱敏指令即可交给任意 AI Agent 全权配置节点、测速与排障，且绝不对老用户或后续重开高频打扰；在保留全部 8 大功能页与全部高阶配置的前提下重构渐进式默认体验。
- **后台静默预下载 + 开屏询问重启 / 跳过版本删包更新弹窗**：新版本默认在后台流式校验预下载，下次打开应用时弹出清晰询问框（立即重启更新 / 稍后提醒 / 跳过此版本不再提醒并立刻清理预下载安装包），便携版支持受控换轨与防白屏回正（注：`v0.1.0 -> v0.1.1` 由旧版流程完成，自 `v0.1.1` 起向后续版本正式全面生效）。

### 软路由 / 透明网关导出、手写规则兼容、加密 DNS 与多端同步
- **一键导出给软路由 / 透明网关（桌面端 + `catcloud config export-gateway`）**：新增四语导出弹窗与命令行子命令，提供「仅国内中转与防环片段」「完整透明网关配置（OpenWrt / Linux 旁路由 TProxy，自动关闭桌面 TUN）」「优选节点 + 中转片段」三档模式，默认 AST 级脱敏预览防误发，可手动切换为含真实凭据一键复制或保存 `.yaml`。
- **完整兼容自己手写规则与内联 YAML 覆写**：分流规则页新增默认折叠高阶区，支持批量粘贴原始规则（兼容正则、`RULE-SET` 与 `AND/OR/NOT`）、一键切换「纯自写规则模式」（保留最底层防环与局域网直连，跳过内置国内/AI 规则干预并尊重自写 `MATCH`），以及直接粘贴 `rule-providers:` 等内联 YAML 覆写并在落盘前实时编译校验。
- **加密 DNS 异构备份与多端端到端加密同步**：修复单上游 DoH 证书故障与 IPv6 混合池黑洞，支持局域网互传与二维码中转同步配置（含 Android 端 `arm64-v8a` 协同基线），并同步修复社区反馈的 Issue #1/#2/#3 与 Windows 安装包架构防误装拦截。

## [0.1.0] - 2026-11-25

### Campus Network Hardening & Honest TUN Privilege Gate
- **Pure-IP DoH 443 Default & Schema v2 -> v3 Auto-Migration**: Upgraded default `default_nameserver`, `direct_nameserver`, and `proxy_server_nameserver` from plaintext UDP 53 to pure-IP DoH 443 (`https://223.5.5.5/dns-query`, `https://1.12.12.12/dns-query`) with non-destructive migration preserving custom DNS settings, solving campus networks that block outbound UDP 53 while keeping `+.edu.cn` and LAN suffixes on `system` DNS.
- **Honest Virtual NIC (TUN) Privilege Gate**: Strictly separated persisted TUN intent (`tun_configured`) from effective runtime state (`tun_enabled`) across Core, CLI, Desktop, Tray, and all four UI surfaces (Overview, Sidebar, Floating Capsule, Settings). Standard non-elevated runs never falsely report TUN active and offer one-click UAC elevation or a clean "disable TUN for now" opt-out.
- **Runtime Controller Metadata & Zero-401 CLI Stethoscope**: Added atomic restricted `data/run/runtime-controller.json` metadata (with PID liveness verification, L2 secret rotation refresh, shifted port preservation, exit/crash cleanup, and `serde_yaml_ng` `runtime.yaml` fallback) so local `catcloud net doctor`, `net connections`, `net match`, and `config reload` authenticate seamlessly against the active desktop core without exposing secrets.

### Share Bundles, AI Assistant, Multi-Language UI & Domestic Relay Upgrades
- **Friend-Friendly & Agent-Friendly `.zip` Share Bundles (`catcloud-share/v1`)**: Select arbitrary proxy nodes and domestic `:443` relays to export as a portable `.zip` with human/agent-readable `README.md` + `manifest.json`, with one-click preview, deduplicated import, and Zip-Slip/symlink/Zip-Bomb protection (GUI + `catcloud share`).
- **Dedicated AI Assistant Menu, 4-Language UI & One-Click GitHub Issue Feedback**: Promoted **AI Assistant** to a top-level sidebar menu featuring 8 four-language (`zh-CN` / `en` / `ja` / `ru`) bundled guides, one-click sanitized onboarding & troubleshooting packs (with 256-entry key-event ring), and pre-filled sanitized GitHub Issue reporting.
- **Domestic `:443` Pre-Acceleration (AnyTLS / Hysteria2 / Global WinDivert)**: Added real per-relay upload/download speed testing via isolated temporary cores (`preaccel test --speed`), `tfo: true` + `AnyTLS` idle session pooling + conservative `Hysteria2` bandwidth defaults, unified master pre-acceleration switch across Overview/Capsule/PreAccel/Tray, pure-loopback WinDivert dataplane self-test with automatic anti-disconnect fallback and deduplicated security guidance, and domestic QUIC UDP 443 allow-before-reject rules for smooth domestic IM media loading.
- **Smart Multi-Group Health Pool & Live Capture Wizard**: Added dual-origin (`gstatic` + `Cloudflare`) watchdog with 1.5s retry-before-penalize, exponential cooldown (`60s -> 180s -> 600s`), probation recovery, EWMA anti-flapping, background task persistence across route/window switches, `1->2->3` live capture wizard with PE display-name extraction, subscription rename/merge, and non-polluting golden-node view sorting.

### Cross-Platform Packaging, CI/CD & Bundled Headless CLI
- **Out-of-the-Box Multi-Platform Bundles**: Bundled official verified `mihomo` and headless `catcloud` CLI directly into Windows (MSI, NSIS, Portable ZIP with `portable.flag` & QuickStart), macOS (Apple Silicon & Intel `.dmg` / `.app.tar.gz`), and Linux (`.AppImage` / `.deb` / `.rpm`), alongside standalone zero-GTK/WebKit CLI archives, `SHA256SUMS.txt`, and `latest.json` next-launch auto-update manifests.
- **Performance & Memory Footprint**: Destroyable WebView2 windowless tray mode (`<= 70 MB` RAM budget), active-node YAML pruning (`>90%` reduction in rule mode), `geodata-loader: memconservative`, adaptive `GOMEMLIMIT`, `Global -> Rule` heap reclaim guard, and OS-native zero-zombie subprocess cleanup (`JobGuard`).
