# 猫猫云梯（CatCloud）

**面向日常使用、校园网与 AI 开发工作流的跨平台智能代理桌面客户端与无头 CLI**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB.svg)](https://v2.tauri.app/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/JuryBu/CatCloud/releases)

> **English Quick Overview**: **CatCloud** is a performance-focused, extensible, Agent-friendly, and highly personalizable cross-platform intelligent proxy desktop client (Windows / macOS / Linux) and headless CLI (`catcloud`). Built with a decoupled **Forwarding Engine (Mihomo) × Rust Control Brain (`catcloud-core`) × Destroyable Desktop UI (Tauri v2 + React 19)** architecture, CatCloud delivers a `<= 70 MB` windowless tray memory footprint, zero-interference isolated probing, smart per-site multi-node orchestration, domestic `:443` pre-acceleration (AnyTLS / Hysteria2 / Trojan / VLESS), campus-network DoH-443 protection, one-click `.zip` share bundles, and a built-in AI assistant with four-language guides.

---

## 下载与内测快速上手

前往 [GitHub Releases](https://github.com/JuryBu/CatCloud/releases) 下载对应平台安装包（全部桌面包均已内置官方 `mihomo` 核心与无头 `catcloud` 命令行工具，开箱即用）：

| 操作系统 | 推荐安装包 | 架构说明 | 当前实测状态 |
|---|---|---|---|
| **Windows** | `CatCloud-*-windows-x64-portable.zip`（推荐绿色便携）或 `*-setup.exe` / `*.msi` | 常见电脑选 `x64`；骁龙 ARM 选 `arm64` | **深度实测主力可用**（含高校校园网、虚拟网卡、底层全局国内提速） |
| **macOS** | `CatCloud-*-macos-aarch64.dmg`（M 系列芯片）或 `*-x64.dmg`（Intel） | Apple Silicon 选 `aarch64` | 已通过云端真机构建与自动化测试，欢迎首批内测反馈 |
| **Linux 桌面** | `CatCloud-*-linux-x86_64.AppImage` / `*.deb` / `*.rpm` | 64 位 x86_64 桌面 | 已通过云端构建与自动化测试，欢迎首批内测反馈 |
| **服务器 / 无头 CLI** | `catcloud-windows-*.zip` / `catcloud-macos-*.tar.gz` / `catcloud-linux-x86_64.tar.gz` | Linux 零 GTK/WebKit 依赖 | 全平台自动化门禁验证通过 |

> 提示：若国内直连下载 GitHub Releases 较慢，可请朋友直接转传对应平台安装包，下载后对照发布页里的 `SHA256SUMS.txt` 核验完整性即可。

### 首次运行安全提示放行说明
- **Windows**：当前内测包暂未购置商业代码签名证书。首次双击若弹出 Windows SmartScreen 蓝色提示框，点击 **「更多信息」→「仍要运行」** 即可。使用绿色便携版时请先完整解压到可写目录再运行 `CatCloud.exe`。
- **macOS**：当前内测包尚未做 Apple Developer ID 公证，且 `CatCloud.app` 内部包含随包 `mihomo` 核心与 `catcloud` CLI。将应用拖入「应用程序」后，**推荐在终端执行一次以下命令统一移除主程序与内置二进制的隔离属性**：
  ```bash
  xattr -dr com.apple.quarantine /Applications/CatCloud.app
  ```
  （注：macOS 15 Sequoia 及以上已取消 Finder 右键直接放行未签名应用；如系统仍有拦截，请在「系统设置 → 隐私与安全性」底部点击「仍要打开」。）
- **管理员权限说明**：仅开启系统代理（浏览器等）无需管理员权限；开启 **「虚拟网卡（接管全部桌面应用与 IDE）」** 或 Windows 下点击 **「开启国内提速」** 启用底层全局透明提速时，界面会明确提示并在你点击确认后拉起系统提权。

### 30 秒上手路径（小白 / 朋友内测推荐）
1. **收到朋友发的 `.zip` 分享包**：打开左侧 **「节点与测速 → 订阅与导入」**，在「已导入订阅」标题栏点击 **「导入分享包 (.zip)」**（或在 **「国内提速」** 页中转列表头部点击 **「分享包」**），选中 `.zip` 预览并一键导入（可同时导入节点与国内提速中转，自动去重且不覆盖原有线路）。需要给朋友打包导出时，在「节点与测速」主表勾选目标节点后点击顶部 **「导出已选 (.zip)」**，或在「国内提速」页点击 **「分享包」**。
2. **已有订阅链接或其它客户端**：打开 **「节点与测速 → 订阅与导入」**，粘贴订阅链接、只读迁移本机开源客户端配置，或使用 `1→2→3` 实时捕捉向导。
3. **让自己的 AI 帮你配置或排障**：点击左侧 **「AI 助手」** 一级菜单：
   - **发给网页 AI（DeepSeek / 豆包 / Kimi / ChatGPT / Gemini 等，未开启代理时优先用国内网页 AI）**：在左卡点击 **「复制新手上手指南」** 或 **「复制排障诊断包」**（亦支持 **「导出单文件 (.md)」**）直接粘贴发问；
   - **发给本机 AI Agent（Codex / Claude Code 等）**：在右卡点击 **「复制本机 Agent 引导」** 或 **「复制完整排障包」**，会自动附带随包 `catcloud` CLI 精确路径与手册树以便 Agent 自主听诊（注：Linux AppImage 运行时该路径位于临时挂载目录，仅在本次应用运行期间有效）；
   - **反馈问题与建议**：点击顶栏 **「反馈问题到 GitHub」** 或页底 **「复制脱敏摘要并打开 GitHub Issue」**（自动预填脱敏环境摘要）。

---

## 核心特性亮点

### 1. 朋友分享包（`catcloud-share/v1` 人类 & Agent 双友好 `.zip`）
- 在界面自由勾选指定节点与国内加速中转，一键导出标准 `.zip` 分享包（内置结构化清单 `manifest.json`、人类与 Agent 均可直读的 `README.md` 与去敏规范结构）。
- 导入端支持预览内容、自动指纹去重、保留本机冲突线路，并内建 Zip Slip / 符号链接 / Zip Bomb 防护；命令行同步支持 `catcloud share export / inspect / import`。

### 2. 智能多选组与常驻轻量健康池
- **四种按站点独立模式**：`sticky_best`（AI 专线默认粘性锁定防 IP 跳变）、`conditional_pool`（按倍率/地区/干净度动态纳新）、`load_balance_consistent_hash` 与 `load_balance_round_robin`。
- **无 `eval` 安全 AST 评分公式与三选一兜底**：内置「低倍率性价比优先」与「纯性能最快」模板；支持 `degrade_best_warn`、`cross_pool_escalate`（借道备用池并滞回回切）与 `strict_circuit_break`。
- **双源防半残守护**：结合 Google + Cloudflare 并发双源探活、1.5 秒失败即时复测（避免误杀）、渐进冷却恢复观察态与 EWMA 平滑防乒乓切换。

### 3. 零干扰临时隔离测速引擎
- **现役业务零断流**：按需拉起临时隔离 Mihomo 子进程（严格仅监听 `127.0.0.1`、`tun.enable: false`、`redir-host` + 纯 IP DoH 443 防现役 TUN 劫持、`GOMEMLIMIT=32MiB`），测完立即销毁回收。
- **实时流式出结果 & 真暂停保留**：支持延迟/抖动、Google 侧真值区域检测、Claude / ChatGPT（含 `ab.chatgpt.com`）/ Gemini / Windsurf 零风控语义解锁、512 KB 慢链路快速熔断上下行实测与 60 秒静默断流复检；支持按住 Ctrl 滑动多选与后台切页不中断。

### 4. 国内 `:443` 预加速与高校校园网深度适配
- **多协议支持与真实上下行测速**：支持 `AnyTLS`（空闲连接池低延迟复用）、`Hysteria2`（UDP 443 抗丢包高上行）、`Trojan` 与 `VLESS`，内置纯 IP 无 SNI 强校验、`mmrelay://v1/...` 剪贴板导入及每条中转的独立隔离上下行实测。
- **底层全局国内提速（免开猫云代理）**：即使关闭猫云系统代理与虚拟网卡，也可通过独立轻量 `:443` 隧道 + Windows 官方签名 WinDivert 透明重定向（带启动实测探测、自动防断网保护回退与安全软件放行指引）为本机其它代理软件与 SSH/SCP 提速。
- **高校校园网防阻断**：针对封杀外网明文 UDP 53 的校园网环境，默认并自动无损迁移至纯 IP 加密 DoH 443，同时为 `*.edu.cn` 与局域网后缀保留系统校内解析，配合 Captive Portal 302 检测防假连。

### 5. 独立 AI 助手、四语界面与零僵尸低内存架构
- **独立「AI 助手」一级菜单**：内置 8 篇四语（简体中文 / English / 日本語 / Русский）随装权威手册、一键脱敏诊断包与一键提交 GitHub Issue；无头 `catcloud` CLI 自动安全识别桌面端运行期控制口令，免去手动配置密码即可执行 `net doctor`、`net connections`、`net match`、`logs tail` 与热重载。
- **极简低内存与个性化体验**：可销毁 WebView 窗口架构实现关窗托盘态 `<= 70 MB` 内存、按需裁剪活跃节点 YAML、纯原生 SVG 10 分钟流量波形、三段自动昼夜主题、自定义本地壁纸、四边磁吸可缩放悬浮胶囊与全站界面偏好持久化。

---

## 与传统代理客户端对比

| 维度 | 传统桌面代理客户端（Electron / 常驻 WebView） | 猫猫云梯（CatCloud） |
|---|---|---|
| **后台托盘内存** | 窗口隐藏后常驻完整渲染进程，通常 `400 ~ 800 MB` | 关窗即销毁 WebView，纯无窗托盘态内存预算 **`<= 70 MB`**，唤醒目标 `< 600 ms` |
| **节点测速方式** | 常复用现役核心或仅测简单 Ping，难检上行限速与静默断流 | 临时隔离核心 + 纯 IP DoH 防污染，支持真实上下行、AI 语义解锁与长连复检 |
| **朋友分享与迁移** | 手工传明文订阅链接或复杂 YAML，中转与节点割裂 | 一键勾选节点 + 国内中转导出 `.zip` 分享包，人机双读、安全去重导入 |
| **校园网与弱网适应** | 明文 53 解析常被校园网阻断，普通权限开网卡易假状态 | 默认纯 IP DoH 443 + 校内系统解析 + 虚拟网卡真实权限诚实门禁 |
| **自动化与 AI 协同** | 强耦合图形界面，排障靠人工截屏 | 独立 AI 助手菜单 + 内置无头 `catcloud` CLI（自动鉴权、`--json`、默认脱敏） |
| **进程与更新治理** | 异常退出偶留僵尸内核；便携版覆盖易冲突 | OS 原生 JobObject / `PR_SET_PDEATHSIG` 零僵尸回收 + 同卷换轨自动回滚 |

---

## 安装模式与绿色便携模式

运行时数据目录按严格优先级解析：
1. 命令行参数 `--data-dir <PATH>`（最高优先级，支持多实例物理隔离）
2. 环境变量 `CATCLOUD_DATA_DIR`
3. 便携标记：可执行文件同级目录存在 `portable.flag` 或 `data/`（或从便携包 `cli/catcloud(.exe)` 启动时自动向上识别 `../portable.flag`）即进入便携模式，全部配置、数据库、日志与 WebView2 数据收敛至 `./data/`
4. 平台标准应用数据目录（Windows `%APPDATA%\CatCloud` / macOS `~/Library/Application Support/CatCloud` / Linux `~/.local/share/catcloud`）

---

## 无头 `catcloud` CLI 速览

桌面安装包与绿色便携包均已内置无头 `catcloud` CLI（Linux 版经 CI `ldd` 强制验证**零 GTK / WebKit 共享库依赖**），所有只读命令默认脱敏，适合终端与 AI Agent 协同听诊：

```bash
# 查看运行状态、权限与便携路径
catcloud status --json

# 一键分层只读听诊（自动对接桌面端运行期控制口令）
catcloud net doctor --json
catcloud net connections --limit 25 --json
catcloud net match api.openai.com --json
catcloud logs tail --lines 80 --json

# 分享包导出 / 预览 / 导入
catcloud share inspect friend-bundle.zip --json
catcloud share import friend-bundle.zip --apply --json

# 国内提速校验与真实上下行实测
catcloud preaccel pool --json
catcloud preaccel test --speed --json

# 导出内置四语权威手册
catcloud docs list --lang zh-CN --json
catcloud docs export all --format json
```

完整 CLI 契约、外部适配器与国内预加速部署指引请参阅 [docs/AGENT_GUIDE.md](./docs/AGENT_GUIDE.md) 与 [docs/DOMESTIC_PREACCEL.md](./docs/DOMESTIC_PREACCEL.md)。

---

## 从源码构建与开发

### 前置依赖
- **Rust**：`1.92+`（最低版本声明见 [`Cargo.toml`](./Cargo.toml)）
- **Node.js**：`20+`（推荐 `22 LTS`）与 **pnpm** `10.30.3`
- **Linux 桌面构建额外系统库**：`libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`, `libssl-dev`, `libxdo-dev`（仅构建无头 `catcloud-cli` 无需上述库）

### 常用开发命令
```bash
pnpm install --frozen-lockfile
pnpm build
node scripts/release/fetch_mihomo.mjs
CARGO_BUILD_JOBS=2 cargo test --workspace
cargo build --release -p catcloud-cli --bin catcloud
pnpm exec tauri build
pnpm check:sanitize
node --check scripts/release/*.mjs
```
> 说明：`pnpm exec tauri build` 使用默认的 `src-tauri/tauri.conf.json` 生成本地开发构建；如需像 GitHub Releases 一样将 `mihomo` 核心与无头 `catcloud` CLI 打包进安装包，请参考 [`.github/workflows/release.yml`](./.github/workflows/release.yml) 通过 `--config` 临时覆盖配置挂载 `resources/bin/` 与 `resources/cli/`。

---

## 开源许可

本项目采用 [MIT License](./LICENSE) 开源。欢迎提交 Issue 与 Pull Request，提交日志或配置前请确认使用应用内置的自动脱敏诊断功能，切勿公开任何私人服务器地址、订阅链接或凭据。
