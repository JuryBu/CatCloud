# 猫猫云梯（CatCloud）

**面向现代开发与 AI 工作流的跨平台智能代理桌面客户端与无头 CLI**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB.svg)](https://v2.tauri.app/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/JuryBu/CatCloud/releases)

> **English Quick Overview**: **CatCloud** is a performance-focused, extensible, Agent-friendly, and highly personalizable cross-platform intelligent proxy desktop client (Windows / macOS / Linux) and headless CLI (`catcloud`). Built with a decoupled **Forwarding Engine (Mihomo) × Rust Control Brain (`catcloud-core`) × Destroyable Desktop UI (Tauri v2 + React 19)** architecture, CatCloud achieves a `<= 70 MB` windowless tray memory budget, zero-interference isolated probing, per-site smart multi-node orchestration with safe AST scoring formulas, domestic `:443` pre-acceleration chaining, and zero-GUI Linux CLI operation.

---

## 核心理念

1. **极致优化（Performance First）**：通过可销毁 WebView 窗口架构实现纯无窗托盘态 `<= 70 MB` 常驻内存、三档自适应 Mihomo `GOMEMLIMIT` 内存封顶、零重型 UI/图表库（纯原生 SVG 环形缓冲区波形）、以及基于 OS 原生机制的 `500 ms` 零僵尸子进程回收。
2. **高度可扩展（Extensible by Design）**：内嵌核心适配抽象（`CoreAdapter`）、可动态注册的隔离探针注册表（`ProbeRegistry`，支持 7 类内置与外部脚本探针）、无 `eval` 安全 AST 评分公式引擎，以及开放的外部订阅适配器协议 `catcloud-adapter/v1`。
3. **Agent 辅助友好（Agent-First Tooling）**：全核心模块内置四段式人机双读指南（何时启用 / 前置契约 / GUI 与 CLI 验真 / 回退排障），配套零 GUI 依赖的无头 `catcloud` CLI（统一 `--json` 输出）与三级配置热加载防断流机制。
4. **一切皆可个性化（Personalizable Experience）**：支持按时段三段自动昼夜主题切换（暖纸浅色 / 深苔暖金 / 午夜星蓝）、自定义壁纸与受控局部毛玻璃、全局与分项动效开关、多套可自定义托盘状态图标映射及独立轻量悬浮胶囊窗。

---

## 核心特性亮点

### 智能多选组与安全 AST 公式引擎
- **四种按站点独立模式**：`sticky_best`（AI 专线默认粘性锁定防 IP 跳变）、`conditional_pool`（按倍率/地区/干净度动态纳新）、`load_balance_consistent_hash` 与 `load_balance_round_robin`（经硬门禁过滤后的受控均衡）。
- **无 `eval` 安全递归下降公式引擎**：支持主探针标量（`up_mbps`、`down_mbps`、`ping_ms`、`jitter_ms`、`loss_pct`、`multiplier`、`keepalive_ok`、`google_clean`）及按探针 ID 寻址函数（`probe_up("id")`、`probe_ping("id")`、`probe_ok("id")`）。内置「低倍率性价比优先」与「纯性能最快」两套开箱模板。
- **全员低于门槛三选一兜底**：
  - `degrade_best_warn`（默认）：保留最高分合规节点不断网并缩短复检间隔；
  - `cross_pool_escalate`：自动临时借道备用池，后台低频探活主池并在主池连续达标恢复后滞回自动切回，避免长期消耗高倍率流量；
  - `strict_circuit_break`：全员未通过关键合规门禁时立即切至内置 `REJECT` 槽位并按组断开旧连接。
- **按组独立旧连接处置**：支持 `force_close_old`（精准断开当前组僵尸长连接，不影响其他业务组）与 `graceful_new_only`。

### 零干扰临时隔离探针引擎
- **现役业务零断流**：测速按需拉起临时隔离 Mihomo 子进程（严格仅监听 `127.0.0.1`、`tun.enable: false`、`redir-host` + 直连物理 DNS 防现役 TUN Fake-IP 污染、`GOMEMLIMIT=32MiB`），测完立即销毁回收。
- **三级省流漏斗**：`L0` 延迟/抖动/丢包 → `L1` Google 侧真值区域检测（避免仅凭 CDN 差异误杀正常海外节点）与 AI/自定义正则站点解锁 → `L2` 真实上下行吞吐（`512 KB` 慢链路快速熔断省流）与 `20s / 40s / 60s` 静默 Keep-Alive 黑洞复检。
- **动态可扩展**：支持 GUI/CLI 增删自定义 HTTP 探针及外部可执行脚本探针（`external_cmd`）。

### 国内预加速技术（Domestic Pre-Acceleration）
- 针对非 `:443` 端口跨境单流上行受限场景，通过前端国内纯 IP 无 SNI `:443` 中继链（`dialer-proxy`）显著改善长连接与大体积上传吞吐。
- **底层全局国内预代理（免开代理/免开 TUN）**：支持在不启动 CatCloud 自身代理与虚拟网卡的情况下，通过独立轻量 `:443` 双活隧道与 Windows 按需加载官方签名 WinDivert 透明重定向（macOS / Linux 提供独立本地 `socks5h://` 入口），直接为其他代理软件与 SSH/SCP 工具提供底层 `:443` 提速，并实现首页、悬浮胶囊、国内提速页与系统托盘四端实时联动。
- 内置 `mmrelay/v1` JSON 与单行 `mmrelay://v1/<base64url>` 剪贴板格式导入、分协议无 SNI 强校验（Trojan/AnyTLS `sni` 与 VLESS `servername`）、原生 443 节点智能跳过、国内 204 双活秒切、自动防环规则生成与高校校园网 Captive Portal 防假连。
- 详见 [docs/DOMESTIC_PREACCEL.md](./docs/DOMESTIC_PREACCEL.md)。

### 全面专业网络控制与实时监控
- 首页内置 10 分钟原生 SVG 流量波形（定长 300 点 `Float64Array` 环形缓冲）、上传/下载速率与累计流量、活跃连接数、实时内核内存、自定义快捷网站测活与脱敏出口信息卡。
- 完整支持系统代理、PAC 模式、Proxy Guard 守护、TUN 虚拟网卡（`mixed / system / gvisor`）、核心与 DNS IPv6 独立开关、完整进阶 DNS 与 Fallback Filter、UWP 回环解除工具、GeoIP/GeoSite/MMDB/ASN 独立与一键更新、YAML Merge Patch 覆写管线、实时日志流与按进程/域名单条踢断连接。

---

## 与传统代理客户端对比

| 维度 | 传统桌面代理客户端（Electron / 常驻 WebView） | 猫猫云梯（CatCloud） |
|---|---|---|
| **后台托盘内存** | 窗口隐藏后常驻完整渲染进程，通常 `400 ~ 800 MB` | 关窗即销毁 WebView，纯无窗托盘态 **`<= 70 MB`**，唤醒 `< 600 ms` |
| **节点测速方式** | 常复用现役核心或简单 HTTP Ping，难以识别上行限速与静默断流 | 临时隔离核心 + `redir-host` 防污染，支持真实上下行、Keep-Alive 与自定义解锁探针 |
| **选点与均衡** | 手动选点或全局黑盒均衡，易出现 IP 跳变或混入受限出口 | 按站点 4 种模式、安全 AST 公式打分、滞回防抖与 3 选 1 兜底自动回切 |
| **热加载与防断流** | 外部修改配置常需整体重启或导致现役连接全断 | L1/L2/L3 三级热加载 + `300 ms` 防抖去重 + 静态/内核预检拒载 + 选组态重放 |
| **自动化与 AI 协同** | 强耦合图形界面，无统一机器可读协议 | 原生无头 `catcloud` CLI（Linux 零 GTK/WebKit）、`--json` 输出与四段式 Agent 文档 |
| **进程与更新治理** | 异常退出偶留僵尸内核进程；便携版更新易遇文件锁冲突 | OS 原生 JobObject / `PR_SET_PDEATHSIG` 零僵尸回收 + 便携版同卷换轨自动回滚 |

---

## 安装模式与绿色便携模式

CatCloud 在 Windows、macOS 与 Linux 上提供完整安装包与便携形态，运行时数据目录按严格优先级解析：

1. 命令行参数 `--data-dir <PATH>`（最高优先级，支持多实例隔离运行）
2. 环境变量 `CATCLOUD_DATA_DIR`
3. 便携标记：可执行文件同级目录存在 `portable.flag` 或 `data/` 目录时自动进入便携模式，将配置、SQLite 数据库、日志、内核二进制与 WebView2 用户数据全部收敛至 `data/` 子目录
4. 平台标准应用数据目录：
   - Windows: `%APPDATA%\CatCloud`
   - macOS: `~/Library/Application Support/CatCloud`
   - Linux: `$XDG_DATA_HOME/catcloud`（默认 `~/.local/share/catcloud`）

- **单实例按数据目录隔离**：通过规范化 `data_dir` 的 SHA-256 前 8 位生成独立实例锁，主力实例与独立 `--data-dir` 测试实例互不冲突。
- **下次启动自动更新**：消费 GitHub Releases 的 `latest.json` 与 `SHA256SUMS.txt`（严格每跳 HTTPS 白名单校验），Windows 绿色便携版采用同卷 `.exe.old` 换轨与延迟清理，严格保护 `data/`、`portable.flag` 与 `*.sqlite*` 不被覆盖，任意步骤异常自动从 `.update_backup/` 全量回滚。

---

## 国内预加速概览

```text
应用流量 -> CatCloud 本地代理 -> 业务节点 (dialer-proxy)
                                    │
                                    ▼
                        ⚡ 国内预加速入口 (select)
                                    │
                                    ▼
                     🔄 预加速自动双活 (fallback, lazy: false)
                        ├── 主用国内 :443 纯 IP 无 SNI 中继
                        └── 备用国内 :443 纯 IP 无 SNI 中继
                                    │
                       (国内 204 探针健康监测 + 自动防环)
```

完整协议规范（`mmrelay/v1`）、纯 IP 无 SNI 安全说明与高校校园网 Captive Portal 防护请阅读 [docs/DOMESTIC_PREACCEL.md](./docs/DOMESTIC_PREACCEL.md)。

---

## 无头 `catcloud` CLI 速览

`catcloud` 是独立编译的纯 Rust 无头命令行工具，Linux 发布包通过 CI `ldd` 强制门禁验证**零 GTK / WebKit 共享库依赖**，适合服务器、WSL、SSH 终端与 AI Agent 自动化调用。

```bash
# 查看运行状态、便携模式与隔离实例哈希
catcloud status --json

# 指定独立数据目录（隔离多实例）
catcloud --data-dir /tmp/catcloud-sandbox status --json

# 导出内置四段式人机双读 Agent 指南（支持 markdown / json）
catcloud docs export preaccel --format markdown
catcloud docs export all --format json

# 常用管理与验证命令（详见 docs/AGENT_GUIDE.md）
catcloud config validate --json
catcloud config reload --json
catcloud node list --region TW --max-multiplier 1.0 --json
catcloud group list --json
catcloud preaccel test --json
catcloud update check --json
```

完整 CLI 契约、`--json` 输出规范与 `catcloud-adapter/v1` 外部适配器开发指南请参阅 [docs/AGENT_GUIDE.md](./docs/AGENT_GUIDE.md)。

---

## 从源码构建与开发

### 前置依赖
- **Rust**：`1.92+`（见 [`rust-toolchain.toml`](./rust-toolchain.toml)）
- **Node.js**：`20+`（推荐 `22 LTS`）与 **pnpm** `10.30.3`
- **Linux 桌面构建额外系统库**：`libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`, `libssl-dev`, `libxdo-dev`（仅构建无头 `catcloud-cli` 时**无需**上述 GUI 依赖）

### 常用开发命令

```bash
# 1. 安装前端依赖并验证构建
pnpm install --frozen-lockfile
pnpm build

# 2. 拉取并校验当前平台对应的官方 Mihomo 二进制（写入 src-tauri/resources/bin/）
node scripts/release/fetch_mihomo.mjs

# 3. 运行 Rust Workspace 测试（受控并发）
CARGO_BUILD_JOBS=2 cargo test --workspace

# 4. 构建无头 CLI
cargo build --release -p catcloud-cli --bin catcloud

# 5. 运行桌面开发模式或生产打包
pnpm exec tauri dev
pnpm exec tauri build

# 6. 提交前运行公开仓脱敏门禁与脚本语法检查
pnpm check:sanitize
node --check scripts/release/*.mjs
```

### 发布产物矩阵（GitHub Actions）

打入 `v*` Tag 或通过 `workflow_dispatch` 触发 [`.github/workflows/release.yml`](./.github/workflows/release.yml) 后，流水线将自动产出并校验以下产物，并生成 `SHA256SUMS.txt`、`latest.json` 与 Draft GitHub Release：

- **Windows (`x86_64` / `aarch64`)**：`.msi`、NSIS `-setup.exe`、绿色便携 `-portable.zip`（内置 `portable.flag` 与 `resources/bin/mihomo.exe`）、`catcloud-windows-<arch>.zip`
- **macOS (`aarch64` / `x86_64`)**：`.dmg`、`.app.tar.gz`、`catcloud-macos-<arch>.tar.gz`
- **Linux (`x86_64`)**：`.AppImage`、`.deb`、`.rpm`、`catcloud-linux-x86_64.tar.gz`（含 `ldd` 零 GTK/WebKit 门禁断言）

---

## 文档导航

- [系统架构与三态内存治理](./docs/ARCHITECTURE.md)
- [Agent 辅助友好指南、CLI 契约与 Adapter 规范](./docs/AGENT_GUIDE.md)
- [国内预加速技术与校园网 Captive Portal 防护](./docs/DOMESTIC_PREACCEL.md)
- [更新日志（CHANGELOG）](./CHANGELOG.md)

---

## 贡献与行为规范

欢迎通过 Issue 与 Pull Request 参与改进：
- 所有提交须通过公开仓脱敏检查（`node scripts/ci/check_public_sanitization.mjs`），禁止提交任何个人路径、真实订阅链接、私有密钥或非 RFC 5737 示例公网 IP；
- 禁止在主仓库引入任何第三方闭源商业客户端的逆向或私有解密逻辑，动态源接入请统一使用公开的 `catcloud-adapter/v1` 槽位。

## 开源许可

本项目基于 [MIT License](./LICENSE) 开源。
