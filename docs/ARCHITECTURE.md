# CatCloud 系统架构与性能治理指南

本文档面向开发者与高级用户，阐述猫猫云梯（CatCloud）的三层解耦架构、持久化与便携隔离机制、三态内存预算、三级热加载、零僵尸进程回收以及安全自更新设计。

---

## 1. 三层解耦架构

CatCloud 采用 **转发引擎 × 智能控制大脑 × 轻量可销毁界面** 三层严格解耦设计，将所有状态管理、配置编译、测速编排与平台抽象收敛在零 GUI 依赖的纯 Rust 核心库中：

```text
+-------------------------------------------------------------------+
|  Layer 3: Presentation Shells (可完全销毁 / 按需运行)                |
|  +-----------------------------+   +---------------------------+  |
|  | src-tauri + ui/ (React 19)  |   | crates/catcloud-cli       |  |
|  | - 主窗口 (关窗即 destroy)     |   | - 独立无头二进制 `catcloud` |  |
|  | - 悬浮胶囊 (独立轻量入口)     |   | - Linux 零 GTK/WebKit 依赖 |  |
|  | - 预烘焙多态系统托盘          |   | - 全命令 `--json` 机器接口  |  |
|  +--------------+--------------+   +-------------+-------------+  |
+-----------------|--------------------------------|----------------+
                  | Tauri IPC / Events             | Direct Rust API
                  v                                v
+-------------------------------------------------------------------+
|  Layer 2: Intelligent Control Brain (crates/catcloud-core)        |
|  - paths / config (原子写) / storage (SQLite WAL 6 表)             |
|  - subscription (多格式解析 / 只读迁移 / 进程只读探测 / Adapter)    |
|  - preaccel (mmrelay/v1 / 纯 IP 无 SNI 校验 / 防环 / 校园网检测)    |
|  - probe (隔离临时测速核 / 三级漏斗 / 7 类探针注册表)                |
|  - strategy (无 eval AST 公式 / 4 模式 / 3 选 1 兜底与滞回回切)     |
|  - core_adapter (CoreAdapter / Mihomo 编译 / 端口防撞 / L1-L3 热载) |
|  - platform (Win / macOS / Linux 系统代理、守护、自启、UWP)         |
|  - process_guard (JobGuard / 三路逃逸自重启 / 按 data_dir 单实例锁)  |
|  - updater (HTTPS 白名单 / SHA256SUMS / 便携版同卷换轨与回滚)       |
|  - agent_docs (6 模块四段式人机双读文档注册表)                      |
+---------------------------------+---------------------------------+
                                  | Bearer Auth REST / NDJSON Streams
                                  | + Child Process Supervision
                                  v
+-------------------------------------------------------------------+
|  Layer 1: Forwarding Engine (External Mihomo Core Binary)         |
|  - 主转发核心 (自适应 GOMEMLIMIT 48/64/96 MiB + GOGC=35)           |
|  - 临时隔离测速核 (仅 127.0.0.1 / 无 TUN / redir-host / 32 MiB)    |
+-------------------------------------------------------------------+
```

### Cargo Workspace 布局

```text
CatCloud/
├── Cargo.toml                  # Workspace 根配置 (opt-level="s", lto="thin", strip="symbols")
├── rust-toolchain.toml         # stable 工具链声明 (MSRV 1.92+, Edition 2024)
├── package.json                # 单根前端与 Tauri CLI 编排 (pnpm 10.30.3)
├── crates/
│   ├── catcloud-core/          # 零 GUI 纯 Rust 业务核心
│   └── catcloud-cli/           # 独立无头 CLI 二进制 (`catcloud`)
├── src-tauri/                  # Tauri v2 桌面壳（生命周期、托盘、快捷键、IPC）
├── ui/                         # 极轻 React 19 + Vite 7 + Tailwind CSS v4 前端
├── scripts/
│   ├── ci/                     # 公开仓脱敏门禁脚本
│   └── release/                # 官方 Mihomo 拉取、跨平台 Staging 与 latest.json 生成
└── docs/                       # 公开技术文档
```

### 外挂 Mihomo 内核解析优先级

为确保主程序与转发内核松耦合且支持免重启热替换，内核解析器按如下优先级查找 `mihomo`（Windows 为 `mihomo.exe`）：

1. 用户自定义显式路径（`config.json` 中 `core_runtime.custom_binary_path`）
2. 数据目录热替换内核（`<data_dir>/bin/mihomo(.exe)`，最高常规优先级）
3. 随包内置官方校验内核（`<app_dir>/resources/bin/mihomo(.exe)`，由 Release CI 拉取 `MetaCubeX/mihomo` 官方发布包并验证 SHA-256 后打入）
4. 缺失兜底指引（提供官方版本、SHA-256 校验与一键下载引导）

---

## 2. 三态内存硬预算与性能治理

CatCloud 严格区分三种桌面运行形态的内存口径，避免将「仅隐藏窗口的常驻 WebView」与「真正释放渲染进程的无窗托盘态」混淆：

| 运行形态 | 内存硬预算（总 Working Set） | CPU / GPU 目标 | 关键落地机制 |
|---|---|---|---|
| **纯无窗托盘省内存态** | **`<= 70 MB`**（Rust 大脑 `<= 20 MB` + Mihomo `<= 50 MB` + WebView `0 MB`） | 空载 CPU `< 0.3%`，GPU `0%` | 关闭主窗口（且悬浮胶囊未开启）时拦截关闭事件并调用异步 `WebviewWindow::destroy()` 彻底销毁 WebView2 进程树；托盘唤醒通过 `WebviewWindowBuilder::from_config` 异步重建（目标 `< 600 ms`，冷启动 `< 1.2 s`），并附带 `220 ms` 销毁冷却防 Windows `EBWebView` 用户目录锁竞争。 |
| **仅悬浮胶囊开启态** | **`<= 165 MB`** | 低占用 | 悬浮胶囊使用独立极简入口 `index.html#capsule`（300×64 透明无边框），仅承载核心状态与快捷切点；关闭胶囊即 `destroy()` 回落至 `<= 70 MB`。 |
| **完整主窗含动效态** | **`< 260 MB`**（优化目标 `< 220 MB`） | 稳态 CPU `< 1.5%` | 零 MUI / AntD / ECharts 依赖；10 分钟波形采用定长 `300` 点 `Float64Array` 环形缓冲与纯原生单 `<path>` SVG；像素吉祥物使用预裁剪精灵表与整数缩放 Canvas，页面不可见或关闭动效时 100% 清除定时器；自定义壁纸支持透明度/毛玻璃调节且无壁纸时不创建 `backdrop-filter` 合成层（推荐使用长边 `<= 1920px` 的轻量 WebP，自动离线缩放缓存列为后续迭代项）。 |
| **临时隔离测速瞬态** | **`+12 ~ 20 MB`**（测完即回落至 `0 MB`） | 短时突增 | 独立子进程显式注入 `GOMEMLIMIT=32MiB`、`GOGC=25`，关闭 TUN 与 GeoData，结束后立即终止并由 `JobGuard` 兜底回收。 |

### Mihomo 内存与吞吐平衡策略

- **三档自适应 `GOMEMLIMIT`**：根据编译后的节点数与规则规模自动选择 `48 MiB`（默认小中规模）/ `64 MiB`（中等规模）/ `96 MiB`（大规模规则集，防止频繁 GC thrashing 导致长尾延迟劣化），配合 `GOGC=35` 抑制堆膨胀。
- **按需 GeoData**：默认 `geodata-mode: false`（采用轻量 MMDB + `.mrs`）；当用户显式开启 geodata 模式时强制配置 `geodata-loader: memconservative`（流式读取），并关闭 `profile.store-selected` 与 `profile.store-fake-ip` 避免大体积无界缓存。
- **有界流式缓冲**：控制口 `/logs`、`/traffic`、`/memory` 流式订阅采用固定上限环形缓冲（日志上限 2000 条），防止长时间挂机产生内存泄漏。

---

## 3. 数据隔离、单实例锁与持久化

### 运行时目录解析优先级

启动入口在初始化 Tauri 与 WebView 之前先完成 `AppPaths::resolve`：

1. CLI `--data-dir <PATH>`
2. 环境变量 `CATCLOUD_DATA_DIR`
3. 便携模式标记：`<exe_dir>/portable.flag` 文件存在或 `<exe_dir>/data/` 目录存在
4. 操作系统标准用户数据目录（Windows `%APPDATA%\CatCloud` / macOS `~/Library/Application Support/CatCloud` / Linux `$XDG_DATA_HOME/catcloud`）

便携模式下，程序在首帧将 `WEBVIEW2_USER_DATA_FOLDER` 重定向至 `<data_dir>/webview2`，并通过 Tauri `AppDirectoryOverrides` 将 `config`、`data`、`local_data`、`cache`、`log` 严格收敛到 `<data_dir>` 子树，确保不在系统盘散落残留文件。

### 按 `data_dir` 隔离的单实例锁

CatCloud 不采用全局单实例互斥，而是对规范化后的 `canonical_data_dir` 计算 SHA-256 取前 8 位十六进制作为 `instance_hash`：

- **Windows**：创建 `Local\CatCloud_SI_<hash>` Named Mutex 与 `Local\CatCloud_Wake_<hash>` Named Event；重复启动同目录实例时仅触发 Wakeup Event 唤醒主窗并退出，而指定不同 `--data-dir` 的测试/沙箱实例可并行共存。
- **Unix (macOS / Linux)**：在 `<data_dir>/run/instance.lock` 上施加 `flock` 文件锁。
- **平滑重启宽限**：携带 `--restarting` 启动的新实例最多等待 `12 s` 接管旧实例释放的锁，确保自重启与更新换轨无缝衔接。

### 原子配置与 SQLite WAL 存储

- **`data/config.json`**：写入 `<file>.tmp.<pid>` 后执行原子 `rename`，配套带 SHA-256 完整性校验的导出/导入备份机制。
- **`data/catcloud.sqlite`**：启用 `journal_mode=WAL`、`foreign_keys=ON`、`busy_timeout=5000` 及 `PRAGMA user_version` 幂等迁移，持久化 6 张核心表：
  - `subscriptions`（订阅源、类型、流量统计、ETag、错误记录）
  - `nodes`（归一化代理节点、地区码、倍率、443 原生标记、预加速覆盖标记）
  - `probe_definitions`（内置与自定义 7 类探针定义）
  - `probe_results`（带时间戳的探测历史结果与解锁映射）
  - `multi_groups`（智能多选组模式、门禁、AST 公式、触发规则、3 选 1 兜底与跨池借道恢复态）
  - `preaccel_relays`（国内预加速跳板、协议、优先级、到期时间与最近测速指标）

---

## 4. 三级热加载与选组态保活

CatCloud 围绕「外部改配置免重启、错误配置零断流」设计了 L1 / L2 / L3 三级热加载体系：

| 级别 | 触发变更类型 | 执行路径 | 现役连接影响 |
|---|---|---|---|
| **L1（毫秒级 REST）** | 代理模式切换、手动/策略切点、按组踢断旧连接 | 直调带 `Authorization: Bearer <32B-secret>` 鉴权的 Mihomo REST API | **0 断流**（仅 `force_close_old` 按需断开目标组旧流） |
| **L2（校验后热载）** | 规则、DNS、多选组、订阅更新、国内预加速配置、YAML Merge Patch 覆写 | 文件监听触发 `300 ms` 防抖 + SHA-256 内容去重 → 配置编译 → 静态防环/空组/海外国内探针预检 → 可选 `mihomo -t -f` 校验 → 失败原子拒载，通过后原子写入 `<data_dir>/run/runtime.yaml` 并执行 `PUT /configs?force=true` | 失败 **0 断流**；成功热重载后**立即按 SQLite 持久化选组态重放 `PUT /proxies/{group}`**，消除 `store-selected: false` 下的选组重置问题 |
| **L3（仅重启内核）** | 代理/控制/DNS 端口变更、TUN 栈切换、热替换 Mihomo 内核二进制 | 通过 `port_guard` 执行 TCP + UDP 双协议冲突检测（支持自动顺延），仅数百毫秒重启 Mihomo 子进程而不重启主界面 | 仅内核重连，桌面壳与状态保持不变 |

> **强重读承诺**：在 UI 中将代理总开关执行「关闭 → 开启」时，系统强制从磁盘重新加载 `config.json` 与 SQLite 并走完整 L2 预检链，保证外部编辑的配置最坏只需开关一次代理即可生效。

### 当前实现边界说明（本地 PAC 与配置覆写管线）

- **本地 PAC 模式**：配置模型（`system_proxy.pac`）与平台适配层支持校验、生成（`http://127.0.0.1:<pac.port>/proxy.pac`）、下发与读取系统 PAC URL（如 Windows `AutoConfigURL`）；当前版本尚未内置嵌入式本地 PAC HTTP 托管服务端，开启 PAC 模式时需搭配本地或外部 PAC HTTP 服务使用，常规场景推荐直接使用系统代理配合 Mihomo 规则引擎分流。
- **配置覆写管线**：配置编译器（`core_adapter::config_compiler`）当前完整支持并执行声明式 **YAML Merge Patch**（`override_mode: merge_patch`，遵循 RFC 7396 语义、支持 `<<` 锚点展开与 `16 MiB` 限体，校验失败原子拒载不污染活跃配置）；`override_mode: script` / `override_script_path` 与 `override_script_timeout_ms` 当前仅作为配置 Schema 与静态校验字段预留，尚未启用外部覆写脚本的运行时执行器（`override_mode: both` 现阶段仅执行 `override_merge_path` 指定的 YAML Merge Patch）。

---

## 5. 零僵尸进程回收与安全自更新

### 跨平台确定性子进程回收（`JobGuard`）

- **Windows**：主进程启动即创建匿名 Win32 Job Object 并设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，将主 Mihomo 内核与所有临时测速核心子进程全部纳管（若加入 Job 失败则立即终止该子进程）；主进程正常退出、崩溃或被任务管理器强杀后，操作系统内核在 `500 ms` 内自动终止全部托管子进程。自重启或更新后重拉时通过三路 Job 逃逸机制（Direct / `CREATE_BREAKAWAY_FROM_JOB` / WMI `Win32_Process.Create`）脱离当前 Job，确保新主进程不受旧进程退出牵连。
- **Linux**：子进程在 `pre_exec` 阶段执行 `setpgid(0, 0)` 独立进程组并注册 `prctl(PR_SET_PDEATHSIG, SIGKILL)`（附 `getppid()` 竞态校验），保证父进程被 `SIGKILL` 时子进程立即随同终止。
- **macOS**：通过独立进程组终止（`SIGTERM -> SIGKILL`）与 PID 追踪文件清理双保险，确保无孤儿残留。

### 下次启动安全自更新与便携版同卷换轨

CatCloud 更新器消费 `https://github.com/JuryBu/CatCloud/releases/latest/download/latest.json` 与 `SHA256SUMS.txt`：

1. **严格传输安全**：仅允许 HTTPS `:443`、无 userinfo、主机精确命中 5 个 GitHub 官方域名白名单（`github.com`、`api.github.com`、`objects.githubusercontent.com`、`release-assets.githubusercontent.com`、`raw.githubusercontent.com`），每跳重定向请求前强制校验且上限 5 跳。
2. **元数据与压缩包防护**：拒绝 `0.0.0` 版本号，强制比对 `SHA256SUMS.txt`（恒定时间比较），限制压缩包 `<= 64 MiB`、声明与真实解压流 `<= 192 MiB`、条目数 `<= 1000`，阻断符号链接与路径穿越。
3. **用户数据绝对保留白名单**：永远跳过 `data/`、`portable.flag`、`*.sqlite*`、`*.db*`、`*.local.*`、`.update_staging/`、`.update_backup/`。
4. **Windows 绿色便携版同卷换轨**：为规避 Windows 运行中 `.exe` 的文件写锁，下次启动检测到校验通过的 `.update_staging/pending_apply.json` 后：
   - 将正在运行的 `CatCloud.exe` 同卷 `rename` 至 `.update_backup/CatCloud.exe.<old_ver>.old`；
   - 原子替换所有新程序文件（将 `version.json` 置末作为提交标记）；
   - 通过 Job 逃逸携带 `--restarting --post-update-cleanup` 启动新版本并退出旧进程，由新进程清理 `.update_backup/`；
   - 任意一步发生 I/O 或校验失败，立即逆序从 `.update_backup/` 全量回滚，保持用户数据 100% 完好。
5. **安装版与 Linux 建议**：Windows/macOS 安装版通过 `tauri-plugin-updater` 验签暂存并在下次启动应用；Linux 桌面端静默自更新主推 `.AppImage`，`.deb` / `.rpm` 用户按发行版包管理器升级。
