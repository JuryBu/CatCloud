# CatCloud Agent 辅助友好指南与开放契约规范

CatCloud 从架构层面将 **AI Agent 与自动化脚本** 视为与图形界面同等重要的一等公民。本文档涵盖内置 8 篇多语言随装权威手册树、独立「AI 助手」双通道交付、无头 `catcloud` CLI 命令与 `--json` / 脱敏契约、开放外部订阅适配器协议 `catcloud-adapter/v1`、外部自定义探针脚本规范以及 `.zip` 分享包契约 `catcloud-share/v1`。

---

## 1. 全产品「Agent 辅助友好」设计原则

1. **单一权威真源 + 多语言随装手册树**：CatCloud 在 `catcloud-core::agent_docs` 中以简体中文（`zh-CN`）为权威真源、英文（`en`）为精校完整基线，并绑定日文（`ja`）与俄文（`ru`）UI 词条，维护 **8 篇详尽手册**；启动时经 `.manifest_hash` 幂等校验（内容未变零写盘）同步释放至 `<data_dir>/agent_docs/{zh-CN,en,ja,ru}/` 与 `INDEX.md`。
2. **双人群双通道（「AI 助手」独立一级菜单）**：
   - **网页 AI 通道**：把 **DeepSeek、豆包、通义千问、Kimi** 等国内直连网页 AI 排在最前（消除未翻墙前打不开海外 AI 的断网悖论），一键复制或导出自包含 `.md` + 脱敏实时状态快照；
   - **本机 Agent 通道**：复制十余行轻量 Bootstrap Prompt（首行强锁输出语言 + 当前实例精确 `catcloud(.exe)` 绝对路径 + `--data-dir` + `agent_docs/<lang>/INDEX.md` 路径 + 「先只读自查、修改前征求同意、尽量代办全流程、严禁泄露明文密钥」契约）。
3. **零 GUI 依赖与便携 CLI 向上寻址**：`catcloud` 独立链接 `catcloud-core`，不依赖 Tauri/WebView/GTK/WebKit；当便携版将其置于 `<portable_root>/cli/catcloud(.exe)` 时，会自动向上一层检测 `../portable.flag`（排除盘符根且绝不仅凭 `../data` 劫持）共享同一份 `data/` 与 `../resources/bin` 内核。
4. **全链路默认脱敏与零断流预检**：所有只读听诊与查询命令默认复用 `catcloud_core::sanitize` 自动掩码密码、UUID、Token、本机路径与非白名单 IP（敏感只读命令仅在显式传 `--reveal-secrets` 时输出明文）；外部改配置先校验再热载，失败原子拒载零断流。

### 内置 8 大权威 Agent 手册模块 ID

| 随装文件名 | 模块 ID（含兼容别名） | 覆盖范围 |
|---|---|---|
| `00-general-troubleshooting.md` | `troubleshooting` | 通用网络 6 层排障总纲、听诊 CLI 与 `JuryBu/CatCloud` 脱敏 GitHub Issue 反馈模板 |
| `01-onboarding.md` | `onboarding` | 全中文小白上手总纲（0 节点「车与油」三要素、6 大核心玩法、5 步引导节奏含基础已全通） |
| `02-domestic-preaccel.md` | `preaccel` | 国内提速从 0 到 1 实战手册（省事路线、自建买机/放行 TCP 443/SNI 留空红线/一键脚本直出 `mmrelay://v1`、全局提速） |
| `03-multigroup.md` | `multigroup` | 智能多选组（4 种模式、小白场景公式表、安全 AST 公式、3 选 1 兜底与精确位置参数命令） |
| `04-nodes-and-probes.md` | `nodes_probes`（兼容 `probes`、`nodes_ingest`） | 省流/完整/60s 保活三档零干扰测速、订阅导入、只读迁移、`1→2→3` 捕捉、组更新/改名/合并与 `catcloud-adapter/v1` |
| `05-routing-and-connections.md` | `routing_conns` | 规则/全局/直连分流、国内直连、AI 域独立分流、国内 QUIC 优先放行与实时连接排查 |
| `06-network-and-lifecycle.md` | `network_lifecycle`（兼容 `network_reload`、`updater_lifecycle`） | 系统代理、Proxy Guard、TUN、高级 DNS、三级热加载、无窗托盘省内存、`config backup/restore` 与下次启动安全更新 |
| `07-share-bundle.md` | `share_bundle` | 可勾选 `.zip` 分享包（`catcloud-share/v1`）GUI/CLI 导出导入与严禁 AI 复述明文密钥安全红线 |

---

## 2. 无头 `catcloud` CLI 与 `--json` 契约

### 全局参数与输出规范

```text
catcloud [--data-dir <PATH>] [--json] <SUBCOMMAND> [ARGS...]
```

- 传 `--json` 时，所有命令向 `stdout` 输出单份合法 UTF-8 JSON 对象（人类日志与诊断信息仅写 `stderr`），退出码 `0` 表示成功，非 `0` 表示失败。
- 机器解析信封约定：
  - 成功：`{"ok": true, ...}`
  - 失败：`{"ok": false, "error": "..."}`（`--json` 下任意校验或运行错误均输出结构化 JSON，便于自动化重试或回退）。
- 默认脱敏约定：`preaccel pool`、`node list`、`node migrate --scan`、`node attach-process`、`sub list`、`net doctor`、`net connections`、`logs tail`、`config compile`、`config diag`、`share import --dry-run` 等只读输出默认自动脱敏；仅在明确需要且安全受控时，敏感只读命令支持显式传入 `--reveal-secrets`。

### 命令族全览

| 命令组 | 命令示例 | 说明与契约用途 |
|---|---|---|
| **运行态** | `catcloud status --json` | 返回 `ok`、`version`、`data_dir`、`is_portable`、`instance_hash`、端口、全局提速状态与存储统计 |
| **文档导出** | `catcloud docs list [--lang zh-CN\|en\|ja\|ru] --json` | 列出内置 8 大权威模块 ID、标题与摘要 |
| | `catcloud docs export <module_id\|all> --format markdown\|json [--lang zh-CN\|en\|ja\|ru] [--sync-dir <PATH>]` | 导出单个（支持旧别名）或全部模块，或按需同步落盘多语言 `agent_docs/` 手册树 |
| **听诊与日志** | `catcloud net doctor --json` | 分层只读体检（物理/校园网、冲突代理与环境变量、端口占用、核心与国内提速健康） |
| | `catcloud net connections --json` | 只读拉取当前活跃连接摘要（默认脱敏） |
| | `catcloud net match <domain> --json` | 模拟评估指定域名命中的分流规则与目标策略组 |
| | `catcloud logs tail [--lines 80] [--level warning] --json` | 读取最近已脱敏应用与核心日志行 |
| **订阅组** | `catcloud sub list --json` | 列出全部已导入订阅组与流量/到期统计（默认脱敏订阅 URL） |
| | `catcloud sub rename <sub_id> --name "新名称" --json` | 原地重命名已有订阅组（不改变组 ID 与多选组绑定） |
| | `catcloud sub merge --source <src_sub_id> --target <dst_sub_id> --json` | 事务级合并两个订阅组（按指纹去重、迁探针记录并重映射单节点/多选组引用） |
| | `catcloud sub refresh <sub_id> --json` | 刷新指定订阅组（直连失败自动代理回退，0 节点或异常原子拒载） |
| | `catcloud sub remove <sub_id> --json` | 安全移除指定订阅组及其归属节点 |
| **节点与源** | `catcloud node list --region TW --max-multiplier 1.0 --json` | 支持 `--sub`、`--region`、`--max-multiplier`、`--protocol`、`--only-443`、`--only-google-clean`、`--query` 筛选节点（默认脱敏） |
| | `catcloud node import --file sub.yaml --json` | 从 `--file <PATH>` 或 `--url <URL>` 导入 Clash/Mihomo YAML（上限 16 MiB）或 URI 订阅 |
| | `catcloud node migrate --scan --json` | 只读扫描常见开源客户端明文配置或解析 `--file <PATH>`，仅显式传 `--apply` 时写入节点库 |
| | `catcloud node attach-process --list --json` | 只读枚举运行中代理进程（可选 `--all` 或 `--pid <PID>` 检查参数与控制口） |
| **多选组** | `catcloud group list --json` | 列出全部智能多选组配置与持久化选点状态 |
| | `catcloud group create --id grp-ai --name AI --mode sticky_best --json` | 创建或更新多选组（支持 `--formula`、`--fallback`、`--switch-mode`、`--nodes id1,id2`） |
| | `catcloud group switch <group_id> [--node <node_id>] --json` | 切换多选组持久化 `active_node_id`（位置参数 `<group_id>`，可指定 `--node` 或轮换下一启用候选） |
| | `catcloud group policy <group_id> --formula "..." --fallback degrade_best_warn --json` | 校验并更新安全 AST 公式、`--fallback`、`--switch-mode` 与可重复 `--hard-gate` 门禁 |
| | `catcloud group eval <group_id> --json` | 基于最新测速快照计算候选得分排行与仲裁器决策 |
| **零干扰测速** | `catcloud probe list --json` | 列出内置 9 项与自定义探针定义 |
| | `catcloud probe add --id custom_api --name "Custom API Upload" --kind upload --url https://example.com/up --json` | 注册或更新自定义探针（必填 `--id`、`--name`、`--kind`、`--url`） |
| | `catcloud probe remove --id custom_api --json` | 按 ID 删除自定义探针定义 |
| | `catcloud probe run --tier l0\|l1\|l2\|all [--node <node_id>] [--dry-run] --json` | 拉起临时沙箱测速核执行三档漏斗体检并落库；缺失 Mihomo 时返回 `executed: false` 与官方下载指引 |
| **国内提速** | `catcloud preaccel add --file relay.mmrelay.json --json` | 从 `--file <PATH>` 或 `--uri <URI>` 导入并强校验 `mmrelay/v1` 中继配置（强制核验空 SNI） |
| | `catcloud preaccel pool --json` | 查看国内提速中继池配置与到期状态评估（默认脱敏 `server` 与 `password`） |
| | `catcloud preaccel bind --enabled false --json` | 更新国内提速开关、`--skip-443-native <bool>` 与国内 204 `--probe-url <URL>` |
| | `catcloud preaccel test [--campus] [--speed] [--node-id <id>] --json` | 检验国内提速编译计划、防环规则与国内 204 探针；传 `--campus` 实测校园网认证；传 `--speed` 经独立临时核心逐条实测每条国内中转的真实上传/下载 Mbps 并落库 |
| | `catcloud preaccel global-status --json` | 检查独立底层全局国内提速开关、作用域、WinDivert 就绪态与提权状态 |
| **分享包** | `catcloud share export --output friend.zip --name "朋友分享包" --nodes id1,id2 --relays r1 --json` | 将勾选节点与/或国内提速中转打包为 `catcloud-share/v1` `.zip`（自动剥离原订阅 URL、本机路径、测速缓存与密钥） |
| | `catcloud share inspect friend.zip --json` | 只读脱敏预览 `.zip` 分享包清单、节点数与中转数（不落盘、不回显明文密钥） |
| | `catcloud share import --file friend.zip [--dry-run\|--apply] --json` | 预览（默认脱敏）或安全导入 `.zip` 分享包（防路径穿越、拒符号链接、`<= 16 MiB` 实测解压上限、中转指纹去重防覆盖） |
| **配置与备份** | `catcloud config validate --json` | 校验 `config.json`、编译后 Mihomo YAML、端口占用与静态防环规则 |
| | `catcloud config reload [--dry-run] --json` | 经热载协调器校验候选 `runtime.yaml`（存在本机 Mihomo 时执行 `mihomo -t`），在线则热载并重放选组 |
| | `catcloud config compile [--output runtime-preview.yaml] --json` | 编译并输出或导出 Mihomo YAML（stdout 默认脱敏） |
| | `catcloud config backup --output backup.json --json` | 导出带 SHA-256 完整性校验的配置快照备份 |
| | `catcloud config restore --file backup.json --json` | 校验完整性并原子恢复配置快照备份 |
| | `catcloud config export-env --shell powershell\|cmd\|bash\|fish --json` | 生成含 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY=socks5h://...` 与 `NO_PROXY` 的终端环境变量片段 |
| | `catcloud config diag --json` | 导出 100% 脱敏的系统与运行状态诊断报告 |
| **安全更新** | `catcloud update check [--repo <owner/repo>] [--offline] --json` | 经 GitHub HTTPS 白名单在线查询 `latest.json` 返回最新版本信息；传 `--offline` 仅回显本地更新配置 |
| | `catcloud update stage --manifest latest.json --archive CatCloud-0.2.0-windows-x64-portable.zip --checksums SHA256SUMS.txt [--asset-name <NAME>] --json` | 校验本地清单、校验和与压缩包后暂存至 `.update_staging/` 供下次启动应用 |

> **CLI 状态示例（`catcloud status --json`）**：
> ```json
> {
>   "ok": true,
>   "version": "0.1.0",
>   "data_dir": "/home/<USER>/.local/share/catcloud",
>   "is_portable": false,
>   "instance_hash": "a1b2c3d4",
>   "proxy_mode": "rule",
>   "mixed_port": 7890,
>   "controller_addr": "127.0.0.1:9090",
>   "dns_listen_addr": "127.0.0.1:1053",
>   "preaccel_enabled": false,
>   "counts": {
>     "subscriptions": 0,
>     "nodes": 0,
>     "multi_groups": 0,
>     "preaccel_relays": 0,
>     "probes": 9
>   }
> }
> ```

---

## 3. 安全 AST 评分公式参考（供 Agent 编排策略）

CatCloud 内置零 `eval` 递归下降公式求值器（线性复杂度 $O(L)$，最大表达式长度 `2048`，最大递归深度 `64`，内置除零与 `NaN`/`Inf` 保护）：

- **可用标量**：`up_mbps`、`down_mbps`、`ping_ms`（别名 `latency_ms`）、`jitter_ms`、`loss_pct`、`multiplier`、`keepalive_ok`、`google_clean`、`unlocked`、`is_443_native`、`ok`
- **内置纯函数**：`min(a, b)`、`max(a, b)`、`clamp(x, lo, hi)`、`if(cond, then_val, else_val)`、`abs(x)`
- **按自定义探针 ID 寻址**：`probe_up("probe_id")`、`probe_down("probe_id")`、`probe_ping("probe_id")`、`probe_ok("probe_id")`、`site_unlocked("site_name")`
- **默认内置模板**：
  - 低倍率性价比优先：`(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)`
  - 纯性能最快：`up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1`

---

## 4. 开放外部订阅适配器协议：`catcloud-adapter/v1`

当用户需要接入自定义节点源或由本地运维脚本动态维护节点清单时，可为订阅配置类型为 `process_adapter` 的外部可执行命令槽位。CatCloud 严格保持主仓库开放中立，仅通过标准 `stdin` / `stdout` JSON 协议与用户自维护脚本交互。

### 安全与限流护栏
- **防风暴冷却**：`min_refresh_cooldown_sec >= 60`，防止故障切换期间高频反复拉起外部脚本；
- **执行超时与体量上限**：带严格进程超时与 `16 MiB` `stdout` 限体；
- **零节点原子保护**：若脚本返回非零退出码、畸形 JSON 或 `0` 个有效节点，CatCloud 拒绝覆盖并完整保留现有节点池与用户自建规则。

### `stdin` 请求载荷（CatCloud → Adapter）

```json
{
  "reason": "manual",
  "sub_id": "sub-custom-pool",
  "failed_servers": ["198.51.100.20:443"]
}
```

- `reason` 取值：`"manual"` | `"scheduled"` | `"failover"`
- `failed_servers`：近期探针判定连续失败的节点地址列表（可供适配器按需刷新失效入口）

### `stdout` 响应载荷（Adapter → CatCloud）

```json
{
  "schema": "catcloud-adapter/v1",
  "nodes": [
    {
      "name": "Example-JP-01 1x",
      "type": "trojan",
      "server": "198.51.100.20",
      "port": 443,
      "password": "<PLACEHOLDER>",
      "sni": "example.invalid"
    }
  ],
  "yaml": ""
}
```

- `schema` 必须严格等于 `"catcloud-adapter/v1"`；
- `nodes`（Clash/Mihomo 代理对象数组）与 `yaml`（完整 Clash YAML 字符串）至少提供其一，二者同在时合并去重并进入 L2 预检热载。

---

## 5. 外部自定义探针脚本协议（`ProbeKind::ExternalCmd`）

除内置 6 类探针（`latency`、`upload`、`download`、`keepalive`、`google_cn`、`unlock_regex`）外，用户可注册外部脚本探针执行任意定制检测（例如特定业务 API 延迟、指定区域页面解锁或自定义上传接口）。

### `stdin` 输入（CatCloud 沙箱测速核提供）

```json
{
  "proxy_http": "http://127.0.0.1:41234",
  "proxy_socks5h": "socks5h://127.0.0.1:41234",
  "node_id": "node-jp-01",
  "probe_id": "probe-custom-api",
  "timeout_ms": 8000
}
```

> 请始终使用 `proxy_http`（HTTP CONNECT）或 `proxy_socks5h`（远程解析 DNS），避免本地 DNS 泄漏或受现役 TUN Fake-IP 影响。

### `stdout` 输出（上限 `256 KiB`）

```json
{
  "ok": true,
  "latency_ms": 142.5,
  "up_mbps": 18.4,
  "down_mbps": 96.2,
  "detail": "HTTP 200 OK"
}
```

---

## 6. 典型 AI Agent 协同工作流示例

```bash
# 1. 先做只读自查（默认脱敏），并按需阅读随装 agent_docs/<lang>/INDEX.md
catcloud status --json
catcloud net doctor --json
catcloud docs export preaccel --lang zh-CN --format markdown

# 2. 在沙箱目录验证自定义公式与配置合法性
catcloud --data-dir /tmp/catcloud-eval config validate --json

# 3. 触发省流测速并试算分组排序
catcloud probe run --tier l1 --json
catcloud group eval grp-ai --json

# 4. 征得用户同意后执行 L2 零断流热重载
catcloud config reload --json
```
