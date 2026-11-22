# CatCloud Agent 辅助友好指南与开放契约规范

CatCloud 从架构层面将 **AI Agent 与自动化脚本** 视为与图形界面同等重要的一等公民。本文档涵盖内置四段式人机双读文档注册表、无头 `catcloud` CLI 命令与 `--json` 契约、开放外部订阅适配器协议 `catcloud-adapter/v1` 以及外部自定义探针脚本规范。

---

## 1. 全产品「Agent 辅助友好」设计原则

1. **人机双读四段式内置文档**：CatCloud 在 `catcloud-core` 的 `agent_docs` 注册表中为全部 6 个核心子系统维护结构化指南，界面支持一键复制为 Prompt 交给 AI Agent，CLI 支持 Markdown / JSON 导出：
   - 第 1 段：**何时使用与量化触发信号**（When to Use & Quantitative Signals）
   - 第 2 段：**外部前置条件与标准 Schema**（External Prerequisites & Standard Schema）
   - 第 3 段：**GUI 路径与无头 CLI 接入验真命令**（GUI & Headless CLI Verification）
   - 第 4 段：**一键回退与排障清单**（Rollback & Troubleshooting Checklist）
2. **零 GUI 依赖的无头 CLI**：`catcloud` 独立链接 `catcloud-core`，不依赖 Tauri/WebView/GTK/WebKit，可在 Linux 服务器、容器、WSL 及 SSH 环境中直接运行。
3. **验证优先与失败零断流**：任何由外部脚本或 AI Agent 编辑的 `data/config.json` 或覆写文件，均可先通过静态与内核预检；即使直接写入磁盘触发文件监听热载，无效配置也会被原子拒载并输出结构化错误，绝不中断现役连接。
4. **原生沙箱隔离**：所有命令均支持全局 `--data-dir <PATH>` 参数，AI Agent 可在临时目录中独立演练配置、探针与策略公式，零风险影响用户主力实例。

### 内置 6 大 Agent 文档模块 ID

| 模块 ID | 覆盖范围 |
|---|---|
| `preaccel` | 国内预加速（`mmrelay/v1`、纯 IP 无 SNI、国内 204 双活、校园网防护） |
| `multigroup` | 智能多选组（4 种模式、安全 AST 公式、3 选 1 兜底与滞回回切） |
| `probes` | 零干扰隔离探针引擎（三级省流漏斗、Google 真值、自定义与脚本探针） |
| `nodes_ingest` | 多维节点库、老配置只读迁移、运行中进程只读探测与 `catcloud-adapter/v1` |
| `network_reload` | Proxy Guard、PAC、TUN、进阶 DNS、三级热加载与脱敏诊断 |
| `updater_lifecycle` | 无窗省内存态、便携隔离与下次启动安全自更新 |

---

## 2. 无头 `catcloud` CLI 与 `--json` 契约

### 全局参数与输出规范

```text
catcloud [--data-dir <PATH>] [--json] <SUBCOMMAND> [ARGS...]
```

- 传 `--json` 时，所有命令向 `stdout` 输出单份合法 UTF-8 JSON 对象（人类日志与诊断信息仅写 `stderr`），退出码 `0` 表示成功，非 `0` 表示失败。
- 机器解析信封约定：
  - `ok`: `boolean`（执行是否成功；`status`、`diag` 等还附带 `version` 字段）
  - 失败时在 `--json` 下返回包含 `ok: false` 与 `error` 描述字段的结构化 JSON，便于自动化重试或回退。

### 命令族全览

| 命令组 | 命令示例 | 说明与契约用途 |
|---|---|---|
| **运行态** | `catcloud status --json` | 返回 `ok`、`version`、`data_dir`、`is_portable`、`instance_hash`、端口与存储统计 |
| **文档导出** | `catcloud docs list --json` | 列出内置 6 大核心模块 ID、标题与摘要 |
| | `catcloud docs export <module_id\|all> --format markdown\|json` | 导出单个或全部核心模块的四段式人机双读指南 |
| **节点与源** | `catcloud node list --region TW --max-multiplier 1.0 --json` | 支持 `--sub`、`--region`、`--max-multiplier`、`--protocol`、`--only-443`、`--only-google-clean`、`--query` 筛选节点 |
| | `catcloud node import --file sub.yaml --json` | 从 `--file <PATH>` 或 `--url <URL>` 导入 Clash/Mihomo YAML（含锚点合并，上限 16 MiB）或 URI 订阅（可选 `--sub-id`、`--name`） |
| | `catcloud node migrate --scan --json` | 只读扫描常见开源客户端明文配置或解析 `--file <PATH>`，仅显式传 `--apply` 时写入节点库，绝不修改第三方目录 |
| | `catcloud node attach-process --list --json` | 只读枚举运行中代理进程（可选 `--all` 或 `--pid <PID>` 检查参数与控制口） |
| **多选组** | `catcloud group list --json` | 列出全部智能多选组配置与持久化选点状态 |
| | `catcloud group create --id grp-ai --name AI --mode sticky_best --json` | 创建或更新多选组（支持 `--formula`、`--fallback`、`--switch-mode`、`--nodes id1,id2`） |
| | `catcloud group switch <group_id> [--node <node_id>] --json` | 切换多选组持久化 `active_node_id`（可指定 `--node` 或轮换下一启用候选，随后可配合 `config reload` 同步内核） |
| | `catcloud group policy <group_id> --formula "..." --fallback degrade_best_warn --json` | 校验并更新安全 AST 公式、`--fallback`、`--switch-mode` 与可重复 `--hard-gate` 门禁 |
| | `catcloud group eval <group_id> --json` | 基于 SQLite 最新探针快照计算候选得分排行与仲裁器决策 |
| **隔离探针** | `catcloud probe list --json` | 列出内置与自定义探针定义 |
| | `catcloud probe add --id custom_api --name "Custom API Upload" --kind upload --url https://example.com/up --json` | 注册或更新自定义探针（必填 `--id`、`--name`、`--kind`、`--url`；可选 `--method`、`--expected-status`、`--regex`、`--payload-bytes`、`--timeout-ms`） |
| | `catcloud probe remove --id custom_api --json` | 按 ID 删除自定义探针定义 |
| | `catcloud probe run --tier l0\|l1\|l2\|all [--node <node_id>] [--dry-run] --json` | 定位本机 Mihomo 并拉起临时隔离核心按三级漏斗执行体检且写入 SQLite；传 `--dry-run` 仅输出计划；缺失 Mihomo 时返回 `executed: false`、`reason: "mihomo binary not found"`、`plan` 与 `download_guidance` |
| **国内预加速** | `catcloud preaccel add --file relay.mmrelay.json --json` | 从 `--file <PATH>` 或 `--uri <URI>` 导入并强校验 `mmrelay/v1` 中继配置（检查分协议空 SNI） |
| | `catcloud preaccel pool --json` | 查看国内预加速中继池配置与到期状态评估 |
| | `catcloud preaccel bind --enabled false --json` | 更新并保存 `config.json` 中的国内预加速开关、`--skip-443-native <bool>` 与国内 204 `--probe-url <URL>`（随后执行 `config reload` 生效） |
| | `catcloud preaccel test [--campus] --json` | 检验国内预加速编译计划、防环规则与国内 204 探针；传 `--campus` 时实测校园网 Captive Portal 状态 |
| **配置与诊断** | `catcloud config validate --json` | 校验 `config.json`、编译后 Mihomo YAML、端口占用与静态防环规则 |
| | `catcloud config reload [--dry-run] --json` | 经 `HotReloadCoordinator` 校验候选 `runtime.yaml`（存在本机 Mihomo 时执行 `mihomo -t`）；存在运行中控制面时调用 `PUT /configs?force=true` 热载并重放活跃选组，无运行中核心时落盘 `runtime.yaml` 并标注 `core_not_running: true, validated_and_written: true` |
| | `catcloud config compile [--output runtime-preview.yaml] --json` | 编译并输出或导出 Mihomo YAML |
| | `catcloud config export-env --shell powershell\|cmd\|bash\|fish --json` | 生成含 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY=socks5h://...` 与 `NO_PROXY` 的终端环境变量片段 |
| | `catcloud config diag --json` | 导出 100% 脱敏的系统与运行状态诊断报告 |
| **安全更新** | `catcloud update check [--repo <owner/repo>] [--offline] --json` | 经 GitHub HTTPS 白名单在线查询 `latest.json` 返回最新版本信息（失败时返回 `ok: false` 与 `error`）；传 `--offline` 时仅离线回显本地更新配置 |
| | `catcloud update stage --manifest latest.json --archive CatCloud-0.2.0-windows-x64-portable.zip --checksums SHA256SUMS.txt [--asset-name <NAME>] --json` | 校验本地 `latest.json`、`SHA256SUMS.txt` 与更新包归档后暂存至 `.update_staging/` 供下次启动应用 |

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
>     "probes": 6
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

### 最小 Node.js 适配器参考模板

```javascript
#!/usr/bin/env node
// Minimal catcloud-adapter/v1 reference script (zero dependencies)
import fs from "node:fs";

const rawInput = fs.readFileSync(0, "utf8").trim();
const req = rawInput ? JSON.parse(rawInput) : { reason: "manual", sub_id: "demo", failed_servers: [] };

const response = {
  schema: "catcloud-adapter/v1",
  nodes: [
    {
      name: `Demo-SG-443 (${req.reason}) 1x`,
      type: "trojan",
      server: "203.0.113.40",
      port: 443,
      password: "<PLACEHOLDER>",
      sni: "demo.example.invalid",
    },
  ],
};

process.stdout.write(`${JSON.stringify(response)}\n`);
```

---

## 5. 外部自定义探针脚本协议（`ProbeKind::ExternalCmd`）

除内置 6 类探针（`latency`、`upload`、`download`、`keepalive`、`google_cn`、`unlock_regex`）外，用户可注册外部脚本探针执行任意定制检测（例如特定业务 API 延迟、指定区域页面解锁或自定义上传接口）。

### `stdin` 输入（CatCloud 隔离测速核提供）

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
# 1. 拉取目标模块四段式规范，确保上下文准确
catcloud docs export multigroup --format markdown

# 2. 在沙箱目录验证自定义公式与配置合法性
catcloud --data-dir /tmp/catcloud-eval config validate --json

# 3. 触发隔离探针体检并检查分组状态
catcloud probe run --tier l1 --json
catcloud group list --json

# 4. 校验通过后执行 L2 零断流热重载
catcloud config reload --json
```
