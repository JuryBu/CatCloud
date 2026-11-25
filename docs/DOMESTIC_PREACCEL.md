# 国内提速技术（Domestic Boost）与校园网防护规范

本文档说明 CatCloud「国内提速」的技术原理、纯 IP 无 SNI `:443` 合规与安全规范、`mmrelay/v1` 标准交换契约、双活主动秒切与国内 204 探针设计、高校校园网 Captive Portal 防假连机制以及底层独立全局提速架构。

---

## 1. 背景与技术原理

在部分运营商骨干网、企业内网或校园网环境中，跨境代理流量常表现出显著的**端口特征分化**：

- 非 `443` 端口（尤其是高位随机 TCP/UDP 端口）的单流上行带宽容易遭遇限速或高重传（例如上行被压制在 `2 ~ 4 Mbps` 甚至静默卡顿），在进行大体积图片/视频上传、AI 多模态交互或代码仓库推送时极易超时断流；
- 与此同时，国内主流云机房的 TCP `:443` 标准 TLS 链路通常具备高带宽余量与稳定 RTT（可达 `50 ~ 250+ Mbps`）。

CatCloud 的 **国内提速（Domestic Pre-Acceleration）** 在客户端侧自动编排一条低延迟、可双活切换的前端国内 `:443` 中继链，将受限的非 443 跨境业务节点通过 Mihomo 原生 `dialer-proxy` 封装送出：

```text
+------------+      +------------------------+      +----------------------------+      +--------------+
| 本机应用    | ---> | 业务节点 (非 443 端口)   | ---> | ⚡ 国内提速入口 (select)     | ---> | 目标海外节点  |
|            |      | dialer-proxy 自动挂载   |      |  └─ 🔄 提速自动双活          |      |              |
+------------+      +------------------------+      |     (fallback, lazy:false) |      +--------------+
                                                    |     ├─ 主机: 203.0.113.10  |
                                                    |     └─ 备机: 198.51.100.12 |
                                                    +----------------------------+
                                                                 ^
                                                                 | 仅允许国内 204 探针监测
                                                    hicloud.com / miui.com generate_204
```

### 443 vs 非 443 量化体检

启用国内提速前，可通过 CatCloud 内置的 443 限速体检功能对 443 端口样本与非 443 端口样本进行对照采样；当非 443 上行显著落后且加速比明显时，系统会给出量化启用建议。

---

## 2. 纯 IP 无 SNI `:443` 规范（分协议全检）

在国内公有云轻量应用服务器上部署自用 `:443` 提速中继时，必须遵守 **放行安全组 TCP 443 + 纯 IP 自签 ECDSA 证书 + 空 SNI** 规范：

1. **先放行云安全组 TCP `:443` 入站**：在云厂商控制台防火墙/安全组中放行入站 TCP `443`。
2. **禁止填写未备案第三方 SNI**：国内云机房网关对 TCP `:443` TLS ClientHello 中的 `SNI` 字段实施严格合规拦截。若在配置中填入未在该云厂商备案的第三方域名，TLS 握手将被直接阻断或重置。
3. **使用纯 IP 自签 ECDSA 证书**：服务端监听 `:443` 并签发仅绑定公网 IP SAN 的自签 ECDSA 证书；客户端显式留空 SNI 并开启 `skip_cert_verify: true`（证书验证跳过仅限自控纯 IP 中继，不影响终端目标 HTTPS 站点的端到端 TLS 校验）。
4. **分协议字段全量强检**：CatCloud 校验器按代理协议分别核验 SNI 语义字段：
   - **AnyTLS / Trojan**：校验 `sni` 必须为空（`""` 或 `null`）；
   - **VLESS**：校验 `servername`（同时兼容别名 `sni`）必须为空；
   - 若用户误填非空未备案域名或将 `skip_cert_verify` 设为 `false`，校验器立即在 GUI 与 CLI JSON 中输出强警示或阻断编译。

> 需要开箱即用的 Ubuntu/Debian 一键服务端部署脚本（支持 AnyTLS / Trojan 并直接生成 `mmrelay://v1/...` 导入码），请执行 `catcloud docs export preaccel --format markdown` 或直接查阅随装手册 `agent_docs/zh-CN/02-domestic-preaccel.md`。

---

## 3. `mmrelay/v1` 标准交换契约

为方便用户、朋友间分享、运维自动化工具或 AI Agent 将国内中继参数安全导入 CatCloud，系统定义了标准化的 `mmrelay/v1` JSON Schema、单行剪贴板 URI 及 `.zip` 分享包（`catcloud-share/v1`）。

### 标准 JSON 格式（示例 IP 均遵循 RFC 5737）

```json
{
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
    },
    {
      "id": "relay-cn-south-2",
      "name": "CN-South-443 Standby",
      "provider": "cloud-b",
      "region": "CN-South",
      "server": "198.51.100.12",
      "port": 443,
      "protocol": "trojan",
      "password": "<YOUR_GENERATED_SECRET>",
      "sni": "",
      "skip_cert_verify": true,
      "priority": 20,
      "expires_at": "2027-08-12",
      "enabled": true
    }
  ]
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|---|---|---|
| `schema` | `string` | 固定为 `"mmrelay/v1"` |
| `role` | `string` | 固定为 `"domestic_pre_accel"` |
| `relays[].id` | `string` | 唯一中继标识 |
| `relays[].server` | `string` | 中继纯 IPv4/IPv6 地址（推荐纯 IP） |
| `relays[].port` | `u16` | 监听端口（推荐 `443`） |
| `relays[].protocol` | `string` | `anytls` / `trojan` / `vless` 等支持 TLS 的转发协议 |
| `relays[].sni` | `string` | 别名 `servername`；国内纯 IP `:443` 必须保持 `""` |
| `relays[].skip_cert_verify` | `bool` | 自签纯 IP 证书须设为 `true` |
| `relays[].priority` | `i32` | 数值越小优先级越高，决定双活主备顺序 |
| `relays[].expires_at` | `string?` | 可选 `YYYY-MM-DD` 到期日；剩余 `<= 3` 天自动标黄提醒，到期自动标红预警 |

### 单行剪贴板 URI 与朋友 `.zip` 分享包

```text
mmrelay://v1/<URL_SAFE_BASE64_NO_PAD(JSON)>
```

支持在 GUI「国内提速」面板或 CLI 中一键粘贴导入与导出分享，也支持与节点一起打包为 `.zip` 分享包（`catcloud share export` / `catcloud share import`）；项目 `.gitignore` 与脱敏门禁默认忽略所有 `*.mmrelay.json` 文件以防私钥与真实 IP 意外入库。

---

## 4. 双活主动秒切、原生 443 智能跳过与国内 204 探针

### 双活链路与 `lazy: false`

编译器将启用中的跳板按 `priority` 升序编排为两级结构（主选入口 `type: select` + 自动双活池 `type: fallback` 且强制写入 `lazy: false`），由核心持续保活探测，避免懒惰模式在首次故障时经历漫长超时。主跳板失活时主动刷新测活或直切备机并精准断开旧连接，实现亚秒级故障转移。

### 严禁使用海外探针测试国内跳板

国内提速中继只负责把流量稳定送出国内网络边界，**绝不能**使用 `www.gstatic.com/generate_204` 等海外地址作为跳板组健康探针（否则海外直连不通会导致所有正常国内跳板被集体误判宕机）。

CatCloud 在配置保存与 YAML 编译两个阶段均实施硬性校验：
- **默认主探针**：`http://connectivitycheck.platform.hicloud.com/generate_204`
- **默认备选探针**：`http://connect.rom.miui.com/generate_204`
- **硬性拒绝列表**：检测到 `gstatic.com`、`google.com`、`cloudflare.com` 等海外域名填入国内跳板探针时立即拒绝保存与编译。

### 原生 443 节点智能跳过

对于订阅中本身已经监听在 `:443` 且未受限速的节点（解析时自动标记 `is_443_native = true`），CatCloud 在 `skip_443_native: true`（默认开启）时**自动跳过挂载 `dialer-proxy`**，避免无意义绕行并节省国内中继流量；用户仍可对任意单个节点配置 `preaccel_override`（强制开启或强制关闭）。

---

## 5. 自动防环机制

为杜绝「业务流量 → 跳板 → 规则又命中代理 → 再次进入跳板」的回环死锁，配置编译器在生成规则链时强制将以下条目置顶并同步写入 `dns.fake-ip-filter`：

1. 所有启用中继的公网 IP：`IP-CIDR,<relay_ip>/32,DIRECT,no-resolve`（域名形式则写入 `DOMAIN,<relay_host>,DIRECT` + `fake-ip-filter`）；
2. 已挂载 `dialer-proxy` 的业务节点自身入口地址（防止二跳出口域名解析回落至 Fake-IP）；
3. 国内 204 健康探针域名：`DOMAIN,<probe_host>,DIRECT`、`DOMAIN-SUFFIX,hicloud.com,DIRECT`、`DOMAIN-SUFFIX,miui.com,DIRECT`。

---

## 6. 高校校园网 Captive Portal 防假连

在高校校园网或酒店/企业认证 Wi-Fi 环境下，网络层连通但认证失效时，HTTP 请求会被网关劫持并返回 `302` 重定向至登录页（或直接返回 `200` 认证 HTML）。CatCloud 校园网守护模块采用纯净直连 `.no_proxy()` + `redirect::Policy::none()` 定时探测国内 204：
- 检测到 `301/302/307/308` 或非预期 `200` 时立即自动放行认证页 Host/IP 并加入 `fake-ip-filter`，托盘切提示态引导认证；
- 认证通过恢复 HTTP `204` 后立即自动撤回所有临时放行规则并热重载，不在用户配置中残留脏规则。

---

## 7. 系统底层「全局国内提速」（无代理 / 无 TUN 独立加速）

当用户需要临时使用其他第三方代理软件或命令行工具（如 `ssh` / `scp` / `rsync` / 独立代理核心），不希望开启 CatCloud 自身系统代理或虚拟网卡时，保持「国内提速」总开关开启即可自动运行**独立全局国内提速**：

- **零冲突与物理出口网卡绑定**：不启动第二个虚拟网卡（避免争抢默认路由与 `1053` DNS），按需拉起独立轻量纯 `:443` 双活隧道进程（仅暴露本地动态高位 `socks5h://` 入口，关闭 TUN 与 DNS，常驻内存约 `18~24 MB`），并在 Windows 上绑定真实物理出口网卡，防止与第三方 TUN 死环。
- **Windows 纯环回透明重定向与实战精修**：
  - 按需动态加载官方签名的 WinDivert 驱动，采用 `127.0.0.1` 纯环回反射（请求改写至本机环回端口、回包还原并钳制 `SYN-ACK MSS=1460`），规避 LAND 丢包与防火墙入站弹窗；
  - **进程识别去重与防误杀**：加速进程统计按小写进程名聚合消除卡片分身，自动排除常见国内通讯/办公/浏览器/IDE 进程，并在自检 204 分支之后直接旁路纯国内 IPv4 80 端口，避免白绕中转；
  - **`skip_443_native` 双向联动与高性能热路径**：仅在关闭跳过且命中精准代理核心进程且目标为非国内 IP 时才放开 443 拦截（严防普通浏览器国内/海外 HTTPS 冲击中转机）；环回转发使用 `64 KiB` 双向缓冲与 64K 源端口无锁位图，彻底停用/挂起/退场时有界优雅停止 WinDivert 内核驱动服务（配置热重建仅关句柄防 1072 错误）。
- **真实数据面自检与防断网降级**：驱动启动后自动发起绑定物理网卡的端到端非 443 探测，若被安全软件拦截则立即卸载底层拦截并优雅降级至本地 `SOCKS5` 模式，同时按本机安全环境给出放行指引。
- **跨平台通用模式**：在 macOS / Linux（或 Windows 普通非管理员权限下）自动提供独立本地 `:443` SOCKS5 入口。
- **四端实时联动**：总览、悬浮胶囊、国内提速页及系统托盘实时同步状态；切回 CatCloud TUN 挂起独立隧道时自动清空旧加速进程卡。

---

## 8. 验证与一键回退清单

### 命令行端到端验证（默认脱敏）

```bash
# 1. 导入 mmrelay/v1 中继包或单行导入码
catcloud preaccel add --file ./my-relays.mmrelay.json --json
catcloud preaccel add --uri "mmrelay://v1/..." --json

# 2. 核查中继池优先级、无 SNI 校验与到期状态（默认脱敏 server 与 password）
catcloud preaccel pool --json

# 3. 执行国内 204 探针、防环规则与双活状态测试（加 --speed 可逐条隔离实测中转真实上下行 Mbps）
catcloud preaccel test --json
catcloud preaccel test --speed --json

# 4. 检查底层独立全局国内提速开关、作用域与 WinDivert 就绪态
catcloud preaccel global-status --json
```

### 一键安全回退

如国内机房维护或需立即恢复直连上游节点，可通过 GUI 开关或 CLI 一键关闭并热载，现役其他配置与订阅保持完整不变：

```bash
catcloud preaccel bind --enabled false --json
catcloud config reload --json
```
