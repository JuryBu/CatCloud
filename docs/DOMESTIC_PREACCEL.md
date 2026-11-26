# 国内提速技术（Domestic Boost）与校园网防护规范

本文档说明 CatCloud「国内提速」的技术原理、纯 IP 无 SNI `:443` 合规与安全规范、`mmrelay/v1` 标准交换契约、双活主动秒切与国内 204 探针设计、高校校园网 Captive Portal 防假连机制以及底层独立全局提速架构。

---

## 1. 背景与技术原理

在部分运营商骨干网、企业内网或校园网环境中，跨境代理流量常表现出显著的**端口特征分化**：

- 非 `443` 端口（尤其是高位随机 TCP/UDP 端口）的单流上行带宽容易遭遇限速或高重传（例如上行被压制在 `2 ~ 4 Mbps` 甚至静默卡顿），在进行大体积图片/视频上传、AI 多模态交互或代码仓库推送时极易超时断流；
- 与此同时，国内主流云机房的 TCP `:443` 标准 TLS 链路通常具备高带宽余量与稳定 RTT（可达 `50 ~ 250+ Mbps`）。

CatCloud 的 **国内提速（Domestic Pre-Acceleration）** 在客户端侧自动编排一条低延迟、支持多云负载均衡聚合与主备秒切的前端国内 `:443` 中继链，将受限的非 443 跨境业务节点通过 Mihomo 原生 `dialer-proxy` 封装送出：

```text
+------------+      +------------------------+      +------------------------------------------+      +--------------+
| 本机应用    | ---> | 业务节点 (非 443 端口)   | ---> | ⚡ 国内预加速入口 (select)                | ---> | 目标海外节点  |
|            |      | dialer-proxy 自动挂载   |      |  └─ 🔄 预加速自动双活 (fallback)         |      |              |
+------------+      +------------------------+      |     ├─ ⚖️ 预加速多云均衡 (load-balance)  |      +--------------+
                                                    |     │  ├─ 物理云 A 代表: 203.0.113.10    |
                                                    |     │  └─ 物理云 B 代表: 198.51.100.12   |
                                                    |     ├─ 同机其余协议备选 (如 Hysteria2)    |
                                                    |     └─ DIRECT (最终兜底)                 |
                                                    +------------------------------------------+
                                                                         ^
                                                                         | 仅允许国内 204 探针监测 (lazy: false)
                                                            hicloud.com / miui.com generate_204
```

### 443 vs 非 443 量化体检

启用国内提速前，可通过 CatCloud 内置的 443 限速体检功能对 443 端口样本与非 443 端口样本进行对照采样；当非 443 上行显著落后且加速比明显时，系统会给出量化启用建议。

---

## 2. 纯 IP 无 SNI `:443` 规范（分协议全检）

在国内公有云轻量应用服务器上部署自用 `:443` 提速中继时，必须遵守 **放行安全组 TCP 443（双协议并挂 Hysteria2 时同步放行 UDP 443）+ 纯 IP 自签 ECDSA 证书 + 空 SNI** 规范：

1. **先放行云安全组 `:443` 入站**：在云厂商控制台防火墙/安全组中放行入站 TCP `443`；若在同一台服务器上共存部署 **AnyTLS（TCP 443）+ Hysteria2（UDP 443）** 双协议，请同步放行入站 UDP `443`（两者共享同一份纯 IP 自签证书，互不端口冲突）。
2. **禁止填写未备案第三方 SNI**：国内云机房网关对 `:443` TLS ClientHello 中的 `SNI` 字段实施严格合规拦截。若在配置中填入未在该云厂商备案的第三方域名，TLS 握手将被直接阻断或重置。
3. **使用纯 IP 自签 ECDSA 证书**：服务端监听 `:443` 并签发仅绑定公网 IP SAN 的自签 ECDSA 证书；客户端显式留空 SNI 并开启 `skip_cert_verify: true`（证书验证跳过仅限自控纯 IP 中继，不影响终端目标 HTTPS 站点的端到端 TLS 校验）。
4. **分协议字段全量强检**：CatCloud 校验器按代理协议分别核验 SNI 语义字段：
   - **AnyTLS / Hysteria2 / Trojan**：校验 `sni` 必须为空（`""` 或 `null`）；其中 `hysteria2`（别名 `hy2`）编译时自动注入保守上行 `up: "100 Mbps"` 与 `down: "200 Mbps"`，防止校园网下 Brutal 过载抖动；
   - **VLESS**：校验 `servername`（同时兼容别名 `sni`）必须为空；
   - 若用户误填非空未备案域名或将 `skip_cert_verify` 设为 `false`，校验器立即在 GUI 与 CLI JSON 中输出强警示或阻断编译。

> 需要开箱即用的 Ubuntu/Debian 一键服务端部署脚本（支持 AnyTLS / Hysteria2 UDP 443 / Trojan 并直接生成 `mmrelay://v1/...` 导入码），请执行 `catcloud docs export preaccel --format markdown` 或直接查阅随装手册 `agent_docs/zh-CN/02-domestic-preaccel.md`。

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
| `relays[].protocol` | `string` | `anytls` / `hysteria2`（别名 `hy2`）/ `trojan` / `vless` 等支持 TLS 的转发协议 |
| `relays[].sni` | `string` | 别名 `servername`；国内纯 IP `:443` 必须保持 `""` |
| `relays[].skip_cert_verify` | `bool` | 自签纯 IP 证书须设为 `true` |
| `relays[].priority` | `i32` | 数值越小优先级越高，决定双活主备顺序 |
| `relays[].expires_at` | `string?` | 可选 `YYYY-MM-DD` 到期日；剩余 `<= 3` 天自动标黄提醒，到期自动标红预警 |

> **TCP 443（`AnyTLS`）+ UDP 443（`Hysteria2`）双协议共存**：同一台 `sing-box` 轻量云实例可在 `listen_port: 443` 同时挂载 `anytls`（TCP）与 `hysteria2`（UDP）两个 `inbound`，共享同一份纯 IP 自签 ECDSA 证书（`203.0.113.10` / `<YOUR_PASSWORD>`）且互不冲突；安全组放行 `TCP 443` 与 `UDP 443` 后，客户端既可用 `Hysteria2` 彻底规避 TCP-over-TCP 拥塞，也能在屏蔽 UDP 443 的网络里无缝回落到 `AnyTLS`。

### 单行剪贴板 URI 与朋友 `.zip` 分享包

```text
mmrelay://v1/<URL_SAFE_BASE64_NO_PAD(JSON)>
```

支持在 GUI「国内提速」面板或 CLI 中一键粘贴导入与导出分享，也支持与节点一起打包为 `.zip` 分享包（`catcloud share export` / `catcloud share import`）；项目 `.gitignore` 与脱敏门禁默认忽略所有 `*.mmrelay.json` 文件以防私钥与真实 IP 意外入库。

---

## 4. 多云负载均衡聚合、双活兜底、智能跳过与国内 204 探针

### 两层嵌套多云负载均衡聚合与 `lazy: false`

为兼顾多台国内云的并发带宽叠加与单台故障时的亚秒级容灾，CatCloud 对主内核、底层独立 443 隧道以及批量隔离测速统一采用**按物理云主机 IP 去重的两层嵌套编排**（调度策略由 `dispatch_strategy` 控制，支持 `auto` 默认 / `load_balance` / `fallback`；负载均衡算法由 `lb_strategy` 控制，支持 `round_robin` 默认 / `consistent_hashing`）：

1. **按物理云主机 IP 去重选代表**：以规范化后的中继 `server` 地址作为物理主机键；同一台物理机若同时部署了多种协议（例如 TCP 443 `AnyTLS` + UDP 443 `Hysteria2`），每台物理机仅推选 1 条最高优先级流式传输代表（`anytls` / `trojan` / `vless` 等 TCP 协议优先于同机 `hysteria2` UDP）进入负载均衡池，避免同一台云服务器的 TCP 与 UDP 入口重复参与轮询、互相抢占同一张物理网卡。
2. **内层多云负载均衡池（`⚖️ 预加速多云均衡`）**：当去重后的健康物理云主机数 `>= 2` 且 `dispatch_strategy` 为 `auto` 或 `load_balance` 时，编译器生成内层 `type: load-balance` 组（默认 `strategy: round-robin`，强制 `lazy: false` 与国内 204 探针，`interval: 15`，隔离测速 `10`），**仅纳入多台物理云代表，严禁将 `DIRECT` 放进 `load-balance`**（防止正常流量被随机轮询分流至直连）。Mihomo 会按国内 204 探活结果自动踢除失活物理机，在其余健康物理云之间继续聚合。
3. **外层自动双活与最终兜底（`🔄 预加速自动双活`）**：外层 `type: fallback`（同样强制 `lazy: false`）按顺序编排为 `[⚖️ 预加速多云均衡, 同机其余协议备选..., DIRECT]`。当所有物理云主代表同时不可达时，先依次尝试同机备用协议，极端全挂场景下仍保留 `DIRECT` 兜底不断网。主选入口 `⚡ 国内预加速入口`（`type: select`）默认指向该自动组，同时在下方列出单条中转以便按需临时固定单线。当仅有 1 台物理云主机，或用户显式选择 `fallback` 调度模式时，自动退化为单层 `fallback([relays..., DIRECT])`。
4. **批量隔离测速同步受惠**：数百节点的批量隔离测速同样使用两层嵌套池（`catcloud-probe-relay-lb` → `catcloud-probe-relay-pool` 含 `DIRECT` 兜底），将并发测速流量均摊到多台物理云，避免单机打满导致大面积误判超时。

#### 带宽聚合的真实能力边界与退回单线主备

- **可叠加的场景**：多流并发下载/上传、数百节点批量测速、多人共享同一套多云中转时，不同连接会被分摊至不同物理云主机，总并发吞吐可叠加为多台物理机带宽之和；
- **单连接上限不变**：**单条 TCP 长连接仍受单台物理云带宽上限与本机宽带/校园网单流上限约束**，多云负载均衡不会将单条 TCP 流拆分到两台物理机上；
- **丢包备机一键退回**：若其中某台备机链路质量不佳、丢包严重，混入轮询容易拖慢部分连接（木桶效应），此时可随时在 GUI「国内提速」顶部或通过 CLI（`catcloud preaccel bind --dispatch-strategy fallback --json && catcloud config reload --json`）一键切回单线主备（`fallback`）模式。

### 严禁使用海外探针测试国内跳板

国内提速中继只负责把流量稳定送出国内网络边界，**绝不能**使用 `www.gstatic.com/generate_204` 等海外地址作为跳板组健康探针（否则海外直连不通会导致所有正常国内跳板被集体误判宕机）。

CatCloud 在配置保存与 YAML 编译两个阶段均实施硬性校验：
- **默认主探针**：`http://connectivitycheck.platform.hicloud.com/generate_204`
- **默认备选探针**：`http://connect.rom.miui.com/generate_204`
- **硬性拒绝列表**：检测到 `gstatic.com`、`google.com`、`cloudflare.com` 等海外域名填入国内跳板探针时立即拒绝保存与编译。

### 原生 443 节点与纯 IPv6 业务节点智能跳过

- **原生 443 节点自动跳过**：对于订阅中本身已经监听在 `:443` 且未受限速的节点（解析时自动标记 `is_443_native = true`），CatCloud 在 `skip_443_native: true`（默认开启）时**自动跳过挂载 `dialer-proxy`**，避免无意义绕行并节省国内中继流量；用户仍可对任意单个节点配置 `preaccel_override`（强制开启或强制关闭）。
- **纯 IPv6 业务节点自动跳过纯 IPv4 中转**：大多数国内轻量应用服务器默认仅提供公网 IPv4 出口（中继配置默认 `supports_ipv6: false`）。当业务节点被识别为纯 IPv6 入口（例如 `server` 为 IPv6 字面量、`ip-version: ipv6`、域名带有纯 IPv6 专用标签或节点名显式标明 `ipv6-only` / `v6-only` / `纯ipv6` / `仅ipv6`，不误伤常见双栈节点），且当前启用的国内中转池均不支持 IPv6 出口时，编译器与隔离测速会自动跳过为其挂载 `dialer-proxy`（除非用户对该单节点显式设置了强制开启 `preaccel_override: true`），彻底避免把纯 IPv6 节点送入纯 IPv4 中转引发大量 `network unreachable` 报错。

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

---

## 9. 服务端性能调优与实测避坑要点

1. **必须在线实刷主网卡 `fq` 队列调度**：仅在 `/etc/sysctl.d/` 写入 `net.core.default_qdisc = fq` 不会对开机前已初始化的 `eth0` 生效；若 `tc qdisc show dev eth0` 仍为 `pfifo_fast`，BBR 将失去 pacing 整形并显著放大并发丢包。在服务端执行 `tc qdisc replace dev <iface> root fq`（在线零断流）并注册开机 `systemd` 服务持久化，同时配合 `tcp_fastopen = 3`、`tcp_notsent_lowat = 16384` 与 `16 MiB` TCP 缓冲区。
2. **客户端 `tfo: true` 与 `AnyTLS` 连接池**：CatCloud 编译国内 443 中转时已自动启用 `tfo: true`，并为 `AnyTLS` 自动注入空闲连接池参数（`min-idle-session: 2`），显著降低短并发握手超时；宽带放行国内 UDP 443 时可在同机房 `UDP 443` 并行部署 `Hysteria2` 彻底消除 TCP-over-TCP 拥塞。
3. **单层 TLS 优先与多云聚合边界把控**：外层 443 中转已有完整 TLS 加密，内层优先搭配 `Shadowsocks` 等轻量非 443 海外节点避免双重 TLS 分片损耗；拥有 2 台及以上健康物理云主机时，默认两层嵌套调度（内层 `load-balance` 按物理机 IP 去重聚合 + 外层 `fallback` 保留同机协议备选与 `DIRECT` 兜底）可将多流并发、批量测速与多人共享总吞吐叠加为多台物理机带宽之和，但**单条 TCP 长连接仍受单台物理机与本地宽带上限约束**；若其中某台备机出现持续丢包或高抖动，可随时一键切回单线主备（`fallback`）防止木桶效应。

---

## 10. 中转密钥一键轮换与收回

当内测结束、朋友临时试用期满或怀疑中转密钥外泄时，可使用仓库自带的零依赖跨平台脚本 `scripts/relay/rotate_relay_secrets.mjs` 一键轮换国内云 `sing-box` 中转服务器的全部密码/UUID，并生成全新的 `mmrelay/v1` 清单收回自用。

### 常用命令（示例均使用 RFC 5737 示例 IP 与占位符）

```bash
# 1. 纯本地离线演练（绝不发起 SSH；验证 AnyTLS + Hysteria2 + VLESS 轮换、断言与回退脚本生成）
node scripts/relay/rotate_relay_secrets.mjs --dry-run

# 2. 一键轮换单台国内云中转并将新清单安全导出为 .mmrelay.json（0600 权限，终端默认脱敏）
node scripts/relay/rotate_relay_secrets.mjs \
  --host 203.0.113.10 --user root --key <YOUR_SSH_KEY> \
  --provider cloud-a --region CN-East --name-prefix "CN-East-443" \
  --expires 2027-08-12 --out-file ./cn-east.mmrelay.json

# 3. 多配置 / 多服务 / 非 root 提权场景，并显式在终端输出完整 mmrelay://v1/... 导入码
node scripts/relay/rotate_relay_secrets.mjs \
  --host 198.51.100.12 --user ubuntu --key <YOUR_SSH_KEY> --use-sudo \
  --config /etc/catcloud-relay/config.json --config /etc/catcloud-relay/vless.json \
  --service catcloud-relay --service catcloud-vless \
  --sing-box-bin /opt/sing-box/sing-box \
  --name-prefix "CN-South-443" --print-uri
```

### 安全机制与自动/手动回退

1. **零命令行泄露与强随机轮换**：所有新密码（`24` 字节 `base64url`）与新 `VLESS` / `TUIC` UUID（UUID v4）均在本地由 CSPRNG 生成，并通过 SSH `stdin` 管道传入远端执行器，绝不出现在 SSH 命令行参数中（防止 `ps aux` 泄露）。脚本会遍历每份配置的所有受支持 `inbounds[]`（`anytls` / `hysteria2` / `trojan` / `vless` / `tuic`）并强断言总替换凭据数 `>= 1`。
2. **远端原子替换与重启失败自动回滚**：远端执行器先将原配置完整备份至 `/etc/catcloud-relay/backups/rotate-<timestamp>/`（同时写入 SHA-256 清单与独立可执行 `rollback.sh`），随后写入同目录临时文件、精确保留原文件的 `chmod` 权限与 `chown` 属主，并执行 `sing-box check -c <tmp>` 校验；全部通过后才原子 `os.replace` 替换配置并执行 `systemctl restart` 与 `systemctl is-active` 验活。一旦重启或验活失败，立即自动执行刚生成的 `rollback.sh` 恢复旧配置并重启原服务，同时返回非零退出码。
3. **防凭据误提交公开仓**：使用 `--out-file` 导出新清单时，文件权限自动收紧为 `0o600`；若目标路径位于任意 Git 仓库内且文件名不以 `.mmrelay.json` 结尾（已被 `.gitignore` 忽略），脚本会直接强拦截报错退出。终端默认仅打印脱敏摘要，仅显式传入 `--print-uri` 时才输出完整 `mmrelay://v1/...` 导入码。
4. **事后手动回退**：若轮换后需要主动恢复轮换前的旧密钥，只需在目标服务器上执行脚本输出的对应备份目录回退脚本：

```bash
# 示例时间戳请替换为轮换输出中的真实目录名
sudo bash /etc/catcloud-relay/backups/rotate-<YYYYMMDDTHHMMSSZ>/rollback.sh
```
