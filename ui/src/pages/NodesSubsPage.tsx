import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Download,
  FileCode2,
  FileText,
  Filter,
  FolderOpen,
  Globe,
  Layers,
  Link2,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  type MigrationPreviewDto,
  type MultiGroup,
  type PreAccelOverrideMode,
  type ProbeSnapshot,
  type ProcessCandidateDto,
  type ProcessInspectResult,
  type ProxyNode,
  type SubscriptionRecord,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { formatBytes } from "../components/TrafficSparkline";
import { appActions, useAppSelector } from "../store/appStore";

/* ============================================================================
 * Domain Types & Sanitized Constants (RFC 5737 IPs & Placeholder Labels Only)
 * ============================================================================ */

type MultiplierRange = "all" | "le1" | "1to2" | "ge3";
type Native443Filter = "all" | "only_443" | "non_443";
type MigrationSourceKind =
  | "clash_verge"
  | "flclash"
  | "v2rayn"
  | "local_file"
  | "clipboard_text";

interface HealthFilters {
  googleClean: boolean;
  keepalive60s: boolean;
  aiUnlocked: boolean;
}

interface MigrationPreviewItem {
  id: string;
  source_kind: MigrationSourceKind;
  client_label: string;
  source_path: string | null;
  nodes: ProxyNode[];
  prepend_rules: string[];
  append_rules: string[];
  warnings: string[];
}

interface ProcessCandidateItem {
  pid: number;
  name: string;
  exe_path: string | null;
  cmdline: string[];
  detected_config_dir: string | null;
  detected_config_file: string | null;
  detected_controller_addr: string | null;
  likely_proxy_client: boolean;
}

type AttachRecommendationItem =
  | {
      mode: "read_only_local_file";
      path: string;
      node_count: number;
      reason: string;
    }
  | {
      mode: "public_controller_api";
      endpoint_url: string;
      proxy_count: number;
      requires_secret: boolean;
      reason: string;
    }
  | {
      mode: "external_adapter_template";
      schema: string;
      suggested_command: string;
      template_script: string;
      reason: string;
    };

interface ProcessInspectionItem {
  pid: number;
  process_name: string;
  readable_yaml_file: string | null;
  yaml_node_count: number;
  controller_url: string | null;
  controller_reachable: boolean;
  controller_requires_secret: boolean;
  controller_proxy_count: number;
  recommendation: AttachRecommendationItem;
  notes: string[];
  preview_nodes: ProxyNode[];
}

const ADAPTER_SCHEMA_V1 = "catcloud-adapter/v1";

const SUB_KIND_LABELS: Record<SubscriptionRecord["kind"], string> = {
  url: "URL 订阅",
  file: "本地只读",
  migrated: "老配置迁移",
  process_adapter: "进程 / 外挂源",
};

const REGION_LABELS: Record<string, string> = {
  JP: "日本",
  SG: "新加坡",
  US: "美国",
  TW: "台湾",
  HK: "香港",
  UK: "英国",
  DE: "德国",
  KR: "韩国",
  NL: "荷兰",
  CA: "加拿大",
  AU: "澳大利亚",
  UNK: "其他",
};

const KNOWN_CLIENT_SPECS: Array<{
  kind: "clash_verge" | "flclash" | "v2rayn";
  label: string;
  readonlyPathHint: string;
  desc: string;
}> = [
  {
    kind: "clash_verge",
    label: "Clash Verge / Rev",
    readonlyPathHint:
      "%APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\profiles",
    desc: "只读解析 YAML 节点清单与自定义 prepend/append 分流规则",
  },
  {
    kind: "flclash",
    label: "FlClash",
    readonlyPathHint: "%APPDATA%\\com.follow.clash\\profiles",
    desc: "只读提取多配置文件节点及地区/倍率元信息",
  },
  {
    kind: "v2rayn",
    label: "v2rayN",
    readonlyPathHint: "%APPDATA%\\v2rayN\\guiConfigs\\config.json",
    desc: "只读解析 outbounds 节点与 routing 直连/代理规则",
  },
];

const DEMO_PASTE_SAMPLE = `proxies:
  - name: "JP-Osaka-05 · 0.5x"
    type: vless
    server: 203.0.113.41
    port: 443
    uuid: "00000000-0000-4000-8000-000000000041"
    tls: true
    servername: jp05.example.invalid
  - name: "SG-Lite-06 · 1.5x"
    type: trojan
    server: 198.51.100.42
    port: 8443
    password: "placeholder-demo-pass"
  - name: "UK-London-07 · 2x"
    type: anytls
    server: 203.0.113.43
    port: 443
    password: "placeholder-anytls-pass"
rules:
  - DOMAIN-SUFFIX,local.example.invalid,DIRECT
  - PROCESS-NAME,sample-app.exe,DIRECT`;

const DEMO_MIGRATION_SCANS: Record<
  "clash_verge" | "flclash" | "v2rayn",
  MigrationPreviewItem
> = {
  clash_verge: {
    id: "mig-clash-verge",
    source_kind: "clash_verge",
    client_label: "Clash Verge / Rev",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\io.github.clash-verge-rev.clash-verge-rev\\profiles\\demo_main.yaml",
    nodes: [
      {
        id: "mig-cv-jp-01",
        sub_id: "sub-mig-clash-verge",
        name: "JP-Tokyo-Verge · 0.5x",
        protocol: "vless",
        server: "203.0.113.61",
        port: 443,
        region_code: "JP",
        multiplier: 0.5,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443"],
        enabled: true,
      },
      {
        id: "mig-cv-sg-02",
        sub_id: "sub-mig-clash-verge",
        name: "SG-Transit-Verge · 1.5x",
        protocol: "trojan",
        server: "198.51.100.62",
        port: 8443,
        region_code: "SG",
        multiplier: 1.5,
        is_443_native: false,
        preaccel_override: null,
        tags: ["migrated"],
        enabled: true,
      },
    ],
    prepend_rules: [
      "DOMAIN-SUFFIX,intranet.example.invalid,DIRECT",
      "PROCESS-NAME,sample-sync.exe,DIRECT",
    ],
    append_rules: ["DOMAIN-SUFFIX,openai.com,PROXY"],
    warnings: ["已自动忽略原配置中的 MATCH 兜底规则，避免覆盖猫猫云梯路由策略"],
  },
  flclash: {
    id: "mig-flclash",
    source_kind: "flclash",
    client_label: "FlClash",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\com.follow.clash\\profiles\\demo_pool.yaml",
    nodes: [
      {
        id: "mig-fl-hk-01",
        sub_id: "sub-mig-flclash",
        name: "HK-Edge-FlClash · 2x",
        protocol: "hysteria2",
        server: "203.0.113.71",
        port: 443,
        region_code: "HK",
        multiplier: 2.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443"],
        enabled: true,
      },
    ],
    prepend_rules: ["DOMAIN-SUFFIX,campus.example.invalid,DIRECT"],
    append_rules: [],
    warnings: [],
  },
  v2rayn: {
    id: "mig-v2rayn",
    source_kind: "v2rayn",
    client_label: "v2rayN",
    source_path:
      "C:\\Users\\<USER>\\AppData\\Roaming\\v2rayN\\guiConfigs\\config.json",
    nodes: [
      {
        id: "mig-v2-us-01",
        sub_id: "sub-mig-v2rayn",
        name: "US-SanJose-v2rayN · 1x",
        protocol: "vless",
        server: "198.51.100.75",
        port: 443,
        region_code: "US",
        multiplier: 1.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["migrated", "native-443", "ai-ready"],
        enabled: true,
      },
      {
        id: "mig-v2-de-02",
        sub_id: "sub-mig-v2rayn",
        name: "DE-Frankfurt-v2rayN · 3x",
        protocol: "vmess",
        server: "198.51.100.76",
        port: 2053,
        region_code: "DE",
        multiplier: 3.0,
        is_443_native: false,
        preaccel_override: null,
        tags: ["migrated"],
        enabled: true,
      },
    ],
    prepend_rules: ["DOMAIN-SUFFIX,direct.example.invalid,DIRECT"],
    append_rules: [],
    warnings: ["已跳过 freedom / blackhole 内置出站标签"],
  },
};

const DEMO_PROCESS_CANDIDATES: ProcessCandidateItem[] = [
  {
    pid: 14208,
    name: "mihomo.exe",
    exe_path: "C:\\Users\\<USER>\\Tools\\mihomo\\mihomo.exe",
    cmdline: [
      "mihomo.exe",
      "-d",
      "C:\\Users\\<USER>\\AppData\\Roaming\\clash-demo",
      "-f",
      "runtime.yaml",
      "-ext-ctl",
      "127.0.0.1:19091",
    ],
    detected_config_dir: "C:\\Users\\<USER>\\AppData\\Roaming\\clash-demo",
    detected_config_file:
      "C:\\Users\\<USER>\\AppData\\Roaming\\clash-demo\\runtime.yaml",
    detected_controller_addr: "127.0.0.1:19091",
    likely_proxy_client: true,
  },
  {
    pid: 18540,
    name: "clash-meta.exe",
    exe_path: "C:\\Users\\<USER>\\Tools\\clash-meta\\clash-meta.exe",
    cmdline: ["clash-meta.exe", "--ext-ctl=127.0.0.1:19092"],
    detected_config_dir: null,
    detected_config_file: null,
    detected_controller_addr: "127.0.0.1:19092",
    likely_proxy_client: true,
  },
  {
    pid: 22196,
    name: "mihomo-secure.exe",
    exe_path: "C:\\Users\\<USER>\\Tools\\mihomo-secure\\mihomo-secure.exe",
    cmdline: ["mihomo-secure.exe", "-ext-ctl", "0.0.0.0:19093"],
    detected_config_dir: null,
    detected_config_file: null,
    detected_controller_addr: "0.0.0.0:19093",
    likely_proxy_client: true,
  },
  {
    pid: 26812,
    name: "custom-tunnel-client.exe",
    exe_path: "C:\\Users\\<USER>\\Tools\\custom-tunnel\\custom-tunnel-client.exe",
    cmdline: ["custom-tunnel-client.exe", "--profile=managed"],
    detected_config_dir: null,
    detected_config_file: null,
    detected_controller_addr: null,
    likely_proxy_client: true,
  },
  {
    pid: 9312,
    name: "node.exe",
    exe_path: "C:\\Program Files\\nodejs\\node.exe",
    cmdline: ["node.exe", "vite", "--port", "5173"],
    detected_config_dir: null,
    detected_config_file: null,
    detected_controller_addr: null,
    likely_proxy_client: false,
  },
];

/* ============================================================================
 * Helpers: Formatting, Backend DTO Mappers, Pure Client-Side Parser & Template
 * ============================================================================ */

function getSubSource(sub: SubscriptionRecord): string {
  return sub.url_or_cmd || sub.source || "";
}

function migrationClientLabel(kind: string): string {
  switch (kind) {
    case "clash_verge":
      return "Clash Verge / Rev";
    case "flclash":
      return "FlClash";
    case "v2rayn":
      return "v2rayN";
    case "local_file":
      return "本地配置文件";
    case "clipboard_text":
      return "粘贴文本 / 剪贴板";
    default:
      return kind;
  }
}

function normalizeMigrationKind(kind: string): MigrationSourceKind {
  if (
    kind === "clash_verge" ||
    kind === "flclash" ||
    kind === "v2rayn" ||
    kind === "local_file" ||
    kind === "clipboard_text"
  ) {
    return kind;
  }
  return "local_file";
}

function mapMigrationDtoToPreview(
  dto: MigrationPreviewDto,
  index: number
): MigrationPreviewItem {
  const sourceKind = normalizeMigrationKind(dto.source_kind);
  return {
    id: `mig-${sourceKind}-${index}-${dto.source_path ?? "inline"}`,
    source_kind: sourceKind,
    client_label: migrationClientLabel(sourceKind),
    source_path: dto.source_path ?? null,
    nodes: Array.isArray(dto.nodes) ? dto.nodes : [],
    prepend_rules: Array.isArray(dto.prepend_rules) ? dto.prepend_rules : [],
    append_rules: Array.isArray(dto.append_rules) ? dto.append_rules : [],
    warnings: Array.isArray(dto.warnings) ? dto.warnings : [],
  };
}

function mapProcessCandidateDto(dto: ProcessCandidateDto): ProcessCandidateItem {
  return {
    pid: dto.pid,
    name: dto.name,
    exe_path: dto.exe_path ?? null,
    cmdline: Array.isArray(dto.cmdline) ? dto.cmdline : [],
    detected_config_dir: dto.detected_config_dir ?? null,
    detected_config_file: dto.detected_config_file ?? null,
    detected_controller_addr: dto.detected_controller_addr ?? null,
    likely_proxy_client: Boolean(dto.likely_proxy_client),
  };
}

function mapProcessInspectToUi(
  proc: ProcessCandidateItem,
  res: ProcessInspectResult
): ProcessInspectionItem {
  const processName = res.process_name || res.name || proc.name;
  const configPath =
    res.readable_yaml_file ?? res.config_path ?? proc.detected_config_file ?? null;
  const rawCtrl =
    res.controller_url ?? res.controller_addr ?? proc.detected_controller_addr ?? null;
  const normalizedCtrl = rawCtrl
    ? rawCtrl.startsWith("http://") || rawCtrl.startsWith("https://")
      ? rawCtrl
      : `http://${rawCtrl.replace(/^0\.0\.0\.0/, "127.0.0.1")}`
    : null;
  const yamlNodeCount =
    typeof res.yaml_node_count === "number"
      ? res.yaml_node_count
      : configPath && typeof res.node_count === "number"
        ? res.node_count
        : 0;
  const controllerProxyCount =
    typeof res.controller_proxy_count === "number"
      ? res.controller_proxy_count
      : normalizedCtrl && typeof res.node_count === "number"
        ? res.node_count
        : 0;
  const controllerReachable =
    typeof res.controller_reachable === "boolean"
      ? res.controller_reachable
      : Boolean(normalizedCtrl);
  const controllerRequiresSecret = Boolean(res.controller_requires_secret);
  const rawNotes = Array.isArray(res.notes)
    ? res.notes
    : Array.isArray(res.warnings)
      ? res.warnings
      : [];
  const template = renderAdapterTemplateScript(processName);

  let recommendation: AttachRecommendationItem;
  if (res.recommendation && typeof res.recommendation === "object") {
    recommendation = res.recommendation;
  } else if (configPath) {
    recommendation = {
      mode: "read_only_local_file",
      path: configPath,
      node_count: yamlNodeCount,
      reason:
        "检测到可读明文 YAML 配置文件，优先推荐只读文件关联（零进程侵入、不改写原目录）。",
    };
  } else if (normalizedCtrl) {
    recommendation = {
      mode: "public_controller_api",
      endpoint_url: `${normalizedCtrl.replace(/\/+$/, "")}/proxies`,
      proxy_count: controllerProxyCount,
      requires_secret: controllerRequiresSecret,
      reason: "检测到本地公开控制口，可按只读方式关联拉取节点列表。",
    };
  } else {
    recommendation = {
      mode: "external_adapter_template",
      schema: ADAPTER_SCHEMA_V1,
      suggested_command: `python3 adapters/${processName.replace(/\.exe$/i, "")}_adapter.py`,
      template_script: template,
      reason:
        "未发现明文 YAML 或公开环回控制口，推荐通过开放 catcloud-adapter/v1 外挂脚本槽位对接。",
    };
  }

  return {
    pid: res.pid ?? proc.pid,
    process_name: processName,
    readable_yaml_file: configPath,
    yaml_node_count: yamlNodeCount,
    controller_url: normalizedCtrl,
    controller_reachable: controllerReachable,
    controller_requires_secret: controllerRequiresSecret,
    controller_proxy_count: controllerProxyCount,
    recommendation,
    notes:
      rawNotes.length > 0
        ? rawNotes
        : ["只读解析命令行与公开接口元数据，零进程内存侵入。"],
    preview_nodes: [],
  };
}

function formatTimeShort(iso: string | null): string {
  if (!iso) return "尚未刷新";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${mm}-${dd} ${hh}:${mi}`;
}

function formatExpireInfo(expiresAt: string | null): {
  label: string;
  tone: "normal" | "warn" | "danger";
} {
  if (!expiresAt) return { label: "不限期", tone: "normal" };
  const target = new Date(expiresAt);
  if (Number.isNaN(target.getTime())) {
    return { label: expiresAt, tone: "normal" };
  }
  const diffDays = Math.ceil((target.getTime() - Date.now()) / 86_400_000);
  if (diffDays < 0) {
    return { label: `已过期 (${expiresAt.slice(0, 10)})`, tone: "danger" };
  }
  if (diffDays <= 14) {
    return { label: `剩 ${diffDays} 天 (${expiresAt.slice(0, 10)})`, tone: "warn" };
  }
  return { label: `${expiresAt.slice(0, 10)} (剩 ${diffDays} 天)`, tone: "normal" };
}

function detectRegionFromName(name: string): string {
  const upper = name.toUpperCase();
  const pairs: Array<[string, RegExp]> = [
    ["JP", /(?:^|[^A-Z])JP(?:[^A-Z]|$)|东京|大阪|日本|TOKYO|OSAKA/i],
    ["SG", /(?:^|[^A-Z])SG(?:[^A-Z]|$)|新加坡|狮城|SINGAPORE/i],
    ["US", /(?:^|[^A-Z])US(?:[^A-Z]|$)|美国|洛杉矶|硅谷|圣何塞|SAN\s*JOSE|WEST/i],
    ["TW", /(?:^|[^A-Z])TW(?:[^A-Z]|$)|台湾|台北|TAIPEI/i],
    ["HK", /(?:^|[^A-Z])HK(?:[^A-Z]|$)|香港|HONG\s*KONG/i],
    ["UK", /(?:^|[^A-Z])UK(?:[^A-Z]|$)|英国|伦敦|LONDON/i],
    ["DE", /(?:^|[^A-Z])DE(?:[^A-Z]|$)|德国|法兰克福|FRANKFURT/i],
    ["KR", /(?:^|[^A-Z])KR(?:[^A-Z]|$)|韩国|首尔|SEOUL/i],
  ];
  for (const [code, re] of pairs) {
    if (re.test(upper) || re.test(name)) return code;
  }
  return "UNK";
}

function extractMultiplierFromName(name: string): number {
  const m =
    /(?:^|[\s[\]()·|-])(\d+(?:\.\d+)?)\s*(?:x|倍|倍率)(?:$|[\s[\]()·|-])/i.exec(
      name
    ) ?? /(?:^|[\s[\]()·|-])x(\d+(?:\.\d+)?)(?:$|[\s[\]()·|-])/i.exec(name);
  if (!m) return 1.0;
  const val = Number(m[1]);
  return Number.isFinite(val) && val >= 0 ? val : 1.0;
}

function renderAdapterTemplateScript(targetLabel: string): string {
  const safeLabel =
    targetLabel.replace(/["\\\r\n]/g, "").slice(0, 64) || "custom-source";
  return `#!/usr/bin/env python3
"""
CatCloud external subscription adapter template (${ADAPTER_SCHEMA_V1}).
Target hint: ${safeLabel}

Contract:
  - Read JSON request from stdin: {"reason", "sub_id", "failed_servers"}
  - Print JSON response to stdout (<= 16 MiB):
    {"schema": "${ADAPTER_SCHEMA_V1}", "nodes": [...], "yaml": null}
"""
import json
import sys


def main() -> None:
    raw_req = sys.stdin.read().strip()
    req = json.loads(raw_req) if raw_req else {}
    _reason = req.get("reason", "manual")
    _sub_id = req.get("sub_id", "adapter")
    _failed = set(req.get("failed_servers") or [])

    # Replace the sample node below with your own dynamic node source.
    response = {
        "schema": "${ADAPTER_SCHEMA_V1}",
        "nodes": [
            {
                "name": "JP Sample 1x",
                "type": "vless",
                "server": "203.0.113.10",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "tls": True,
                "servername": "node.example.invalid",
                "udp": True,
            }
        ],
        "yaml": None,
    }
    sys.stdout.write(json.dumps(response, ensure_ascii=False))


if __name__ == "__main__":
    main()
`;
}

function buildMockInspection(proc: ProcessCandidateItem): ProcessInspectionItem {
  const template = renderAdapterTemplateScript(proc.name);

  if (proc.detected_config_file) {
    return {
      pid: proc.pid,
      process_name: proc.name,
      readable_yaml_file: proc.detected_config_file,
      yaml_node_count: 2,
      controller_url: proc.detected_controller_addr
        ? `http://${proc.detected_controller_addr.replace(/^0\.0\.0\.0/, "127.0.0.1")}`
        : null,
      controller_reachable: Boolean(proc.detected_controller_addr),
      controller_requires_secret: false,
      controller_proxy_count: 2,
      recommendation: {
        mode: "read_only_local_file",
        path: proc.detected_config_file,
        node_count: 2,
        reason:
          "在命令行参数 -d/-f 中定位到可读明文 YAML 配置，优先推荐只读文件关联（零进程侵入）。",
      },
      notes: [
        "只读打开配置文件验证 YAML 语法与 proxies 字段，未写入目标目录。",
        "关联后支持按周期只读同步节点变更，异常时自动保护现有节点。",
      ],
      preview_nodes: [
        {
          id: `proc-${proc.pid}-jp-1`,
          sub_id: `sub-proc-${proc.pid}`,
          name: `JP-Proc-${proc.pid} · 1x`,
          protocol: "vless",
          server: "203.0.113.81",
          port: 443,
          region_code: "JP",
          multiplier: 1.0,
          is_443_native: true,
          preaccel_override: null,
          tags: ["process-readonly", "native-443"],
          enabled: true,
        },
        {
          id: `proc-${proc.pid}-sg-2`,
          sub_id: `sub-proc-${proc.pid}`,
          name: `SG-Proc-${proc.pid} · 1.5x`,
          protocol: "trojan",
          server: "198.51.100.82",
          port: 8443,
          region_code: "SG",
          multiplier: 1.5,
          is_443_native: false,
          preaccel_override: null,
          tags: ["process-readonly"],
          enabled: true,
        },
      ],
    };
  }

  if (proc.detected_controller_addr) {
    const normalized = `http://${proc.detected_controller_addr.replace(/^0\.0\.0\.0/, "127.0.0.1")}`;
    const requiresSecret = proc.name.includes("secure");
    return {
      pid: proc.pid,
      process_name: proc.name,
      readable_yaml_file: null,
      yaml_node_count: 0,
      controller_url: normalized,
      controller_reachable: true,
      controller_requires_secret: requiresSecret,
      controller_proxy_count: requiresSecret ? 0 : 2,
      recommendation: {
        mode: "public_controller_api",
        endpoint_url: `${normalized}/proxies`,
        proxy_count: requiresSecret ? 0 : 2,
        requires_secret: requiresSecret,
        reason: requiresSecret
          ? "探测到本地环回控制口返回 HTTP 401，请填入只读 Bearer Secret 后关联公开 REST 接口。"
          : "探测到本地公开 Mihomo REST 控制口 /proxies 响应 200 OK，可直接只读拉取节点列表。",
      },
      notes: [
        `仅访问环回地址 ${normalized}/proxies（GET 只读，超时 2s，上限 8 MiB）。`,
        "未读取任何进程内存或修改目标客户端状态。",
      ],
      preview_nodes: [
        {
          id: `proc-ctl-${proc.pid}-us-1`,
          sub_id: `sub-proc-${proc.pid}`,
          name: `US-Controller-${proc.pid} · 1x`,
          protocol: "anytls",
          server: "203.0.113.85",
          port: 443,
          region_code: "US",
          multiplier: 1.0,
          is_443_native: true,
          preaccel_override: null,
          tags: ["controller-api", "native-443"],
          enabled: true,
        },
        {
          id: `proc-ctl-${proc.pid}-tw-2`,
          sub_id: `sub-proc-${proc.pid}`,
          name: `TW-Controller-${proc.pid} · 2x`,
          protocol: "vless",
          server: "198.51.100.86",
          port: 443,
          region_code: "TW",
          multiplier: 2.0,
          is_443_native: true,
          preaccel_override: null,
          tags: ["controller-api", "native-443"],
          enabled: true,
        },
      ],
    };
  }

  return {
    pid: proc.pid,
    process_name: proc.name,
    readable_yaml_file: null,
    yaml_node_count: 0,
    controller_url: null,
    controller_reachable: false,
    controller_requires_secret: false,
    controller_proxy_count: 0,
    recommendation: {
      mode: "external_adapter_template",
      schema: ADAPTER_SCHEMA_V1,
      suggested_command: `python3 adapters/${proc.name.replace(/\.exe$/i, "")}_adapter.py`,
      template_script: template,
      reason:
        "未发现明文 YAML 或公开环回控制口，推荐通过开放 catcloud-adapter/v1 外挂脚本槽位对接。",
    },
    notes: [
      "严格遵守零内存注入原则：不尝试读取受保护进程内存或私有数据库。",
      "外挂适配器强制防风暴冷却 >= 60s，单次 stdout 上限 16 MiB。",
    ],
    preview_nodes: [],
  };
}

function parsePastedConfigPreview(rawInput: string): MigrationPreviewItem {
  let text = rawInput.trim();
  const warnings: string[] = [];

  // Attempt single-pass Base64 decode when input looks like a compact URI payload
  if (
    text.length >= 24 &&
    !text.includes("://") &&
    !text.includes("proxies:") &&
    /^[A-Za-z0-9+/=\r\n]+$/.test(text)
  ) {
    try {
      const decoded = atob(text.replace(/\s+/g, ""));
      if (decoded.includes("://") || decoded.includes("proxies:")) {
        text = decoded.trim();
      }
    } catch {
      /* keep raw text */
    }
  }

  const subId = `sub-mig-clip-${Date.now()}`;
  const nodes: ProxyNode[] = [];
  const prependRules: string[] = [];
  const appendRules: string[] = [];

  if (/^\s*proxies\s*:/m.test(text)) {
    // Lightweight read-only YAML proxies/rules extractor for instant preview
    const lines = text.split(/\r?\n/);
    let section: "none" | "proxies" | "rules" = "none";
    let current: Record<string, string> | null = null;

    const flushCurrent = () => {
      if (!current) return;
      const name = (current.name ?? "").replace(/^["']|["']$/g, "").trim();
      const protocol = (current.type ?? "").replace(/^["']|["']$/g, "").trim().toLowerCase();
      const server = (current.server ?? "").replace(/^["']|["']$/g, "").trim();
      const port = Number(current.port ?? 0);
      if (name && protocol && server && Number.isFinite(port) && port > 0) {
        const is443 =
          port === 443 &&
          (["trojan", "anytls", "hysteria2", "hy2", "tuic"].includes(protocol) ||
            current.tls === "true" ||
            Boolean(current.servername));
        nodes.push({
          id: `${subId}-n-${nodes.length + 1}`,
          sub_id: subId,
          name,
          protocol: protocol === "hy2" ? "hysteria2" : protocol,
          server,
          port,
          region_code: detectRegionFromName(name),
          multiplier: extractMultiplierFromName(name),
          is_443_native: is443,
          preaccel_override: null,
          tags: is443 ? ["migrated", "native-443"] : ["migrated"],
          enabled: true,
        });
      }
      current = null;
    };

    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      if (/^proxies\s*:/.test(rawLine)) {
        flushCurrent();
        section = "proxies";
        continue;
      }
      if (/^(?:rules|prepend-rules|append-rules)\s*:/.test(rawLine)) {
        flushCurrent();
        section = "rules";
        continue;
      }
      if (/^[a-zA-Z0-9_-]+\s*:/.test(rawLine) && !rawLine.startsWith(" ")) {
        flushCurrent();
        section = "none";
        continue;
      }

      if (section === "proxies") {
        if (trimmed.startsWith("- ")) {
          flushCurrent();
          current = {};
          const rest = trimmed.slice(2).trim();
          const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.+)$/.exec(rest);
          if (kv) current[kv[1].toLowerCase()] = kv[2].trim();
        } else if (current) {
          const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.+)$/.exec(trimmed);
          if (kv) current[kv[1].toLowerCase()] = kv[2].trim();
        }
      } else if (section === "rules" && trimmed.startsWith("- ")) {
        const rule = trimmed
          .slice(2)
          .trim()
          .replace(/^["']|["']$/g, "");
        if (/^MATCH\s*,/i.test(rule)) {
          warnings.push("已跳过 MATCH 兜底规则，保留猫猫云梯主分流结构");
        } else if (/,DIRECT$/i.test(rule)) {
          prependRules.push(rule);
        } else if (rule.includes(",")) {
          appendRules.push(rule);
        }
      }
    }
    flushCurrent();
  } else {
    // Parse plain proxy URI lines
    const uriLines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => Boolean(l) && !l.startsWith("#"));
    for (const line of uriLines) {
      const protoMatch =
        /^(vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls):\/\//i.exec(line);
      if (!protoMatch) continue;
      const rawProto = protoMatch[1].toLowerCase();
      const protocol = rawProto === "hy2" ? "hysteria2" : rawProto;

      let name = `${protocol.toUpperCase()}-Imported-${nodes.length + 1}`;
      let server = "203.0.113.99";
      let port = 443;

      const hashIdx = line.indexOf("#");
      if (hashIdx >= 0) {
        try {
          const decodedHash = decodeURIComponent(line.slice(hashIdx + 1).trim());
          if (decodedHash) name = decodedHash;
        } catch {
          const rawHash = line.slice(hashIdx + 1).trim();
          if (rawHash) name = rawHash;
        }
      }

      const hostPortMatch = /@([^/?#:]+):(\d+)/.exec(line);
      if (hostPortMatch) {
        server = hostPortMatch[1];
        port = Number(hostPortMatch[2]) || 443;
      }

      const is443 =
        port === 443 &&
        ["vless", "trojan", "anytls", "hysteria2", "tuic"].includes(protocol);

      nodes.push({
        id: `${subId}-u-${nodes.length + 1}`,
        sub_id: subId,
        name,
        protocol,
        server,
        port,
        region_code: detectRegionFromName(name),
        multiplier: extractMultiplierFromName(name),
        is_443_native: is443,
        preaccel_override: null,
        tags: is443 ? ["migrated", "native-443"] : ["migrated"],
        enabled: true,
      });
    }
  }

  if (nodes.length === 0) {
    warnings.push("未提取到有效节点，请确认粘贴内容为 Clash YAML 或标准代理 URI 列表");
  }

  return {
    id: `mig-clip-${Date.now()}`,
    source_kind: "clipboard_text",
    client_label: "粘贴文本 / 剪贴板",
    source_path: null,
    nodes,
    prepend_rules: prependRules,
    append_rules: appendRules,
    warnings,
  };
}

function isAiUnlocked(probe: ProbeSnapshot | undefined): boolean {
  if (!probe) return false;
  return Object.values(probe.unlocked_sites).some(Boolean);
}

function countAiUnlocked(probe: ProbeSnapshot | undefined): {
  passed: number;
  total: number;
  detail: string;
} {
  if (!probe) return { passed: 0, total: 0, detail: "暂无解锁快照" };
  const entries = Object.entries(probe.unlocked_sites);
  const passed = entries.filter(([, ok]) => ok).length;
  const detail =
    entries.length > 0
      ? entries.map(([k, ok]) => `${k}: ${ok ? "解锁" : "受限"}`).join(" · ")
      : "暂无解锁快照";
  return { passed, total: entries.length, detail };
}

/* ============================================================================
 * Slide-Over Drawer 1: Read-Only Legacy Config Migration
 * ============================================================================ */

interface MigrationDrawerProps {
  open: boolean;
  onClose: () => void;
  onImport: (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ) => void | Promise<void>;
}

function MigrationDrawer({ open, onClose, onImport }: MigrationDrawerProps) {
  const [tab, setTab] = useState<"scan" | "paste">("scan");
  const [scanningKind, setScanningKind] = useState<string | null>(null);
  const [scannedItems, setScannedItems] = useState<MigrationPreviewItem[]>([]);
  const [selectedPreviewId, setSelectedPreviewId] = useState<string | null>(null);
  const [pasteText, setPasteText] = useState("");
  const [pastePreview, setPastePreview] = useState<MigrationPreviewItem | null>(
    null
  );
  const [customSubName, setCustomSubName] = useState("");
  const [includeRules, setIncludeRules] = useState(true);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const activePreview =
    tab === "scan"
      ? scannedItems.find((item) => item.id === selectedPreviewId) ??
        scannedItems[0] ??
        null
      : pastePreview;

  const runScanClient = async (
    kind: "clash_verge" | "flclash" | "v2rayn" | "all"
  ) => {
    setScanningKind(kind);
    try {
      let items: MigrationPreviewItem[];
      if (isTauriEnv()) {
        const rawList = await catcloudApi.scanLocalMigrations();
        const mapped = rawList.map((dto, idx) => mapMigrationDtoToPreview(dto, idx));
        items =
          kind === "all"
            ? mapped
            : mapped.filter((item) => item.source_kind === kind);
      } else {
        items =
          kind === "all"
            ? [
                DEMO_MIGRATION_SCANS.clash_verge,
                DEMO_MIGRATION_SCANS.flclash,
                DEMO_MIGRATION_SCANS.v2rayn,
              ]
            : [DEMO_MIGRATION_SCANS[kind]];
      }

      setScannedItems((prev) => {
        const merged = new Map<string, MigrationPreviewItem>();
        for (const p of prev) merged.set(p.id, p);
        for (const next of items) merged.set(next.id, next);
        return Array.from(merged.values());
      });
      if (items.length > 0) {
        setSelectedPreviewId(items[0].id);
        setCustomSubName(`迁移 · ${items[0].client_label}`);
        appActions.showToast(
          `只读扫描完成：发现 ${items.reduce((acc, i) => acc + i.nodes.length, 0)} 个可迁移节点（原目录零改动）`,
          "ok"
        );
      } else {
        appActions.showToast("未在本机标准目录检测到可迁移配置", "info");
      }
    } catch (err) {
      appActions.showToast(`只读扫描失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setScanningKind(null);
    }
  };

  const handleParsePaste = async () => {
    if (!pasteText.trim()) {
      appActions.showToast("请先粘贴 Clash YAML、Base64 或代理 URI 文本", "warn");
      return;
    }
    try {
      let parsed: MigrationPreviewItem;
      if (isTauriEnv()) {
        const res = await catcloudApi.previewMigrationFromText(
          customSubName.trim() || "剪贴板只读迁移源",
          pasteText
        );
        parsed = {
          id: `mig-clip-${Date.now()}`,
          source_kind: "clipboard_text",
          client_label: res.name || "粘贴文本 / 剪贴板",
          source_path: null,
          nodes: Array.isArray(res.nodes) ? res.nodes : [],
          prepend_rules: Array.isArray(res.prepend_rules) ? res.prepend_rules : [],
          append_rules: Array.isArray(res.append_rules) ? res.append_rules : [],
          warnings: Array.isArray(res.warnings) ? res.warnings : [],
        };
      } else {
        parsed = parsePastedConfigPreview(pasteText);
      }
      setPastePreview(parsed);
      setCustomSubName(parsed.client_label || "剪贴板只读迁移源");
      if (parsed.nodes.length > 0) {
        appActions.showToast(
          `只读解析成功：提取 ${parsed.nodes.length} 个节点`,
          "ok"
        );
      } else {
        appActions.showToast("未识别到有效节点，请检查文本格式", "warn");
      }
    } catch (err) {
      appActions.showToast(`只读解析失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleConfirmImport = () => {
    if (!activePreview || activePreview.nodes.length === 0) return;
    const finalName =
      customSubName.trim() || `迁移 · ${activePreview.client_label}`;
    onImport(activePreview, finalName, includeRules);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="老配置一键只读迁移"
      onClick={onClose}
    >
      <div
        className="cc-surface flex h-full w-full max-w-[620px] flex-col border-l border-[var(--line-strong)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[var(--line)] px-5 py-4">
          <div>
            <div className="flex items-center gap-2">
              <FolderOpen className="h-4 w-4 text-[var(--accent)]" />
              <h2 className="text-sm font-semibold text-[var(--text)]">
                老配置一键只读迁移
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              支持只读扫描 Clash Verge / FlClash / v2rayN 或粘贴 YAML / URI 文本。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="关闭迁移抽屉"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Read-Only Safety Banner */}
        <div className="mx-5 mt-3 flex items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--green-soft)] px-3 py-2 text-xs text-[var(--green)]">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span>
            严格只读模式：仅读取配置副本并导入猫猫云梯本地存储，绝不修改原客户端目录或文件。
          </span>
        </div>

        {/* Mode Tabs */}
        <div className="mx-5 mt-3 flex items-center gap-2 border-b border-[var(--line)] pb-2.5">
          <button
            type="button"
            onClick={() => setTab("scan")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "scan"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Search className="h-3.5 w-3.5" />
            只读扫描本地客户端
          </button>
          <button
            type="button"
            onClick={() => setTab("paste")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "paste"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <FileText className="h-3.5 w-3.5" />
            粘贴 YAML / URI 文本
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {tab === "scan" ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-[var(--text-secondary)]">
                  标准开源客户端配置目录
                </span>
                <button
                  type="button"
                  disabled={scanningKind !== null}
                  onClick={() => void runScanClient("all")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)] bg-[var(--accent-soft)] px-2.5 py-1 text-xs font-medium text-[var(--accent)] hover:opacity-90 disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${scanningKind === "all" ? "animate-spin" : ""}`}
                  />
                  一键只读扫描全部
                </button>
              </div>

              <div className="space-y-2">
                {KNOWN_CLIENT_SPECS.map((spec) => {
                  const found = scannedItems.find(
                    (s) => s.source_kind === spec.kind
                  );
                  const isBusy =
                    scanningKind === spec.kind || scanningKind === "all";
                  return (
                    <div
                      key={spec.kind}
                      className={`rounded-xl border p-3 transition-colors ${
                        found && activePreview?.id === found.id
                          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                          : "border-[var(--line)] bg-[var(--card)]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-[var(--text)]">
                              {spec.label}
                            </span>
                            {found && (
                              <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                                {found.nodes.length} 节点 ·{" "}
                                {found.prepend_rules.length +
                                  found.append_rules.length}{" "}
                                规则
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                            {spec.readonlyPathHint}
                          </div>
                          <div className="mt-1 text-[11px] text-[var(--text-secondary)]">
                            {spec.desc}
                          </div>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          {found && (
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedPreviewId(found.id);
                                setCustomSubName(`迁移 · ${found.client_label}`);
                              }}
                              className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                            >
                              预览
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => void runScanClient(spec.kind)}
                            className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                          >
                            <Search className="h-3 w-3" />
                            {isBusy ? "扫描中" : "扫描"}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="cc-migration-paste"
                  className="text-xs font-medium text-[var(--text-secondary)]"
                >
                  支持 Clash/Mihomo YAML、Base64 或多行代理 URI（vless / trojan / anytls / hy2 / tuic / vmess / ss）
                </label>
                <button
                  type="button"
                  onClick={() => setPasteText(DEMO_PASTE_SAMPLE)}
                  className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--accent)] hover:border-[var(--accent)]"
                >
                  填入脱敏示例
                </button>
              </div>
              <textarea
                id="cc-migration-paste"
                value={pasteText}
                onChange={(e) => setPasteText(e.target.value)}
                rows={8}
                placeholder="粘贴 YAML 配置片段或 vless:// / trojan:// / anytls:// 节点行..."
                className="cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setPasteText("");
                    setPastePreview(null);
                  }}
                  className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
                >
                  清空
                </button>
                <button
                  type="button"
                  onClick={() => void handleParsePaste()}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                >
                  <Upload className="h-3.5 w-3.5" />
                  只读解析预览
                </button>
              </div>
            </div>
          )}

          {/* Active Preview Panel */}
          {activePreview && (
            <div className="space-y-3 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-semibold text-[var(--text)]">
                    预览结果 · {activePreview.client_label}
                  </div>
                  {activePreview.source_path && (
                    <div className="mt-0.5 break-all cc-mono text-[10px] text-[var(--muted)]">
                      {activePreview.source_path}
                    </div>
                  )}
                </div>
                <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                  {activePreview.nodes.length} 个节点
                </span>
              </div>

              {activePreview.warnings.length > 0 && (
                <div className="space-y-1 rounded-lg bg-[var(--amber-soft)] px-2.5 py-2 text-[11px] text-[var(--amber)]">
                  {activePreview.warnings.map((w, idx) => (
                    <div key={idx} className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}

              {activePreview.nodes.length > 0 && (
                <div className="max-h-44 space-y-1.5 overflow-y-auto pr-1">
                  {activePreview.nodes.map((node) => (
                    <div
                      key={node.id}
                      className="flex items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-medium text-[var(--text)]">
                          {node.name}
                        </div>
                        <div className="cc-mono text-[10px] text-[var(--muted)]">
                          {node.protocol.toUpperCase()} · {node.server}:{node.port}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5 cc-mono text-[10px]">
                        <span className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]">
                          {node.region_code}
                        </span>
                        <span className="rounded bg-[var(--accent-soft)] px-1.5 py-0.5 text-[var(--accent)]">
                          {node.multiplier}x
                        </span>
                        {node.is_443_native && (
                          <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[var(--green)]">
                            443 原生
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {(activePreview.prepend_rules.length > 0 ||
                activePreview.append_rules.length > 0) && (
                <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[var(--text)]">
                      可合并分流规则（前置 {activePreview.prepend_rules.length} 条 / 后置{" "}
                      {activePreview.append_rules.length} 条）
                    </span>
                    <label className="inline-flex cursor-pointer items-center gap-1.5 text-[var(--text-secondary)]">
                      <input
                        type="checkbox"
                        checked={includeRules}
                        onChange={(e) => setIncludeRules(e.target.checked)}
                        className="accent-[var(--accent)]"
                      />
                      同步导入规则
                    </label>
                  </div>
                  <div className="mt-1.5 space-y-0.5 cc-mono text-[10px] text-[var(--muted)]">
                    {[...activePreview.prepend_rules, ...activePreview.append_rules]
                      .slice(0, 4)
                      .map((r, idx) => (
                        <div key={idx} className="truncate">
                          {r}
                        </div>
                      ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 gap-2 pt-1">
                <label className="text-[11px] text-[var(--muted)]">
                  导入后的订阅来源名称
                  <input
                    type="text"
                    value={customSubName}
                    onChange={(e) => setCustomSubName(e.target.value)}
                    placeholder={`迁移 · ${activePreview.client_label}`}
                    className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                  />
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-[var(--line)] px-5 py-3">
          <span className="text-[11px] text-[var(--muted)]">
            导入仅写入猫猫云梯 SQLite，原客户端零修改
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
            >
              取消
            </button>
            <button
              type="button"
              disabled={!activePreview || activePreview.nodes.length === 0}
              onClick={handleConfirmImport}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
            >
              <Check className="h-3.5 w-3.5" />
              确认只读导入
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
 * Slide-Over Drawer 2: Manual Process Smart Attach & catcloud-adapter/v1 Slot
 * ============================================================================ */

interface ProcessAttachDrawerProps {
  open: boolean;
  onClose: () => void;
  onAttachSource: (payload: {
    name: string;
    source: string;
    kind: SubscriptionRecord["kind"];
    nodes: ProxyNode[];
  }) => void | Promise<void>;
}

function ProcessAttachDrawer({
  open,
  onClose,
  onAttachSource,
}: ProcessAttachDrawerProps) {
  const inTauri = isTauriEnv();
  const [onlyLikelyProxy, setOnlyLikelyProxy] = useState(true);
  const [keyword, setKeyword] = useState("");
  const [loadingList, setLoadingList] = useState(false);
  const [candidates, setCandidates] = useState<ProcessCandidateItem[]>(() =>
    inTauri ? [] : DEMO_PROCESS_CANDIDATES
  );
  const [selectedPid, setSelectedPid] = useState<number | null>(() =>
    inTauri ? null : DEMO_PROCESS_CANDIDATES[0].pid
  );
  const [inspecting, setInspecting] = useState(false);
  const [inspection, setInspection] = useState<ProcessInspectionItem | null>(() =>
    inTauri ? null : buildMockInspection(DEMO_PROCESS_CANDIDATES[0])
  );
  const [bearerSecret, setBearerSecret] = useState("");
  const [showAdapterSlot, setShowAdapterSlot] = useState(false);
  const [adapterCmd, setAdapterCmd] = useState(
    "python3 adapters/custom_tunnel_adapter.py"
  );
  const [adapterCooldownSec, setAdapterCooldownSec] = useState(60);
  const [adapterTimeoutSec, setAdapterTimeoutSec] = useState(30);
  const [copiedScript, setCopiedScript] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    if (!open || !inTauri) return;
    let cancelled = false;
    setLoadingList(true);
    void catcloudApi
      .listRunningProcesses(false)
      .then((list) => {
        if (cancelled) return;
        setCandidates(list.map(mapProcessCandidateDto));
      })
      .catch((err) => {
        if (!cancelled) {
          appActions.showToast(`拉取进程列表失败：${formatErrorMessage(err)}`, "warn");
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingList(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, inTauri]);

  const filteredCandidates = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return candidates.filter((proc) => {
      if (onlyLikelyProxy && !proc.likely_proxy_client) return false;
      if (!kw) return true;
      return (
        proc.name.toLowerCase().includes(kw) ||
        String(proc.pid).includes(kw) ||
        proc.cmdline.join(" ").toLowerCase().includes(kw)
      );
    });
  }, [candidates, onlyLikelyProxy, keyword]);

  if (!open) return null;

  const selectedProc =
    candidates.find((c) => c.pid === selectedPid) ?? filteredCandidates[0] ?? null;

  const refreshProcesses = async () => {
    setLoadingList(true);
    try {
      if (inTauri) {
        const ipcList = await catcloudApi.listRunningProcesses(false);
        const mapped = ipcList.map(mapProcessCandidateDto);
        setCandidates(mapped);
        appActions.showToast(`已刷新本机进程清单（共 ${mapped.length} 项）`, "info");
      } else {
        setCandidates(DEMO_PROCESS_CANDIDATES);
        appActions.showToast(`预览模式：共 ${DEMO_PROCESS_CANDIDATES.length} 项演示进程`, "info");
      }
    } catch (err) {
      appActions.showToast(`刷新进程清单失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setLoadingList(false);
    }
  };

  const inspectSelected = async (proc: ProcessCandidateItem) => {
    setSelectedPid(proc.pid);
    setInspecting(true);
    setShowAdapterSlot(false);
    setBearerSecret("");
    try {
      let report: ProcessInspectionItem;
      if (inTauri) {
        const ipcInspect = await catcloudApi.inspectProcessSource(proc.pid);
        report = mapProcessInspectToUi(proc, ipcInspect);
      } else {
        report = buildMockInspection(proc);
      }
      setInspection(report);
      if (report.recommendation.mode === "external_adapter_template") {
        setAdapterCmd(report.recommendation.suggested_command);
        setShowAdapterSlot(true);
      } else {
        setAdapterCmd(
          `python3 adapters/${proc.name.replace(/\.exe$/i, "")}_adapter.py`
        );
      }
    } catch (err) {
      appActions.showToast(`探测进程失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setInspecting(false);
    }
  };

  const activeTemplateScript =
    inspection?.recommendation.mode === "external_adapter_template"
      ? inspection.recommendation.template_script
      : renderAdapterTemplateScript(selectedProc?.name ?? "custom-source");

  const handleCopyScript = async () => {
    try {
      await navigator.clipboard.writeText(activeTemplateScript);
      setCopiedScript(true);
      appActions.showToast("已复制 catcloud-adapter/v1 脚本模板", "ok");
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        copyTimerRef.current = null;
        setCopiedScript(false);
      }, 1800);
    } catch {
      appActions.showToast("复制失败，请手动选中代码区域复制", "warn");
    }
  };

  const handleDownloadScript = () => {
    const fileStem = (selectedProc?.name ?? "custom_source")
      .replace(/\.exe$/i, "")
      .replace(/[^a-zA-Z0-9_-]/g, "_");
    const blob = new Blob([activeTemplateScript], {
      type: "text/x-python;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${fileStem}_catcloud_adapter.py`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    appActions.showToast("已导出 catcloud-adapter/v1 模板文件", "ok");
  };

  const handleBindReadOnlySource = () => {
    if (!inspection) return;
    if (inspection.recommendation.mode === "read_only_local_file") {
      onAttachSource({
        name: `进程只读 · ${inspection.process_name} (PID ${inspection.pid})`,
        source: inspection.recommendation.path,
        kind: "file",
        nodes: inTauri ? [] : inspection.preview_nodes,
      });
      onClose();
      return;
    }
    if (inspection.recommendation.mode === "public_controller_api") {
      if (
        inspection.recommendation.requires_secret &&
        !bearerSecret.trim()
      ) {
        appActions.showToast(
          "该控制口返回 401，请先填入只读 Bearer Secret",
          "warn"
        );
        return;
      }
      onAttachSource({
        name: `控制口只读 · ${inspection.process_name} (PID ${inspection.pid})`,
        source: inspection.recommendation.endpoint_url,
        kind: "process_adapter",
        nodes: inTauri ? [] : inspection.preview_nodes,
      });
      onClose();
    }
  };

  const handleRegisterAdapterSlot = () => {
    const trimmedCmd = adapterCmd.trim();
    if (!trimmedCmd) {
      appActions.showToast("请输入外挂适配器执行命令", "warn");
      return;
    }
    const safeCooldown = Math.max(60, Math.round(adapterCooldownSec));
    const safeTimeout = Math.min(300, Math.max(5, Math.round(adapterTimeoutSec)));
    const procLabel = selectedProc?.name ?? "external";
    const subId = `sub-adapter-${Date.now()}`;
    onAttachSource({
      name: `外挂槽位 · ${procLabel} (${ADAPTER_SCHEMA_V1})`,
      source: inTauri ? trimmedCmd : `${trimmedCmd} [timeout=${safeTimeout}s, cooldown=${safeCooldown}s]`,
      kind: "process_adapter",
      nodes: inTauri
        ? []
        : [
            {
              id: `${subId}-sample-1`,
              sub_id: subId,
              name: `JP-Adapter-${procLabel.replace(/\.exe$/i, "")} · 1x`,
              protocol: "vless",
              server: "203.0.113.90",
              port: 443,
              region_code: "JP",
              multiplier: 1.0,
              is_443_native: true,
              preaccel_override: null,
              tags: ["adapter-v1", "native-443"],
              enabled: true,
            },
          ],
    });
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="手动选择运行中进程智能对口"
      onClick={onClose}
    >
      <div
        className="cc-surface flex h-full w-full max-w-[760px] flex-col border-l border-[var(--line-strong)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[var(--line)] px-5 py-4">
          <div>
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-[var(--accent)]" />
              <h2 className="text-sm font-semibold text-[var(--text)]">
                手动选择运行中进程智能对口
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              只读解析命令行参数（-d / -f / -ext-ctl）与公开环回控制口，或生成开放{" "}
              <span className="cc-mono text-[var(--accent)]">
                {ADAPTER_SCHEMA_V1}
              </span>{" "}
              外挂脚本槽位。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="关闭进程对口抽屉"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] px-5 py-2.5">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
            <input
              type="text"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              placeholder="按 PID、进程名或命令行参数筛选..."
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={onlyLikelyProxy}
                onChange={(e) => setOnlyLikelyProxy(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              仅显示疑似代理进程
            </label>
            <button
              type="button"
              onClick={() => void refreshProcesses()}
              disabled={loadingList}
              className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${loadingList ? "animate-spin" : ""}`}
              />
              刷新进程
            </button>
          </div>
        </div>

        {/* Two-Pane Body */}
        <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto md:grid-cols-12">
          {/* Left: Process Candidate List */}
          <div className="space-y-2 border-b border-[var(--line)] p-4 md:col-span-5 md:border-b-0 md:border-r md:overflow-y-auto">
            <div className="text-[11px] font-medium text-[var(--muted)]">
              运行中候选进程（{filteredCandidates.length}）
            </div>
            {filteredCandidates.length === 0 ? (
              <div className="rounded-xl border border-dashed border-[var(--line)] p-4 text-center text-xs text-[var(--muted)]">
                无匹配进程，可取消勾选“仅显示疑似代理进程”
              </div>
            ) : (
              filteredCandidates.map((proc) => {
                const active = selectedProc?.pid === proc.pid;
                return (
                  <button
                    key={proc.pid}
                    type="button"
                    onClick={() => void inspectSelected(proc)}
                    className={`w-full rounded-xl border p-3 text-left transition-colors ${
                      active
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                        : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-xs font-semibold text-[var(--text)]">
                        {proc.name}
                      </span>
                      <span className="cc-mono shrink-0 rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                        PID {proc.pid}
                      </span>
                    </div>

                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {proc.detected_config_dir && (
                        <span className="rounded bg-[var(--sky-soft)] px-1.5 py-0.5 cc-mono text-[10px] text-[var(--sky)]">
                          -d
                        </span>
                      )}
                      {proc.detected_config_file && (
                        <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 cc-mono text-[10px] text-[var(--green)]">
                          -f YAML
                        </span>
                      )}
                      {proc.detected_controller_addr && (
                        <span className="rounded bg-[var(--accent-soft)] px-1.5 py-0.5 cc-mono text-[10px] text-[var(--accent)]">
                          -ext-ctl {proc.detected_controller_addr}
                        </span>
                      )}
                      {!proc.detected_config_file &&
                        !proc.detected_controller_addr && (
                          <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            需外挂槽位
                          </span>
                        )}
                    </div>

                    <div className="mt-1.5 line-clamp-2 break-all cc-mono text-[10px] text-[var(--muted)]">
                      {proc.cmdline.join(" ")}
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* Right: Inspection Report & Attach Actions */}
          <div className="space-y-3.5 p-4 md:col-span-7 md:overflow-y-auto">
            {!selectedProc ? (
              <div className="rounded-xl border border-dashed border-[var(--line)] p-6 text-center text-xs text-[var(--muted)]">
                请从左侧选择一个运行中进程以执行只读探测
              </div>
            ) : (
              <>
                {/* Selected Process Cmdline Breakdown */}
                <div className="rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-[var(--accent)]" />
                      <span className="text-xs font-semibold text-[var(--text)]">
                        {selectedProc.name}
                      </span>
                      <span className="cc-mono text-[11px] text-[var(--muted)]">
                        PID {selectedProc.pid}
                      </span>
                    </div>
                    <button
                      type="button"
                      disabled={inspecting}
                      onClick={() => void inspectSelected(selectedProc)}
                      className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                    >
                      <RefreshCw
                        className={`h-3 w-3 ${inspecting ? "animate-spin" : ""}`}
                      />
                      重新探测
                    </button>
                  </div>

                  <dl className="mt-2.5 space-y-1.5 text-[11px]">
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">配置目录 (-d)</dt>
                      <dd className="cc-selectable break-all text-right cc-mono text-[var(--text-secondary)]">
                        {selectedProc.detected_config_dir ?? "未显式指定"}
                      </dd>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">配置文件 (-f)</dt>
                      <dd className="cc-selectable break-all text-right cc-mono text-[var(--text-secondary)]">
                        {selectedProc.detected_config_file ?? "未显式指定"}
                      </dd>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">
                        公开控制口 (-ext-ctl)
                      </dt>
                      <dd className="cc-selectable text-right cc-mono text-[var(--accent)]">
                        {selectedProc.detected_controller_addr ?? "未检测到"}
                      </dd>
                    </div>
                  </dl>
                </div>

                {/* Probe Result Card */}
                {inspection && (
                  <div className="space-y-3 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[var(--text)]">
                        只读探测结论与推荐接入方式
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                          inspection.recommendation.mode ===
                          "external_adapter_template"
                            ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                            : "bg-[var(--green-soft)] text-[var(--green)]"
                        }`}
                      >
                        {inspection.recommendation.mode === "read_only_local_file"
                          ? "推荐：只读明文 YAML"
                          : inspection.recommendation.mode ===
                              "public_controller_api"
                            ? "推荐：公开控制口 REST"
                            : `推荐：${ADAPTER_SCHEMA_V1} 外挂槽位`}
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                      {inspection.recommendation.reason}
                    </p>

                    {/* Probe Telemetry Summary */}
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2">
                        <div className="text-[var(--muted)]">本地 YAML 探测</div>
                        <div className="mt-0.5 cc-mono font-medium text-[var(--text)]">
                          {inspection.readable_yaml_file
                            ? `可读 · ${inspection.yaml_node_count} 节点`
                            : "无明文可读文件"}
                        </div>
                      </div>
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2">
                        <div className="text-[var(--muted)]">公开控制口探测</div>
                        <div className="mt-0.5 cc-mono font-medium text-[var(--text)]">
                          {inspection.controller_reachable
                            ? inspection.controller_requires_secret
                              ? "可达 (401 需 Secret)"
                              : `可达 · ${inspection.controller_proxy_count} 代理`
                            : "未监听或不可达"}
                        </div>
                      </div>
                    </div>

                    {/* Direct Bind Action for File or Public Controller */}
                    {inspection.recommendation.mode ===
                      "read_only_local_file" && (
                      <div className="space-y-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5">
                        <div className="break-all cc-mono text-[11px] text-[var(--text)]">
                          {inspection.recommendation.path}
                        </div>
                        <button
                          type="button"
                          onClick={handleBindReadOnlySource}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                        >
                          <Link2 className="h-3.5 w-3.5" />
                          一键关联为只读配置文件源（{inspection.recommendation.node_count} 节点）
                        </button>
                      </div>
                    )}

                    {inspection.recommendation.mode ===
                      "public_controller_api" && (
                      <div className="space-y-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5">
                        <div className="cc-mono text-[11px] text-[var(--accent)]">
                          GET {inspection.recommendation.endpoint_url}
                        </div>
                        {inspection.recommendation.requires_secret && (
                          <input
                            type="password"
                            value={bearerSecret}
                            onChange={(e) => setBearerSecret(e.target.value)}
                            placeholder="填入控制口只读 Bearer Secret..."
                            className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 cc-mono text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                          />
                        )}
                        <button
                          type="button"
                          onClick={handleBindReadOnlySource}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                        >
                          <Link2 className="h-3.5 w-3.5" />
                          一键关联公开控制口只读源
                        </button>
                      </div>
                    )}

                    {/* Notes */}
                    <ul className="space-y-1 text-[11px] text-[var(--muted)]">
                      {inspection.notes.map((note, idx) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-[var(--green)]" />
                          <span>{note}</span>
                        </li>
                      ))}
                    </ul>

                    {/* Toggle External Adapter Slot View */}
                    {inspection.recommendation.mode !==
                      "external_adapter_template" && (
                      <button
                        type="button"
                        onClick={() => setShowAdapterSlot((v) => !v)}
                        className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--accent)] hover:underline"
                      >
                        <FileCode2 className="h-3.5 w-3.5" />
                        {showAdapterSlot
                          ? "收起 catcloud-adapter/v1 外挂脚本槽位"
                          : "或者生成开放 catcloud-adapter/v1 外挂脚本槽位模板"}
                      </button>
                    )}
                  </div>
                )}

                {/* Open External Adapter v1 Slot & Template Generator */}
                {showAdapterSlot && (
                  <div className="space-y-3 rounded-xl border border-[var(--accent)]/60 bg-[var(--card)] p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <FileCode2 className="h-4 w-4 text-[var(--accent)]" />
                        <span className="text-xs font-semibold text-[var(--text)]">
                          开放外挂脚本槽位（{ADAPTER_SCHEMA_V1}）
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => void handleCopyScript()}
                          className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                        >
                          {copiedScript ? (
                            <Check className="h-3 w-3 text-[var(--green)]" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          {copiedScript ? "已复制" : "复制模板"}
                        </button>
                        <button
                          type="button"
                          onClick={handleDownloadScript}
                          className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                        >
                          <Download className="h-3 w-3" />
                          下载 .py
                        </button>
                      </div>
                    </div>

                    <div className="rounded-lg bg-[var(--bg-elevated)] p-2.5 text-[11px] text-[var(--muted)]">
                      标准进程协议：<span className="cc-mono text-[var(--text)]">stdin</span> 传入{" "}
                      <span className="cc-mono">{`{"reason","sub_id","failed_servers"}`}</span>，
                      <span className="cc-mono text-[var(--text)]">stdout</span> 返回{" "}
                      <span className="cc-mono">{`{"schema":"catcloud-adapter/v1","nodes":[...],"yaml":null}`}</span>
                      （上限 16 MiB，防风暴冷却 &gt;= 60s）。
                    </div>

                    <pre className="cc-selectable max-h-52 overflow-auto rounded-lg border border-[var(--line)] bg-[var(--bg)] p-3 cc-mono text-[11px] leading-relaxed text-[var(--text-secondary)]">
                      {activeTemplateScript}
                    </pre>

                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                      <label className="text-[11px] text-[var(--muted)] sm:col-span-6">
                        适配器启动命令
                        <input
                          type="text"
                          value={adapterCmd}
                          onChange={(e) => setAdapterCmd(e.target.value)}
                          className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 cc-mono text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                        />
                      </label>
                      <label className="text-[11px] text-[var(--muted)] sm:col-span-3">
                        超时 (秒)
                        <input
                          type="number"
                          min={5}
                          max={300}
                          value={adapterTimeoutSec}
                          onChange={(e) =>
                            setAdapterTimeoutSec(Number(e.target.value) || 30)
                          }
                          className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 cc-mono text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                        />
                      </label>
                      <label className="text-[11px] text-[var(--muted)] sm:col-span-3">
                        冷却 (&gt;=60s)
                        <input
                          type="number"
                          min={60}
                          max={86400}
                          value={adapterCooldownSec}
                          onChange={(e) =>
                            setAdapterCooldownSec(
                              Math.max(60, Number(e.target.value) || 60)
                            )
                          }
                          className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 cc-mono text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                        />
                      </label>
                    </div>

                    <div className="flex justify-end">
                      <button
                        type="button"
                        onClick={handleRegisterAdapterSlot}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        注册外挂适配器订阅源
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
 * Main Page Export: NodesSubsPage
 * ============================================================================ */

export function NodesSubsPage() {
  const storeSubs = useAppSelector((s) => s.subscriptions);
  const storeNodes = useAppSelector((s) => s.nodes);
  const storeProbes = useAppSelector((s) => s.probes);
  const storeGroups = useAppSelector((s) => s.groups);
  const globalPreAccel = useAppSelector((s) => s.config.preaccel);

  // Interactive page state synced cleanly with initial store hydration
  const [subscriptions, setSubscriptions] = useState<SubscriptionRecord[]>(() => [
    ...storeSubs,
  ]);
  const [nodes, setNodes] = useState<ProxyNode[]>(() => [...storeNodes]);
  const [groups, setGroups] = useState<MultiGroup[]>(() => [...storeGroups]);
  const [hydratedKey, setHydratedKey] = useState<string>(
    () => `${storeSubs.length}:${storeNodes.length}:${storeGroups.length}`
  );

  useEffect(() => {
    const incomingKey = `${storeSubs.length}:${storeNodes.length}:${storeGroups.length}`;
    if (incomingKey === hydratedKey) return;
    if (
      subscriptions.length === 0 &&
      nodes.length === 0 &&
      (storeSubs.length > 0 || storeNodes.length > 0 || storeGroups.length > 0)
    ) {
      setSubscriptions([...storeSubs]);
      setNodes([...storeNodes]);
      setGroups([...storeGroups]);
      setHydratedKey(incomingKey);
    } else if (groups.length === 0 && storeGroups.length > 0) {
      setGroups([...storeGroups]);
      setHydratedKey(incomingKey);
    }
  }, [
    storeSubs,
    storeNodes,
    storeGroups,
    hydratedKey,
    subscriptions.length,
    nodes.length,
    groups.length,
  ]);

  // Top subscription controls & add-subscription form
  const [refreshingIds, setRefreshingIds] = useState<Record<string, boolean>>({});
  const [refreshingAll, setRefreshingAll] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [addKind, setAddKind] = useState<"url" | "file">("url");
  const [newSubName, setNewSubName] = useState("");
  const [newSubSource, setNewSubSource] = useState("");
  const [newSubIntervalSec, setNewSubIntervalSec] = useState(21600);

  // Drawers
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [processAttachOpen, setProcessAttachOpen] = useState(false);

  // Multi-dimensional node filters
  const [keyword, setKeyword] = useState("");
  const [filterSubId, setFilterSubId] = useState<string>("all");
  const [filterRegion, setFilterRegion] = useState<string>("all");
  const [filterMultiplier, setFilterMultiplier] =
    useState<MultiplierRange>("all");
  const [filterProtocol, setFilterProtocol] = useState<string>("all");
  const [filter443, setFilter443] = useState<Native443Filter>("all");
  const [healthFilters, setHealthFilters] = useState<HealthFilters>({
    googleClean: false,
    keepalive60s: false,
    aiUnlocked: false,
  });

  // Cross-subscription batch selection & target multi-group
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(
    () => new Set()
  );
  const [targetGroupId, setTargetGroupId] = useState<string>(
    () => storeGroups[0]?.id ?? "grp-ai"
  );

  useEffect(() => {
    if (groups.length > 0 && !groups.some((g) => g.id === targetGroupId)) {
      setTargetGroupId(groups[0].id);
    }
  }, [groups, targetGroupId]);

  // Derived lookup maps
  const subNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) map.set(s.id, s.name);
    return map;
  }, [subscriptions]);

  const subNodeCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  const nodeGroupMembership = useMemo(() => {
    const map = new Map<string, MultiGroup[]>();
    for (const g of groups) {
      for (const nid of g.member_node_ids) {
        const list = map.get(nid);
        if (list) list.push(g);
        else map.set(nid, [g]);
      }
    }
    return map;
  }, [groups]);

  const regionStats = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      const code = n.region_code || "UNK";
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [nodes]);

  const protocolStats = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      const proto = n.protocol.toLowerCase();
      counts.set(proto, (counts.get(proto) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [nodes]);

  const native443Count = useMemo(
    () => nodes.filter((n) => n.is_443_native).length,
    [nodes]
  );

  const filteredNodes = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return nodes.filter((node) => {
      if (filterSubId !== "all" && node.sub_id !== filterSubId) return false;
      if (filterRegion !== "all" && node.region_code !== filterRegion) {
        return false;
      }
      if (
        filterProtocol !== "all" &&
        node.protocol.toLowerCase() !== filterProtocol
      ) {
        return false;
      }
      if (filterMultiplier === "le1" && node.multiplier > 1.0) return false;
      if (
        filterMultiplier === "1to2" &&
        (node.multiplier < 1.0 || node.multiplier > 2.0)
      ) {
        return false;
      }
      if (filterMultiplier === "ge3" && node.multiplier < 3.0) return false;

      if (filter443 === "only_443" && !node.is_443_native) return false;
      if (filter443 === "non_443" && node.is_443_native) return false;

      const probe = storeProbes[node.id];
      if (
        healthFilters.googleClean &&
        !(probe?.google_clean === true && !probe.google_risk_mismatch)
      ) {
        return false;
      }
      if (healthFilters.keepalive60s && probe?.keepalive_60s_ok !== true) {
        return false;
      }
      if (healthFilters.aiUnlocked && !isAiUnlocked(probe)) {
        return false;
      }

      if (kw) {
        const subName = (subNameMap.get(node.sub_id) ?? "").toLowerCase();
        const hit =
          node.name.toLowerCase().includes(kw) ||
          node.server.toLowerCase().includes(kw) ||
          node.protocol.toLowerCase().includes(kw) ||
          node.region_code.toLowerCase().includes(kw) ||
          subName.includes(kw) ||
          node.tags.some((t) => t.toLowerCase().includes(kw));
        if (!hit) return false;
      }

      return true;
    });
  }, [
    nodes,
    keyword,
    filterSubId,
    filterRegion,
    filterProtocol,
    filterMultiplier,
    filter443,
    healthFilters,
    storeProbes,
    subNameMap,
  ]);

  const selectedCrossSubCount = useMemo(() => {
    const subSet = new Set<string>();
    for (const n of nodes) {
      if (selectedNodeIds.has(n.id)) subSet.add(n.sub_id);
    }
    return subSet.size;
  }, [nodes, selectedNodeIds]);

  const hasActiveFilters =
    keyword.trim().length > 0 ||
    filterSubId !== "all" ||
    filterRegion !== "all" ||
    filterMultiplier !== "all" ||
    filterProtocol !== "all" ||
    filter443 !== "all" ||
    healthFilters.googleClean ||
    healthFilters.keepalive60s ||
    healthFilters.aiUnlocked;

  const allFilteredSelected =
    filteredNodes.length > 0 &&
    filteredNodes.every((n) => selectedNodeIds.has(n.id));

  /* ---------- Subscription Actions ---------- */

  const inTauri = isTauriEnv();
  const timersRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      for (const id of timersRef.current) {
        window.clearTimeout(id);
      }
      timersRef.current = [];
    };
  }, []);

  const syncListsFromBackend = async () => {
    const [latestSubs, latestNodes, latestGroups] = await Promise.all([
      catcloudApi.listSubscriptions(),
      catcloudApi.listNodes(),
      catcloudApi.listGroups(),
    ]);
    setSubscriptions(latestSubs);
    setNodes(latestNodes);
    setGroups(latestGroups);
    appActions.syncSubscriptions(latestSubs);
    appActions.syncNodes(latestNodes);
    appActions.syncGroups(latestGroups);
  };

  const waitManaged = (ms: number) =>
    new Promise<void>((resolve) => {
      const id = window.setTimeout(() => {
        timersRef.current = timersRef.current.filter((item) => item !== id);
        resolve();
      }, ms);
      timersRef.current.push(id);
    });

  const refreshSingleSubscription = async (
    sub: SubscriptionRecord,
    simulateFault = false
  ) => {
    setRefreshingIds((prev) => ({ ...prev, [sub.id]: true }));
    appActions.setMascotState("searching");

    if (inTauri && !simulateFault) {
      try {
        const res = await catcloudApi.refreshSubscription(sub.id);
        await syncListsFromBackend();
        const warnNote = res.warnings.length > 0 ? `（提醒：${res.warnings[0]}）` : "";
        appActions.showToast(
          `${sub.name} 已刷新，当前 ${res.node_count} 个节点${warnNote}`,
          res.warnings.length > 0 ? "warn" : "ok"
        );
      } catch (err) {
        const errMsg = formatErrorMessage(err);
        setSubscriptions((prev) =>
          prev.map((item) =>
            item.id === sub.id ? { ...item, last_error: errMsg } : item
          )
        );
        appActions.showToast(
          `${sub.name} 刷新失败（已保留现有节点）：${errMsg}`,
          "warn"
        );
      } finally {
        setRefreshingIds((prev) => ({ ...prev, [sub.id]: false }));
        appActions.setMascotState("idle");
      }
      return;
    }

    // Browser preview mode
    await waitManaged(240);
    const nowIso = new Date().toISOString();
    if (simulateFault) {
      const errMsg =
        "远端返回 HTTP 503 或 0 节点，已自动中止覆盖并保留现有老节点与自建规则";
      setSubscriptions((prev) =>
        prev.map((item) =>
          item.id === sub.id ? { ...item, last_error: errMsg } : item
        )
      );
      appActions.showToast(
        `${sub.name} 刷新异常（预览演练）：已自动保护老节点与自建规则`,
        "warn"
      );
    } else {
      setSubscriptions((prev) =>
        prev.map((item) =>
          item.id === sub.id
            ? { ...item, last_ok_at: nowIso, last_error: null }
            : item
        )
      );
      appActions.showToast(`${sub.name} 已安全刷新`, "ok");
    }

    setRefreshingIds((prev) => ({ ...prev, [sub.id]: false }));
    appActions.setMascotState("idle");
  };

  const refreshAllSubscriptions = async () => {
    if (subscriptions.length === 0 || refreshingAll) return;
    setRefreshingAll(true);
    appActions.setMascotState("searching");

    if (inTauri) {
      try {
        const res = await catcloudApi.refreshAllSubscriptions();
        await syncListsFromBackend();
        if (res.errors.length > 0) {
          appActions.showToast(
            `已刷新 ${res.refreshed} 个订阅（共 ${res.total_nodes} 节点），${res.errors.length} 个失败：${res.errors[0]}`,
            "warn"
          );
        } else {
          appActions.showToast(
            `已刷新 ${res.refreshed} 个启用订阅，共 ${res.total_nodes} 个节点`,
            "ok"
          );
        }
      } catch (err) {
        appActions.showToast(`批量刷新订阅失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setRefreshingAll(false);
        appActions.setMascotState("idle");
      }
      return;
    }

    await waitManaged(300);
    const nowIso = new Date().toISOString();
    setSubscriptions((prev) =>
      prev.map((item) =>
        item.enabled ? { ...item, last_ok_at: nowIso, last_error: null } : item
      )
    );
    setRefreshingAll(false);
    appActions.setMascotState("idle");
    appActions.showToast(
      `已并发校验并刷新 ${subscriptions.filter((s) => s.enabled).length} 个启用订阅`,
      "ok"
    );
  };

  const handleAddSubscription = async () => {
    const name = newSubName.trim();
    const source = newSubSource.trim();
    if (!name || !source) {
      appActions.showToast("请填写订阅名称与来源地址 / 文件路径", "warn");
      return;
    }
    if (addKind === "url" && !/^https?:\/\//i.test(source)) {
      appActions.showToast("URL 订阅请以 http:// 或 https:// 开头", "warn");
      return;
    }

    const subId = `sub-${addKind}-${Date.now()}`;
    const nextSub: SubscriptionRecord = {
      id: subId,
      name,
      kind: addKind,
      url_or_cmd: source,
      source,
      refresh_interval_sec: newSubIntervalSec,
      traffic_used_bytes: 0,
      traffic_total_bytes: 0,
      expires_at: null,
      last_ok_at: null,
      last_error: null,
      enabled: true,
    };

    if (inTauri) {
      try {
        const saved = await catcloudApi.upsertSubscription(nextSub);
        let refreshNotice = "";
        let refreshWarn = false;
        try {
          const res = await catcloudApi.refreshSubscription(saved.id);
          refreshNotice = `，已拉取 ${res.node_count} 个节点`;
        } catch (refreshErr) {
          refreshWarn = true;
          refreshNotice = `，首次拉取失败（${formatErrorMessage(refreshErr)}）`;
        }
        await syncListsFromBackend();
        setNewSubName("");
        setNewSubSource("");
        setShowAddForm(false);
        appActions.showToast(
          `已保存${SUB_KIND_LABELS[addKind]}：${name}${refreshNotice}`,
          refreshWarn ? "warn" : "ok"
        );
      } catch (err) {
        appActions.showToast(`新增订阅失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }

    const previewSub: SubscriptionRecord = {
      ...nextSub,
      traffic_total_bytes: 300 * 1024 * 1024 * 1024,
      expires_at: "2027-12-31",
      last_ok_at: new Date().toISOString(),
    };
    const seedNode: ProxyNode = {
      id: `${subId}-node-1`,
      sub_id: subId,
      name: `${name} · JP-01 · 1x`,
      protocol: addKind === "url" ? "vless" : "trojan",
      server: addKind === "url" ? "203.0.113.55" : "198.51.100.56",
      port: 443,
      region_code: "JP",
      multiplier: 1.0,
      is_443_native: true,
      preaccel_override: null,
      tags: ["native-443"],
      enabled: true,
    };

    setSubscriptions((prev) => {
      const next = [...prev, previewSub];
      appActions.syncSubscriptions(next);
      return next;
    });
    setNodes((prev) => {
      const next = [...prev, seedNode];
      appActions.syncNodes(next);
      return next;
    });
    setNewSubName("");
    setNewSubSource("");
    setShowAddForm(false);
    appActions.showToast(`已新增${SUB_KIND_LABELS[addKind]}（预览）：${name}`, "ok");
  };

  const handleRemoveSubscription = async (sub: SubscriptionRecord) => {
    try {
      await catcloudApi.deleteSubscription(sub.id);
      if (inTauri) {
        await syncListsFromBackend();
      } else {
        setSubscriptions((prev) => {
          const next = prev.filter((item) => item.id !== sub.id);
          appActions.syncSubscriptions(next);
          return next;
        });
        const removedIds = new Set(
          nodes.filter((n) => n.sub_id === sub.id).map((n) => n.id)
        );
        setNodes((prev) => {
          const next = prev.filter((n) => n.sub_id !== sub.id);
          appActions.syncNodes(next);
          return next;
        });
        setSelectedNodeIds((prev) => {
          const next = new Set(prev);
          for (const id of removedIds) next.delete(id);
          return next;
        });
      }
      if (filterSubId === sub.id) setFilterSubId("all");
      appActions.showToast(`已移除订阅：${sub.name}`, "info");
    } catch (err) {
      appActions.showToast(`移除订阅失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  /* ---------- Drawer Callbacks ---------- */

  const handleMigrationImport = async (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ) => {
    if (inTauri) {
      try {
        const count = await catcloudApi.applyMigrationNodes(customName, preview.nodes);
        await syncListsFromBackend();
        appActions.showToast(
          `只读迁移完成：已落盘 ${count} 个节点（原目录零改动）`,
          "ok"
        );
      } catch (err) {
        appActions.showToast(`导入迁移节点失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }

    const subId = `sub-mig-${Date.now()}`;
    const importedNodes: ProxyNode[] = preview.nodes.map((node, idx) => ({
      ...node,
      id: `${subId}-${idx + 1}`,
      sub_id: subId,
    }));
    const sourceVal = preview.source_path ?? "clipboard://readonly-import";
    const nextSub: SubscriptionRecord = {
      id: subId,
      name: customName,
      kind: "migrated",
      url_or_cmd: sourceVal,
      source: sourceVal,
      refresh_interval_sec: 0,
      traffic_used_bytes: 0,
      traffic_total_bytes: 0,
      expires_at: null,
      last_ok_at: new Date().toISOString(),
      last_error: null,
      enabled: true,
    };
    setSubscriptions((prev) => [...prev, nextSub]);
    setNodes((prev) => [...prev, ...importedNodes]);
    setFilterSubId(subId);

    const ruleCount = includeRules
      ? preview.prepend_rules.length + preview.append_rules.length
      : 0;
    appActions.showToast(
      `只读迁移完成：导入 ${importedNodes.length} 个节点${ruleCount > 0 ? `、${ruleCount} 条规则` : ""}（原目录零改动）`,
      "ok"
    );
  };

  const handleProcessAttach = async (payload: {
    name: string;
    source: string;
    kind: SubscriptionRecord["kind"];
    nodes: ProxyNode[];
  }) => {
    const subId = `sub-proc-${Date.now()}`;
    const nextSub: SubscriptionRecord = {
      id: subId,
      name: payload.name,
      kind: payload.kind,
      url_or_cmd: payload.source,
      source: payload.source,
      refresh_interval_sec: 1800,
      traffic_used_bytes: 0,
      traffic_total_bytes: 0,
      expires_at: null,
      last_ok_at: null,
      last_error: null,
      enabled: true,
    };

    if (inTauri) {
      try {
        const saved = await catcloudApi.upsertSubscription(nextSub);
        let note = "";
        if (payload.nodes.length > 0) {
          const imported = await catcloudApi.applyMigrationNodes(payload.name, payload.nodes);
          note = `（已落盘 ${imported} 节点）`;
        } else {
          try {
            const refreshed = await catcloudApi.refreshSubscription(saved.id);
            note = `（已拉取 ${refreshed.node_count} 节点）`;
          } catch {
            note = "（已注册来源，可点击刷新拉取）";
          }
        }
        await syncListsFromBackend();
        setFilterSubId(saved.id);
        appActions.showToast(`已关联 ${payload.name}${note}`, "ok");
      } catch (err) {
        appActions.showToast(`关联进程源失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }

    const boundNodes: ProxyNode[] = payload.nodes.map((node, idx) => ({
      ...node,
      id: `${subId}-${idx + 1}`,
      sub_id: subId,
    }));
    const previewSub: SubscriptionRecord = {
      ...nextSub,
      last_ok_at: new Date().toISOString(),
    };
    setSubscriptions((prev) => [...prev, previewSub]);
    setNodes((prev) => [...prev, ...boundNodes]);
    setFilterSubId(subId);
    appActions.showToast(
      `已关联 ${payload.name}（引入 ${boundNodes.length} 个节点）`,
      "ok"
    );
  };

  /* ---------- Node Selection, Batch Group Join & PreAccel Override ---------- */

  const toggleSelectNode = (nodeId: string) => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  const toggleSelectAllFiltered = () => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (allFilteredSelected) {
        for (const n of filteredNodes) next.delete(n.id);
      } else {
        for (const n of filteredNodes) next.add(n.id);
      }
      return next;
    });
  };

  const handleBatchAddToGroup = async () => {
    if (selectedNodeIds.size === 0) return;
    const targetGroup = groups.find((g) => g.id === targetGroupId);
    if (!targetGroup) {
      appActions.showToast("请先选择目标多选组", "warn");
      return;
    }

    const existing = new Set(targetGroup.member_node_ids);
    const toAdd: string[] = [];
    for (const nid of selectedNodeIds) {
      if (!existing.has(nid)) toAdd.push(nid);
    }

    if (toAdd.length === 0) {
      appActions.showToast(
        `所选 ${selectedNodeIds.size} 个节点均已在「${targetGroup.name}」中`,
        "info"
      );
      return;
    }

    const updatedMemberIds = [...targetGroup.member_node_ids, ...toAdd];
    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        updatedMemberIds
      );
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === updated.id ? updated : g));
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(
        `已将 ${toAdd.length} 个节点批量加入「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`批量入组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleSingleGroupMember = async (nodeId: string) => {
    const targetGroup = groups.find((g) => g.id === targetGroupId);
    if (!targetGroup) return;
    const inGroup = targetGroup.member_node_ids.includes(nodeId);
    const nextMembers = inGroup
      ? targetGroup.member_node_ids.filter((id) => id !== nodeId)
      : [...targetGroup.member_node_ids, nodeId];

    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        nextMembers
      );
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === updated.id ? updated : g));
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(
        inGroup
          ? `已从「${targetGroup.name}」移出该节点`
          : `已加入「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`更新组成员失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSetPreAccelOverride = async (
    nodeIds: string[],
    overrideValue: boolean | null
  ) => {
    const overrideMode: PreAccelOverrideMode =
      overrideValue === null
        ? "inherit"
        : overrideValue
          ? "force_on"
          : "force_off";
    const idSet = new Set(nodeIds);
    const prevNodes = nodes;
    const optimistic = nodes.map((n) =>
      idSet.has(n.id) ? { ...n, preaccel_override: overrideValue } : n
    );
    setNodes(optimistic);
    try {
      await catcloudApi.setNodesPreAccelOverride(nodeIds, overrideMode);
      appActions.syncNodes(optimistic);
      const label =
        overrideValue === null
          ? "跟随全局"
          : overrideValue
            ? "强制开启预加速"
            : "强制关闭预加速";
      appActions.showToast(
        nodeIds.length > 1
          ? `已将 ${nodeIds.length} 个节点预加速策略设为「${label}」`
          : `已更新单节点预加速策略：${label}`,
        "ok"
      );
    } catch (err) {
      setNodes(prevNodes);
      appActions.showToast(`设置预加速覆写失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const resetAllFilters = () => {
    setKeyword("");
    setFilterSubId("all");
    setFilterRegion("all");
    setFilterMultiplier("all");
    setFilterProtocol("all");
    setFilter443("all");
    setHealthFilters({
      googleClean: false,
      keepalive60s: false,
      aiUnlocked: false,
    });
  };

  return (
    <div className="space-y-4">
      {/* ====================================================================
       * 1. Page Header & Quick Entry Toolbar
       * ==================================================================== */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
              节点与多订阅混池
            </h1>
            <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
              {subscriptions.length} 订阅 · {nodes.length} 节点 · {native443Count} 个 443 原生
            </span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
            <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--green)]">
              <ShieldCheck className="h-3.5 w-3.5" />
              刷新异常自动保护老节点与自建规则
            </span>
            <span>
              支持多云混合筛选、跨家一键入组、只读迁移与进程外挂对口
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setMigrationOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)]"
          >
            <FolderOpen className="h-3.5 w-3.5 text-[var(--accent)]" />
            老配置只读迁移
          </button>

          <button
            type="button"
            onClick={() => setProcessAttachOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)]"
          >
            <Cpu className="h-3.5 w-3.5 text-[var(--sky)]" />
            选进程智能对口
          </button>

          <button
            type="button"
            onClick={() => setShowAddForm((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
              showAddForm
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)]"
            }`}
          >
            <Plus className="h-3.5 w-3.5" />
            新增订阅
          </button>

          <button
            type="button"
            disabled={refreshingAll || subscriptions.length === 0}
            onClick={() => void refreshAllSubscriptions()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshingAll ? "animate-spin" : ""}`}
            />
            全部刷新
          </button>
        </div>
      </section>

      {/* ====================================================================
       * 2. Collapsible Add URL / Local File Subscription Form
       * ==================================================================== */}
      {showAddForm && (
        <section className="cc-card cc-glass space-y-3 rounded-2xl border-[var(--accent)]/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-[var(--text)]">
                新增订阅来源
              </span>
              <div className="inline-flex rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setAddKind("url")}
                  className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                    addKind === "url"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                >
                  URL 远程订阅
                </button>
                <button
                  type="button"
                  onClick={() => setAddKind("file")}
                  className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                    addKind === "file"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                >
                  本地配置文件
                </button>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="text-xs text-[var(--muted)] hover:text-[var(--text)]"
            >
              收起
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            <label className="text-[11px] text-[var(--muted)] md:col-span-3">
              订阅名称
              <input
                type="text"
                value={newSubName}
                onChange={(e) => setNewSubName(e.target.value)}
                placeholder={
                  addKind === "url" ? "例如：Demo Cloud Beta" : "例如：本地原生节点集"
                }
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </label>

            <label className="text-[11px] text-[var(--muted)] md:col-span-6">
              {addKind === "url" ? "订阅链接（支持 Clash YAML / Base64 / URI）" : "本地只读配置文件路径"}
              <input
                type="text"
                value={newSubSource}
                onChange={(e) => setNewSubSource(e.target.value)}
                placeholder={
                  addKind === "url"
                    ? "https://example.invalid/sub/demo-provider.yaml"
                    : "data/subs/demo-custom.yaml"
                }
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </label>

            <label className="text-[11px] text-[var(--muted)] md:col-span-3">
              自动刷新周期
              <select
                value={newSubIntervalSec}
                onChange={(e) => setNewSubIntervalSec(Number(e.target.value))}
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
              >
                <option value={21600}>每 6 小时</option>
                <option value={43200}>每 12 小时</option>
                <option value={86400}>每 24 小时</option>
                <option value={0}>仅手动刷新</option>
              </select>
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px] text-[var(--muted)]">
            <span>
              单次拉取严格限制 &lt;= 16 MiB；若返回非 2xx、空节点或解析失败，自动中止覆盖保护现有老节点。
            </span>
            <button
              type="button"
              onClick={() => void handleAddSubscription()}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
            >
              <Check className="h-3.5 w-3.5" />
              保存并校验拉取
            </button>
          </div>
        </section>
      )}

      {/* ====================================================================
       * 3. Horizontal Multi-Cloud Subscription Cards Strip
       * ==================================================================== */}
      <section aria-label="多云订阅卡片">
        <div className="flex gap-3 overflow-x-auto pb-1.5">
          {subscriptions.map((sub) => {
            const hasQuota = sub.traffic_total_bytes > 0;
            const usedBytes = Math.max(0, sub.traffic_used_bytes);
            const remainingBytes = hasQuota
              ? Math.max(0, sub.traffic_total_bytes - usedBytes)
              : 0;
            const usagePct = hasQuota
              ? Math.min(100, Math.round((usedBytes / sub.traffic_total_bytes) * 100))
              : 0;
            const barColor =
              usagePct >= 90
                ? "var(--red)"
                : usagePct >= 75
                  ? "var(--amber)"
                  : "var(--accent)";
            const expire = formatExpireInfo(sub.expires_at);
            const nodeCount = subNodeCountMap.get(sub.id) ?? 0;
            const isSelectedFilter = filterSubId === sub.id;
            const isRefreshing = Boolean(refreshingIds[sub.id]) || refreshingAll;

            return (
              <article
                key={sub.id}
                className={`cc-card cc-glass flex min-w-[300px] max-w-[360px] flex-1 flex-col justify-between rounded-2xl p-3.5 ${
                  isSelectedFilter ? "border-[var(--accent)]" : ""
                }`}
              >
                <div>
                  {/* Card Top Header */}
                  <div className="flex items-start justify-between gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        setFilterSubId(isSelectedFilter ? "all" : sub.id)
                      }
                      className="min-w-0 text-left"
                      title="点击按此订阅筛选下方节点库"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-sm font-semibold text-[var(--text)]">
                          {sub.name}
                        </span>
                        <span className="shrink-0 rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          {SUB_KIND_LABELS[sub.kind]}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                        {getSubSource(sub)}
                      </div>
                    </button>

                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        disabled={isRefreshing}
                        onClick={() => void refreshSingleSubscription(sub, false)}
                        className="inline-flex h-7 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                        title="单卡安全刷新（异常自动保护老节点与自建规则）"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${isRefreshing ? "animate-spin" : ""}`}
                        />
                        刷新
                      </button>
                      {!inTauri && (
                        <button
                          type="button"
                          disabled={isRefreshing}
                          onClick={() => void refreshSingleSubscription(sub, true)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--amber)] hover:text-[var(--amber)] disabled:opacity-50"
                          title="演练刷新异常保护（预览演示：验证老节点不被清空）"
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                        </button>
                      )}
                      {(inTauri || subscriptions.length > 1) && (
                        <button
                          type="button"
                          onClick={() => void handleRemoveSubscription(sub)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
                          title="移除此订阅源"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Traffic Progress Bar */}
                  <div className="mt-3">
                    {hasQuota ? (
                      <>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-[var(--muted)]">
                            已用{" "}
                            <span className="cc-mono text-[var(--text)]">
                              {formatBytes(usedBytes)}
                            </span>{" "}
                            / {formatBytes(sub.traffic_total_bytes)}
                          </span>
                          <span className="cc-mono font-medium text-[var(--text-secondary)]">
                            余 {formatBytes(remainingBytes)} ({100 - usagePct}%)
                          </span>
                        </div>
                        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-elevated)]">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${usagePct}%`,
                              backgroundColor: barColor,
                            }}
                          />
                        </div>
                      </>
                    ) : (
                      <div className="rounded-lg bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px] text-[var(--muted)]">
                        无远端流量配额头 · 当前已托管{" "}
                        <span className="cc-mono text-[var(--text)]">
                          {nodeCount}
                        </span>{" "}
                        个只读节点
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Bottom Meta & Error Protection Status */}
                <div className="mt-3 space-y-1.5 border-t border-[var(--line)] pt-2.5 text-[11px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">到期时间</span>
                    <span
                      className="cc-mono"
                      style={{
                        color:
                          expire.tone === "danger"
                            ? "var(--red)"
                            : expire.tone === "warn"
                              ? "var(--amber)"
                              : "var(--text-secondary)",
                      }}
                    >
                      {expire.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--muted)]">
                      最近刷新 · {nodeCount} 节点
                    </span>
                    <span className="cc-mono text-[var(--text-secondary)]">
                      {formatTimeShort(sub.last_ok_at)}
                    </span>
                  </div>

                  {sub.last_error && (
                    <div className="flex items-start gap-1.5 rounded-lg bg-[var(--amber-soft)] px-2 py-1.5 text-[10px] leading-snug text-[var(--amber)]">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>{sub.last_error}</span>
                    </div>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      </section>

      {/* ====================================================================
       * 4. Multi-Dimensional Filter Matrix
       * ==================================================================== */}
      <section className="cc-card cc-glass space-y-3 rounded-2xl p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-xs font-semibold text-[var(--text)]">
              多维节点库叠加筛选
            </h2>
            <span className="cc-mono text-[11px] text-[var(--muted)]">
              命中 {filteredNodes.length} / {nodes.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-60">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder="搜节点名、地区、协议、标签或域名..."
                className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </div>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetAllFilters}
                className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--text)]"
              >
                <RotateCcw className="h-3 w-3" />
                重置筛选
              </button>
            )}
          </div>
        </div>

        {/* Filter Rows */}
        <div className="space-y-2 text-[11px]">
          {/* Row A: Subscription Source & Region */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">来源订阅</span>
              <button
                type="button"
                onClick={() => setFilterSubId("all")}
                className={`rounded-lg border px-2 py-0.5 transition-colors ${
                  filterSubId === "all"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                全部
              </button>
              {subscriptions.map((sub) => (
                <button
                  key={sub.id}
                  type="button"
                  onClick={() => setFilterSubId(sub.id)}
                  className={`rounded-lg border px-2 py-0.5 transition-colors ${
                    filterSubId === sub.id
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {sub.name} ({subNodeCountMap.get(sub.id) ?? 0})
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">地区</span>
              <button
                type="button"
                onClick={() => setFilterRegion("all")}
                className={`rounded-lg border px-2 py-0.5 transition-colors ${
                  filterRegion === "all"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                全部
              </button>
              {regionStats.map(([code, count]) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => setFilterRegion(code)}
                  className={`rounded-lg border px-2 py-0.5 cc-mono transition-colors ${
                    filterRegion === code
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                  title={REGION_LABELS[code] ?? code}
                >
                  {code} {REGION_LABELS[code] ? `· ${REGION_LABELS[code]}` : ""} ({count})
                </button>
              ))}
            </div>
          </div>

          {/* Row B: Multiplier Range, Protocol, 443 Native & Health Checks */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-[var(--line)]/70 pt-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">倍率区间</span>
              {(
                [
                  { id: "all", label: "全部" },
                  { id: "le1", label: "<= 1x" },
                  { id: "1to2", label: "1x..2x" },
                  { id: "ge3", label: "3x+" },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setFilterMultiplier(opt.id)}
                  className={`rounded-lg border px-2 py-0.5 cc-mono transition-colors ${
                    filterMultiplier === opt.id
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">协议</span>
              <button
                type="button"
                onClick={() => setFilterProtocol("all")}
                className={`rounded-lg border px-2 py-0.5 transition-colors ${
                  filterProtocol === "all"
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                    : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                }`}
              >
                全部
              </button>
              {protocolStats.map(([proto, count]) => (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setFilterProtocol(proto)}
                  className={`rounded-lg border px-2 py-0.5 cc-mono uppercase transition-colors ${
                    filterProtocol === proto
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {proto} ({count})
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">443 原生</span>
              {(
                [
                  { id: "all", label: "全部" },
                  { id: "only_443", label: "仅 443 原生" },
                  { id: "non_443", label: "非 443" },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setFilter443(opt.id)}
                  className={`rounded-lg border px-2 py-0.5 transition-colors ${
                    filter443 === opt.id
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--muted)]">体检状态</span>
              {(
                [
                  { key: "googleClean", label: "零送中" },
                  { key: "keepalive60s", label: "60s 保活" },
                  { key: "aiUnlocked", label: "AI 解锁" },
                ] as const
              ).map((item) => {
                const active = healthFilters[item.key];
                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() =>
                      setHealthFilters((prev) => ({
                        ...prev,
                        [item.key]: !prev[item.key],
                      }))
                    }
                    className={`inline-flex items-center gap-1 rounded-lg border px-2 py-0.5 transition-colors ${
                      active
                        ? "border-[var(--green)] bg-[var(--green-soft)] font-medium text-[var(--green)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    {active && <Check className="h-3 w-3" />}
                    {item.label}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* ====================================================================
       * 5. Cross-Subscription Batch Grouping & PreAccel Override Bar
       * ==================================================================== */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3">
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <button
            type="button"
            onClick={toggleSelectAllFiltered}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
          >
            <Check className="h-3 w-3 text-[var(--accent)]" />
            {allFilteredSelected ? "取消全选当前页" : "全选当前筛选结果"}
          </button>

          {selectedNodeIds.size > 0 ? (
            <>
              <span className="rounded-full bg-[var(--accent-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                已勾选 {selectedNodeIds.size} 个节点
                {selectedCrossSubCount > 1
                  ? `（跨 ${selectedCrossSubCount} 家订阅）`
                  : ""}
              </span>
              <button
                type="button"
                onClick={() => setSelectedNodeIds(new Set())}
                className="text-[11px] text-[var(--muted)] hover:text-[var(--text)]"
              >
                清空勾选
              </button>
            </>
          ) : (
            <span className="text-[11px] text-[var(--muted)]">
              可跨多家订阅自由勾选节点，一键批量编入指定智能多选组
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs">
            <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
            <select
              aria-label="目标智能多选组"
              value={targetGroupId}
              onChange={(e) => setTargetGroupId(e.target.value)}
              className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}（{g.member_node_ids.length} 节点）
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            disabled={selectedNodeIds.size === 0 || groups.length === 0}
            onClick={() => void handleBatchAddToGroup()}
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <Plus className="h-3.5 w-3.5" />
            批量加入所选多选组
          </button>

          {selectedNodeIds.size > 0 && (
            <div className="inline-flex items-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), true)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--accent)]"
                title="将所选节点批量设为强制开启国内预加速"
              >
                批量预加速开
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), false)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--red)]"
                title="将所选节点批量设为强制关闭国内预加速"
              >
                强制关
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), null)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                title="将所选节点恢复为跟随全局预加速策略"
              >
                跟全局
              </button>
            </div>
          )}
        </div>
      </section>

      {/* ====================================================================
       * 6. Mixed Node Pool Table with Single-Node PreAccel Override
       * ==================================================================== */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)] text-[11px] font-medium text-[var(--muted)]">
                <th className="w-10 px-3.5 py-2.5">
                  <input
                    type="checkbox"
                    checked={allFilteredSelected}
                    onChange={toggleSelectAllFiltered}
                    aria-label="全选当前筛选节点"
                    className="accent-[var(--accent)]"
                  />
                </th>
                <th className="px-3 py-2.5">节点名称 / 来源订阅 / 所属多选组</th>
                <th className="px-3 py-2.5">地区 · 倍率 · 协议</th>
                <th className="px-3 py-2.5">体检真值（延迟 / 零送中 / 60s 保活 / AI）</th>
                <th className="px-3 py-2.5">
                  <div className="inline-flex items-center gap-1">
                    <Zap className="h-3.5 w-3.5 text-[var(--accent)]" />
                    国内预加速单节点覆写
                  </div>
                </th>
                <th className="px-3.5 py-2.5 text-right">快捷编组</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]/70">
              {filteredNodes.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-6 py-10 text-center text-xs text-[var(--muted)]"
                  >
                    <Globe className="mx-auto mb-2 h-6 w-6 opacity-50" />
                    当前多维筛选条件下暂无匹配节点，请放宽筛选条件或新增/迁移订阅。
                  </td>
                </tr>
              ) : (
                filteredNodes.map((node) => {
                  const selected = selectedNodeIds.has(node.id);
                  const probe = storeProbes[node.id];
                  const aiInfo = countAiUnlocked(probe);
                  const subName = subNameMap.get(node.sub_id) ?? node.sub_id;
                  const memberGroups = nodeGroupMembership.get(node.id) ?? [];
                  const targetGroup = groups.find((g) => g.id === targetGroupId);
                  const inTargetGroup =
                    targetGroup?.member_node_ids.includes(node.id) ?? false;

                  const effectiveGlobalPreAccel =
                    globalPreAccel.enabled &&
                    !(globalPreAccel.skip_443_native && node.is_443_native);

                  return (
                    <tr
                      key={node.id}
                      className={`transition-colors ${
                        selected
                          ? "bg-[var(--accent-soft)]/60"
                          : "hover:bg-[var(--card-hover)]"
                      }`}
                    >
                      {/* Checkbox */}
                      <td className="px-3.5 py-3 align-middle">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => toggleSelectNode(node.id)}
                          aria-label={`选择节点 ${node.name}`}
                          className="accent-[var(--accent)]"
                        />
                      </td>

                      {/* Node Name, Source Sub & Group Membership */}
                      <td className="px-3 py-3 align-middle">
                        <div className="flex items-center gap-2">
                          <Server className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                          <span className="font-semibold text-[var(--text)]">
                            {node.name}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px]">
                          <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--text-secondary)]">
                            {subName}
                          </span>
                          <span className="cc-mono text-[var(--muted)]">
                            {node.server}:{node.port}
                          </span>
                          {memberGroups.map((g) => (
                            <span
                              key={g.id}
                              className="rounded-full bg-[var(--sky-soft)] px-1.5 py-0.5 font-medium text-[var(--sky)]"
                            >
                              {g.name}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Region, Multiplier, Protocol & 443 Native */}
                      <td className="px-3 py-3 align-middle">
                        <div className="flex flex-wrap items-center gap-1.5 cc-mono text-[11px]">
                          <span className="rounded-md border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-0.5 font-medium text-[var(--text)]">
                            {node.region_code}
                          </span>
                          <span
                            className={`rounded-md px-1.5 py-0.5 font-medium ${
                              node.multiplier >= 3
                                ? "bg-[var(--coral-soft)] text-[var(--coral)]"
                                : node.multiplier <= 1
                                  ? "bg-[var(--green-soft)] text-[var(--green)]"
                                  : "bg-[var(--amber-soft)] text-[var(--amber)]"
                            }`}
                          >
                            {node.multiplier}x
                          </span>
                          <span className="rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 uppercase text-[var(--text-secondary)]">
                            {node.protocol}
                          </span>
                          {node.is_443_native ? (
                            <span className="rounded-md bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                              443 原生
                            </span>
                          ) : (
                            <span className="rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                              :{node.port}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Health Snapshot Badges */}
                      <td className="px-3 py-3 align-middle">
                        <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                          <span className="cc-mono rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--text)]">
                            {probe?.latency_ms != null
                              ? `${probe.latency_ms} ms`
                              : "未测"}
                            {probe?.up_mbps != null
                              ? ` · ↑${probe.up_mbps.toFixed(1)}M`
                              : ""}
                          </span>

                          <span
                            className={`rounded-md px-1.5 py-0.5 font-medium ${
                              probe?.google_clean === true &&
                              !probe.google_risk_mismatch
                                ? "bg-[var(--green-soft)] text-[var(--green)]"
                                : probe?.google_clean === false ||
                                    probe?.google_risk_mismatch
                                  ? "bg-[var(--red-soft)] text-[var(--red)]"
                                  : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                            }`}
                          >
                            {probe?.google_clean === true &&
                            !probe.google_risk_mismatch
                              ? "零送中"
                              : probe?.google_risk_mismatch
                                ? "风控告警"
                                : probe?.google_clean === false
                                  ? "送中"
                                  : "未验送中"}
                          </span>

                          <span
                            className={`rounded-md px-1.5 py-0.5 font-medium ${
                              probe?.keepalive_60s_ok === true
                                ? "bg-[var(--green-soft)] text-[var(--green)]"
                                : probe?.keepalive_60s_ok === false
                                  ? "bg-[var(--red-soft)] text-[var(--red)]"
                                  : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                            }`}
                          >
                            {probe?.keepalive_60s_ok === true
                              ? "60s 保活"
                              : probe?.keepalive_60s_ok === false
                                ? "断流风险"
                                : "未验保活"}
                          </span>

                          <span
                            title={aiInfo.detail}
                            className={`rounded-md px-1.5 py-0.5 font-medium ${
                              aiInfo.passed > 0
                                ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                                : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                            }`}
                          >
                            {aiInfo.total > 0
                              ? `AI ${aiInfo.passed}/${aiInfo.total}`
                              : "AI 未测"}
                          </span>
                        </div>
                      </td>

                      {/* Single-Node PreAccel 3-State Override */}
                      <td className="px-3 py-3 align-middle">
                        <div className="flex flex-col gap-1">
                          <div className="inline-flex w-fit rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[10px]">
                            {(
                              [
                                { value: null, label: "跟随全局" },
                                { value: true, label: "强制开" },
                                { value: false, label: "强制关" },
                              ] as const
                            ).map((opt) => {
                              const active = node.preaccel_override === opt.value;
                              const activeClass =
                                opt.value === true
                                  ? "bg-[var(--accent)] text-[var(--accent-ink)] font-semibold"
                                  : opt.value === false
                                    ? "bg-[var(--red-soft)] text-[var(--red)] font-semibold"
                                    : "bg-[var(--card)] text-[var(--text)] font-semibold";
                              return (
                                <button
                                  key={String(opt.value)}
                                  type="button"
                                  onClick={() =>
                                    void handleSetPreAccelOverride([node.id], opt.value)
                                  }
                                  className={`rounded-md px-2 py-0.5 transition-colors ${
                                    active
                                      ? activeClass
                                      : "text-[var(--muted)] hover:text-[var(--text)]"
                                  }`}
                                >
                                  {opt.label}
                                </button>
                              );
                            })}
                          </div>
                          {node.preaccel_override === null && (
                            <span className="text-[10px] text-[var(--muted)]">
                              当前全局生效：
                              {effectiveGlobalPreAccel
                                ? "启用预加速"
                                : node.is_443_native &&
                                    globalPreAccel.skip_443_native
                                  ? "443 原生自动直连跳过"
                                  : "全局已关"}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Single-Node Quick Group Action */}
                      <td className="px-3.5 py-3 text-right align-middle">
                        <button
                          type="button"
                          disabled={!targetGroup}
                          onClick={() => void handleToggleSingleGroupMember(node.id)}
                          className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                            inTargetGroup
                              ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)] hover:opacity-85"
                              : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)]"
                          }`}
                        >
                          {inTargetGroup ? (
                            <>
                              <Check className="h-3 w-3" />
                              已在组
                            </>
                          ) : (
                            <>
                              <Plus className="h-3 w-3" />
                              入组
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ====================================================================
       * 7. Slide-Over Drawers: Legacy Read-Only Migration & Process Attach
       * ==================================================================== */}
      <MigrationDrawer
        open={migrationOpen}
        onClose={() => setMigrationOpen(false)}
        onImport={handleMigrationImport}
      />

      <ProcessAttachDrawer
        open={processAttachOpen}
        onClose={() => setProcessAttachOpen(false)}
        onAttachSource={handleProcessAttach}
      />
    </div>
  );
}
