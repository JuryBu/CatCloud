import {
  AlertTriangle,
  ArrowLeft,
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
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
  Minus,
  Play,
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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import {
  ContinentRegionFilter,
  PaginationBar,
} from "../components/ContinentRegionFilter";
import { appActions, useAppSelector } from "../store/appStore";
import {
  type ContinentId,
  buildContinentRegionStats,
  getRegionLabel,
  nodeMatchesContinentAndRegion,
  resolveNodeRegionCode,
} from "../utils/regions";

/* ============================================================================
 * Domain Types & Demo Presets
 * ============================================================================ */

type MultiplierRange = "all" | "le1" | "1to2" | "ge3";
type Native443Filter = "all" | "only_443" | "non_443";
type NodeSortBy = "default" | "latency" | "up" | "down";
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
  url: "订阅链接",
  file: "本地文件",
  migrated: "已有软件导入",
  process_adapter: "软件抓取",
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
    desc: "只读复制里面的节点列表和自定义分流规则，不改原软件",
  },
  {
    kind: "flclash",
    label: "落云 / FlClash",
    readonlyPathHint: "%APPDATA%\\com.follow.clash\\profiles",
    desc: "只读提取多份配置里的节点、地区和倍率信息",
  },
  {
    kind: "v2rayn",
    label: "v2rayN",
    readonlyPathHint: "%APPDATA%\\v2rayN\\guiConfigs\\config.json",
    desc: "只读读取已保存的节点以及直连/代理规则",
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
    warnings: ["已自动忽略原配置中的默认兜底规则，避免覆盖猫猫云梯路由策略"],
  },
  flclash: {
    id: "mig-flclash",
    source_kind: "flclash",
    client_label: "落云 / FlClash",
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

function maskSubscriptionSource(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";

  const secretSepIdx = trimmed.indexOf("|secret=");
  const hasInlineSecret = secretSepIdx >= 0;
  const basePart = hasInlineSecret ? trimmed.slice(0, secretSepIdx).trim() : trimmed;

  if (/^https?:\/\//i.test(basePart)) {
    try {
      const parsed = new URL(basePart);
      const isLocalLoopback =
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "localhost" ||
        parsed.hostname === "::1";
      const segs = parsed.pathname.split("/").filter(Boolean);
      const hasQuery = parsed.search.length > 0;

      if (isLocalLoopback) {
        const cleanPath = segs.length > 0 ? `/${segs.join("/")}` : "";
        const secretHint = hasInlineSecret || hasQuery ? "（已设口令）" : "";
        return `${parsed.protocol}//${parsed.host}${cleanPath}${secretHint}`;
      }

      if (segs.length === 0) {
        return hasQuery
          ? `${parsed.protocol}//${parsed.host}/••••••`
          : `${parsed.protocol}//${parsed.host}`;
      }
      const firstSeg = segs[0];
      const firstLooksSecret = firstSeg.length >= 12 || /[0-9a-f]{10,}/i.test(firstSeg);
      const maskedPath = firstLooksSecret ? "/••••••" : `/${firstSeg}/••••••`;
      return `${parsed.protocol}//${parsed.host}${maskedPath}`;
    } catch {
      return basePart.replace(/([?&][^=&\s]+=)[^&\s]+/g, "$1••••••");
    }
  }

  return basePart
    .replace(/[A-Za-z]:[\\/]Users[\\/][^\\/]+/gi, "C:\\Users\\<USER>")
    .replace(/\/(?:Users|home)\/[^/]+/g, "/home/<USER>");
}

function formatQuotaBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0.0 GB";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  if (idx === 0) return `${Math.round(value)} B`;
  return `${value.toFixed(1)} ${units[idx]}`;
}

function inferSubNameFromUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.replace(/^www\./i, "");
    if (host) return host;
  } catch {
    /* use fallback */
  }
  return "我的订阅";
}

function migrationClientLabel(kind: string): string {
  switch (kind) {
    case "clash_verge":
      return "Clash Verge / Rev";
    case "flclash":
      return "落云 / FlClash";
    case "v2rayn":
      return "v2rayN";
    case "local_file":
      return "本地配置文件";
    case "clipboard_text":
      return "粘贴的配置文本";
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
        "找到了该软件正在使用的配置文件，可以直接安全读取节点，不会修改原文件。",
    };
  } else if (normalizedCtrl) {
    recommendation = {
      mode: "public_controller_api",
      endpoint_url: `${normalizedCtrl.replace(/\/+$/, "")}/proxies`,
      proxy_count: controllerProxyCount,
      requires_secret: controllerRequiresSecret,
      reason: controllerRequiresSecret
        ? "检测到本地软件接口，填入访问口令后即可安全读取节点列表。"
        : "检测到该软件的本地公开接口，可以直接安全抓取可用节点。",
    };
  } else {
    recommendation = {
      mode: "external_adapter_template",
      schema: ADAPTER_SCHEMA_V1,
      suggested_command: `python3 adapters/${processName.replace(/\.exe$/i, "")}_adapter.py`,
      template_script: template,
      reason:
        "这个软件没有公开配置文件或本地接口，暂时无法直接自动抓节点。建议优先尝试「粘贴订阅链接」或「从电脑已有梯子导入」，也可在下方展开高级自定义刷新脚本。",
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
        : ["安全只读模式：仅读取配置或本地公开接口，不会修改对方软件。"],
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
          "找到了该软件正在使用的配置文件，可以直接安全读取节点，不会修改原文件。",
      },
      notes: [
        "仅只读打开配置文件提取节点，不会修改原软件目录。",
        "关联后支持定期安全同步节点，读取异常会自动保留旧节点。",
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
          ? "检测到该软件的本地接口设有访问口令，填入后即可安全抓取节点。"
          : "检测到该软件的本地公开接口，可以直接安全抓取可用节点。",
      },
      notes: [
        `仅在本机安全读取接口 ${normalized}/proxies。`,
        "不会修改原软件配置，也不会影响它正常运行。",
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
        "这个软件没有公开配置文件或本地接口，暂时无法直接自动抓节点。建议优先尝试「粘贴订阅链接」或「从电脑已有梯子导入」，也可在下方展开高级自定义刷新脚本。",
    },
    notes: [
      "安全只读原则：不会读取受保护的程序内存或私密数据。",
      "如果你熟悉写脚本，可以在下方「高级：自定义刷新脚本」中接入自定义来源。",
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
          warnings.push("已跳过默认兜底规则，保留猫猫云梯主分流结构");
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
    warnings.push("未提取到有效节点，请确认粘贴的是完整的节点配置或节点分享链接");
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

function getNodeAiInfo(probe: ProbeSnapshot | undefined): {
  passed: number;
  total: number;
  unlockedLabels: string[];
  detail: string;
} {
  if (!probe) {
    return { passed: 0, total: 0, unlockedLabels: [], detail: "暂无解锁快照" };
  }
  const sites = probe.unlocked_sites ?? {};
  const geminiVal = sites.gemini ?? sites.gemini_aistudio ?? sites.google_ai;
  const claudeVal = sites.claude;
  const chatgptVal = sites.chatgpt;
  const windsurfVal = sites.windsurf ?? probe.per_probe_ok?.builtin_unlock_windsurf;

  const normalized: Array<{ label: string; short: string; val: boolean | undefined }> = [
    { label: "Claude", short: "Claude", val: claudeVal },
    { label: "Gemini", short: "Gemini", val: geminiVal },
    { label: "ChatGPT", short: "GPT", val: chatgptVal },
    { label: "Windsurf", short: "WS", val: windsurfVal },
  ];

  const measured = normalized.filter((item) => item.val !== undefined);
  const unlocked = measured.filter((item) => item.val === true);
  if (measured.length === 0) {
    const fallbackEntries = Object.entries(sites);
    const passed = fallbackEntries.filter(([, ok]) => ok).length;
    return {
      passed,
      total: fallbackEntries.length,
      unlockedLabels: fallbackEntries.filter(([, ok]) => ok).map(([k]) => k),
      detail:
        fallbackEntries.length > 0
          ? fallbackEntries.map(([k, ok]) => `${k}: ${ok ? "解锁" : "受限"}`).join(" · ")
          : "暂无解锁快照",
    };
  }
  return {
    passed: unlocked.length,
    total: measured.length,
    unlockedLabels: unlocked.map((item) => item.short),
    detail: measured.map((item) => `${item.label}: ${item.val ? "可用" : "受限"}`).join(" · "),
  };
}

function isAiUnlocked(probe: ProbeSnapshot | undefined): boolean {
  return getNodeAiInfo(probe).passed > 0;
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
  const openSessionRef = useRef(false);

  const runScanClient = useCallback(
    async (
      kind: "clash_verge" | "flclash" | "v2rayn" | "all",
      autoTriggered = false
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
          setCustomSubName(`导入 · ${items[0].client_label}`);
          appActions.showToast(
            `已找到 ${items.reduce((acc, i) => acc + i.nodes.length, 0)} 个可导入节点（不会改动原软件）`,
            "ok"
          );
        } else if (!autoTriggered) {
          appActions.showToast(
            "未在常见位置找到已有软件配置，也可以切换到「粘贴配置文本」导入",
            "info"
          );
        }
      } catch (err) {
        appActions.showToast(`扫描已有配置失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setScanningKind(null);
      }
    },
    []
  );

  useEffect(() => {
    if (!open) {
      openSessionRef.current = false;
      return;
    }
    if (!openSessionRef.current) {
      openSessionRef.current = true;
      setTab("scan");
      void runScanClient("all", true);
    }
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose, runScanClient]);

  if (!open) return null;

  const activePreview =
    tab === "scan"
      ? scannedItems.find((item) => item.id === selectedPreviewId) ??
        scannedItems[0] ??
        null
      : pastePreview;

  const handleParsePaste = async () => {
    if (!pasteText.trim()) {
      appActions.showToast("请先粘贴配置文件内容或节点链接", "warn");
      return;
    }
    try {
      let parsed: MigrationPreviewItem;
      if (isTauriEnv()) {
        const res = await catcloudApi.previewMigrationFromText(
          customSubName.trim() || "粘贴导入的节点",
          pasteText
        );
        parsed = {
          id: `mig-clip-${Date.now()}`,
          source_kind: "clipboard_text",
          client_label: res.name || "粘贴的配置文本",
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
      setCustomSubName(parsed.client_label || "粘贴导入的节点");
      if (parsed.nodes.length > 0) {
        appActions.showToast(
          `解析成功：找到 ${parsed.nodes.length} 个可用节点`,
          "ok"
        );
      } else {
        appActions.showToast("没有识别出可用节点，请检查粘贴的内容是否完整", "warn");
      }
    } catch (err) {
      appActions.showToast(`解析失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleConfirmImport = () => {
    if (!activePreview || activePreview.nodes.length === 0) return;
    const finalName =
      customSubName.trim() || `导入 · ${activePreview.client_label}`;
    onImport(activePreview, finalName, includeRules);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="从电脑已有梯子导入"
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
                从电脑已有梯子导入
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              自动查找 Clash Verge / 落云 / v2rayN 的已有配置，也支持直接粘贴配置或节点链接。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="关闭导入窗口"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Read-Only Safety Banner */}
        <div className="mx-5 mt-3 flex items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--green-soft)] px-3 py-2 text-xs text-[var(--green)]">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span>
            只读安全复制：只会把节点复制一份进猫猫云梯，绝不改动你原来的软件和配置文件。
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
            自动找电脑里的梯子
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
            粘贴配置文本 / 节点链接
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {tab === "scan" ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-[var(--text-secondary)]">
                  常见梯子软件配置位置
                </span>
                <button
                  type="button"
                  disabled={scanningKind !== null}
                  onClick={() => void runScanClient("all", false)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)] bg-[var(--accent-soft)] px-2.5 py-1 text-xs font-medium text-[var(--accent)] hover:opacity-90 disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${scanningKind === "all" ? "animate-spin" : ""}`}
                  />
                  {scanningKind === "all" ? "正在扫描..." : "重新扫描全部"}
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
                                setCustomSubName(`导入 · ${found.client_label}`);
                              }}
                              className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
                            >
                              查看
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => void runScanClient(spec.kind, false)}
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
                  支持粘贴其他软件的配置文件内容、编码文本或单条/多条节点分享链接
                </label>
                <button
                  type="button"
                  onClick={() => setPasteText(DEMO_PASTE_SAMPLE)}
                  className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--accent)] hover:border-[var(--accent)]"
                >
                  填入示例内容
                </button>
              </div>
              <textarea
                id="cc-migration-paste"
                value={pasteText}
                onChange={(e) => setPasteText(e.target.value)}
                rows={8}
                placeholder="在这里粘贴配置内容，或者粘贴 vless:// / trojan:// / ss:// 等节点链接..."
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
                  解析并预览节点
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
                        <span
                          title={getRegionLabel(resolveNodeRegionCode(node))}
                          className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                        >
                          {resolveNodeRegionCode(node)}
                        </span>
                        <span className="rounded bg-[var(--accent-soft)] px-1.5 py-0.5 text-[var(--accent)]">
                          {node.multiplier}x
                        </span>
                        {node.is_443_native && (
                          <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[var(--green)]">
                            直连 443
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
                      检测到分流规则（优先 {activePreview.prepend_rules.length} 条 / 兜底{" "}
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
                  导入后的订阅名称
                  <input
                    type="text"
                    value={customSubName}
                    onChange={(e) => setCustomSubName(e.target.value)}
                    placeholder={`导入 · ${activePreview.client_label}`}
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
            只复制到猫猫云梯本地，不会修改原软件
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
              确认导入
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
          appActions.showToast(`读取运行中的软件列表失败：${formatErrorMessage(err)}`, "warn");
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
        appActions.showToast(`已刷新运行中的软件列表（共 ${mapped.length} 项）`, "info");
      } else {
        setCandidates(DEMO_PROCESS_CANDIDATES);
        appActions.showToast(`演示模式：共找到 ${DEMO_PROCESS_CANDIDATES.length} 个示例软件`, "info");
      }
    } catch (err) {
      appActions.showToast(`刷新软件列表失败：${formatErrorMessage(err)}`, "warn");
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
      } else {
        setAdapterCmd(
          `python3 adapters/${proc.name.replace(/\.exe$/i, "")}_adapter.py`
        );
      }
    } catch (err) {
      appActions.showToast(`识别该软件失败：${formatErrorMessage(err)}`, "warn");
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
      appActions.showToast("已复制自定义刷新脚本模板", "ok");
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
    appActions.showToast("已下载自定义刷新脚本模板", "ok");
  };

  const handleBindReadOnlySource = () => {
    if (!inspection) return;
    if (inspection.recommendation.mode === "read_only_local_file") {
      onAttachSource({
        name: `软件抓取 · ${inspection.process_name}`,
        source: inspection.recommendation.path,
        kind: "file",
        nodes: inTauri ? [] : inspection.preview_nodes,
      });
      onClose();
      return;
    }
    if (inspection.recommendation.mode === "public_controller_api") {
      const trimmedSecret = bearerSecret.trim();
      if (inspection.recommendation.requires_secret && !trimmedSecret) {
        appActions.showToast(
          "该软件的本地接口需要口令，请先填入后再抓取",
          "warn"
        );
        return;
      }
      const sourceWithSecret = trimmedSecret
        ? `${inspection.recommendation.endpoint_url}|secret=${trimmedSecret}`
        : inspection.recommendation.endpoint_url;
      onAttachSource({
        name: `接口抓取 · ${inspection.process_name}`,
        source: sourceWithSecret,
        kind: "process_adapter",
        nodes: inTauri ? [] : inspection.preview_nodes,
      });
      onClose();
    }
  };

  const handleRegisterAdapterSlot = () => {
    const trimmedCmd = adapterCmd.trim();
    if (!trimmedCmd) {
      appActions.showToast("请先填写自定义刷新脚本的执行命令", "warn");
      return;
    }
    const safeCooldown = Math.max(60, Math.round(adapterCooldownSec));
    const safeTimeout = Math.min(300, Math.max(5, Math.round(adapterTimeoutSec)));
    const procLabel = selectedProc?.name ?? "external";
    const subId = `sub-adapter-${Date.now()}`;
    onAttachSource({
      name: `自定义脚本 · ${procLabel}`,
      source: inTauri ? trimmedCmd : `${trimmedCmd} [timeout=${safeTimeout}s, cooldown=${safeCooldown}s]`,
      kind: "process_adapter",
      nodes: inTauri
        ? []
        : [
            {
              id: `${subId}-sample-1`,
              sub_id: subId,
              name: `JP-Script-${procLabel.replace(/\.exe$/i, "")} · 1x`,
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
      aria-label="从正在运行的软件抓节点"
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
                从正在运行的软件抓节点
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              先打开你的专用梯子软件，点选左侧对应程序，自动识别并安全抓取可用节点（只读，不修改原软件）。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="关闭软件抓取窗口"
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
              placeholder="搜索软件名称或进程号..."
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
              只看常见代理软件
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
              重新扫描
            </button>
          </div>
        </div>

        {/* Two-Pane Body */}
        <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto md:grid-cols-12">
          {/* Left: Process Candidate List */}
          <div className="space-y-2 border-b border-[var(--line)] p-4 md:col-span-5 md:border-b-0 md:border-r md:overflow-y-auto">
            <div className="text-[11px] font-medium text-[var(--muted)]">
              正在运行的软件（{filteredCandidates.length}）
            </div>
            {filteredCandidates.length === 0 ? (
              <div className="rounded-xl border border-dashed border-[var(--line)] p-4 text-center text-xs text-[var(--muted)]">
                没找到匹配的程序，请先打开你的梯子软件，或取消勾选「只看常见代理软件」
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
                        #{proc.pid}
                      </span>
                    </div>

                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {proc.detected_config_dir && (
                        <span className="rounded bg-[var(--sky-soft)] px-1.5 py-0.5 text-[10px] text-[var(--sky)]">
                          有配置目录
                        </span>
                      )}
                      {proc.detected_config_file && (
                        <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] text-[var(--green)]">
                          找到配置文件
                        </span>
                      )}
                      {proc.detected_controller_addr && (
                        <span className="rounded bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] text-[var(--accent)]">
                          找到本地接口
                        </span>
                      )}
                      {!proc.detected_config_file &&
                        !proc.detected_controller_addr && (
                          <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            未发现公开配置
                          </span>
                        )}
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
                请点击左侧正在运行的软件，自动识别可用的节点来源
              </div>
            ) : (
              <>
                {/* Selected Software Summary */}
                <div className="rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-[var(--accent)]" />
                      <span className="text-xs font-semibold text-[var(--text)]">
                        {selectedProc.name}
                      </span>
                      <span className="cc-mono text-[11px] text-[var(--muted)]">
                        进程 #{selectedProc.pid}
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
                      重新识别
                    </button>
                  </div>

                  <dl className="mt-2.5 space-y-1.5 text-[11px]">
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">配置目录</dt>
                      <dd className="cc-selectable break-all text-right cc-mono text-[var(--text-secondary)]">
                        {selectedProc.detected_config_dir ?? "未检测到"}
                      </dd>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">配置文件</dt>
                      <dd className="cc-selectable break-all text-right cc-mono text-[var(--text-secondary)]">
                        {selectedProc.detected_config_file ?? "未检测到"}
                      </dd>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <dt className="shrink-0 text-[var(--muted)]">本地接口</dt>
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
                        识别结果与抓取方式
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
                          ? "可直接读取配置文件"
                          : inspection.recommendation.mode ===
                              "public_controller_api"
                            ? "可直接通过本地接口抓取"
                            : "暂不支持直接自动抓取"}
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                      {inspection.recommendation.reason}
                    </p>

                    {/* Probe Telemetry Summary */}
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2">
                        <div className="text-[var(--muted)]">配置文件识别</div>
                        <div className="mt-0.5 cc-mono font-medium text-[var(--text)]">
                          {inspection.readable_yaml_file
                            ? `可读取 · ${inspection.yaml_node_count} 个节点`
                            : "未发现可读配置文件"}
                        </div>
                      </div>
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2">
                        <div className="text-[var(--muted)]">本地接口识别</div>
                        <div className="mt-0.5 cc-mono font-medium text-[var(--text)]">
                          {inspection.controller_reachable
                            ? inspection.controller_requires_secret
                              ? "已开启（需要访问口令）"
                              : `已开启 · ${inspection.controller_proxy_count} 个节点`
                            : "未开启或不可访问"}
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
                          一键抓取这些节点（{inspection.recommendation.node_count} 个）
                        </button>
                      </div>
                    )}

                    {inspection.recommendation.mode ===
                      "public_controller_api" && (
                      <div className="space-y-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5">
                        <div className="cc-mono text-[11px] text-[var(--accent)]">
                          {inspection.recommendation.endpoint_url}
                        </div>
                        {inspection.recommendation.requires_secret && (
                          <input
                            type="password"
                            value={bearerSecret}
                            onChange={(e) => setBearerSecret(e.target.value)}
                            placeholder="填入该软件的本地接口访问口令..."
                            className="w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 cc-mono text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                          />
                        )}
                        <button
                          type="button"
                          onClick={handleBindReadOnlySource}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                        >
                          <Link2 className="h-3.5 w-3.5" />
                          一键从本地接口抓取节点
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
                  </div>
                )}

                {/* Collapsible Advanced: Custom Refresh Script */}
                <div className="overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--card)]">
                  <button
                    type="button"
                    onClick={() => setShowAdapterSlot((v) => !v)}
                    className="flex w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-elevated)]/60 hover:text-[var(--text)]"
                  >
                    <span className="inline-flex items-center gap-1.5">
                      <FileCode2 className="h-3.5 w-3.5 text-[var(--muted)]" />
                      高级：自定义刷新脚本
                    </span>
                    {showAdapterSlot ? (
                      <ChevronDown className="h-3.5 w-3.5 text-[var(--muted)]" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5 text-[var(--muted)]" />
                    )}
                  </button>

                  {showAdapterSlot && (
                    <div className="space-y-3 border-t border-[var(--line)] p-3.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[11px] text-[var(--muted)]">
                          供熟悉编程的用户接入自定义来源（协议：{ADAPTER_SCHEMA_V1}）
                        </span>
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
                        标准协议：<span className="cc-mono text-[var(--text)]">stdin</span> 传入{" "}
                        <span className="cc-mono">{`{"reason","sub_id","failed_servers"}`}</span>，
                        <span className="cc-mono text-[var(--text)]">stdout</span> 返回{" "}
                        <span className="cc-mono">{`{"schema":"catcloud-adapter/v1","nodes":[...],"yaml":null}`}</span>
                        （上限 16 MiB，冷却 &gt;= 60s）。
                      </div>

                      <pre className="cc-selectable max-h-52 overflow-auto rounded-lg border border-[var(--line)] bg-[var(--bg)] p-3 cc-mono text-[11px] leading-relaxed text-[var(--text-secondary)]">
                        {activeTemplateScript}
                      </pre>

                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                        <label className="text-[11px] text-[var(--muted)] sm:col-span-6">
                          脚本启动命令
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
                          添加自定义刷新脚本
                        </button>
                      </div>
                    </div>
                  )}
                </div>
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

export interface NodesSubsPageProps {
  embeddedSubsOnly?: boolean;
  onViewSubNodes?: (subId: string | null) => void;
}

export function NodesSubsPage({
  embeddedSubsOnly = false,
  onViewSubNodes,
}: NodesSubsPageProps = {}) {
  const storeSubs = useAppSelector((s) => s.subscriptions);
  const storeNodes = useAppSelector((s) => s.nodes);
  const storeProbes = useAppSelector((s) => s.probes);
  const storeGroups = useAppSelector((s) => s.groups);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.config.preaccel);
  const isSingleMode = runtime.route_mode === "single";

  // Directly subscribe to appStore so edits on other pages always stay in sync
  const subscriptions = storeSubs;
  const nodes = storeNodes;
  const groups = storeGroups;

  // Top subscription controls & quick import form
  const [refreshingIds, setRefreshingIds] = useState<Record<string, boolean>>({});
  const [refreshingAll, setRefreshingAll] = useState(false);
  const [importingSub, setImportingSub] = useState(false);
  const [selectingSingleNodeId, setSelectingSingleNodeId] = useState<string | null>(null);
  const [showLocalFileForm, setShowLocalFileForm] = useState(false);
  const [newSubName, setNewSubName] = useState("");
  const [newSubSource, setNewSubSource] = useState("");
  const [localFileName, setLocalFileName] = useState("");
  const [localFilePath, setLocalFilePath] = useState("");
  const [newSubIntervalSec, setNewSubIntervalSec] = useState(21600);

  // Drawers & Delete Confirmation
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [processAttachOpen, setProcessAttachOpen] = useState(false);
  const [pendingDeleteSub, setPendingDeleteSub] = useState<SubscriptionRecord | null>(null);
  const [deletingSub, setDeletingSub] = useState(false);
  const closeMigration = useCallback(() => setMigrationOpen(false), []);
  const closeProcessAttach = useCallback(() => setProcessAttachOpen(false), []);

  useEffect(() => {
    if (!pendingDeleteSub) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !deletingSub) {
        setPendingDeleteSub(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingDeleteSub, deletingSub]);

  // Multi-dimensional node filters, sorting & pagination
  const [keyword, setKeyword] = useState("");
  const [filterSubId, setFilterSubId] = useState<string>("all");
  const [filterContinent, setFilterContinent] = useState<ContinentId>("all");
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
  const [sortBy, setSortBy] = useState<NodeSortBy>("default");
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  const [pageSize, setPageSize] = useState<number>(30);
  const [currentPage, setCurrentPage] = useState<number>(1);

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

  // Prune stale selected node IDs whenever the backing node list shrinks
  useEffect(() => {
    setSelectedNodeIds((prev) => {
      if (prev.size === 0) return prev;
      const validIds = new Set(nodes.map((n) => n.id));
      let changed = false;
      const next = new Set<string>();
      for (const id of prev) {
        if (validIds.has(id)) {
          next.add(id);
        } else {
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [nodes]);

  // Reset pagination to page 1 when filters or page size change
  useEffect(() => {
    setCurrentPage(1);
  }, [
    keyword,
    filterSubId,
    filterContinent,
    filterRegion,
    filterMultiplier,
    filterProtocol,
    filter443,
    healthFilters,
    sortBy,
    pageSize,
  ]);

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

  const nodesForRegionStats = useMemo(
    () =>
      filterSubId === "all"
        ? nodes
        : nodes.filter((n) => n.sub_id === filterSubId),
    [nodes, filterSubId]
  );

  const continentRegionStats = useMemo(
    () => buildContinentRegionStats(nodesForRegionStats),
    [nodesForRegionStats]
  );

  // Clear stale continent/region filter if switching source leaves zero nodes in that bucket
  useEffect(() => {
    if (nodesForRegionStats.length === 0) return;
    if (
      filterContinent !== "all" &&
      continentRegionStats.continentCounts[filterContinent] === 0
    ) {
      setFilterContinent("all");
      if (filterRegion !== "all") setFilterRegion("all");
      return;
    }
    if (
      filterRegion !== "all" &&
      !continentRegionStats.allRegions.some((r) => r.code === filterRegion)
    ) {
      setFilterRegion("all");
    }
  }, [
    nodesForRegionStats.length,
    continentRegionStats,
    filterContinent,
    filterRegion,
  ]);

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
    const matched = nodes.filter((node) => {
      if (filterSubId !== "all" && node.sub_id !== filterSubId) return false;
      if (!nodeMatchesContinentAndRegion(node, filterContinent, filterRegion)) {
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
      if (healthFilters.googleClean && probe?.google_clean !== true) {
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
        const regionCode = resolveNodeRegionCode(node);
        const regionLabel = getRegionLabel(regionCode).toLowerCase();
        const hit =
          node.name.toLowerCase().includes(kw) ||
          node.server.toLowerCase().includes(kw) ||
          node.protocol.toLowerCase().includes(kw) ||
          regionCode.toLowerCase().includes(kw) ||
          regionLabel.includes(kw) ||
          subName.includes(kw) ||
          node.tags.some((t) => t.toLowerCase().includes(kw));
        if (!hit) return false;
      }

      return true;
    });

    if (sortBy === "default") return matched;

    return [...matched].sort((a, b) => {
      const pa = storeProbes[a.id];
      const pb = storeProbes[b.id];
      if (sortBy === "latency") {
        const aOk = pa?.ok !== false && pa?.latency_ms != null;
        const bOk = pb?.ok !== false && pb?.latency_ms != null;
        if (aOk !== bOk) return aOk ? -1 : 1;
        if (aOk && bOk) return (pa!.latency_ms ?? 99999) - (pb!.latency_ms ?? 99999);
        return a.name.localeCompare(b.name);
      }
      if (sortBy === "up") {
        const aHas = pa?.up_mbps != null;
        const bHas = pb?.up_mbps != null;
        if (aHas !== bHas) return aHas ? -1 : 1;
        if (aHas && bHas) return (pb!.up_mbps ?? -1) - (pa!.up_mbps ?? -1);
        return a.name.localeCompare(b.name);
      }
      const aHas = pa?.down_mbps != null;
      const bHas = pb?.down_mbps != null;
      if (aHas !== bHas) return aHas ? -1 : 1;
      if (aHas && bHas) return (pb!.down_mbps ?? -1) - (pa!.down_mbps ?? -1);
      return a.name.localeCompare(b.name);
    });
  }, [
    nodes,
    keyword,
    filterSubId,
    filterContinent,
    filterRegion,
    filterProtocol,
    filterMultiplier,
    filter443,
    healthFilters,
    sortBy,
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

  const targetGroup = useMemo(
    () => groups.find((g) => g.id === targetGroupId) ?? null,
    [groups, targetGroupId]
  );

  const targetGroupMemberSet = useMemo(
    () => new Set(targetGroup?.member_node_ids ?? []),
    [targetGroup]
  );

  const advancedFilterCount =
    (filterMultiplier !== "all" ? 1 : 0) +
    (filterProtocol !== "all" ? 1 : 0) +
    (filter443 !== "all" ? 1 : 0) +
    (healthFilters.keepalive60s ? 1 : 0);

  const hasActiveFilters =
    keyword.trim().length > 0 ||
    filterSubId !== "all" ||
    filterContinent !== "all" ||
    filterRegion !== "all" ||
    healthFilters.googleClean ||
    healthFilters.aiUnlocked ||
    sortBy !== "default" ||
    advancedFilterCount > 0;

  const totalPages = Math.max(1, Math.ceil(filteredNodes.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStartIndex = (safePage - 1) * pageSize;
  const pagedNodes = useMemo(
    () => filteredNodes.slice(pageStartIndex, pageStartIndex + pageSize),
    [filteredNodes, pageStartIndex, pageSize]
  );

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
        appActions.syncSubscriptions(
          subscriptions.map((item) =>
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
        "远端返回异常或 0 个节点，已自动中止覆盖并保留现有老节点与自建规则";
      appActions.syncSubscriptions(
        subscriptions.map((item) =>
          item.id === sub.id ? { ...item, last_error: errMsg } : item
        )
      );
      appActions.showToast(
        `${sub.name} 刷新异常（预览演练）：已自动保护老节点与自建规则`,
        "warn"
      );
    } else {
      appActions.syncSubscriptions(
        subscriptions.map((item) =>
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
    appActions.syncSubscriptions(
      subscriptions.map((item) =>
        item.enabled ? { ...item, last_ok_at: nowIso, last_error: null } : item
      )
    );
    setRefreshingAll(false);
    appActions.setMascotState("idle");
    appActions.showToast(
      `已刷新 ${subscriptions.filter((s) => s.enabled).length} 个已启用的订阅`,
      "ok"
    );
  };

  const submitSubscriptionSource = async (
    kind: "url" | "file",
    rawSource: string,
    rawName: string
  ) => {
    if (importingSub) return;
    const source = rawSource.trim();
    if (!source) {
      appActions.showToast(
        kind === "url"
          ? "请先粘贴你的订阅链接"
          : "请填写本地配置文件路径",
        "warn"
      );
      return;
    }
    if (kind === "url" && !/^https?:\/\//i.test(source)) {
      appActions.showToast("订阅链接需要以 http:// 或 https:// 开头", "warn");
      return;
    }
    const name =
      rawName.trim() ||
      (kind === "url"
        ? inferSubNameFromUrl(source)
        : source.split(/[\\/]/).pop()?.replace(/\.[^.]+$/, "") || "本地配置");

    const subId = `sub-${kind}-${Date.now()}`;
    const nextSub: SubscriptionRecord = {
      id: subId,
      name,
      kind,
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

    setImportingSub(true);
    appActions.setMascotState("searching");
    try {
      if (inTauri) {
        try {
          const saved = await catcloudApi.upsertSubscription(nextSub);
          let refreshNotice = "";
          let refreshWarn = false;
          try {
            const res = await catcloudApi.refreshSubscription(saved.id);
            refreshNotice = `，已拉回 ${res.node_count} 个节点`;
          } catch (refreshErr) {
            refreshWarn = true;
            refreshNotice = `，拉取失败（${formatErrorMessage(refreshErr)}）`;
          }
          await syncListsFromBackend();
          if (kind === "url") {
            setNewSubName("");
            setNewSubSource("");
          } else {
            setLocalFileName("");
            setLocalFilePath("");
            setShowLocalFileForm(false);
          }
          appActions.showToast(
            `已导入「${name}」${refreshNotice}`,
            refreshWarn ? "warn" : "ok"
          );
        } catch (err) {
          appActions.showToast(`导入订阅失败：${formatErrorMessage(err)}`, "warn");
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
        protocol: kind === "url" ? "vless" : "trojan",
        server: kind === "url" ? "203.0.113.55" : "198.51.100.56",
        port: 443,
        region_code: "JP",
        multiplier: 1.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["native-443"],
        enabled: true,
      };

      appActions.syncSubscriptions([...subscriptions, previewSub]);
      appActions.syncNodes([...nodes, seedNode]);
      if (kind === "url") {
        setNewSubName("");
        setNewSubSource("");
      } else {
        setLocalFileName("");
        setLocalFilePath("");
        setShowLocalFileForm(false);
      }
      appActions.showToast(`已导入「${name}」（演示预览）`, "ok");
    } finally {
      setImportingSub(false);
      appActions.setMascotState("idle");
    }
  };

  const handleConfirmRemoveSubscription = async () => {
    if (!pendingDeleteSub || deletingSub) return;
    const sub = pendingDeleteSub;
    setDeletingSub(true);
    const removedIds = new Set(
      nodes.filter((n) => n.sub_id === sub.id).map((n) => n.id)
    );
    try {
      await catcloudApi.deleteSubscription(sub.id);
      if (inTauri) {
        await syncListsFromBackend();
      } else {
        appActions.syncSubscriptions(
          subscriptions.filter((item) => item.id !== sub.id)
        );
        appActions.syncNodes(nodes.filter((n) => n.sub_id !== sub.id));
      }
      if (removedIds.size > 0) {
        setSelectedNodeIds((prev) => {
          const next = new Set(prev);
          for (const id of removedIds) next.delete(id);
          return next;
        });
      }
      if (filterSubId === sub.id) setFilterSubId("all");
      setPendingDeleteSub(null);
      appActions.showToast(`已移除订阅：${sub.name}（同时移除 ${removedIds.size} 个节点）`, "info");
    } catch (err) {
      appActions.showToast(`移除订阅失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingSub(false);
    }
  };

  /* ---------- Drawer Callbacks ---------- */

  const persistMigratedRules = async (
    prependRules: string[],
    appendRules: string[]
  ): Promise<{ savedCount: number; error: string | null }> => {
    if (prependRules.length === 0 && appendRules.length === 0) {
      return { savedCount: 0, error: null };
    }
    try {
      const fullCfg = await catcloudApi.getFullConfig();
      const prevPrepend = Array.isArray(fullCfg.rules_override?.global_prepend_rules)
        ? fullCfg.rules_override.global_prepend_rules
        : [];
      const prevAppend = Array.isArray(fullCfg.rules_override?.global_append_rules)
        ? fullCfg.rules_override.global_append_rules
        : [];
      const global_prepend_rules = Array.from(
        new Set([...prevPrepend, ...prependRules])
      );
      const global_append_rules = Array.from(
        new Set([...prevAppend, ...appendRules])
      );
      await catcloudApi.saveExtendedSettings({
        rules_override: {
          global_prepend_rules,
          global_append_rules,
        },
      });
      return {
        savedCount: prependRules.length + appendRules.length,
        error: null,
      };
    } catch (err) {
      return {
        savedCount: 0,
        error: formatErrorMessage(err),
      };
    }
  };

  const handleMigrationImport = async (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ) => {
    if (inTauri) {
      try {
        const count = await catcloudApi.applyMigrationNodes(customName, preview.nodes);
        const ruleRes = includeRules
          ? await persistMigratedRules(preview.prepend_rules, preview.append_rules)
          : { savedCount: 0, error: null };
        await syncListsFromBackend();
        if (ruleRes.error) {
          appActions.showToast(
            `已导入 ${count} 个节点，但分流规则保存失败：${ruleRes.error}`,
            "warn"
          );
        } else {
          appActions.showToast(
            `导入完成：已保存 ${count} 个节点${ruleRes.savedCount > 0 ? `、${ruleRes.savedCount} 条分流规则` : ""}（原软件未改动）`,
            "ok"
          );
        }
      } catch (err) {
        appActions.showToast(`导入节点失败：${formatErrorMessage(err)}`, "warn");
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
    appActions.syncSubscriptions([...subscriptions, nextSub]);
    appActions.syncNodes([...nodes, ...importedNodes]);
    setFilterSubId(subId);

    const ruleRes = includeRules
      ? await persistMigratedRules(preview.prepend_rules, preview.append_rules)
      : { savedCount: 0, error: null };

    appActions.showToast(
      `导入完成：已保存 ${importedNodes.length} 个节点${ruleRes.savedCount > 0 ? `、${ruleRes.savedCount} 条分流规则` : ""}（原软件未改动）`,
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
        let refreshErrMsg: string | null = null;
        if (payload.nodes.length > 0) {
          const imported = await catcloudApi.applyMigrationNodes(payload.name, payload.nodes);
          note = `（已保存 ${imported} 个节点）`;
        } else {
          try {
            const refreshed = await catcloudApi.refreshSubscription(saved.id);
            note = `（已抓回 ${refreshed.node_count} 个节点）`;
          } catch (refreshErr) {
            refreshErrMsg = formatErrorMessage(refreshErr);
          }
        }
        await syncListsFromBackend();
        setFilterSubId(saved.id);
        if (refreshErrMsg) {
          appActions.showToast(
            `已添加「${payload.name}」，但抓节点失败：${refreshErrMsg}`,
            "warn"
          );
        } else {
          appActions.showToast(`已关联 ${payload.name}${note}`, "ok");
        }
      } catch (err) {
        appActions.showToast(`抓取软件节点失败：${formatErrorMessage(err)}`, "warn");
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
    appActions.syncSubscriptions([...subscriptions, previewSub]);
    appActions.syncNodes([...nodes, ...boundNodes]);
    setFilterSubId(subId);
    appActions.showToast(
      `已抓取 ${payload.name}（共 ${boundNodes.length} 个节点）`,
      "ok"
    );
  };

  /* ---------- Node Selection, Batch Group Join/Remove & PreAccel Override ---------- */

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
    if (!targetGroup) {
      appActions.showToast("请先选择目标多选组", "warn");
      return;
    }

    const toAdd: string[] = [];
    for (const nid of selectedNodeIds) {
      if (!targetGroupMemberSet.has(nid)) toAdd.push(nid);
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
      appActions.syncGroups(
        groups.map((g) => (g.id === updated.id ? updated : g))
      );
      appActions.showToast(
        `已将 ${toAdd.length} 个节点加入「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`加入多选组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleBatchRemoveFromGroup = async () => {
    if (selectedNodeIds.size === 0) return;
    if (!targetGroup) {
      appActions.showToast("请先选择目标多选组", "warn");
      return;
    }

    let removeCount = 0;
    for (const nid of selectedNodeIds) {
      if (targetGroupMemberSet.has(nid)) removeCount += 1;
    }

    if (removeCount === 0) {
      appActions.showToast(
        `所选节点都不在「${targetGroup.name}」中`,
        "info"
      );
      return;
    }

    const updatedMemberIds = targetGroup.member_node_ids.filter(
      (id) => !selectedNodeIds.has(id)
    );
    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        updatedMemberIds
      );
      appActions.syncGroups(
        groups.map((g) => (g.id === updated.id ? updated : g))
      );
      appActions.showToast(
        `已将 ${removeCount} 个节点移出「${targetGroup.name}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`移出多选组失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleSingleGroupMember = async (nodeId: string) => {
    if (!targetGroup) return;
    const inGroup = targetGroupMemberSet.has(nodeId);
    const nextMembers = inGroup
      ? targetGroup.member_node_ids.filter((id) => id !== nodeId)
      : [...targetGroup.member_node_ids, nodeId];

    try {
      const updated = await catcloudApi.updateMultiGroupMembers(
        targetGroup.id,
        nextMembers
      );
      appActions.syncGroups(
        groups.map((g) => (g.id === updated.id ? updated : g))
      );
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
    appActions.syncNodes(optimistic);
    try {
      await catcloudApi.setNodesPreAccelOverride(nodeIds, overrideMode);
      const label =
        overrideValue === null
          ? "自动跟随全局"
          : overrideValue
            ? "强制开启中转加速"
            : "强制关闭中转加速";
      appActions.showToast(
        nodeIds.length > 1
          ? `已将 ${nodeIds.length} 个节点的中转加速设为「${label}」`
          : `已更新中转加速方式：${label}`,
        "ok"
      );
    } catch (err) {
      appActions.syncNodes(prevNodes);
      appActions.showToast(`设置中转加速失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSelectSingleNode = async (nodeId: string) => {
    if (selectingSingleNodeId) return;
    setSelectingSingleNodeId(nodeId);
    try {
      await appActions.selectSingleNode(nodeId);
    } finally {
      setSelectingSingleNodeId(null);
    }
  };

  const resetAllFilters = () => {
    setKeyword("");
    setFilterSubId("all");
    setFilterContinent("all");
    setFilterRegion("all");
    setFilterMultiplier("all");
    setFilterProtocol("all");
    setFilter443("all");
    setHealthFilters({
      googleClean: false,
      keepalive60s: false,
      aiUnlocked: false,
    });
    setSortBy("default");
  };

  return (
    <div className="space-y-3">
      {/* ====================================================================
       * 1. Compact Header, Route Mode Guide Bar & Refresh All Bar
       * ==================================================================== */}
      {!embeddedSubsOnly && (
      <section className="cc-card cc-glass space-y-2.5 rounded-2xl px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                节点与订阅
              </h1>
              <span className="rounded-full bg-[var(--accent-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                {subscriptions.length} 个订阅 · {nodes.length} 个节点 · {native443Count} 个直连 443
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--green)]">
                <ShieldCheck className="h-3.5 w-3.5" />
                刷新失败时自动保留原有节点，不会清空
              </span>
            </div>
          </div>

          <button
            type="button"
            disabled={refreshingAll || subscriptions.length === 0}
            onClick={() => void refreshAllSubscriptions()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-[var(--accent)] ${refreshingAll ? "animate-spin" : ""}`}
            />
            全部刷新
          </button>
        </div>

        {/* Active Route Mode Status Guide Bar */}
        <div
          className={`flex flex-wrap items-center justify-between gap-2.5 rounded-xl border px-3 py-2 text-xs ${
            isSingleMode
              ? "border-[var(--green)]/40 bg-[var(--bg-elevated)]/85"
              : "border-[var(--accent)]/40 bg-[var(--bg-elevated)]/85"
          }`}
        >
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {isSingleMode ? (
              <>
                <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--green)]/35 bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--green)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                  当前：单节点模式
                </span>
                <span className="truncate text-[11px] text-[var(--text-secondary)]">
                  正在使用：
                  <strong className="font-semibold text-[var(--text)]">
                    {runtime.active_node_name || "未选择"}
                  </strong>
                </span>
              </>
            ) : (
              <>
                <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--accent)]/35 bg-[var(--accent-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
                  当前：智能多选组（{runtime.active_group_name || "未启用"}）
                </span>
                <span className="text-[11px] text-[var(--text-secondary)]">
                  点下方任意节点的「用它」，可立刻切为单节点固定使用
                </span>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => appActions.setNav("overview")}
            className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <ArrowLeft className="h-3 w-3 shrink-0" />
            <span>返回总览</span>
          </button>
        </div>
      </section>
      )}

      {/* ====================================================================
       * 2. Beginner-Friendly 3-Card Quick Import Hub
       * ==================================================================== */}
      <section
        aria-label="快速导入节点入口"
        className="grid grid-cols-1 gap-3.5 lg:grid-cols-3"
      >
        {/* Card 1: Paste Subscription URL */}
        <div className="cc-card cc-glass flex flex-col justify-between gap-3 rounded-2xl border-[var(--accent)]/45 p-4">
          <div className="space-y-2.5">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                  <Link2 className="h-4 w-4" />
                </div>
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-[var(--accent)] text-[10px] font-bold text-[var(--accent-ink)]">
                      1
                    </span>
                    <h2 className="text-sm font-semibold text-[var(--text)]">
                      粘贴订阅链接
                    </h2>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    贴上机场给的订阅地址，点一下立刻拉回节点
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowLocalFileForm((v) => !v)}
                className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  showLocalFileForm
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                }`}
              >
                <FileText className="h-3 w-3" />
                {showLocalFileForm ? "收起本地文件" : "本地文件"}
              </button>
            </div>

            <input
              type="text"
              value={newSubSource}
              onChange={(e) => setNewSubSource(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  void submitSubscriptionSource("url", newSubSource, newSubName);
                }
              }}
              placeholder="粘贴 https:// 开头的订阅链接..."
              className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newSubName}
              onChange={(e) => setNewSubName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  void submitSubscriptionSource("url", newSubSource, newSubName);
                }
              }}
              placeholder="名称（可选，留空自动命名）"
              className="min-w-0 flex-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
            <button
              type="button"
              disabled={importingSub}
              onClick={() =>
                void submitSubscriptionSource("url", newSubSource, newSubName)
              }
              className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {importingSub ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5" />
              )}
              {importingSub ? "导入中..." : "一键导入"}
            </button>
          </div>
        </div>

        {/* Card 2: Import from Existing VPN Client */}
        <div className="cc-card cc-glass flex flex-col justify-between gap-3 rounded-2xl p-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--green-soft)] text-[var(--green)]">
                <FolderOpen className="h-4 w-4" />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-[var(--green)] text-[10px] font-bold text-[var(--accent-ink)]">
                  2
                </span>
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  从电脑已有梯子导入
                </h2>
              </div>
            </div>
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              自动找 Clash Verge / 落云 / v2rayN 已有配置，只读安全复制，不改你原来的软件。
            </p>
          </div>

          <button
            type="button"
            onClick={() => setMigrationOpen(true)}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-xl border border-[var(--green)]/50 bg-[var(--green-soft)] px-4 py-2 text-xs font-semibold text-[var(--green)] transition-opacity hover:opacity-90"
          >
            <Search className="h-3.5 w-3.5" />
            自动扫描并导入
          </button>
        </div>

        {/* Card 3: Capture Nodes from Running Software */}
        <div className="cc-card cc-glass flex flex-col justify-between gap-3 rounded-2xl p-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--sky-soft)] text-[var(--sky)]">
                <Cpu className="h-4 w-4" />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-[var(--sky)] text-[10px] font-bold text-[var(--accent-ink)]">
                  3
                </span>
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  从正在运行的软件抓节点
                </h2>
              </div>
            </div>
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              先打开你的专用梯子软件，点这里自动识别并抓取可用节点。
            </p>
          </div>

          <button
            type="button"
            onClick={() => setProcessAttachOpen(true)}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-xl border border-[var(--sky)]/50 bg-[var(--sky-soft)] px-4 py-2 text-xs font-semibold text-[var(--sky)] transition-opacity hover:opacity-90"
          >
            <Cpu className="h-3.5 w-3.5" />
            识别运行中的软件
          </button>
        </div>
      </section>

      {/* Optional Collapsible Local File Import Form */}
      {showLocalFileForm && (
        <section className="cc-card cc-glass space-y-3 rounded-2xl border-[var(--accent)]/50 p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-[var(--text)]">
              导入电脑里的本地配置文件（只读）
            </span>
            <button
              type="button"
              onClick={() => setShowLocalFileForm(false)}
              className="text-xs text-[var(--muted)] hover:text-[var(--text)]"
            >
              收起
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            <label className="text-[11px] text-[var(--muted)] md:col-span-3">
              名称（可选）
              <input
                type="text"
                value={localFileName}
                onChange={(e) => setLocalFileName(e.target.value)}
                placeholder="例如：我的本地节点"
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </label>

            <label className="text-[11px] text-[var(--muted)] md:col-span-6">
              本地配置文件路径
              <input
                type="text"
                value={localFilePath}
                onChange={(e) => setLocalFilePath(e.target.value)}
                placeholder="例如：data/subs/my-nodes.yaml"
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
              如果文件暂时读不到或内容为空，会自动保留原有节点不会丢失。
            </span>
            <button
              type="button"
              disabled={importingSub}
              onClick={() =>
                void submitSubscriptionSource("file", localFilePath, localFileName)
              }
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
            >
              <Check className="h-3.5 w-3.5" />
              保存并读取节点
            </button>
          </div>
        </section>
      )}

      {/* ====================================================================
       * 3. Adaptive Subscription Cards Grid
       * ==================================================================== */}
      <section aria-label="已导入订阅卡片" className="space-y-2.5">
        {embeddedSubsOnly && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-xs font-semibold text-[var(--text)]">
                已导入订阅（{subscriptions.length}）
              </h2>
              <span className="inline-flex items-center gap-1 text-[11px] text-[var(--green)]">
                <ShieldCheck className="h-3.5 w-3.5" />
                刷新失败时自动保留原有节点
              </span>
            </div>
            <button
              type="button"
              disabled={refreshingAll || subscriptions.length === 0}
              onClick={() => void refreshAllSubscriptions()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 text-[var(--accent)] ${refreshingAll ? "animate-spin" : ""}`}
              />
              全部刷新
            </button>
          </div>
        )}

        {subscriptions.length === 0 ? (
          <div className="cc-card cc-glass rounded-2xl px-4 py-6 text-center text-xs text-[var(--muted)]">
            还没有导入订阅来源，请先在上方任选一种方式添加节点
          </div>
        ) : (
        <div
          className={
            subscriptions.length >= 3
              ? "grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3"
              : "grid grid-cols-1 gap-3 md:grid-cols-2"
          }
        >
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
            const isSelectedFilter = !embeddedSubsOnly && filterSubId === sub.id;
            const isRefreshing = Boolean(refreshingIds[sub.id]) || refreshingAll;
            const maskedSource = maskSubscriptionSource(getSubSource(sub));

            return (
              <article
                key={sub.id}
                className={`cc-card cc-glass flex min-w-0 flex-col justify-between rounded-2xl p-3.5 ${
                  isSelectedFilter ? "border-[var(--accent)]" : ""
                }`}
              >
                <div>
                  {/* Card Top Header */}
                  <div className="flex items-start justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        if (onViewSubNodes) {
                          onViewSubNodes(sub.id);
                        } else {
                          setFilterSubId(isSelectedFilter ? "all" : sub.id);
                        }
                      }}
                      className="min-w-0 text-left"
                      title={onViewSubNodes ? "查看这个订阅下的节点" : "点击只看这个订阅的节点"}
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
                        {maskedSource}
                      </div>
                    </button>

                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        disabled={isRefreshing}
                        onClick={() => void refreshSingleSubscription(sub, false)}
                        className="inline-flex h-7 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                        title="刷新节点列表（失败自动保留原有节点）"
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
                          title="演示刷新失败保护效果"
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                        </button>
                      )}
                      {(inTauri || subscriptions.length > 1) && (
                        <button
                          type="button"
                          onClick={() => setPendingDeleteSub(sub)}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
                          title="删除此订阅"
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
                              {formatQuotaBytes(usedBytes)}
                            </span>{" "}
                            / {formatQuotaBytes(sub.traffic_total_bytes)}
                          </span>
                          <span className="cc-mono font-medium text-[var(--text-secondary)]">
                            余 {formatQuotaBytes(remainingBytes)} ({100 - usagePct}%)
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
                        暂未提供流量统计 · 当前共{" "}
                        <span className="cc-mono text-[var(--text)]">
                          {nodeCount}
                        </span>{" "}
                        个节点
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

                  {onViewSubNodes && (
                    <div className="flex items-center justify-end pt-1">
                      <button
                        type="button"
                        onClick={() => onViewSubNodes(sub.id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
                      >
                        <span>查看节点（{nodeCount}）</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    </div>
                  )}
                </div>
              </article>
            );
          })}
        </div>
        )}
      </section>

      {!embeddedSubsOnly && (
      <>

      {/* ====================================================================
       * 4. Compact Node Filter Bar (Primary: Search + Source + Region; More Filters Collapsible)
       * ==================================================================== */}
      <section className="cc-card cc-glass space-y-2.5 rounded-2xl p-3.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-[var(--accent)]" />
            <h2 className="text-xs font-semibold text-[var(--text)]">
              筛选节点
            </h2>
            <span className="cc-mono text-[11px] text-[var(--muted)]">
              显示 {filteredNodes.length} / {nodes.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-56">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <input
                type="text"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder="搜节点名称、地区、协议或地址..."
                className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </div>

            <button
              type="button"
              onClick={() =>
                setHealthFilters((prev) => ({ ...prev, googleClean: !prev.googleClean }))
              }
              className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                healthFilters.googleClean
                  ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              {healthFilters.googleClean && <Check className="h-3 w-3" />}
              <span>仅看谷歌正常</span>
            </button>

            <button
              type="button"
              onClick={() =>
                setHealthFilters((prev) => ({ ...prev, aiUnlocked: !prev.aiUnlocked }))
              }
              className={`inline-flex items-center gap-1 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                healthFilters.aiUnlocked
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              {healthFilters.aiUnlocked && <Check className="h-3 w-3" />}
              <span>仅看 AI 可用</span>
            </button>

            <div className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5">
              <ArrowUpDown className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
              <select
                aria-label="节点排序方式"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as NodeSortBy)}
                className="bg-transparent text-xs text-[var(--text)] outline-none"
              >
                <option value="default">排序：默认</option>
                <option value="latency">排序：延迟最低</option>
                <option value="up">排序：上传最快</option>
                <option value="down">排序：下载最快</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setShowMoreFilters((v) => !v)}
              className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                showMoreFilters || advancedFilterCount > 0
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
              }`}
            >
              <span>更多筛选</span>
              {advancedFilterCount > 0 && (
                <span className="cc-mono rounded-full bg-[var(--accent)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--accent-ink)]">
                  {advancedFilterCount}
                </span>
              )}
              {showMoreFilters ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5" />
              )}
            </button>

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
          {/* Row A: Subscription Source */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[var(--muted)]">来源</span>
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

          {/* Row A2: Two-Tier Continent -> Country/Region Filter */}
          <ContinentRegionFilter
            variant="pills"
            stats={continentRegionStats}
            continent={filterContinent}
            region={filterRegion}
            onContinentChange={(c) => {
              setFilterContinent(c);
              setCurrentPage(1);
            }}
            onRegionChange={(r) => {
              setFilterRegion(r);
              setCurrentPage(1);
            }}
          />

          {/* Collapsible Row B: Multiplier Range, Protocol, Direct 443 & Health Checks */}
          {showMoreFilters && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-[var(--line)]/70 pt-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[var(--muted)]">流量倍率</span>
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
                <span className="text-[var(--muted)]">端口类型</span>
                {(
                  [
                    { id: "all", label: "全部" },
                    { id: "only_443", label: "仅直连 443" },
                    { id: "non_443", label: "其他端口" },
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
                <span className="text-[var(--muted)]">长连接</span>
                <button
                  type="button"
                  onClick={() =>
                    setHealthFilters((prev) => ({
                      ...prev,
                      keepalive60s: !prev.keepalive60s,
                    }))
                  }
                  className={`inline-flex items-center gap-1 rounded-lg border px-2 py-0.5 transition-colors ${
                    healthFilters.keepalive60s
                      ? "border-[var(--green)] bg-[var(--green-soft)] font-medium text-[var(--green)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  {healthFilters.keepalive60s && <Check className="h-3 w-3" />}
                  60 秒长连接稳定
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ====================================================================
       * 5. Batch Group Add/Remove & Relay Override Bar
       * ==================================================================== */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3">
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <button
            type="button"
            onClick={toggleSelectAllFiltered}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)]"
          >
            <Check className="h-3 w-3 text-[var(--accent)]" />
            {allFilteredSelected
              ? "取消全选筛选结果"
              : `全选当前筛选 (${filteredNodes.length})`}
          </button>

          {selectedNodeIds.size > 0 ? (
            <>
              <span className="rounded-full bg-[var(--accent-soft)] px-2.5 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                已勾选 {selectedNodeIds.size} 个节点
                {selectedCrossSubCount > 1
                  ? `（来自 ${selectedCrossSubCount} 个订阅）`
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
              勾选下方节点，可批量加入或移出指定多选组
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
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-3 py-1.5 text-xs font-semibold transition-colors ${
              selectedNodeIds.size === 0 || groups.length === 0
                ? "cursor-not-allowed border border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                : "bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90"
            }`}
          >
            <Plus className="h-3.5 w-3.5 shrink-0" />
            加入多选组
          </button>

          <button
            type="button"
            disabled={selectedNodeIds.size === 0 || groups.length === 0}
            onClick={() => void handleBatchRemoveFromGroup()}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
              selectedNodeIds.size === 0 || groups.length === 0
                ? "cursor-not-allowed border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)]"
                : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--red)] hover:text-[var(--red)]"
            }`}
          >
            <Minus className="h-3.5 w-3.5 shrink-0" />
            移出多选组
          </button>

          {selectedNodeIds.size > 0 && (
            <div className="inline-flex items-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), true)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--accent)]"
                title="让所选节点强制走中转加速"
              >
                中转开
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), false)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--red)]"
                title="让所选节点强制直连不走中转"
              >
                中转关
              </button>
              <button
                type="button"
                onClick={() =>
                  void handleSetPreAccelOverride(Array.from(selectedNodeIds), null)
                }
                className="rounded-lg px-2 py-1 text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                title="恢复为自动跟随全局设置"
              >
                自动
              </button>
            </div>
          )}
        </div>
      </section>

      {/* ====================================================================
       * 6. Node List Table (Paginated + Fixed-Width Right Controls)
       * ==================================================================== */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        {filteredNodes.length > 0 && (
          <PaginationBar
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={filteredNodes.length}
            pageSize={pageSize}
            pageSizeOptions={[30, 50, 100]}
            onPageChange={setCurrentPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setCurrentPage(1);
            }}
            className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/70 px-4 py-2"
          />
        )}
        <div className="overflow-x-auto">
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)] text-[11px] font-medium text-[var(--muted)]">
                <th className="w-8 px-2 py-2.5 text-center">
                  <input
                    type="checkbox"
                    checked={allFilteredSelected}
                    onChange={toggleSelectAllFiltered}
                    aria-label="全选当前筛选节点"
                    className="accent-[var(--accent)]"
                  />
                </th>
                <th className="whitespace-nowrap px-2 py-2.5">
                  节点名称 / 来源 / 分组
                </th>
                <th className="w-[132px] whitespace-nowrap px-2 py-2.5">
                  地区 · 倍率 · 协议
                </th>
                <th className="w-[236px] whitespace-nowrap px-2 py-2.5">
                  延迟 · 上下行 · 解锁
                </th>
                <th className="w-[148px] whitespace-nowrap px-2 py-2.5">
                  <div className="inline-flex items-center gap-1 whitespace-nowrap">
                    <Zap className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    国内提速
                  </div>
                </th>
                <th className="w-[148px] whitespace-nowrap px-2 py-2.5 text-right">
                  使用 / 分组
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]/70">
              {pagedNodes.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-6 py-10 text-center text-xs text-[var(--muted)]"
                  >
                    <Globe className="mx-auto mb-2 h-6 w-6 opacity-50" />
                    暂无符合条件的节点，可以在上方导入订阅链接或放宽筛选条件。
                  </td>
                </tr>
              ) : (
                pagedNodes.map((node) => {
                  const selected = selectedNodeIds.has(node.id);
                  const probe = storeProbes[node.id];
                  const aiInfo = getNodeAiInfo(probe);
                  const subName = subNameMap.get(node.sub_id) ?? node.sub_id;
                  const memberGroups = nodeGroupMembership.get(node.id) ?? [];
                  const inTargetGroup = targetGroupMemberSet.has(node.id);
                  const regionCode = resolveNodeRegionCode(node);
                  const regionLabel = getRegionLabel(regionCode);
                  const isSingleActive =
                    isSingleMode && runtime.active_node_id === node.id;
                  const isSwitchingSingle = selectingSingleNodeId === node.id;

                  const effectiveGlobalPreAccel =
                    globalPreAccel.enabled &&
                    !(globalPreAccel.skip_443_native && node.is_443_native);

                  return (
                    <tr
                      key={node.id}
                      className={`transition-colors ${
                        isSingleActive
                          ? "bg-[var(--green-soft)]/35"
                          : selected
                            ? "bg-[var(--accent-soft)]/60"
                            : "hover:bg-[var(--card-hover)]"
                      }`}
                    >
                      {/* Checkbox */}
                      <td className="w-8 px-2 py-2.5 text-center align-middle">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => toggleSelectNode(node.id)}
                          aria-label={`选择节点 ${node.name}`}
                          className="accent-[var(--accent)]"
                        />
                      </td>

                      {/* Node Name, Source Sub & Group Membership */}
                      <td className="px-2 py-2.5 align-middle">
                        <div className="flex min-w-0 items-center gap-1.5">
                          <Server className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                          <span
                            title={node.name}
                            className="block min-w-0 flex-1 truncate font-semibold text-[var(--text)]"
                          >
                            {node.name}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px]">
                          <span
                            title={subName}
                            className="max-w-[110px] truncate rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                          >
                            {subName}
                          </span>
                          <span
                            title={`${node.server}:${node.port}`}
                            className="max-w-[100px] truncate cc-mono text-[var(--muted)]"
                          >
                            {node.server}:{node.port}
                          </span>
                          {memberGroups.map((g) => (
                            <span
                              key={g.id}
                              title={g.name}
                              className="max-w-[96px] truncate rounded-full bg-[var(--sky-soft)] px-1.5 py-0.5 font-medium text-[var(--sky)]"
                            >
                              {g.name}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Region, Multiplier, Protocol & Direct 443 */}
                      <td className="w-[132px] px-2 py-2.5 align-middle">
                        <div className="flex flex-col gap-1 cc-mono text-[10px]">
                          <div className="flex items-center gap-1">
                            <span
                              title={regionLabel}
                              className="shrink-0 rounded border border-[var(--line)] bg-[var(--bg-elevated)] px-1 py-0.5 font-semibold text-[var(--text)]"
                            >
                              {regionCode}
                            </span>
                            <span
                              className={`shrink-0 rounded px-1 py-0.5 font-medium ${
                                node.multiplier >= 3
                                  ? "bg-[var(--coral-soft)] text-[var(--coral)]"
                                  : node.multiplier <= 1
                                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                                    : "bg-[var(--amber-soft)] text-[var(--amber)]"
                              }`}
                            >
                              {node.multiplier}x
                            </span>
                            <span className="truncate rounded bg-[var(--bg-elevated)] px-1 py-0.5 uppercase text-[var(--text-secondary)]">
                              {node.protocol}
                            </span>
                          </div>
                          <div>
                            {node.is_443_native ? (
                              <span className="inline-block whitespace-nowrap rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                                直连 443
                              </span>
                            ) : (
                              <span className="inline-block rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                                :{node.port}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Health Snapshot Badges: Latency, Up/Down Speed, Google Clean/CN & AI Unlocks */}
                      <td className="w-[236px] px-2 py-2.5 align-middle">
                        <div className="flex flex-col gap-1 text-[10px]">
                          <div className="flex items-center gap-2 cc-mono">
                            <span
                              className={`shrink-0 whitespace-nowrap rounded-md px-1.5 py-0.5 font-semibold ${
                                probe?.ok === false
                                  ? "bg-[var(--red-soft)] text-[var(--red)]"
                                  : probe?.latency_ms != null
                                    ? probe.latency_ms <= 140
                                      ? "bg-[var(--green-soft)] text-[var(--green)]"
                                      : probe.latency_ms <= 300
                                        ? "bg-[var(--amber-soft)] text-[var(--amber)]"
                                        : "bg-[var(--red-soft)] text-[var(--red)]"
                                    : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                              }`}
                            >
                              {probe?.ok === false
                                ? "超时"
                                : probe?.latency_ms != null
                                  ? `${Math.round(probe.latency_ms)} ms`
                                  : "未测速"}
                            </span>
                            {(probe?.up_mbps != null || probe?.down_mbps != null) && (
                              <div className="flex flex-col leading-tight text-[11px]">
                                {probe?.up_mbps != null && (
                                  <span className="whitespace-nowrap font-medium text-[var(--coral)]">
                                    ↑{probe.up_mbps.toFixed(1)}M
                                  </span>
                                )}
                                {probe?.down_mbps != null && (
                                  <span className="whitespace-nowrap font-medium text-[var(--sky)]">
                                    ↓
                                    {probe.down_mbps >= 100
                                      ? Math.round(probe.down_mbps)
                                      : probe.down_mbps.toFixed(1)}
                                    M
                                  </span>
                                )}
                              </div>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-1">
                            <span
                              className={`whitespace-nowrap rounded-md px-1.5 py-0.5 font-medium ${
                                probe?.google_clean === true
                                  ? "bg-[var(--green-soft)] text-[var(--green)]"
                                  : probe?.google_clean === false
                                    ? "bg-[var(--red-soft)] text-[var(--red)]"
                                    : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                              }`}
                            >
                              {probe?.google_clean === true
                                ? "谷歌正常"
                                : probe?.google_clean === false
                                  ? "谷歌送中"
                                  : "未测地区"}
                            </span>

                            {probe?.google_risk_mismatch && (
                              <span
                                className="whitespace-nowrap rounded-md bg-[var(--amber-soft)] px-1.5 py-0.5 font-medium text-[var(--amber)]"
                                title="不同网站识别出的地区存在差异，仅供参考"
                              >
                                地区有偏差
                              </span>
                            )}

                            {aiInfo.unlockedLabels.length > 0 ? (
                              <span
                                title={aiInfo.detail}
                                className="inline-flex flex-wrap items-center gap-1"
                              >
                                {aiInfo.unlockedLabels.map((lbl) => (
                                  <span
                                    key={lbl}
                                    className="whitespace-nowrap rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 font-medium text-[var(--accent)]"
                                  >
                                    {lbl}
                                  </span>
                                ))}
                              </span>
                            ) : (
                              <span
                                title={aiInfo.detail}
                                className="whitespace-nowrap rounded-md bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]"
                              >
                                {aiInfo.total > 0 ? "AI 受限" : "AI 未测"}
                              </span>
                            )}

                            {probe?.keepalive_60s_ok !== null &&
                              probe?.keepalive_60s_ok !== undefined && (
                                <span
                                  className={`whitespace-nowrap rounded-md px-1.5 py-0.5 font-medium ${
                                    probe.keepalive_60s_ok
                                      ? "bg-[var(--green-soft)] text-[var(--green)]"
                                      : "bg-[var(--red-soft)] text-[var(--red)]"
                                  }`}
                                >
                                  {probe.keepalive_60s_ok ? "长连接稳" : "易断连"}
                                </span>
                              )}
                          </div>
                        </div>
                      </td>

                      {/* Single-Node Relay 3-State Override */}
                      <td className="w-[148px] whitespace-nowrap px-2 py-2.5 align-middle">
                        <div className="flex flex-col gap-1">
                          <div className="inline-flex w-fit shrink-0 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[10px]">
                            {(
                              [
                                { value: null, label: "自动" },
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
                                  className={`shrink-0 whitespace-nowrap rounded-md px-1.5 py-0.5 transition-colors ${
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
                            <span className="whitespace-nowrap text-[10px] text-[var(--muted)]">
                              当前：
                              {effectiveGlobalPreAccel
                                ? "自动走中转"
                                : node.is_443_native &&
                                    globalPreAccel.skip_443_native
                                  ? "直连免中转"
                                  : "全局中转已关"}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Single-Node Use & Quick Group Actions */}
                      <td className="w-[148px] whitespace-nowrap px-2 py-2.5 text-right align-middle">
                        <div className="inline-flex flex-nowrap items-center justify-end gap-1">
                          <button
                            type="button"
                            disabled={isSingleActive || isSwitchingSingle}
                            onClick={() => void handleSelectSingleNode(node.id)}
                            title={
                              isSingleActive
                                ? "当前正处于单节点模式并使用此节点"
                                : "切换为单节点模式，固定使用此节点"
                            }
                            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border px-2 py-1 text-[11px] font-semibold transition-colors disabled:cursor-default ${
                              isSingleActive
                                ? "border-[var(--green)] bg-[var(--green)] text-[var(--accent-ink)]"
                                : "border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:opacity-60"
                            }`}
                          >
                            {isSingleActive ? (
                              <>
                                <Check className="h-3 w-3 shrink-0" />
                                <span>在用</span>
                              </>
                            ) : (
                              <>
                                <Play className="h-2.5 w-2.5 shrink-0 fill-current" />
                                <span>{isSwitchingSingle ? "切换中" : "用它"}</span>
                              </>
                            )}
                          </button>

                          <button
                            type="button"
                            disabled={!targetGroup}
                            onClick={() => void handleToggleSingleGroupMember(node.id)}
                            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border px-2 py-1 text-[11px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                              inTargetGroup
                                ? "border-[var(--green)] bg-[var(--green-soft)] text-[var(--green)] hover:opacity-85"
                                : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)]"
                            }`}
                          >
                            {inTargetGroup ? (
                              <>
                                <Check className="h-3 w-3 shrink-0" />
                                <span>已在组</span>
                              </>
                            ) : (
                              <>
                                <Plus className="h-3 w-3 shrink-0" />
                                <span>加组</span>
                              </>
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {filteredNodes.length > 0 && (
          <PaginationBar
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={filteredNodes.length}
            pageSize={pageSize}
            pageSizeOptions={[30, 50, 100]}
            onPageChange={setCurrentPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setCurrentPage(1);
            }}
            className="border-t border-[var(--line)] bg-[var(--bg-elevated)]/60 px-4 py-2.5"
          />
        )}
      </section>
      </>
      )}

      {/* ====================================================================
       * 7. Slide-Over Drawers: Legacy Read-Only Migration & Process Attach
       * ==================================================================== */}
      <MigrationDrawer
        open={migrationOpen}
        onClose={closeMigration}
        onImport={handleMigrationImport}
      />

      <ProcessAttachDrawer
        open={processAttachOpen}
        onClose={closeProcessAttach}
        onAttachSource={handleProcessAttach}
      />

      {/* Delete Subscription Two-Step Confirmation Modal */}
      {pendingDeleteSub && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
          onClick={() => {
            if (!deletingSub) setPendingDeleteSub(null);
          }}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label="确认删除订阅"
            onClick={(e) => e.stopPropagation()}
            className="cc-surface w-full max-w-md rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--red-soft)] text-[var(--red)]">
                  <AlertTriangle className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-[var(--text)]">
                    确认删除整条订阅？
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                    即将删除订阅「
                    <span className="font-semibold text-[var(--text)]">
                      {pendingDeleteSub.name}
                    </span>
                    」，并同时移除该订阅下的{" "}
                    <strong className="cc-mono text-[var(--red)]">
                      {subNodeCountMap.get(pendingDeleteSub.id) ?? 0} 个节点
                    </strong>
                    。此操作无法撤销，请确认后再继续。
                  </p>
                </div>
              </div>
              <button
                type="button"
                disabled={deletingSub}
                onClick={() => setPendingDeleteSub(null)}
                className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                aria-label="关闭弹窗"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                disabled={deletingSub}
                onClick={() => setPendingDeleteSub(null)}
                className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
              >
                取消
              </button>
              <button
                type="button"
                disabled={deletingSub}
                onClick={() => void handleConfirmRemoveSubscription()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--red)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>{deletingSub ? "删除中…" : "确认删除"}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
