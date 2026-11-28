import type { MigrationPreviewItem } from "./utils";

/**
 * Browser preview fixtures & paste sample loaded on demand via dynamic import
 * so desktop Tauri builds never bundle demo payloads into main chunks.
 */

export const DEMO_PASTE_SAMPLE = `proxies:
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

export const DEMO_MIGRATION_SCANS: Record<
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
