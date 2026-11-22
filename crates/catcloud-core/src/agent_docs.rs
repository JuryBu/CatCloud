use crate::error::{CatError, CatResult};
use serde::{Deserialize, Serialize};

/// Four-section dual-read (Human + AI Agent) guidance contract embedded in every core module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentModuleDoc {
    pub module_id: String,
    pub title: String,
    pub summary: String,
    /// Section 1: When to enable/use this module and concrete quantitative signals.
    pub when_to_use_and_signals: Vec<String>,
    /// Section 2: External prerequisites, standard schemas, and required fields.
    pub external_prereqs_and_schema: Vec<String>,
    /// Section 3: Exact GUI paths and headless `catcloud` CLI commands for integration & verification.
    pub gui_and_cli_verification: Vec<String>,
    /// Section 4: Safe rollback and troubleshooting checklist.
    pub rollback_and_troubleshooting: Vec<String>,
    /// Optional structured contract example (JSON / YAML / CLI snippet) for copy-paste to an AI Agent.
    pub contract_example: String,
}

impl AgentModuleDoc {
    /// Render a clean, copy-ready Markdown prompt/guide for handing directly to an AI Agent.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# CatCloud Agent Guide: {} (`{}`)\n\n", self.title, self.module_id));
        out.push_str(&format!("> {}\n\n", self.summary));

        out.push_str("## 1. When to Use & Quantitative Signals\n");
        for item in &self.when_to_use_and_signals {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 2. External Prerequisites & Standard Schema\n");
        for item in &self.external_prereqs_and_schema {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 3. GUI & Headless CLI Integration / Verification\n");
        for item in &self.gui_and_cli_verification {
            out.push_str(&format!("- {item}\n"));
        }

        out.push_str("\n## 4. Rollback & Troubleshooting Checklist\n");
        for item in &self.rollback_and_troubleshooting {
            out.push_str(&format!("- {item}\n"));
        }

        if !self.contract_example.trim().is_empty() {
            out.push_str("\n## Reference Contract Snippet\n```json\n");
            out.push_str(self.contract_example.trim());
            out.push_str("\n```\n");
        }
        out
    }
}

/// Return all 6 built-in four-section Agent-friendly module guides.
pub fn list_agent_docs() -> Vec<AgentModuleDoc> {
    vec![
        AgentModuleDoc {
            module_id: "preaccel".to_string(),
            title: "Domestic Pre-Acceleration (国内预加速)".to_string(),
            summary: "Front-end domestic TCP :443 pure-IP TLS relay chain (dialer-proxy) with active-standby failover, domestic 204 health probing, and campus portal detection.".to_string(),
            when_to_use_and_signals: vec![
                "Single-stream upload on non-443 proxy ports is throttled around 2-4 Mbps while TCP :443 TLS sustains 50-250+ Mbps.".to_string(),
                "Frequent TCP retransmissions (> 2%) or slow multi-image AI upload turns despite healthy downstream bandwidth.".to_string(),
                "Running inside campus/enterprise networks where high overseas UDP/TCP ports experience instability or Captive Portal dropouts.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Provision 1-2 lightweight domestic cloud relays listening on TCP :443 with Trojan-TLS, AnyTLS, or VLESS-TLS using a self-signed ECDSA IP certificate.".to_string(),
                "CRITICAL: Keep TLS `sni` (and VLESS `servername`) strictly EMPTY (`\"\"`) with `skip_cert_verify: true`; third-party unfiled SNI domains on domestic :443 are blocked by cloud gateways.".to_string(),
                "Deliver relay parameters to CatCloud using the `mmrelay/v1` JSON schema or single-line `mmrelay://v1/<base64url>` URI.".to_string(),
                "Health probe URL MUST remain domestic (`http://connectivitycheck.platform.hicloud.com/generate_204` or `http://connect.rom.miui.com/generate_204`); overseas `gstatic` URLs are rejected.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '国内预加速' -> Import `mmrelay/v1` -> Verify '自动跳过原生 443 节点' -> Run 443 vs non-443 benchmark.".to_string(),
                "CLI import: `catcloud preaccel add --file relay.mmrelay.json --json`".to_string(),
                "CLI pool status: `catcloud preaccel pool --json`".to_string(),
                "CLI end-to-end verification: `catcloud preaccel test --json` (checks domestic 204, anti-loop DIRECT rules, and active-standby failover).".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "One-click disable via GUI switch or `catcloud preaccel bind --enabled false --json` followed by `catcloud config reload --json`.".to_string(),
                "If relay connects but loops: verify relay IP/domain and domestic 204 probe domains appear at top of compiled `rules` as `DIRECT,no-resolve` and inside `dns.fake-ip-filter`.".to_string(),
                "If campus portal returns 302: authenticate via the automatically exempted portal URL; CatCloud revokes temporary DIRECT rules once 204 returns.".to_string(),
            ],
            contract_example: r#"{
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
    }
  ]
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "multigroup".to_string(),
            title: "Smart Multi-Groups & Custom Weighting Engine (智能多选组)".to_string(),
            summary: "Per-site orchestration supporting sticky-best, conditional pools, filtered load-balancing, safe AST scoring formulas, and three-way below-threshold fallbacks.".to_string(),
            when_to_use_and_signals: vec![
                "AI/coding tools (OpenAI, Claude, Gemini/Antigravity, Windsurf/Devin/Codeium) break on random IP rotation or silent region-restricted exits.".to_string(),
                "Need cross-provider node pools combining low-multiplier (0.5x/1x) daily nodes with automatic escalation to premium (3x) backup pools only when needed.".to_string(),
                "Want controlled per-site load balancing without letting region-restricted nodes enter the balance set.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "At least 2 enabled nodes imported into the node library plus recent probe snapshots from the isolated probe runner.".to_string(),
                "Formula uses CatCloud safe AST (zero `eval`): supports `up_mbps`, `down_mbps`, `ping_ms`, `jitter_ms`, `loss_pct`, `multiplier`, `keepalive_ok`, `google_clean`, `unlocked`, plus per-probe functions `probe_up(\"id\")`, `probe_down(\"id\")`, `probe_ping(\"id\")`, `probe_ok(\"id\")`.".to_string(),
                "Fallback policy options when all nodes miss threshold: `degrade_best_warn` (default), `cross_pool_escalate` (with automatic hysteresis return to primary pool), or `strict_circuit_break` (switches group to `REJECT`).".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '智能多选组' -> Choose mode (`sticky_best` / `conditional_pool` / `load_balance_*`), formula template, fallback policy, and `force_close_old` vs `graceful_new_only`.".to_string(),
                "CLI list groups: `catcloud group list --json`".to_string(),
                "CLI switch next best: `catcloud group switch <group_id> --json`".to_string(),
                "CLI update policy: `catcloud group policy <group_id> --formula \"...\" --fallback degrade_best_warn --json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Reset any group formula to built-in `DEFAULT_COST_EFFECTIVE_FORMULA` if custom expression yields zero candidates.".to_string(),
                "If a group stays in `circuit_open` (`REJECT`), inspect `hard_gates` against latest probe snapshots or switch fallback policy to `degrade_best_warn`.".to_string(),
                "If switching does not unstick existing HTTP/2 streams, set `switch_mode` to `force_close_old` for that group.".to_string(),
            ],
            contract_example: r#"{
  "id": "grp-ai-core",
  "name": "AI Primary Sticky Pool",
  "mode": "sticky_best",
  "match_rules": [
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,anthropic.com",
    "DOMAIN-SUFFIX,windsurf.com",
    "DOMAIN-SUFFIX,codeium.com",
    "DOMAIN-SUFFIX,devin.ai"
  ],
  "hard_gates": ["google_clean == 1", "keepalive_ok == 1"],
  "formula_expr": "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)",
  "fallback_policy": "cross_pool_escalate",
  "switch_mode": "force_close_old"
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "probes".to_string(),
            title: "Zero-Interference Isolated Probe Registry (隔离探针引擎)".to_string(),
            summary: "Ephemeral isolated Mihomo probe core (`127.0.0.1` only, `redir-host`, `GOMEMLIMIT=32MiB`) with extensible URL, upload/download, 60s keep-alive, Google region truth, and unlock probes.".to_string(),
            when_to_use_and_signals: vec![
                "Nodes appear 'pingable' yet stall on real AI requests, multi-image uploads, or 20-60s silent streams.".to_string(),
                "Need to measure real throughput and unlock status against custom endpoints (ChatGPT, Claude, Windsurf, custom APIs) without interrupting active traffic.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Requires a local Mihomo binary (`data/bin/mihomo` or `resources/bin/mihomo`).".to_string(),
                "Isolated runner binds strictly `127.0.0.1`, sets `enhanced-mode: redir-host` + direct physical `proxy-server-nameserver`, and forces `.no_proxy()` + `socks5h://` to avoid active TUN Fake-IP contamination.".to_string(),
                "Google cleanliness hard gate checks Google-side ground truth (`google.cn` redirect, YouTube GL, AI Studio availability); CF-vs-YT mismatch is logged as an advisory risk tag only.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '隔离测速' -> Add custom probe (`latency|upload|download|keepalive|google_cn|unlock_regex|external_cmd`) -> Run 3-stage funnel.".to_string(),
                "CLI run probes: `catcloud probe run --tier l1 --json`".to_string(),
                "CLI register custom probe: `catcloud probe add --id custom_api --kind upload --url https://example.com/up --json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Temporary probe cores are tracked by `JobGuard` and terminated immediately after completion (0 residual processes).".to_string(),
                "If all L2 upload probes time out at 512 KB fast-cut, check whether domestic :443 pre-acceleration is needed.".to_string(),
            ],
            contract_example: r#"{
  "id": "probe-ai-upload",
  "name": "Custom AI Upload Check",
  "kind": "upload",
  "target_url": "https://speed.cloudflare.com/__up",
  "method": "POST",
  "expected_status": 200,
  "payload_bytes": 524288,
  "timeout_ms": 10000
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "nodes_ingest".to_string(),
            title: "Multi-Dimensional Nodes, Migration & Process Adapter (节点与对口)".to_string(),
            summary: "Multi-provider subscription pool with 0-node/error protection, read-only local config migration, process inspection, and open `catcloud-adapter/v1` slots.".to_string(),
            when_to_use_and_signals: vec![
                "Consolidating nodes from multiple subscriptions or local open-source proxy clients into one filterable cross-provider pool.".to_string(),
                "Integrating dynamic-endpoint sources that rotate nodes via a user-supplied refresh script (`catcloud-adapter/v1`).".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Supports Clash/Mihomo YAML (with YAML merge anchors, capped at 16 MiB) and Base64/plain URI lists.".to_string(),
                "External adapter scripts receive JSON on `stdin` and return `{\"schema\":\"catcloud-adapter/v1\",\"nodes\":[...],\"yaml\":\"...\"}` on `stdout` (subject to `>= 60s` anti-storm cooldown).".to_string(),
                "Process attachment only inspects read-only CLI flags (`-d`, `-f`, `-ext-ctl`) and open standard controller endpoints; never alters third-party files.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '节点与订阅' -> Filter by provider / region / multiplier / protocol / 443-native / probe status -> Multi-select across providers into any multi-group.".to_string(),
                "CLI list nodes: `catcloud node list --region TW --max-multiplier 1.0 --json`".to_string(),
                "CLI import / migrate / attach: `catcloud node import --file sub.yaml --json`, `catcloud node migrate --scan --json`, `catcloud node attach-process --list --json`.".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Failed refreshes (HTTP 500, timeout, malformed YAML, or 0 parsed nodes) are atomically rejected; existing nodes and custom rules remain untouched.".to_string(),
                "To remove a migrated source, delete only its `sub_id` via SQLite cascade without touching other subscriptions.".to_string(),
            ],
            contract_example: r#"{
  "schema": "catcloud-adapter/v1",
  "nodes": [
    {
      "name": "Example-SG-01 1x",
      "type": "trojan",
      "server": "198.51.100.20",
      "port": 443,
      "password": "<PLACEHOLDER>"
    }
  ]
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "network_reload".to_string(),
            title: "Network, DNS, TUN & Three-Level Hot Reload (网络与热加载)".to_string(),
            summary: "Full Proxy Guard, PAC, TUN stack, split core/DNS IPv6, advanced DNS/fallback-filter, and zero-restart L1/L2/L3 configuration hot reload.".to_string(),
            when_to_use_and_signals: vec![
                "External tools or AI Agents edit `data/config.json` or override YAML and need immediate validated hot apply without restarting CatCloud.".to_string(),
                "Troubleshooting DNS leaks, port collisions, Windows system proxy hijacking by other apps, or UWP loopback blocks.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "L1 changes (proxy mode, group selection, connection close) apply in milliseconds via authenticated Mihomo REST API (`Authorization: Bearer <secret>`).".to_string(),
                "L2 changes trigger 300ms debounced SHA-256 deduplicated static + anti-loop + `mihomo -t` validation; invalid configs are rejected safely with zero traffic interruption.".to_string(),
                "L3 changes (ports, TUN stack, kernel swap) restart only the core child process; toggling the main proxy switch off->on always forces a fresh disk reload.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Open '设置与 CLI' -> Configure Proxy Guard, TUN stack, advanced DNS/Fallback-filter, GeoData 4-item refresh, or copy PowerShell/CMD/Bash env snippets.".to_string(),
                "CLI validate before apply: `catcloud config validate --json`".to_string(),
                "CLI hot reload: `catcloud config reload --json`".to_string(),
                "CLI shell env & sanitized diagnostics: `catcloud config export-env --shell powershell --json`, `catcloud config diag --json`.".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Export and restore integrity-checked config snapshots via `config::export_backup` / `config::import_backup`.".to_string(),
                "If default ports collide, `port_guard` checks both TCP and UDP and shifts cleanly when `port_guard_auto_shift` is enabled.".to_string(),
            ],
            contract_example: r#"{
  "reload_levels": {
    "L1": "REST API (mode switch, select node, close connections)",
    "L2": "300ms debounced preflight (syntax + anti-loop + mihomo -t) -> PUT /configs?force=true + replay active selections",
    "L3": "Core-only child restart (ports / TUN stack / kernel binary swap)"
  }
}"#.to_string(),
        },
        AgentModuleDoc {
            module_id: "updater_lifecycle".to_string(),
            title: "Windowless Memory Saver & Next-Launch Auto Updater (无窗省内存与自动更新)".to_string(),
            summary: "Destroyable WebView2 windowless tray mode (<= 70 MB), portable data isolation, and GitHub Releases next-launch verified updater with automatic rollback.".to_string(),
            when_to_use_and_signals: vec![
                "Running CatCloud continuously in the background while keeping host RAM and CPU footprint lower than traditional Electron/always-open WebView clients.".to_string(),
                "Checking or staging new releases from `JuryBu/CatCloud` for seamless application on next launch without touching user `data/`.".to_string(),
            ],
            external_prereqs_and_schema: vec![
                "Update checks strictly allow HTTPS `:443` on official GitHub hosts only, verifying `latest.json` + `SHA256SUMS.txt` before staging to `.update_staging/`.".to_string(),
                "Portable Windows updates perform same-volume `.exe.old` swap into `.update_backup/` and strictly preserve `data/`, `portable.flag`, and `*.sqlite*`.".to_string(),
                "Isolated multi-instance testing uses `--data-dir <PATH>` so sandbox instances never conflict with the daily primary instance.".to_string(),
            ],
            gui_and_cli_verification: vec![
                "GUI: Close main window to destroy WebView2 and drop to pure windowless tray mode; click tray icon or hotkey to rebuild in < 600ms.".to_string(),
                "CLI check updates: `catcloud update check --json`".to_string(),
                "CLI stage verified update for next launch: `catcloud update stage --json`".to_string(),
                "CLI export module docs: `catcloud docs export <module_id|all> --format markdown|json`".to_string(),
            ],
            rollback_and_troubleshooting: vec![
                "Any failure during portable update swap automatically restores all original files from `.update_backup/` while keeping `data/` intact.".to_string(),
                "On exit or crash, Windows `JobGuard` (`KILL_ON_JOB_CLOSE`) and Unix process-group cleanup terminate all child cores within 500ms.".to_string(),
            ],
            contract_example: r#"{
  "repo": "JuryBu/CatCloud",
  "mode": "next_launch",
  "preserved_paths": ["data/", "portable.flag", "*.sqlite*", ".update_backup/"]
}"#.to_string(),
        },
    ]
}

/// Look up a single module's four-section Agent guide by ID (case-insensitive).
pub fn get_agent_doc(module_id: &str) -> CatResult<AgentModuleDoc> {
    let needle = module_id.trim().to_ascii_lowercase();
    list_agent_docs()
        .into_iter()
        .find(|d| d.module_id == needle)
        .ok_or_else(|| CatError::NotFound(format!("unknown agent doc module `{module_id}`")))
}

/// Export either one module or `"all"` modules as Markdown or JSON.
pub fn export_agent_docs(module_id: &str, as_json: bool) -> CatResult<String> {
    let needle = module_id.trim().to_ascii_lowercase();
    if needle.is_empty() || needle == "all" {
        let all = list_agent_docs();
        if as_json {
            Ok(serde_json::to_string_pretty(&all)?)
        } else {
            let rendered: Vec<String> = all.iter().map(AgentModuleDoc::to_markdown).collect();
            Ok(rendered.join("\n---\n\n"))
        }
    } else {
        let doc = get_agent_doc(&needle)?;
        if as_json {
            Ok(serde_json::to_string_pretty(&doc)?)
        } else {
            Ok(doc.to_markdown())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_six_core_modules_with_four_sections() {
        let docs = list_agent_docs();
        assert_eq!(docs.len(), 6);
        for doc in &docs {
            assert!(!doc.when_to_use_and_signals.is_empty(), "{}", doc.module_id);
            assert!(!doc.external_prereqs_and_schema.is_empty(), "{}", doc.module_id);
            assert!(!doc.gui_and_cli_verification.is_empty(), "{}", doc.module_id);
            assert!(!doc.rollback_and_troubleshooting.is_empty(), "{}", doc.module_id);
            let md = doc.to_markdown();
            assert!(md.contains("## 1. When to Use"));
            assert!(md.contains("## 2. External Prerequisites"));
            assert!(md.contains("## 3. GUI & Headless CLI"));
            assert!(md.contains("## 4. Rollback & Troubleshooting"));
        }
    }

    #[test]
    fn export_single_and_all_in_json_and_markdown() {
        let json_all = export_agent_docs("all", true).expect("export all json");
        let parsed: Vec<AgentModuleDoc> = serde_json::from_str(&json_all).expect("parse json");
        assert_eq!(parsed.len(), 6);

        let preaccel_md = export_agent_docs("preaccel", false).expect("export preaccel md");
        assert!(preaccel_md.contains("mmrelay/v1"));
        assert!(preaccel_md.contains("hicloud.com"));

        assert!(export_agent_docs("nonexistent_module", false).is_err());
    }
}
