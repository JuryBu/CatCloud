//! Top-level Mihomo configuration compiler orchestration (`compile_mihomo_config*`),
//! post-override MTU/dialer reconciliation, and unified preview redaction.

use super::types::{
    CompileInput, CompileStats, CompiledCoreConfig, CompiledGroupMapping,
    DEFAULT_FALLBACK_GROUP_NAME, DEFAULT_LOAD_BALANCE_URL, PREACCEL_FALLBACK_GROUP_NAME,
    PREACCEL_LB_GROUP_NAME, PREACCEL_SELECT_GROUP_NAME, SINGLE_NODE_GROUP_NAME,
    direct_rule_for_host_or_ip, extract_url_host, insert_bool, insert_str, insert_u64,
    make_unique_name, push_unique, sha256_hex, str_val, string_seq,
};
use super::rules::{
    collect_valid_rule_target_names, enforce_mandatory_safety_rules_at_top,
    expand_group_match_rule_with_known_targets, is_match_rule, is_plausible_global_rule,
    normalize_global_rule_for_emit,
};
use super::proxies_net::{
    build_dns_section, build_node_proxy_mapping, build_relay_proxy_mapping, build_sniffer_section,
    build_tun_section, select_nodes_and_groups_for_compile, strip_dangling_dialer_proxies,
};
use super::validation::{apply_yaml_merge_patch, validate_compiled_yaml};
use crate::config::validate_config;
use crate::core_adapter::format_host_port;
use crate::error::{CatError, CatResult};
use crate::models::{
    FallbackPolicy, MultiGroupMode, MultiGroupState, OverrideMode, PreAccelRelay, RouteTargetMode,
    is_ipv6_only_node, pick_smart_default_node_id,
};
use crate::preaccel::generator::build_preaccel_proxy_groups;
use serde_yaml_ng::{Mapping, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

/// Compile a full Mihomo YAML configuration from CatCloud's strongly-typed configuration,
/// nodes, multi-groups, and domestic pre-acceleration relays (without inspecting a runtime
/// directory for GeoData files; safe for offline/unit-test compilation).
pub fn compile_mihomo_config(input: &CompileInput<'_>) -> CatResult<CompiledCoreConfig> {
    compile_mihomo_config_with_runtime_dir(input, None)
}

/// Compile a full Mihomo YAML configuration while optionally inspecting `runtime_dir` for
/// locally installed `geosite.dat` / `geoip.dat` / `Country.mmdb` databases
/// so GeoSite/GeoIP rules and filters are only emitted when their backing files actually exist on disk.
pub fn compile_mihomo_config_with_runtime_dir(
    input: &CompileInput<'_>,
    runtime_dir: Option<&Path>,
) -> CatResult<CompiledCoreConfig> {
    let cfg = input.config;
    validate_config(cfg)?;
    cfg.rules_override
        .validate_inline_override_yaml()
        .map_err(CatError::Validation)?;

    let secret = input.controller_secret.trim();
    if secret.is_empty() {
        return Err(CatError::Validation(
            "controller_secret cannot be empty when compiling Mihomo config".into(),
        ));
    }

    let (has_geosite, has_geoip) = match runtime_dir {
        Some(dir) => {
            let geosite =
                dir.join("geosite.dat").is_file() || dir.join("GeoSite.dat").is_file();
            let geoip = if cfg.geodata.geodata_mode {
                dir.join("geoip.dat").is_file() || dir.join("GeoIP.dat").is_file()
            } else {
                dir.join("Country.mmdb").is_file() || dir.join("country.mmdb").is_file()
            };
            (geosite, geoip)
        }
        None => (false, false),
    };

    // 1. Collect enabled domestic pre-acceleration relays sorted by (priority ASC, id ASC).
    let mut enabled_relays: Vec<&PreAccelRelay> =
        input.relays.iter().filter(|r| r.enabled).collect();
    enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    let preaccel_active = cfg.preaccel.enabled && !enabled_relays.is_empty();

    // Determine which enabled business nodes (and optional active group subset) need compilation.
    let (compiled_nodes, allowed_group_ids) = select_nodes_and_groups_for_compile(input);

    let mut root = Mapping::new();

    // 2. Core listener & runtime fields (covering all 7 settings screenshots).
    insert_u64(
        &mut root,
        "mixed-port",
        u64::from(input.allocated_ports.mixed_port),
    );
    if let Some(p) = cfg.socks_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "socks-port", u64::from(p));
    }
    if let Some(p) = cfg.http_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "port", u64::from(p));
    }
    if let Some(p) = cfg.redir_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "redir-port", u64::from(p));
    }
    if let Some(p) = cfg.tproxy_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "tproxy-port", u64::from(p));
    }

    insert_bool(&mut root, "allow-lan", cfg.allow_lan);
    let bind_address = if cfg.allow_lan {
        let configured = cfg.bind_address.trim();
        if configured.is_empty() || configured == "127.0.0.1" {
            "*".to_string()
        } else {
            configured.to_string()
        }
    } else {
        "127.0.0.1".to_string()
    };
    insert_str(&mut root, "bind-address", &bind_address);
    insert_str(&mut root, "mode", cfg.proxy_mode.as_str());
    insert_str(&mut root, "log-level", cfg.log_level.as_str());
    insert_bool(&mut root, "ipv6", cfg.core_ipv6);
    insert_bool(&mut root, "unified-delay", cfg.unified_delay);
    insert_bool(&mut root, "tcp-concurrent", cfg.tcp_concurrent);
    insert_u64(&mut root, "keep-alive-idle", 45);
    insert_u64(&mut root, "keep-alive-interval", 15);
    insert_str(
        &mut root,
        "find-process-mode",
        cfg.find_process_mode.as_str(),
    );

    let controller_host = if cfg.allow_lan {
        cfg.controller_host.trim()
    } else {
        "127.0.0.1"
    };
    insert_str(
        &mut root,
        "external-controller",
        &format_host_port(controller_host, input.allocated_ports.controller_port),
    );
    insert_str(&mut root, "secret", secret);

    let mut profile_map = Mapping::new();
    insert_bool(
        &mut profile_map,
        "store-selected",
        cfg.core_runtime.store_selected,
    );
    insert_bool(
        &mut profile_map,
        "store-fake-ip",
        cfg.core_runtime.store_fake_ip,
    );
    root.insert(str_val("profile"), Value::Mapping(profile_map));

    insert_bool(&mut root, "geodata-mode", cfg.geodata.geodata_mode);
    insert_bool(&mut root, "geo-auto-update", cfg.geodata.auto_update);
    // Unconditionally enforce memconservative streaming loader so geosite.dat never expands
    // fully onto the Go heap (even when geodata-mode is false and only geosite rules are loaded).
    insert_str(&mut root, "geodata-loader", "memconservative");

    let mut geox_url = Mapping::new();
    if !cfg.geodata.geoip_url.trim().is_empty() {
        insert_str(&mut geox_url, "geoip", cfg.geodata.geoip_url.trim());
    }
    if !cfg.geodata.geosite_url.trim().is_empty() {
        insert_str(&mut geox_url, "geosite", cfg.geodata.geosite_url.trim());
    }
    if !cfg.geodata.mmdb_url.trim().is_empty() {
        insert_str(&mut geox_url, "mmdb", cfg.geodata.mmdb_url.trim());
    }
    if !cfg.geodata.asn_url.trim().is_empty() {
        insert_str(&mut geox_url, "asn", cfg.geodata.asn_url.trim());
    }
    if !geox_url.is_empty() {
        root.insert(str_val("geox-url"), Value::Mapping(geox_url));
    }

    let custom_rules_only = cfg.rules_override.custom_rules_only;
    root.insert(
        str_val("sniffer"),
        Value::Mapping(build_sniffer_section(
            !custom_rules_only && cfg.rules_override.block_quic_udp_443,
            !custom_rules_only && cfg.rules_override.domestic_direct_enabled,
            has_geoip,
        )),
    );

    if cfg.dns.use_hosts && !cfg.dns.hosts.is_empty() {
        let mut hosts_map = Mapping::new();
        for (domain, target) in &cfg.dns.hosts {
            insert_str(&mut hosts_map, domain, target);
        }
        root.insert(str_val("hosts"), Value::Mapping(hosts_map));
    }

    // 3. Build domestic pre-acceleration loop-prevention entries (domains/IPs + fake-ip-filter).
    let mut anti_loop_rules: Vec<String> = Vec::new();
    let mut anti_loop_fake_ip_domains: Vec<String> = Vec::new();
    let mut relay_servers_for_validation: Vec<String> = Vec::new();

    if preaccel_active {
        for relay in &enabled_relays {
            let server = relay.server.trim();
            if server.is_empty() {
                continue;
            }
            relay_servers_for_validation.push(server.to_string());
            push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(server));
            if server.parse::<IpAddr>().is_err() {
                push_unique(&mut anti_loop_fake_ip_domains, server.to_string());
            }
        }

        for probe_url in [&cfg.preaccel.probe_url, &cfg.preaccel.fallback_probe_url] {
            if let Some(host) = extract_url_host(probe_url) {
                push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(&host));
                if host.parse::<IpAddr>().is_err() {
                    push_unique(&mut anti_loop_fake_ip_domains, host);
                }
            }
        }
    }

    // Merge campus direct domains into both anti-loop rules and fake-ip-filter.
    for raw_domain in &cfg.preaccel.campus_direct_domains {
        let entry = raw_domain.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.contains(',') {
            if is_plausible_global_rule(entry) {
                push_unique(&mut anti_loop_rules, entry.to_string());
            }
        } else if entry.parse::<IpAddr>().is_ok() {
            push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(entry));
        } else {
            let normalized = entry.trim_start_matches("*.").trim_start_matches("+.");
            push_unique(
                &mut anti_loop_rules,
                format!("DOMAIN-SUFFIX,{normalized},DIRECT"),
            );
            push_unique(&mut anti_loop_fake_ip_domains, entry.to_string());
        }
    }

    // Add compiled business proxy node domain servers to fake-ip-filter to prevent TUN
    // Fake-IP resolution loops. Do NOT force DIRECT rules on business nodes (otherwise nodes
    // wrapped with domestic :443 relays would bypass pre-acceleration).
    for &node in &compiled_nodes {
        let server_candidate = {
            let s = node.server.trim();
            if !s.is_empty() {
                Some(s)
            } else {
                node.raw_config
                    .get("server")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
            }
        };
        if let Some(raw_server) = server_candidate {
            let clean = raw_server.trim_start_matches('[').trim_end_matches(']');
            if !clean.is_empty() && clean.parse::<IpAddr>().is_err() {
                push_unique(&mut anti_loop_fake_ip_domains, clean.to_string());
            }
        }
    }

    // 4. Full 7-screenshot DNS section with anti-leak nameserver-policy & disk-aware GeoData gating.
    let dns_map = build_dns_section(
        cfg,
        input.allocated_ports,
        &anti_loop_fake_ip_domains,
        input.extra_fake_ip_filters,
        has_geosite,
        has_geoip,
    );
    root.insert(str_val("dns"), Value::Mapping(dns_map));

    // 5. Compile proxies (domestic relays + business nodes with optional dialer-proxy).
    //    (TUN section is emitted immediately after dangling `dialer-proxy` stripping so
    //    `effective_tun_mtu` accurately reflects whether any proxy remains dialer-wrapped.)
    // Pre-seed Mihomo built-in target names and pre-acceleration group names so user-provided
    // relay/node names (e.g. a relay literally named `DIRECT`) never collide with reserved names
    // or get filtered out of load-balance groups.
    let mut used_proxy_names: HashSet<String> = [
        "DIRECT",
        "REJECT",
        "PASS",
        PREACCEL_SELECT_GROUP_NAME,
        PREACCEL_FALLBACK_GROUP_NAME,
        PREACCEL_LB_GROUP_NAME,
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect();
    let mut compiled_proxies: Vec<Value> = Vec::new();
    let mut relay_id_to_name: HashMap<String, String> = HashMap::new();
    let mut relay_names_ordered: Vec<String> = Vec::new();

    if preaccel_active {
        for relay in &enabled_relays {
            let base_name = if relay.name.trim().is_empty() {
                format!("PreAccel-{}", relay.id)
            } else {
                relay.name.trim().to_string()
            };
            let unique_name = make_unique_name(&base_name, &mut used_proxy_names);
            let relay_yaml = build_relay_proxy_mapping(relay, &unique_name)?;
            compiled_proxies.push(Value::Mapping(relay_yaml));
            relay_id_to_name.insert(relay.id.clone(), unique_name.clone());
            relay_names_ordered.push(unique_name);
        }
    }

    let mut node_id_to_name: HashMap<String, String> = HashMap::new();
    let mut all_enabled_node_names: Vec<String> = Vec::new();
    let mut dialer_wrapped_proxies = 0usize;
    let mut skipped_443_native_proxies = 0usize;
    let mut skipped_ipv6_proxies = 0usize;
    let relays_support_ipv6 =
        !enabled_relays.is_empty() && enabled_relays.iter().all(|r| r.supports_ipv6);

    for &node in &compiled_nodes {
        let base_name = if node.name.trim().is_empty() {
            format!("Node-{}", node.id)
        } else {
            node.name.trim().to_string()
        };
        let unique_name = make_unique_name(&base_name, &mut used_proxy_names);
        let mut proxy_map = build_node_proxy_mapping(node, &unique_name)?;

        if preaccel_active {
            let wants_preaccel = node.should_apply_preaccel(cfg.preaccel.skip_443_native);
            let skip_for_ipv6 = wants_preaccel
                && !relays_support_ipv6
                && is_ipv6_only_node(node)
                && node.preaccel_override != Some(true);
            if wants_preaccel && !skip_for_ipv6 {
                insert_str(&mut proxy_map, "dialer-proxy", PREACCEL_SELECT_GROUP_NAME);
                dialer_wrapped_proxies += 1;
            } else {
                if proxy_map.get("dialer-proxy").and_then(Value::as_str)
                    == Some(PREACCEL_SELECT_GROUP_NAME)
                {
                    proxy_map.shift_remove("dialer-proxy");
                }
                if skip_for_ipv6 {
                    skipped_ipv6_proxies += 1;
                } else if cfg.preaccel.skip_443_native
                    && node.is_443_native
                    && node.preaccel_override.is_none()
                {
                    skipped_443_native_proxies += 1;
                }
            }
        } else if proxy_map.get("dialer-proxy").and_then(Value::as_str)
            == Some(PREACCEL_SELECT_GROUP_NAME)
        {
            proxy_map.shift_remove("dialer-proxy");
        }

        compiled_proxies.push(Value::Mapping(proxy_map));
        node_id_to_name.insert(node.id.clone(), unique_name.clone());
        all_enabled_node_names.push(unique_name);
    }

    // 7. Compile proxy-groups: pre-acceleration chain + all 4 MultiGroupMode variants.
    let mut proxy_groups: Vec<Value> = Vec::new();
    let mut group_mappings: Vec<CompiledGroupMapping> = Vec::new();
    let mut active_selections: BTreeMap<String, String> = BTreeMap::new();

    if preaccel_active {
        let enabled_owned: Vec<PreAccelRelay> =
            enabled_relays.iter().map(|r| (*r).clone()).collect();
        let built = build_preaccel_proxy_groups(
            &cfg.preaccel,
            &enabled_owned,
            &relay_id_to_name,
            &relay_names_ordered,
            cfg.preaccel.probe_url.trim(),
            cfg.preaccel.probe_interval_sec,
        );
        active_selections.insert(
            PREACCEL_SELECT_GROUP_NAME.to_string(),
            built.default_select_target,
        );
        proxy_groups.extend(built.proxy_groups);
    }

    let mut default_match_target: Option<String> = None;
    let mut effective_active_group_id: Option<String> = None;
    let preferred_active_group_id = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    for group in input.groups {
        if let Some(ref allowed_groups) = allowed_group_ids {
            if !allowed_groups.contains(group.id.trim()) {
                continue;
            }
        }
        let group_name = if group.name.trim().is_empty() {
            group.id.trim().to_string()
        } else {
            group.name.trim().to_string()
        };
        if group_name.is_empty() {
            continue;
        }
        if preferred_active_group_id == Some(group.id.trim()) {
            default_match_target = Some(group_name.clone());
            effective_active_group_id = Some(group.id.trim().to_string());
        } else if default_match_target.is_none() {
            default_match_target = Some(group_name.clone());
            effective_active_group_id = Some(group.id.trim().to_string());
        }

        // Resolve member list: honor hard-gate filtered override (including explicit empty list).
        let explicit_filtered = input
            .group_filtered_members
            .get(&group.id)
            .or_else(|| input.group_filtered_members.get(&group_name));

        let mut members: Vec<String> = Vec::new();
        if let Some(filtered_ids) = explicit_filtered {
            for nid in filtered_ids {
                if let Some(proxy_name) = node_id_to_name.get(nid) {
                    push_unique(&mut members, proxy_name.clone());
                } else if nid == "REJECT" || nid == "DIRECT" {
                    push_unique(&mut members, nid.clone());
                }
            }
        } else if !group.member_node_ids.is_empty() {
            for nid in &group.member_node_ids {
                if let Some(proxy_name) = node_id_to_name.get(nid) {
                    push_unique(&mut members, proxy_name.clone());
                } else if nid == "REJECT" || nid == "DIRECT" {
                    push_unique(&mut members, nid.clone());
                }
            }
        } else if group.mode == MultiGroupMode::ConditionalPool {
            for name in &all_enabled_node_names {
                push_unique(&mut members, name.clone());
            }
        }

        // Keep a REJECT slot on select groups when fallback_policy == StrictCircuitBreak.
        // For load-balance groups, NEVER mix REJECT alongside healthy nodes (Mihomo would
        // route a fraction of healthy traffic to REJECT); only emit ["REJECT"] when CircuitOpen
        // or when zero healthy members remain.
        let is_load_balance = matches!(
            group.mode,
            MultiGroupMode::LoadBalanceConsistentHash | MultiGroupMode::LoadBalanceRoundRobin
        );
        let has_reject_slot = group.fallback_policy == FallbackPolicy::StrictCircuitBreak;
        if has_reject_slot {
            if is_load_balance {
                if group.state == MultiGroupState::CircuitOpen || members.is_empty() {
                    members.clear();
                    members.push("REJECT".to_string());
                }
            } else {
                push_unique(&mut members, "REJECT".to_string());
            }
        }

        // Prevent Mihomo from failing on an empty group if no nodes exist yet.
        if members.is_empty() {
            members.push("DIRECT".to_string());
        }

        // Resolve active proxy name for sticky selection preservation.
        // Only accept a candidate that actually belongs to `members` (except explicit
        // `CircuitOpen` -> `REJECT`, which is already guaranteed present when `has_reject_slot`).
        // Never re-inject a removed/ghost `active_node_id` back into `members`.
        let resolved_active: Option<String> = if group.state == MultiGroupState::CircuitOpen
            && has_reject_slot
        {
            Some("REJECT".to_string())
        } else if let Some(ref active_id) = group.active_node_id {
            let candidate = if active_id == "REJECT" && has_reject_slot {
                Some("REJECT".to_string())
            } else if active_id == "DIRECT" {
                Some("DIRECT".to_string())
            } else {
                node_id_to_name.get(active_id).cloned()
            };
            candidate.filter(|name| members.iter().any(|m| m == name))
        } else {
            None
        };

        let mut group_map = Mapping::new();
        insert_str(&mut group_map, "name", &group_name);

        let (mihomo_type, final_active) = match group.mode {
            MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool => {
                // Move valid active_node_id to index 0 so `store-selected: false` never resets it
                // on reload. Ghost nodes absent from `members` are discarded above so `members[0]`
                // becomes the active selection cleanly.
                if let Some(ref active_name) = resolved_active {
                    if let Some(pos) = members.iter().position(|m| m == active_name) {
                        let chosen = members.remove(pos);
                        members.insert(0, chosen);
                    } else if group.state == MultiGroupState::CircuitOpen
                        && active_name == "REJECT"
                    {
                        members.insert(0, active_name.clone());
                    }
                }
                insert_str(&mut group_map, "type", "select");
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                let head = members.first().cloned();
                if let Some(ref h) = head {
                    active_selections.insert(group_name.clone(), h.clone());
                }
                ("select".to_string(), head)
            }
            MultiGroupMode::LoadBalanceConsistentHash => {
                insert_str(&mut group_map, "type", "load-balance");
                insert_str(&mut group_map, "strategy", "consistent-hashing");
                insert_str(&mut group_map, "url", DEFAULT_LOAD_BALANCE_URL);
                insert_u64(&mut group_map, "interval", 300);
                insert_bool(&mut group_map, "lazy", true);
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                ("load-balance".to_string(), None)
            }
            MultiGroupMode::LoadBalanceRoundRobin => {
                insert_str(&mut group_map, "type", "load-balance");
                insert_str(&mut group_map, "strategy", "round-robin");
                insert_str(&mut group_map, "url", DEFAULT_LOAD_BALANCE_URL);
                insert_u64(&mut group_map, "interval", 300);
                insert_bool(&mut group_map, "lazy", true);
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                ("load-balance".to_string(), None)
            }
        };

        group_mappings.push(CompiledGroupMapping {
            group_id: group.id.clone(),
            group_name: group_name.clone(),
            mihomo_type,
            active_proxy_name: final_active,
            member_proxy_names: members,
            has_reject_slot,
        });
        proxy_groups.push(Value::Mapping(group_map));
    }

    let resolved_single_proxy_name: Option<String> = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|nid| node_id_to_name.get(nid))
            .cloned()
    } else {
        None
    };

    // Compile direct single-node selector when active, otherwise fall back to multi-group / default.
    let single_mode_active = resolved_single_proxy_name.is_some();
    let match_target = if let Some(single_proxy_name) = resolved_single_proxy_name {
        let mut single_members: Vec<String> =
            Vec::with_capacity(all_enabled_node_names.len().max(1));
        single_members.push(single_proxy_name.clone());
        for name in &all_enabled_node_names {
            push_unique(&mut single_members, name.clone());
        }
        active_selections.insert(
            SINGLE_NODE_GROUP_NAME.to_string(),
            single_proxy_name.clone(),
        );
        let mut single_group = Mapping::new();
        insert_str(&mut single_group, "name", SINGLE_NODE_GROUP_NAME);
        insert_str(&mut single_group, "type", "select");
        single_group.insert(
            str_val("proxies"),
            string_seq(single_members.iter().map(String::as_str)),
        );
        proxy_groups.push(Value::Mapping(single_group));
        SINGLE_NODE_GROUP_NAME.to_string()
    } else {
        match default_match_target {
            Some(target) => target,
            None => {
                let mut default_members = all_enabled_node_names.clone();
                if let Some(smart_id) = pick_smart_default_node_id(input.nodes, None) {
                    if let Some(smart_name) = node_id_to_name.get(&smart_id) {
                        if let Some(pos) = default_members.iter().position(|n| n == smart_name) {
                            let chosen = default_members.remove(pos);
                            default_members.insert(0, chosen);
                        }
                    }
                }
                if default_members.is_empty() {
                    default_members.push("DIRECT".to_string());
                }
                if let Some(first) = default_members.first() {
                    active_selections.insert(DEFAULT_FALLBACK_GROUP_NAME.to_string(), first.clone());
                }
                let mut default_group = Mapping::new();
                insert_str(&mut default_group, "name", DEFAULT_FALLBACK_GROUP_NAME);
                insert_str(&mut default_group, "type", "select");
                default_group.insert(
                    str_val("proxies"),
                    string_seq(default_members.iter().map(String::as_str)),
                );
                proxy_groups.push(Value::Mapping(default_group));
                DEFAULT_FALLBACK_GROUP_NAME.to_string()
            }
        }
    };

    // Strip dangling/invalid/self-referencing `dialer-proxy` entries inherited from raw
    // subscriptions unless their target exists in the compiled proxies or proxy-groups.
    let removed_preaccel_dialers =
        strip_dangling_dialer_proxies(&mut compiled_proxies, &proxy_groups);
    dialer_wrapped_proxies = dialer_wrapped_proxies.saturating_sub(removed_preaccel_dialers);

    // Emit TUN section after final `dialer_wrapped_proxies` is known (never mutating `cfg.tun.mtu`).
    let effective_tun_mtu = if dialer_wrapped_proxies > 0 {
        cfg.tun.mtu.min(1400)
    } else {
        cfg.tun.mtu
    };
    let tun_map = build_tun_section(cfg, effective_tun_mtu);
    root.insert(str_val("tun"), Value::Mapping(tun_map));

    root.insert(str_val("proxies"), Value::Sequence(compiled_proxies));
    root.insert(str_val("proxy-groups"), Value::Sequence(proxy_groups));

    // 8. Compile ordered rules chain:
    //    (1) anti-loop -> (2) isolated probe core PROCESS-NAME bypass ->
    //    (3) private LAN/loopback direct -> (4) domestic public DNS IP direct ->
    //    (5) extra_prepend_rules + global_prepend_rules -> (6) QUIC UDP/443 reject ->
    //    (7) group match_rules (skipped in single mode) ->
    //    (8) global_append_rules -> (9) domestic direct rules -> (10) MATCH
    let mut rules: Vec<String> = Vec::new();
    let mut mandatory_safety_rules: Vec<String> = Vec::new();
    for r in anti_loop_rules {
        push_unique(&mut mandatory_safety_rules, r.clone());
        push_unique(&mut rules, r);
    }
    let probe_bypass_rule = format!(
        "PROCESS-NAME,{},DIRECT",
        crate::probe::isolated_runner::PROBE_CORE_PROCESS_NAME
    );
    push_unique(&mut mandatory_safety_rules, probe_bypass_rule.clone());
    push_unique(&mut rules, probe_bypass_rule);

    const PRIVATE_LAN_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
        "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    ];
    for r in PRIVATE_LAN_DIRECT_RULES {
        push_unique(&mut mandatory_safety_rules, (*r).to_string());
        push_unique(&mut rules, (*r).to_string());
    }
    const PRIVATE_LOCAL_DOMAIN_DIRECT_RULES: &[&str] = &[
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,localhost,DIRECT",
        "DOMAIN-SUFFIX,localdomain,DIRECT",
        "DOMAIN-SUFFIX,home.arpa,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT",
    ];
    for r in PRIVATE_LOCAL_DOMAIN_DIRECT_RULES {
        push_unique(&mut mandatory_safety_rules, (*r).to_string());
        push_unique(&mut rules, (*r).to_string());
    }
    if has_geosite {
        push_unique(&mut rules, "GEOSITE,private,DIRECT".to_string());
    }

    const DOMESTIC_PUBLIC_DNS_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
        "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve",
        "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
        "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
        "IP-CIDR,119.28.28.28/32,DIRECT,no-resolve",
        "IP-CIDR,120.53.53.53/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.114.114/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.115.115/32,DIRECT,no-resolve",
        "IP-CIDR,180.76.76.76/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.1.1/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.2.2/32,DIRECT,no-resolve",
        "IP-CIDR,1.2.4.8/32,DIRECT,no-resolve",
        "IP-CIDR,210.2.4.8/32,DIRECT,no-resolve",
        "DOMAIN,dns.alidns.com,DIRECT",
        "DOMAIN,doh.pub,DIRECT",
        "DOMAIN,dot.pub,DIRECT",
        "DOMAIN,dns.pub,DIRECT",
    ];
    for r in DOMESTIC_PUBLIC_DNS_DIRECT_RULES {
        push_unique(&mut mandatory_safety_rules, (*r).to_string());
        push_unique(&mut rules, (*r).to_string());
    }

    for r in input.extra_prepend_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, normalize_global_rule_for_emit(trimmed));
        }
    }
    for r in &cfg.rules_override.global_prepend_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, normalize_global_rule_for_emit(trimmed));
        }
    }

    const DOMESTIC_QUIC_DIRECT_DOMAINS: &[&str] = &[
        "cn",
        "qq.com",
        "qpic.cn",
        "qlogo.cn",
        "gtimg.cn",
        "gtimg.com",
        "weixin.qq.com",
        "wechat.com",
        "tencent.com",
        "qcloud.com",
        "myqcloud.com",
        "qcloudimg.com",
        "tencentcs.com",
        "tencent-cloud.net",
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
    ];
    if !custom_rules_only && cfg.rules_override.block_quic_udp_443 {
        if cfg.rules_override.domestic_direct_enabled {
            for domain in DOMESTIC_QUIC_DIRECT_DOMAINS {
                push_unique(
                    &mut rules,
                    format!(
                        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{domain})),DIRECT"
                    ),
                );
            }
            if has_geosite {
                push_unique(
                    &mut rules,
                    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT".to_string(),
                );
            }
            if has_geoip {
                push_unique(
                    &mut rules,
                    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT".to_string(),
                );
            }
        }
        push_unique(
            &mut rules,
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string(),
        );
    }
    if !custom_rules_only && !single_mode_active {
        let mut known_targets = collect_valid_rule_target_names(input.groups, input.nodes);
        for gm in &group_mappings {
            if !gm.group_name.trim().is_empty() {
                known_targets.insert(gm.group_name.clone());
            }
        }
        for pname in &all_enabled_node_names {
            if !pname.trim().is_empty() {
                known_targets.insert(pname.clone());
            }
        }
        let active_group_id_ref = effective_active_group_id.as_deref();
        // Emit the active home group's match_rules FIRST for highest priority, followed ONLY by
        // other groups with `independent_routing == true`. Unselected groups with
        // `independent_routing == false` still keep their compiled `proxy-group` for instant
        // switching, but never inject match_rules that could silently hijack traffic.
        let active_first = input
            .groups
            .iter()
            .filter(|g| active_group_id_ref == Some(g.id.trim()));
        let independent_others = input
            .groups
            .iter()
            .filter(|g| active_group_id_ref != Some(g.id.trim()) && g.independent_routing);

        for group in active_first.chain(independent_others) {
            let target = if group.name.trim().is_empty() {
                group.id.trim()
            } else {
                group.name.trim()
            };
            if target.is_empty() {
                continue;
            }
            for raw_rule in &group.match_rules {
                for expanded in
                    expand_group_match_rule_with_known_targets(raw_rule, target, Some(&known_targets))
                {
                    push_unique(&mut rules, expanded);
                }
            }
        }
    }
    for r in &cfg.rules_override.global_append_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, normalize_global_rule_for_emit(trimmed));
        }
    }

    // Group A: Always-emitted strictly domestic / system download CDN & NTP whitelist
    // (placed before `GEOSITE,cn,DIRECT` even when `geosite.dat` is present).
    // Conservative red line: never include broad overseas/hybrid root domains such as
    // `microsoft.com`, `apple.com`, `steampowered.com`, `steamcommunity.com`, `github.com`, etc.
    const ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS: &[&str] = &[
        // Microsoft connectivity checks, Windows push notifications & Windows Update download CDNs
        "msftconnecttest.com",
        "msftncsi.com",
        "wns.windows.com",
        "notify.windows.com",
        "time.windows.com",
        "windowsupdate.com",
        "update.microsoft.com",
        "dl.delivery.mp.microsoft.com",
        "tlu.dl.delivery.mp.microsoft.com",
        // Apple China downloads, push notifications & NTP
        "icloud.com.cn",
        "push.apple.com",
        "time.apple.com",
        "swcdn.apple.com",
        "appldnld.apple.com",
        "mesu.apple.com",
        "updates-http.cdn-apple.com",
        "osxapps.itunes.apple.com",
        // Steam pure download CDNs (excluding store/community)
        "steamcontent.com",
        "steamserver.net",
        "dl.steam.clngaa.com",
        "dl.steam.ksyna.com",
        "st.dl.eccdnx.com",
        "st.dl.pinyuncloud.com",
        "st.dl.bscstorage.net",
        "xz.pphimalayanrt.com",
        // Domestic NTP
        "ntp.aliyun.com",
        "ntp.tencent.com",
        "cn.pool.ntp.org",
    ];

    // Group B: Expanded fallback whitelist for strictly domestic sites and core CDNs
    // used when `geosite.dat` is absent.
    const FALLBACK_DOMESTIC_DIRECT_DOMAINS: &[&str] = &[
        // Core domestic portals & Tencent / QQ / WeChat
        "qq.com",
        "weixin.qq.com",
        "gtimg.cn",
        "gtimg.com",
        "qpic.cn",
        "qlogo.cn",
        "wechat.com",
        "wechatpay.com",
        "tenpay.com",
        "tencent.com",
        "myqcloud.com",
        "qcloud.com",
        "qcloudimg.com",
        "tencentcs.com",
        "tencent-cloud.net",
        // Taobao / Aliyun / Alipay / DingTalk / Amap (excluding international alibaba.com)
        "taobao.com",
        "tmall.com",
        "alicdn.com",
        "aliyuncs.com",
        "aliyun.com",
        "alipay.com",
        "alipayobjects.com",
        "dingtalk.com",
        "amap.com",
        "autonavi.com",
        // ByteDance / Douyin / Feishu (strictly domestic; never tiktok.com / larksuite.com)
        "douyin.com",
        "bytedance.com",
        "byteimg.com",
        "pstatp.com",
        "snssdk.com",
        "toutiao.com",
        "iesdouyin.com",
        "douyinvod.com",
        "volces.com",
        "volcengine.com",
        "feishu.cn",
        // Bilibili & video CDNs
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
        "hdslb.com",
        "biliapi.com",
        "biliapi.net",
        "b23.tv",
        // NetEase / Youdao
        "163.com",
        "126.net",
        "126.com",
        "netease.com",
        "ydstatic.com",
        "youdao.com",
        // Baidu & Baidu Netdisk
        "baidu.com",
        "bdimg.com",
        "bdstatic.com",
        "bcebos.com",
        "baidupcs.com",
        // JD / Zhihu / Xiaohongshu / Weibo / Douban
        "jd.com",
        "360buyimg.com",
        "zhihu.com",
        "zhimg.com",
        "xiaohongshu.com",
        "xhscdn.com",
        "weibo.com",
        "sinaimg.cn",
        "douban.com",
        "doubanio.com",
        // Local services & e-commerce
        "meituan.com",
        "meituan.net",
        "dianping.com",
        "pinduoduo.com",
        // Domestic video / livestreaming
        "iqiyi.com",
        "youku.com",
        "mgtv.com",
        "huya.com",
        "douyu.com",
        "kuaishou.com",
        // Cloud drives & domestic developer mirrors (excluding international wps.com)
        "aliyundrive.com",
        "alipan.com",
        "quark.cn",
        "csdn.net",
        "gitee.com",
        "juejin.cn",
        "npmmirror.com",
        // OEMs, logistics & education
        "mi.com",
        "xiaomi.com",
        "miui.com",
        "huawei.com",
        "hicloud.com",
        "vmall.com",
        "sf-express.com",
        "cainiao.com",
        "edu.cn",
    ];
    if !custom_rules_only && cfg.rules_override.domestic_direct_enabled {
        push_unique(&mut rules, "DOMAIN-SUFFIX,cn,DIRECT".to_string());
        for domain in ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS {
            push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},DIRECT"));
        }
        if has_geosite {
            push_unique(&mut rules, "GEOSITE,cn,DIRECT".to_string());
        } else {
            for domain in FALLBACK_DOMESTIC_DIRECT_DOMAINS {
                push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},DIRECT"));
            }
        }
        if has_geoip {
            push_unique(&mut rules, "GEOIP,CN,DIRECT,no-resolve".to_string());
        }
    }

    let has_match_rule = rules.iter().any(|r| is_match_rule(r));
    if !has_match_rule {
        rules.push(format!("MATCH,{match_target}"));
    }

    root.insert(
        str_val("rules"),
        string_seq(rules.iter().map(String::as_str)),
    );

    // 9. Apply optional declarative YAML Merge Patch override (file and/or inline) without
    //    mutating the base configuration on error.
    let mut final_value = Value::Mapping(root);
    let mut applied_override_patch = false;
    if matches!(
        cfg.rules_override.override_mode,
        OverrideMode::MergePatch | OverrideMode::Both
    ) {
        if let Some(patch_path_str) = cfg
            .rules_override
            .override_merge_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let patch_path = Path::new(patch_path_str);
            let patch_yaml = std::fs::read_to_string(patch_path).map_err(|e| {
                CatError::Config(format!(
                    "failed to read YAML merge patch `{}`: {e}",
                    patch_path.display()
                ))
            })?;
            final_value = apply_yaml_merge_patch(&final_value, &patch_yaml)?;
            applied_override_patch = true;
        }
    }
    if let Some(inline_yaml) = cfg
        .rules_override
        .inline_override_yaml
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        cfg.rules_override
            .validate_inline_override_yaml()
            .map_err(CatError::Validation)?;
        final_value = apply_yaml_merge_patch(&final_value, inline_yaml).map_err(|e| {
            CatError::Validation(format!(
                "内联 YAML 覆写片段应用失败（基础配置未被破坏）：{e}"
            ))
        })?;
        applied_override_patch = true;
    }

    // Re-prepend mandatory anti-loop, isolated probe core bypass, and private LAN/DNS safety rules
    // at the top of final `rules` so RFC 7396 sequence replacement can never wipe the safety base.
    if applied_override_patch {
        enforce_mandatory_safety_rules_at_top(&mut final_value, &mandatory_safety_rules);
    }

    // Re-scan final `proxies[].dialer-proxy` and `proxy-providers.*.override.dialer-proxy` after
    // merge patches/inline overrides and re-clamp `tun.mtu <= 1400` whenever TUN is enabled and
    // any dialer-proxy exists (including when an override deleted `tun.mtu` via `mtu: null`).
    let (final_dialer_wrapped_proxies, final_effective_tun_mtu) =
        reconcile_post_override_dialer_and_tun_mtu(&mut final_value, effective_tun_mtu);
    dialer_wrapped_proxies = final_dialer_wrapped_proxies;

    let yaml = serde_yaml_ng::to_string(&final_value)?;
    let validation = validate_compiled_yaml(&yaml, &relay_servers_for_validation)?;

    let total_proxies = final_value
        .get("proxies")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);
    let total_groups = final_value
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);
    let total_rules = final_value
        .get("rules")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);

    let stats = CompileStats {
        total_proxies,
        relay_proxies: relay_names_ordered.len(),
        dialer_wrapped_proxies,
        skipped_443_native_proxies,
        skipped_ipv6_proxies,
        proxy_groups: total_groups,
        total_rules,
        preaccel_active,
        effective_tun_mtu: final_effective_tun_mtu,
    };

    let sha256 = sha256_hex(yaml.as_bytes());

    Ok(CompiledCoreConfig {
        yaml,
        value: final_value,
        group_mappings,
        active_selections,
        node_id_to_proxy_name: node_id_to_name,
        stats,
        validation,
        sha256,
    })
}

/// Redact sensitive credential fields, controller secrets, and upstream/relay IP or domain
/// endpoints from compiled Mihomo YAML for safe UI/diagnostics preview by delegating to the
/// unified [`crate::sanitize::redact_compiled_yaml`] pipeline.
pub fn redact_compiled_yaml_for_preview(
    compiled: &CompiledCoreConfig,
    _relays: &[PreAccelRelay],
) -> CatResult<String> {
    let source_yaml = if compiled.yaml.trim().is_empty() {
        serde_yaml_ng::to_string(&compiled.value)?
    } else {
        compiled.yaml.clone()
    };
    Ok(crate::sanitize::redact_compiled_yaml(&source_yaml))
}

fn reconcile_post_override_dialer_and_tun_mtu(
    final_value: &mut Value,
    fallback_tun_mtu: u16,
) -> (usize, u16) {
    let Some(root_map) = final_value.as_mapping_mut() else {
        return (0, fallback_tun_mtu);
    };

    let proxy_dialers = root_map
        .get("proxies")
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter(|item| {
                    item.as_mapping()
                        .and_then(|m| m.get("dialer-proxy"))
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.trim().is_empty())
                })
                .count()
        })
        .unwrap_or(0);

    let provider_dialers = root_map
        .get("proxy-providers")
        .and_then(Value::as_mapping)
        .map(|providers| {
            providers
                .values()
                .filter(|prov| {
                    prov.as_mapping()
                        .and_then(|m| m.get("override"))
                        .and_then(Value::as_mapping)
                        .and_then(|ov| ov.get("dialer-proxy"))
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.trim().is_empty())
                })
                .count()
        })
        .unwrap_or(0);

    let total_dialers = proxy_dialers.saturating_add(provider_dialers);

    let mut effective_mtu = fallback_tun_mtu;
    if let Some(tun_map) = root_map.get_mut("tun").and_then(Value::as_mapping_mut) {
        let tun_enabled = tun_map
            .get("enable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let parsed_mtu = tun_map
            .get("mtu")
            .and_then(Value::as_u64)
            .filter(|&v| v > 0)
            .and_then(|v| u16::try_from(v).ok());

        if total_dialers > 0 && tun_enabled {
            match parsed_mtu {
                Some(mtu) if mtu <= 1400 => {
                    effective_mtu = mtu;
                }
                _ => {
                    insert_u64(tun_map, "mtu", 1400);
                    effective_mtu = 1400;
                }
            }
        } else if let Some(mtu) = parsed_mtu {
            effective_mtu = mtu;
        }
    }

    (total_dialers, effective_mtu)
}
