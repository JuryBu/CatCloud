//! Node/group compilation selection, chained `dialer-proxy` expansion, dangling dialer
//! pruning, Sniffer/DNS/TUN builders, and proxy YAML mapping helpers.

use super::types::{
    CompileInput, PREACCEL_SELECT_GROUP_NAME, insert_bool, insert_str, insert_u64, push_unique,
    str_val, string_seq,
};
use super::rules::{expand_group_match_rule, extract_mihomo_rule_target};
use crate::core_adapter::format_host_port;
use crate::core_adapter::port_guard::AllocatedPorts;
use crate::error::{CatError, CatResult};
use crate::models::{
    AppConfig, MultiGroup, MultiGroupMode, PreAccelRelay, ProxyMode, ProxyNode, RouteTargetMode,
};
use serde_yaml_ng::{Mapping, Number, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use url::Url;

/// Strip dangling, empty, or self-referencing `dialer-proxy` entries from `compiled_proxies`
/// unless their target exists in `compiled_proxies` or `proxy_groups`. Returns the count of
/// removed `PREACCEL_SELECT_GROUP_NAME` references so callers can keep stats accurate.
pub(super) fn strip_dangling_dialer_proxies(
    compiled_proxies: &mut [Value],
    proxy_groups: &[Value],
) -> usize {
    let mut valid_dialer_targets: HashSet<String> =
        HashSet::with_capacity(compiled_proxies.len() + proxy_groups.len());
    for proxy_val in compiled_proxies.iter() {
        if let Some(name) = proxy_val
            .as_mapping()
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
        {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                valid_dialer_targets.insert(trimmed.to_string());
            }
        }
    }
    for group_val in proxy_groups {
        if let Some(name) = group_val
            .as_mapping()
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
        {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                valid_dialer_targets.insert(trimmed.to_string());
            }
        }
    }

    let mut removed_preaccel = 0usize;
    for proxy_val in compiled_proxies.iter_mut() {
        if let Some(map) = proxy_val.as_mapping_mut() {
            if !map.contains_key("dialer-proxy") {
                continue;
            }
            let self_name = map
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(ToString::to_string);
            let keep = map
                .get("dialer-proxy")
                .and_then(Value::as_str)
                .map(str::trim)
                .is_some_and(|target| {
                    !target.is_empty()
                        && self_name.as_deref() != Some(target)
                        && valid_dialer_targets.contains(target)
                });
            if !keep {
                let is_preaccel = map
                    .get("dialer-proxy")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    == Some(PREACCEL_SELECT_GROUP_NAME);
                map.shift_remove("dialer-proxy");
                if is_preaccel {
                    removed_preaccel += 1;
                }
            }
        }
    }
    removed_preaccel
}

/// Select enabled business nodes (and optional active group-ID subset) for compilation.
///
/// When `!compile_all_nodes`, `proxy_mode != ProxyMode::Global`, and `input.nodes.len() > 32`,
/// trims compiled proxies and `fake-ip-filter` entries down to nodes referenced by:
/// - `RouteTargetMode::Single`: `active_single_node_id` (if enabled), plus any user multi-groups
///   (and their transitive `fallback_pool_id` / members) or nodes referenced by global/extra rules;
/// - `RouteTargetMode::Group` (or Single fallback): the active home group, every
///   `independent_routing == true` group, any user multi-groups/nodes referenced by global/extra
///   rules or emitted group `match_rules`, and any transitive `fallback_pool_id` backup groups,
///   plus any chained `dialer-proxy` node references.
///
/// Safety fallback: if the active referenced set is empty (or an active `ConditionalPool`
/// consumes all enabled nodes dynamically), all enabled nodes and groups are preserved.
pub(super) fn select_nodes_and_groups_for_compile<'a>(
    input: &CompileInput<'a>,
) -> (Vec<&'a ProxyNode>, Option<HashSet<String>>) {
    let cfg = input.config;
    let enabled_nodes: Vec<&'a ProxyNode> = input.nodes.iter().filter(|n| n.enabled).collect();
    let should_prune = !cfg.core_runtime.compile_all_nodes
        && cfg.proxy_mode != ProxyMode::Global
        && input.nodes.len() > 32;
    if !should_prune || enabled_nodes.is_empty() {
        return (enabled_nodes, None);
    }

    let enabled_node_ids: HashSet<&'a str> = enabled_nodes.iter().map(|n| n.id.as_str()).collect();
    let mut enabled_nodes_by_name: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    for &node in &enabled_nodes {
        let trimmed = node.name.trim();
        if !trimmed.is_empty() {
            enabled_nodes_by_name
                .entry(trimmed)
                .or_default()
                .push(node.id.as_str());
        }
    }

    let mut active_node_ids: HashSet<&'a str> = HashSet::new();

    // Index all valid user multi-groups by ID and compiled name, and resolve effective active group.
    let preferred_active_group_id = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut effective_active_group_id: Option<&'a str> = None;
    let mut group_by_id: HashMap<&'a str, &'a MultiGroup> = HashMap::new();
    let mut group_ids_by_name: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    for group in input.groups {
        let g_id = group.id.trim();
        let g_name = if group.name.trim().is_empty() {
            g_id
        } else {
            group.name.trim()
        };
        if g_name.is_empty() {
            continue;
        }
        group_by_id.insert(g_id, group);
        group_ids_by_name.entry(g_name).or_default().push(g_id);
        if preferred_active_group_id == Some(g_id) {
            effective_active_group_id = Some(g_id);
        } else if effective_active_group_id.is_none() {
            effective_active_group_id = Some(g_id);
        }
    }

    // 1. Determine whether direct single-node mode has a valid enabled single node selected.
    let single_mode_node_id: Option<&'a str> = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|single_id| enabled_node_ids.get(single_id).copied())
    } else {
        None
    };

    let mut active_group_ids: HashSet<String> = HashSet::new();
    let mut queue: Vec<&'a str> = Vec::new();

    if let Some(single_id) = single_mode_node_id {
        // Direct single-node mode: always keep the selected single node; unrelated groups are
        // pruned unless referenced by global/extra rules below.
        active_node_ids.insert(single_id);
    } else {
        // Group mode (or Single fallback when active_single_node_id is absent/disabled).
        if let Some(active_gid) = effective_active_group_id {
            queue.push(active_gid);
        }
        for group in input.groups {
            if group.independent_routing {
                let g_id = group.id.trim();
                if !g_id.is_empty() {
                    queue.push(g_id);
                }
            }
        }
    }

    // 2. Regardless of Single or Group mode, scan global/extra rules so AI preset and custom
    //    routing rules targeting any user multi-group (or proxy node) never become dangling.
    let global_rule_iter = input
        .extra_prepend_rules
        .iter()
        .chain(cfg.rules_override.global_prepend_rules.iter())
        .chain(cfg.rules_override.global_append_rules.iter())
        .chain(
            cfg.preaccel
                .campus_direct_domains
                .iter()
                .filter(|entry| entry.contains(',')),
        );
    for raw_rule in global_rule_iter {
        if let Some(target) = extract_mihomo_rule_target(raw_rule) {
            if let Some(gids) = group_ids_by_name.get(target) {
                for &gid in gids {
                    queue.push(gid);
                }
            }
            if let Some(nids) = enabled_nodes_by_name.get(target) {
                for &nid in nids {
                    active_node_ids.insert(nid);
                }
            }
        }
    }

    // Also preserve any proxy groups or nodes referenced by `rules:` inside `inline_override_yaml`
    // so >32 node pruning never strips targets referenced by inline overrides.
    if let Some(inline_yaml) = cfg
        .rules_override
        .inline_override_yaml
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(mut parsed) = serde_yaml_ng::from_str::<Value>(inline_yaml) {
            let _ = parsed.apply_merge();
            if let Some(rules_seq) = parsed
                .as_mapping()
                .and_then(|m| m.get("rules"))
                .and_then(Value::as_sequence)
            {
                for item in rules_seq {
                    if let Some(raw_rule) = item.as_str() {
                        if let Some(target) = extract_mihomo_rule_target(raw_rule) {
                            if let Some(gids) = group_ids_by_name.get(target) {
                                for &gid in gids {
                                    queue.push(gid);
                                }
                            }
                            if let Some(nids) = enabled_nodes_by_name.get(target) {
                                for &nid in nids {
                                    active_node_ids.insert(nid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Transitively expand active groups via `fallback_pool_id` and emitted `match_rules`.
    while let Some(gid) = queue.pop() {
        if !active_group_ids.insert(gid.to_string()) {
            continue;
        }
        if let Some(group) = group_by_id.get(gid) {
            if let Some(fb_id) = group
                .fallback_pool_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if !active_group_ids.contains(fb_id) {
                    queue.push(fb_id);
                }
            }
            if single_mode_node_id.is_none()
                && !cfg.rules_override.custom_rules_only
                && (effective_active_group_id == Some(gid) || group.independent_routing)
            {
                let g_name = if group.name.trim().is_empty() {
                    gid
                } else {
                    group.name.trim()
                };
                for raw_rule in &group.match_rules {
                    for expanded in expand_group_match_rule(raw_rule, g_name) {
                        if let Some(target) = extract_mihomo_rule_target(&expanded) {
                            if let Some(target_gids) = group_ids_by_name.get(target) {
                                for &target_gid in target_gids {
                                    if !active_group_ids.contains(target_gid) {
                                        queue.push(target_gid);
                                    }
                                }
                            }
                            if let Some(nids) = enabled_nodes_by_name.get(target) {
                                for &nid in nids {
                                    active_node_ids.insert(nid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut need_all_enabled = false;
    for group in input.groups {
        let g_id = group.id.trim();
        if !active_group_ids.contains(g_id) {
            continue;
        }
        let group_name = if group.name.trim().is_empty() {
            g_id
        } else {
            group.name.trim()
        };
        let explicit_filtered = input
            .group_filtered_members
            .get(&group.id)
            .or_else(|| input.group_filtered_members.get(group_name));
        if let Some(filtered_ids) = explicit_filtered {
            for nid in filtered_ids {
                if let Some(&id_ref) = enabled_node_ids.get(nid.as_str()) {
                    active_node_ids.insert(id_ref);
                }
            }
        } else if !group.member_node_ids.is_empty() {
            for nid in &group.member_node_ids {
                if let Some(&id_ref) = enabled_node_ids.get(nid.as_str()) {
                    active_node_ids.insert(id_ref);
                }
            }
        } else if group.mode == MultiGroupMode::ConditionalPool {
            need_all_enabled = true;
            break;
        }
    }

    if need_all_enabled || active_node_ids.is_empty() {
        return (enabled_nodes, None);
    }

    expand_chained_dialer_nodes(&enabled_nodes, &mut active_node_ids);
    let selected: Vec<&'a ProxyNode> = enabled_nodes
        .into_iter()
        .filter(|n| active_node_ids.contains(n.id.as_str()))
        .collect();
    if selected.is_empty() {
        let all_enabled: Vec<&'a ProxyNode> = input.nodes.iter().filter(|n| n.enabled).collect();
        return (all_enabled, None);
    }
    (selected, Some(active_group_ids))
}

fn expand_chained_dialer_nodes<'a>(
    enabled_nodes: &[&'a ProxyNode],
    active_node_ids: &mut HashSet<&'a str>,
) {
    let mut by_name: HashMap<&str, Vec<&'a ProxyNode>> = HashMap::new();
    for &node in enabled_nodes {
        let trimmed = node.name.trim();
        if !trimmed.is_empty() {
            by_name.entry(trimmed).or_default().push(node);
        }
    }
    loop {
        let mut added = false;
        let snapshot: Vec<&'a str> = active_node_ids.iter().copied().collect();
        for &node in enabled_nodes {
            if !snapshot.contains(&node.id.as_str()) {
                continue;
            }
            let Some(dp) = node
                .raw_config
                .get("dialer-proxy")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != PREACCEL_SELECT_GROUP_NAME)
            else {
                continue;
            };
            if let Some(targets) = by_name.get(dp) {
                for target in targets {
                    if active_node_ids.insert(target.id.as_str()) {
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
}

pub(super) fn build_sniffer_section(
    block_quic_udp_443: bool,
    domestic_direct_enabled: bool,
    has_geoip: bool,
) -> Mapping {
    let mut map = Mapping::new();
    insert_bool(&mut map, "enable", true);
    insert_bool(&mut map, "force-dns-mapping", true);
    insert_bool(&mut map, "parse-pure-ip", true);
    insert_bool(&mut map, "override-destination", false);

    let mut sniff = Mapping::new();

    let mut http = Mapping::new();
    http.insert(
        str_val("ports"),
        Value::Sequence(vec![
            Value::Number(Number::from(80u64)),
            str_val("8080-8880"),
        ]),
    );
    insert_bool(&mut http, "override-destination", true);
    sniff.insert(str_val("HTTP"), Value::Mapping(http));

    let mut tls = Mapping::new();
    tls.insert(
        str_val("ports"),
        Value::Sequence(vec![
            Value::Number(Number::from(443u64)),
            Value::Number(Number::from(8443u64)),
        ]),
    );
    sniff.insert(str_val("TLS"), Value::Mapping(tls));

    // When `block_quic_udp_443` and `domestic_direct_enabled` are both active while GeoIP
    // (`Country.mmdb` / `geoip.dat`) is absent, keep QUIC sniffing enabled so Mihomo can extract
    // the SNI from QUIC ClientHello on real-IP (`fake-ip-filter`) packets and match domestic IM
    // `DOMAIN-SUFFIX` DIRECT rules (e.g. QQ/WeChat) before falling through to UDP/443 REJECT.
    if !block_quic_udp_443 || (domestic_direct_enabled && !has_geoip) {
        let mut quic = Mapping::new();
        quic.insert(
            str_val("ports"),
            Value::Sequence(vec![
                Value::Number(Number::from(443u64)),
                Value::Number(Number::from(8443u64)),
            ]),
        );
        sniff.insert(str_val("QUIC"), Value::Mapping(quic));
    }

    map.insert(str_val("sniff"), Value::Mapping(sniff));
    map.insert(
        str_val("skip-domain"),
        string_seq(["Mijia Cloud", "+.push.apple.com"]),
    );
    map
}

pub(super) fn build_dns_section(
    cfg: &AppConfig,
    allocated_ports: &AllocatedPorts,
    anti_loop_fake_ip_domains: &[String],
    extra_fake_ip_filters: &[String],
    has_geosite: bool,
    has_geoip: bool,
) -> Mapping {
    let dns = &cfg.dns;
    let mut map = Mapping::new();

    let dns_host = if cfg.allow_lan {
        cfg.dns_listen_host.trim()
    } else {
        "127.0.0.1"
    };

    let mut effective_default_ns: Vec<String> = dns
        .default_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_default_ns.is_empty() {
        effective_default_ns = crate::config::DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }

    let mut effective_direct_ns: Vec<String> = dns
        .direct_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_direct_ns.is_empty() {
        effective_direct_ns = crate::config::DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }

    let mut effective_proxy_server_ns: Vec<String> = dns
        .proxy_server_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if dns.respect_rules && effective_proxy_server_ns.is_empty() {
        let cleaned_default_ns: Vec<String> = dns
            .default_nameserver
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if !cleaned_default_ns.is_empty()
            && !crate::config::is_legacy_plaintext_domestic_dns_list(&cleaned_default_ns)
        {
            effective_proxy_server_ns = cleaned_default_ns;
        } else {
            effective_proxy_server_ns = crate::config::DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }
    }

    if dns.respect_rules {
        for entry in &mut effective_direct_ns {
            if !entry.contains('#') && !entry.eq_ignore_ascii_case("system") {
                entry.push_str("#DIRECT");
            }
        }
    }

    let effective_nameserver: Vec<String> = dns
        .nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if dns.respect_rules
                && !entry.contains('#')
                && is_domestic_default_nameserver(entry)
            {
                format!("{entry}#DIRECT")
            } else {
                entry.to_string()
            }
        })
        .collect();

    let mut effective_fallback: Vec<String> = dns
        .fallback
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_fallback.is_empty() {
        effective_fallback = vec![
            "https://1.1.1.1/dns-query".to_string(),
            "https://8.8.8.8/dns-query".to_string(),
        ];
    }

    insert_bool(&mut map, "enable", dns.enable);
    insert_str(
        &mut map,
        "listen",
        &format_host_port(dns_host, allocated_ports.dns_port),
    );
    insert_bool(&mut map, "ipv6", dns.ipv6);
    insert_bool(&mut map, "use-hosts", dns.use_hosts);
    insert_bool(&mut map, "use-system-hosts", dns.use_system_hosts);
    insert_bool(&mut map, "respect-rules", dns.respect_rules);
    insert_bool(&mut map, "prefer-h3", dns.prefer_h3);
    insert_str(&mut map, "enhanced-mode", dns.mode.as_str());
    insert_str(&mut map, "fake-ip-range", &dns.fake_ip_range);

    let mut merged_fake_ip_filter: Vec<String> = Vec::new();
    for item in &dns.fake_ip_filter {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !has_geosite && trimmed.to_ascii_lowercase().starts_with("geosite:") {
            continue;
        }
        push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
    }
    if has_geosite {
        push_unique(&mut merged_fake_ip_filter, "geosite:cn".to_string());
        push_unique(&mut merged_fake_ip_filter, "geosite:private".to_string());
    }
    const DOMESTIC_DNS_FAKE_IP_FILTERS: &[&str] =
        &["dns.alidns.com", "doh.pub", "dot.pub", "dns.pub"];
    for item in DOMESTIC_DNS_FAKE_IP_FILTERS {
        push_unique(&mut merged_fake_ip_filter, (*item).to_string());
    }
    const DOMESTIC_IM_FAKE_IP_FILTERS: &[&str] = &[
        "+.qq.com",
        "+.qpic.cn",
        "+.qlogo.cn",
        "+.gtimg.cn",
        "+.gtimg.com",
        "+.nt.qq.com.cn",
        "+.weixin.qq.com",
        "+.wechat.com",
        "+.wechatpay.com",
        "+.tenpay.com",
        "+.tencent.com",
        "+.qcloud.com",
        "+.myqcloud.com",
        "+.qcloudimg.com",
        "+.tencentcs.com",
        "+.tencent-cloud.net",
    ];
    for item in DOMESTIC_IM_FAKE_IP_FILTERS {
        push_unique(&mut merged_fake_ip_filter, (*item).to_string());
    }
    const SYSTEM_CERT_FAKE_IP_FILTERS: &[&str] = &["ctldl.windowsupdate.com"];
    for item in SYSTEM_CERT_FAKE_IP_FILTERS {
        push_unique(&mut merged_fake_ip_filter, (*item).to_string());
    }
    for item in anti_loop_fake_ip_domains {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
        }
    }
    for item in extra_fake_ip_filters {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
        }
    }
    map.insert(
        str_val("fake-ip-filter"),
        string_seq(merged_fake_ip_filter.iter().map(String::as_str)),
    );

    map.insert(
        str_val("default-nameserver"),
        string_seq(effective_default_ns.iter().map(String::as_str)),
    );
    map.insert(
        str_val("direct-nameserver"),
        string_seq(effective_direct_ns.iter().map(String::as_str)),
    );

    // Build nameserver-policy: user-configured patterns take precedence, then auto-route
    // sensitive AI / Google / GitHub / X domains through overseas DoH (`fallback`) to prevent
    // domestic DNS leakage/pollution, route campus/LAN intranet suffixes via `system` first
    // (preserving campus DHCP DNS without polluting public DoH 443 or causing TUN loops),
    // plus `geosite:cn,private -> direct-nameserver` when geosite exists.
    let mut policy_map = Mapping::new();
    let mut configured_policy_keys: HashSet<String> = HashSet::new();
    for (pattern, servers) in &dns.nameserver_policy {
        let pat_trimmed = pattern.trim();
        if pat_trimmed.is_empty() {
            continue;
        }
        if !has_geosite && pat_trimmed.to_ascii_lowercase().contains("geosite:") {
            continue;
        }
        policy_map.insert(
            str_val(pat_trimmed),
            string_seq(servers.iter().map(String::as_str)),
        );
        configured_policy_keys.insert(pat_trimmed.to_ascii_lowercase());
    }

    const AI_DNS_POLICY_DOMAINS: &[&str] = &[
        "+.anthropic.com",
        "+.claude.ai",
        "+.claude.com",
        "+.openai.com",
        "api.openai.com",
        "ios.chat.openai.com",
        "+.chatgpt.com",
        "ab.chatgpt.com",
        "+.google.com",
        "+.googleapis.com",
        "+.gstatic.com",
        "+.googleusercontent.com",
        "+.antigravity.google",
        "+.windsurf.com",
        "+.codeium.com",
        "+.codeiumdata.com",
        "+.devin.ai",
        "+.cognition.ai",
        "+.exafunction.com",
        "+.github.com",
        "+.x.com",
        "+.twitter.com",
        "+.twimg.com",
        "+.t.co",
    ];
    if !cfg.rules_override.custom_rules_only {
        for &domain in AI_DNS_POLICY_DOMAINS {
            let key_lower = domain.to_ascii_lowercase();
            if !configured_policy_keys.contains(&key_lower) {
                policy_map.insert(
                    str_val(domain),
                    string_seq(effective_fallback.iter().map(String::as_str)),
                );
                configured_policy_keys.insert(key_lower);
            }
        }
    }

    // Intentionally omit port-853 DoT here so campus firewalls dropping TCP 853 never stall
    // intranet DNS resolution; keep `system` first followed by dual pure-IP 443 DoH fallbacks.
    let campus_policy_servers: [&str; 3] = if dns.respect_rules {
        [
            "system",
            "https://223.5.5.5/dns-query#DIRECT",
            "https://1.12.12.12/dns-query#DIRECT",
        ]
    } else {
        [
            "system",
            "https://223.5.5.5/dns-query",
            "https://1.12.12.12/dns-query",
        ]
    };
    const CAMPUS_INTRANET_DNS_POLICY_DOMAINS: &[&str] = &[
        "+.edu.cn",
        "+.lan",
        "+.local",
        "+.localdomain",
        "+.internal",
        "+.home.arpa",
    ];
    for &domain in CAMPUS_INTRANET_DNS_POLICY_DOMAINS {
        let key_lower = domain.to_ascii_lowercase();
        if !configured_policy_keys.contains(&key_lower) {
            policy_map.insert(
                str_val(domain),
                string_seq(campus_policy_servers.iter().copied()),
            );
            configured_policy_keys.insert(key_lower);
        }
    }
    for raw_domain in &cfg.preaccel.campus_direct_domains {
        if let Some(domain) = normalize_campus_policy_domain(raw_domain) {
            let key_lower = domain.to_ascii_lowercase();
            if !configured_policy_keys.contains(&key_lower) {
                policy_map.insert(
                    str_val(&domain),
                    string_seq(campus_policy_servers.iter().copied()),
                );
                configured_policy_keys.insert(key_lower);
            }
        }
    }

    if has_geosite && !configured_policy_keys.contains("geosite:cn,private") {
        policy_map.insert(
            str_val("geosite:cn,private"),
            string_seq(effective_direct_ns.iter().map(String::as_str)),
        );
    }
    map.insert(str_val("nameserver-policy"), Value::Mapping(policy_map));

    map.insert(
        str_val("nameserver"),
        string_seq(effective_nameserver.iter().map(String::as_str)),
    );
    map.insert(
        str_val("fallback"),
        string_seq(effective_fallback.iter().map(String::as_str)),
    );
    map.insert(
        str_val("proxy-server-nameserver"),
        string_seq(effective_proxy_server_ns.iter().map(String::as_str)),
    );

    let mut ff_map = Mapping::new();
    insert_bool(&mut ff_map, "geoip", dns.fallback_filter.geoip && has_geoip);
    insert_str(&mut ff_map, "geoip-code", &dns.fallback_filter.geoip_code);
    // `fallback-filter.geosite` is deprecated in Mihomo and triggers a warning on every start/reload;
    // geosite DNS routing is already handled by `nameserver-policy` above.
    ff_map.insert(
        str_val("ipcidr"),
        string_seq(dns.fallback_filter.ipcidr.iter().map(String::as_str)),
    );
    ff_map.insert(
        str_val("domain"),
        string_seq(dns.fallback_filter.domain.iter().map(String::as_str)),
    );
    map.insert(str_val("fallback-filter"), Value::Mapping(ff_map));

    map
}

fn normalize_campus_policy_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Campus direct entries may be Mihomo rule lines such as `DOMAIN-SUFFIX,campus.edu,DIRECT`
    // or `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve`. Only extract domain payload from DOMAIN /
    // DOMAIN-SUFFIX rules; reject all other comma-bearing rules so Mihomo never splits them
    // into stray `nameserver-policy` keys.
    let candidate = if trimmed.contains(',') {
        let mut parts = trimmed.split(',').map(str::trim);
        let rule_type = parts.next().unwrap_or_default();
        let payload = parts.next().unwrap_or_default();
        if rule_type.eq_ignore_ascii_case("DOMAIN") {
            payload
        } else if rule_type.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            return normalize_campus_policy_domain(&format!("+.{payload}"));
        } else {
            return None;
        }
    } else {
        trimmed
    };
    if candidate.is_empty()
        || candidate.contains(',')
        || candidate.contains("://")
        || candidate.contains('/')
        || candidate.contains(':')
        || candidate.chars().any(char::is_whitespace)
        || crate::preaccel::parse_server_ip(candidate).is_some()
    {
        return None;
    }
    let normalized = candidate.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(suffix) = normalized
        .strip_prefix("*.")
        .or_else(|| normalized.strip_prefix("+."))
    {
        let clean = suffix.trim_start_matches('.');
        if clean.is_empty() || clean.starts_with("geosite:") {
            return None;
        }
        return Some(format!("+.{clean}"));
    }
    if normalized.starts_with("geosite:") {
        return None;
    }
    Some(normalized)
}

fn is_domestic_default_nameserver(entry: &str) -> bool {
    let raw = entry.split('#').next().unwrap_or(entry).trim();
    if raw.is_empty() {
        return false;
    }
    let host = if raw.contains("://") {
        match Url::parse(raw) {
            Ok(u) => u
                .host_str()
                .map(|h| {
                    h.trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_ascii_lowercase()
                })
                .unwrap_or_default(),
            Err(_) => return false,
        }
    } else if let Ok(ip) = raw.parse::<IpAddr>() {
        ip.to_string()
    } else if let Ok(sock) = raw.parse::<SocketAddr>() {
        sock.ip().to_string()
    } else {
        raw.split(':').next().unwrap_or("").trim().to_ascii_lowercase()
    };

    matches!(
        host.as_str(),
        "223.5.5.5"
            | "223.6.6.6"
            | "1.12.12.12"
            | "119.29.29.29"
            | "119.28.28.28"
            | "120.53.53.53"
            | "114.114.114.114"
            | "114.114.115.115"
            | "180.76.76.76"
            | "180.184.1.1"
            | "180.184.2.2"
            | "1.2.4.8"
            | "210.2.4.8"
            | "dns.alidns.com"
            | "doh.pub"
            | "dot.pub"
            | "dns.pub"
    )
}

/// Decide whether `tun.device` should be emitted into Mihomo YAML for the given target OS.
///
/// On macOS, kernel utun interfaces strictly require `utun[0-9]*` naming (e.g. `utun9`).
/// Emitting non-utun names such as `"CatCloud"` causes Mihomo to fail loading the config on
/// macOS; omitting `device` lets Mihomo auto-allocate a valid `utun[0-9]*` device.
pub fn should_emit_tun_device_name(target_os: &str, device_name: &str) -> bool {
    let trimmed = device_name.trim();
    if trimmed.is_empty() {
        return false;
    }
    if target_os.eq_ignore_ascii_case("macos") {
        trimmed
            .strip_prefix("utun")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
    } else {
        true
    }
}

pub(super) fn build_tun_section(cfg: &AppConfig, effective_mtu: u16) -> Mapping {
    let tun = &cfg.tun;
    let mut map = Mapping::new();
    insert_bool(&mut map, "enable", tun.enabled);
    insert_str(&mut map, "stack", tun.stack_mode.as_str());
    if should_emit_tun_device_name(std::env::consts::OS, &tun.device_name) {
        insert_str(&mut map, "device", tun.device_name.trim());
    }
    insert_bool(&mut map, "auto-route", tun.auto_route);
    insert_bool(&mut map, "auto-detect-interface", tun.auto_detect_interface);
    insert_bool(&mut map, "strict-route", tun.strict_route);
    insert_bool(&mut map, "endpoint-independent-nat", false);
    insert_u64(&mut map, "mtu", u64::from(effective_mtu));
    map.insert(
        str_val("dns-hijack"),
        string_seq(tun.dns_hijack.iter().map(String::as_str)),
    );
    map
}

pub(super) fn build_relay_proxy_mapping(relay: &PreAccelRelay, unique_name: &str) -> CatResult<Mapping> {
    let value = crate::preaccel::generator::compile_relay_to_mihomo_yaml(relay, unique_name)?;
    match value {
        Value::Mapping(map) => Ok(map),
        _ => Err(CatError::Validation(format!(
            "compiled domestic pre-acceleration relay `{unique_name}` did not produce a YAML mapping"
        ))),
    }
}

/// Normalize transport parameters on TCP-based business proxy mappings to prevent TFO stalls and
/// idle zombie-session drops (`anytls`, `trojan`, `vless`, `vmess`, `ss`, `shadowsocks`, `ssr`).
///
/// Strictly whitelisted to TCP protocols so UDP-based transports (`hysteria2`, `hy2`, `tuic`,
/// `wireguard`, etc.) are never mutated.
pub fn sanitize_business_node_transport(map: &mut Mapping, fallback_protocol: &str) {
    let proto = map
        .get("type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_protocol.trim())
        .to_ascii_lowercase();

    if !matches!(
        proto.as_str(),
        "anytls" | "trojan" | "vless" | "vmess" | "ss" | "shadowsocks" | "ssr"
    ) {
        return;
    }

    insert_bool(map, "tfo", false);

    if proto == "anytls" {
        insert_u64(map, "min-idle-session", 0);
        let has_valid_check = map
            .get("idle-session-check-interval")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0);
        if !has_valid_check {
            insert_u64(map, "idle-session-check-interval", 30);
        }
        let has_valid_timeout = map
            .get("idle-session-timeout")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0);
        if !has_valid_timeout {
            insert_u64(map, "idle-session-timeout", 30);
        }
    }
}

pub fn build_node_proxy_mapping(node: &ProxyNode, unique_name: &str) -> CatResult<Mapping> {
    let mut map = match serde_yaml_ng::to_value(&node.raw_config)? {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    };

    insert_str(&mut map, "name", unique_name);
    if !map.contains_key("type") && !node.protocol.trim().is_empty() {
        insert_str(&mut map, "type", &node.protocol.trim().to_ascii_lowercase());
    }
    if !map.contains_key("server") && !node.server.trim().is_empty() {
        insert_str(&mut map, "server", node.server.trim());
    }
    if !map.contains_key("port") && node.port > 0 {
        insert_u64(&mut map, "port", u64::from(node.port));
    }

    sanitize_business_node_transport(&mut map, &node.protocol);

    Ok(map)
}
