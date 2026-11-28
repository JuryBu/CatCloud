//! Soft-router / transparent-gateway YAML exporter covering relay fragments, full
//! transparent gateways, and preferred-node exports.

use super::types::{
    CompileInput, GatewayExportOptions, GatewayExportOutput, GatewayExportProfile,
    PREACCEL_FALLBACK_GROUP_NAME, PREACCEL_LB_GROUP_NAME, PREACCEL_SELECT_GROUP_NAME, insert_bool,
    insert_str, insert_u64, make_unique_name, push_unique, str_val, string_seq,
};
use super::rules::resolve_default_fallback_group_name;
use super::proxies_net::{build_node_proxy_mapping, strip_dangling_dialer_proxies};
use super::validation::{format_static_validation_summary_zh, validate_compiled_yaml};
use super::compiler::compile_mihomo_config_with_runtime_dir;
use super::gateway_redact::redact_gateway_yaml;
use crate::core_adapter::format_host_port;
use crate::core_adapter::port_guard::AllocatedPorts;
use crate::error::{CatError, CatResult};
use crate::models::{
    AppConfig, MultiGroup, MultiGroupState, PreAccelRelay, ProxyNode, is_info_proxy_node,
    is_ipv6_only_node,
};
use crate::preaccel::generator::{build_preaccel_compile_plan, host_to_fake_ip_filter};
use serde_yaml_ng::{Mapping, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Export standardized Mihomo YAML for OpenWrt / Linux transparent gateways, soft-routers,
/// or custom-rule Mihomo deployments.
pub fn export_gateway_yaml(
    cfg: &AppConfig,
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
    runtime_dir: Option<&Path>,
    opts: &GatewayExportOptions,
) -> CatResult<GatewayExportOutput> {
    match opts.profile {
        GatewayExportProfile::RelayFragment => {
            export_gateway_relay_fragment(cfg, relays, opts)
        }
        GatewayExportProfile::TransparentGateway => {
            export_gateway_transparent_full(cfg, nodes, groups, relays, runtime_dir, opts)
        }
        GatewayExportProfile::PreferredNodes => {
            export_gateway_preferred_nodes(cfg, nodes, groups, relays, opts)
        }
    }
}

fn export_gateway_relay_fragment(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    opts: &GatewayExportOptions,
) -> CatResult<GatewayExportOutput> {
    let mut relay_cfg = cfg.preaccel.clone();
    relay_cfg.enabled = true;

    let plan = build_preaccel_compile_plan(&relay_cfg, relays, &[])?;
    let mut warnings = plan.warnings.clone();
    if !cfg.preaccel.enabled && plan.active && !plan.relay_proxies.is_empty() {
        warnings.push(
            "当前桌面国内提速总开关关闭，已按已启用中转池配置一并导出中转片段（合并后即可使用）。"
                .to_string(),
        );
    }
    let mut doc = Mapping::new();

    if !plan.active || plan.relay_proxies.is_empty() {
        warnings.clear();
        warnings.push(
            "当前尚未启用任何国内 443 提速中转，已导出标准空框架模板；请先在「国内提速」添加并启用至少一条中转后重新导出。"
                .to_string(),
        );
        doc.insert(str_val("proxies"), Value::Sequence(Vec::new()));
        doc.insert(str_val("proxy-groups"), Value::Sequence(Vec::new()));
        doc.insert(str_val("rules"), Value::Sequence(Vec::new()));
        let mut dns_map = Mapping::new();
        dns_map.insert(str_val("fake-ip-filter"), Value::Sequence(Vec::new()));
        doc.insert(str_val("dns"), Value::Mapping(dns_map));
    } else {
        doc.insert(str_val("proxies"), Value::Sequence(plan.relay_proxies.clone()));
        doc.insert(
            str_val("proxy-groups"),
            Value::Sequence(plan.proxy_groups.clone()),
        );
        doc.insert(
            str_val("rules"),
            string_seq(plan.anti_loop_rules.iter().map(String::as_str)),
        );
        let mut dns_map = Mapping::new();
        dns_map.insert(
            str_val("fake-ip-filter"),
            string_seq(plan.fake_ip_filter.iter().map(String::as_str)),
        );
        doc.insert(str_val("dns"), Value::Mapping(dns_map));
    }

    let doc_value = Value::Mapping(doc);
    let body_yaml = serde_yaml_ng::to_string(&doc_value)?;
    if plan.active && !plan.relay_proxies.is_empty() {
        let relay_servers_for_validation: Vec<String> = relays
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.server.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let validation = validate_compiled_yaml(&body_yaml, &relay_servers_for_validation)?;
        let hard_errors = validation.errors();
        if !hard_errors.is_empty() {
            let summary = format_static_validation_summary_zh(&validation, None);
            return Err(CatError::Validation(format!(
                "国内提速片段静态防环校验未通过，已阻止导出坏配置：{summary}"
            )));
        }
        for issue in validation.warnings() {
            if issue.code != "missing_match_rule" {
                warnings.push(issue.message.clone());
            }
        }
    }
    let header = format!(
        concat!(
            "# ============================================================================\n",
            "# CatCloud 国内 443 提速标准 Mihomo 片段（Relay Fragment）\n",
            "# 适用场景：OpenWrt / OpenClash / ShellCrash / Linux 透明网关 / 自写规则配置合并\n",
            "# 已内置抗断流调优：tfo: false、min-idle-session: 0、国内 204 探针与多云 consistent-hashing 双活\n",
            "#\n",
            "# 接入方法：\n",
            "# 1. 将下方 proxies 与 proxy-groups 合并进你现有的 Mihomo 配置；\n",
            "# 2. 将下方 rules 置顶插入规则链最前面（防回环），并将 dns.fake-ip-filter 合并进 dns 节；\n",
            "# 3. 在需要走国内 443 提速的非 443 海外节点下新增一行即可生效：\n",
            "#    dialer-proxy: {entry}\n",
            "# ============================================================================\n"
        ),
        entry = PREACCEL_SELECT_GROUP_NAME
    );
    let raw_yaml = format!("{header}{body_yaml}");
    let yaml = if opts.redact_secrets {
        redact_gateway_yaml(&header, doc_value, &[], relays)?
    } else {
        raw_yaml
    };

    let integration_hint = format!(
        "将 proxies / proxy-groups 合并至旁路由 Mihomo 配置，置顶防环 rules 与 dns.fake-ip-filter，并在目标非 443 节点下添加 `dialer-proxy: {PREACCEL_SELECT_GROUP_NAME}`。"
    );

    Ok(GatewayExportOutput {
        profile: GatewayExportProfile::RelayFragment,
        yaml,
        redacted: opts.redact_secrets,
        relay_count: plan.relay_proxies.len(),
        node_count: 0,
        rule_count: plan.anti_loop_rules.len(),
        warnings,
        integration_hint,
    })
}

fn export_gateway_transparent_full(
    cfg: &AppConfig,
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
    _runtime_dir: Option<&Path>,
    opts: &GatewayExportOptions,
) -> CatResult<GatewayExportOutput> {
    if opts.tproxy_port == 0 || opts.redir_port == 0 || opts.dns_listen_port == 0 {
        return Err(CatError::Validation(
            "透明网关导出端口配置无效：tproxy_port、redir_port 与 dns_listen_port 均必须在 1..=65535 之间"
                .to_string(),
        ));
    }
    if opts.tproxy_port == opts.redir_port
        || opts.tproxy_port == opts.dns_listen_port
        || opts.redir_port == opts.dns_listen_port
    {
        return Err(CatError::Validation(format!(
            "透明网关导出端口冲突：tproxy_port({})、redir_port({}) 与 dns_listen_port({}) 必须互不相同",
            opts.tproxy_port, opts.redir_port, opts.dns_listen_port
        )));
    }

    let mut gw_cfg = cfg.clone();
    let mut warnings: Vec<String> = Vec::new();
    if !gw_cfg.preaccel.enabled && relays.iter().any(|r| r.enabled) {
        warnings.push(
            "当前桌面国内提速总开关未开启，本次导出的完整透明网关配置未附带国内 443 中转；如需在软路由启用，请先开启国内提速开关后重新导出。"
                .to_string(),
        );
    }
    let mut reserved_ports: HashSet<u16> =
        [opts.tproxy_port, opts.redir_port, opts.dns_listen_port]
            .into_iter()
            .collect();

    gw_cfg.allow_lan = true;
    gw_cfg.bind_address = "*".to_string();
    gw_cfg.tproxy_port = Some(opts.tproxy_port);
    gw_cfg.redir_port = Some(opts.redir_port);
    gw_cfg.tun.enabled = false;
    gw_cfg.dns_listen_host = "0.0.0.0".to_string();
    gw_cfg.dns_listen_port = opts.dns_listen_port;
    // Decouple exported transparent-gateway configs from desktop GeoData files & auto-update so
    // offline or low-flash soft-routers never fail attempting to load or download `.dat` assets.
    gw_cfg.geodata.geodata_mode = false;
    gw_cfg.geodata.auto_update = false;
    // Always export all enabled nodes & groups for soft-router/gateway deployments so >32 node
    // pruning in desktop Single mode never strips router proxy pools.
    gw_cfg.core_runtime.compile_all_nodes = true;
    if gw_cfg.controller_host.trim().is_empty() {
        gw_cfg.controller_host = "127.0.0.1".to_string();
    }

    if gw_cfg.mixed_port == 0 || reserved_ports.contains(&gw_cfg.mixed_port) {
        let old = gw_cfg.mixed_port;
        let shifted = pick_non_colliding_gateway_port(&reserved_ports, 7890);
        gw_cfg.mixed_port = shifted;
        warnings.push(format!(
            "导出透明网关配置时，原 mixed-port ({old}) 与透明代理/DNS 端口冲突，已自动顺延至 {shifted}。"
        ));
    }
    reserved_ports.insert(gw_cfg.mixed_port);

    if gw_cfg.controller_port == 0 || reserved_ports.contains(&gw_cfg.controller_port) {
        let old = gw_cfg.controller_port;
        let shifted = pick_non_colliding_gateway_port(&reserved_ports, 9090);
        gw_cfg.controller_port = shifted;
        warnings.push(format!(
            "导出透明网关配置时，原控制口端口 ({old}) 与透明代理/DNS 端口冲突，已自动顺延至 {shifted}。"
        ));
    }
    reserved_ports.insert(gw_cfg.controller_port);

    if let Some(sp) = gw_cfg.socks_port {
        if sp == 0 || reserved_ports.contains(&sp) {
            gw_cfg.socks_port = None;
            warnings.push(format!(
                "导出透明网关配置时，原 socks-port ({sp}) 与透明代理端口冲突，已自动省略。"
            ));
        } else {
            reserved_ports.insert(sp);
        }
    }
    if let Some(hp) = gw_cfg.http_port {
        if hp == 0 || reserved_ports.contains(&hp) {
            gw_cfg.http_port = None;
            warnings.push(format!(
                "导出透明网关配置时，原 http-port ({hp}) 与透明代理端口冲突，已自动省略。"
            ));
        } else {
            reserved_ports.insert(hp);
        }
    }
    if gw_cfg.system_proxy.pac.enabled
        && (gw_cfg.system_proxy.pac.port == 0
            || reserved_ports.contains(&gw_cfg.system_proxy.pac.port))
    {
        gw_cfg.system_proxy.pac.enabled = false;
    }

    let controller_secret = match gw_cfg
        .controller_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => {
            warnings.push(
                "当前未设置控制口密钥，导出配置已填入占位值，部署到路由器前请修改 `secret` 字段。"
                    .to_string(),
            );
            "catcloud-gateway-change-me".to_string()
        }
    };

    let allocated_ports = AllocatedPorts {
        bind_host: "*".to_string(),
        mixed_port: gw_cfg.mixed_port,
        controller_port: gw_cfg.controller_port,
        dns_port: gw_cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filtered: HashMap<String, Vec<String>> = HashMap::new();
    let compile_input = CompileInput {
        config: &gw_cfg,
        nodes,
        groups,
        relays,
        controller_secret: &controller_secret,
        allocated_ports: &allocated_ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filtered,
    };

    // Decouple exported router config from the desktop's local GeoData files (`runtime_dir = None`)
    // so OpenWrt/soft-router instances without `geosite.dat`/`Country.mmdb` never fail to load
    // `GEOSITE,cn`/`GEOIP,CN` and always retain conservative domestic direct fallback rules.
    let mut compiled = compile_mihomo_config_with_runtime_dir(&compile_input, None)?;

    // Post-merge gateway contract lock: prevent `override_merge_path` / `inline_override_yaml`
    // from silently turning desktop TUN back on or hijacking TPROXY/REDIR/DNS/LAN bindings.
    if let Some(root_map) = compiled.value.as_mapping_mut() {
        insert_bool(root_map, "allow-lan", true);
        insert_str(root_map, "bind-address", "*");
        insert_u64(root_map, "tproxy-port", u64::from(opts.tproxy_port));
        insert_u64(root_map, "redir-port", u64::from(opts.redir_port));

        let locked_ports = [opts.tproxy_port, opts.redir_port, opts.dns_listen_port];
        if let Some(mixed_p) = root_map
            .get("mixed-port")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
        {
            if locked_ports.contains(&mixed_p) {
                insert_u64(root_map, "mixed-port", u64::from(gw_cfg.mixed_port));
            }
        }

        let tun_entry = root_map
            .entry(str_val("tun"))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if !tun_entry.is_mapping() {
            *tun_entry = Value::Mapping(Mapping::new());
        }
        if let Some(tun_map) = tun_entry.as_mapping_mut() {
            insert_bool(tun_map, "enable", false);
        }

        let dns_entry = root_map
            .entry(str_val("dns"))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if !dns_entry.is_mapping() {
            *dns_entry = Value::Mapping(Mapping::new());
        }
        if let Some(dns_map) = dns_entry.as_mapping_mut() {
            insert_str(
                dns_map,
                "listen",
                &format_host_port("0.0.0.0", opts.dns_listen_port),
            );
        }
    }

    let locked_yaml = serde_yaml_ng::to_string(&compiled.value)?;
    let relay_servers_for_validation: Vec<String> = if gw_cfg.preaccel.enabled {
        relays
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.server.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let final_validation = validate_compiled_yaml(&locked_yaml, &relay_servers_for_validation)?;
    let hard_errors = final_validation.errors();
    if !hard_errors.is_empty() {
        let fallback_hint = resolve_default_fallback_group_name(&gw_cfg, groups);
        let summary = format_static_validation_summary_zh(&final_validation, Some(&fallback_hint));
        return Err(CatError::Validation(format!(
            "透明网关配置静态校验未通过，已阻止导出坏配置：{summary}"
        )));
    }
    for issue in final_validation.warnings() {
        warnings.push(issue.message.clone());
    }

    let header = format!(
        concat!(
            "# ============================================================================\n",
            "# CatCloud 透明网关 / 软路由完整 Mihomo 配置（Transparent Gateway）\n",
            "# 监听端口：tproxy-port={tproxy} | redir-port={redir} | dns.listen=0.0.0.0:{dns}\n",
            "# 局域网模式：allow-lan=true | bind-address=\"*\" | 桌面虚拟网卡 tun.enable=false\n",
            "# 已保留国内 443 提速、防环规则、用户自写规则与内联 YAML / rule-providers 覆写\n",
            "# 部署示例：mihomo -d /etc/mihomo -f config.yaml\n",
            "# ============================================================================\n"
        ),
        tproxy = opts.tproxy_port,
        redir = opts.redir_port,
        dns = opts.dns_listen_port,
    );
    let total_proxies = compiled
        .value
        .get("proxies")
        .and_then(Value::as_sequence)
        .map_or(compiled.stats.total_proxies, Vec::len);
    let relay_count = compiled.stats.relay_proxies;
    let node_count = total_proxies.saturating_sub(relay_count);
    let rule_count = compiled
        .value
        .get("rules")
        .and_then(Value::as_sequence)
        .map_or(compiled.stats.total_rules, Vec::len);

    let yaml = if opts.redact_secrets {
        redact_gateway_yaml(&header, compiled.value, nodes, relays)?
    } else {
        format!("{header}{locked_yaml}")
    };
    let integration_hint = format!(
        "可直接保存为 OpenWrt / Linux 旁路由 Mihomo 配置运行（tproxy-port={}、redir-port={}、dns=0.0.0.0:{}，已关闭桌面 TUN 避免与 nftables/iptables TPROXY 冲突）。",
        opts.tproxy_port, opts.redir_port, opts.dns_listen_port
    );

    Ok(GatewayExportOutput {
        profile: GatewayExportProfile::TransparentGateway,
        yaml,
        redacted: opts.redact_secrets,
        relay_count,
        node_count,
        rule_count,
        warnings,
        integration_hint,
    })
}

fn export_gateway_preferred_nodes(
    cfg: &AppConfig,
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
    opts: &GatewayExportOptions,
) -> CatResult<GatewayExportOutput> {
    let preferred_nodes = rank_preferred_nodes_for_gateway(cfg, nodes, groups);
    let mut warnings: Vec<String> = Vec::new();
    let mut used_names: HashSet<String> = [
        "DIRECT",
        "REJECT",
        "PASS",
        PREACCEL_SELECT_GROUP_NAME,
        PREACCEL_FALLBACK_GROUP_NAME,
        PREACCEL_LB_GROUP_NAME,
        "🌟 优选节点",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect();

    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    let has_enabled_relays = !enabled_relays.is_empty();
    let relays_support_ipv6 =
        has_enabled_relays && enabled_relays.iter().all(|r| r.supports_ipv6);
    let mut effective_preaccel_cfg = cfg.preaccel.clone();
    if !effective_preaccel_cfg.enabled && has_enabled_relays {
        effective_preaccel_cfg.enabled = true;
        warnings.push(
            "当前桌面国内提速总开关关闭，已按中转池配置一并导出（如需直连可删 `dialer-proxy`）。"
                .to_string(),
        );
    }

    // Pass `&[]` for nodes so `anti_loop_rules` strictly contains relay servers, domestic 204
    // probe endpoints, and campus direct guards — never forcing `DIRECT` rules onto business
    // proxy nodes (business node domains belong strictly in `dns.fake-ip-filter`).
    let preaccel_plan = build_preaccel_compile_plan(&effective_preaccel_cfg, relays, &[])?;
    warnings.extend(preaccel_plan.warnings.iter().cloned());

    let mut compiled_proxies: Vec<Value> = Vec::new();
    let mut proxy_groups: Vec<Value> = Vec::new();
    let mut anti_loop_rules: Vec<String> = Vec::new();
    let mut fake_ip_filter: Vec<String> = Vec::new();
    let mut relay_count = 0usize;

    if preaccel_plan.active && !preaccel_plan.relay_proxies.is_empty() {
        for relay_val in &preaccel_plan.relay_proxies {
            if let Some(name) = relay_val
                .as_mapping()
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            {
                used_names.insert(name.to_string());
            }
            compiled_proxies.push(relay_val.clone());
        }
        relay_count = preaccel_plan.relay_proxies.len();
        proxy_groups.extend(preaccel_plan.proxy_groups.clone());
        anti_loop_rules.extend(preaccel_plan.anti_loop_rules.clone());
        fake_ip_filter.extend(preaccel_plan.fake_ip_filter.clone());
    } else if !cfg.preaccel.enabled {
        warnings.push(
            "当前国内提速开关未开启且尚未启用国内 443 中转，本次仅导出优选业务节点（未附带国内 443 中转与 dialer-proxy）。"
                .to_string(),
        );
    }

    let mut preferred_proxy_names: Vec<String> = Vec::with_capacity(preferred_nodes.len());
    for node in &preferred_nodes {
        let base_name = if node.name.trim().is_empty() {
            format!("Node-{}", node.id)
        } else {
            node.name.trim().to_string()
        };
        let unique_name = make_unique_name(&base_name, &mut used_names);
        let mut proxy_map = build_node_proxy_mapping(node, &unique_name)?;

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
            if let Some(filter) = host_to_fake_ip_filter(raw_server) {
                push_unique(&mut fake_ip_filter, filter);
            }
        }

        if preaccel_plan.active {
            let wants_preaccel = node.should_apply_preaccel(effective_preaccel_cfg.skip_443_native);
            let skip_for_ipv6 = wants_preaccel
                && !relays_support_ipv6
                && is_ipv6_only_node(node)
                && node.preaccel_override != Some(true);
            if wants_preaccel && !skip_for_ipv6 {
                insert_str(&mut proxy_map, "dialer-proxy", PREACCEL_SELECT_GROUP_NAME);
            } else if proxy_map.get("dialer-proxy").and_then(Value::as_str)
                == Some(PREACCEL_SELECT_GROUP_NAME)
            {
                proxy_map.shift_remove("dialer-proxy");
            }
        } else if proxy_map.get("dialer-proxy").and_then(Value::as_str)
            == Some(PREACCEL_SELECT_GROUP_NAME)
        {
            proxy_map.shift_remove("dialer-proxy");
        }

        compiled_proxies.push(Value::Mapping(proxy_map));
        preferred_proxy_names.push(unique_name);
    }

    if preferred_proxy_names.is_empty() {
        warnings.push("当前没有已启用的业务节点可供导出，已在优选组写入 DIRECT 占位。".to_string());
    }

    let mut select_group = Mapping::new();
    insert_str(&mut select_group, "name", "🌟 优选节点");
    insert_str(&mut select_group, "type", "select");
    let group_members: Vec<&str> = if preferred_proxy_names.is_empty() {
        vec!["DIRECT"]
    } else {
        preferred_proxy_names.iter().map(String::as_str).collect()
    };
    select_group.insert(str_val("proxies"), string_seq(group_members));
    proxy_groups.push(Value::Mapping(select_group));

    // Strip any dangling or self-referencing `dialer-proxy` inherited from raw subscription nodes
    // so the exported YAML never fails Mihomo config loading with an unresolved dialer target.
    let _ = strip_dangling_dialer_proxies(&mut compiled_proxies, &proxy_groups);

    let mut doc = Mapping::new();
    doc.insert(str_val("proxies"), Value::Sequence(compiled_proxies));
    doc.insert(str_val("proxy-groups"), Value::Sequence(proxy_groups));
    if !anti_loop_rules.is_empty() {
        doc.insert(
            str_val("rules"),
            string_seq(anti_loop_rules.iter().map(String::as_str)),
        );
    }
    if !fake_ip_filter.is_empty() {
        let mut dns_map = Mapping::new();
        dns_map.insert(
            str_val("fake-ip-filter"),
            string_seq(fake_ip_filter.iter().map(String::as_str)),
        );
        doc.insert(str_val("dns"), Value::Mapping(dns_map));
    }

    let doc_value = Value::Mapping(doc);
    let body_yaml = serde_yaml_ng::to_string(&doc_value)?;
    let relay_servers_for_validation: Vec<String> = if preaccel_plan.active {
        relays
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.server.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let validation = validate_compiled_yaml(&body_yaml, &relay_servers_for_validation)?;
    let hard_errors = validation.errors();
    if !hard_errors.is_empty() {
        let summary = format_static_validation_summary_zh(&validation, None);
        return Err(CatError::Validation(format!(
            "优选节点片段静态防环校验未通过，已阻止导出坏配置：{summary}"
        )));
    }
    for issue in validation.warnings() {
        if issue.code != "missing_match_rule" {
            warnings.push(issue.message.clone());
        }
    }
    let header = concat!(
        "# ============================================================================\n",
        "# CatCloud 优选节点与国内 443 中转片段（Preferred Nodes）\n",
        "# 说明：优先排布当前活跃与智能多选组内优选节点；若已开启国内提速，则自动保留 dialer-proxy 与防环规则\n",
        "# 适用场景：按需摘取健康业务节点合并进 OpenWrt / Linux 旁路由自维护配置\n",
        "# ============================================================================\n"
    );
    let raw_yaml = format!("{header}{body_yaml}");
    let yaml = if opts.redact_secrets {
        redact_gateway_yaml(header, doc_value, &preferred_nodes, relays)?
    } else {
        raw_yaml
    };

    let integration_hint = if relay_count > 0 {
        format!(
            "已导出 {} 个优选业务节点与 {} 条国内 443 中转（非 443 节点已保留 `dialer-proxy: {PREACCEL_SELECT_GROUP_NAME}`），合并进旁路由配置时请一并置顶防环 rules。",
            preferred_proxy_names.len(),
            relay_count
        )
    } else {
        format!(
            "已导出 {} 个优选业务节点，可直接复制所需节点段落合并进旁路由 Mihomo 配置。",
            preferred_proxy_names.len()
        )
    };

    Ok(GatewayExportOutput {
        profile: GatewayExportProfile::PreferredNodes,
        yaml,
        redacted: opts.redact_secrets,
        relay_count,
        node_count: preferred_proxy_names.len(),
        rule_count: anti_loop_rules.len(),
        warnings,
        integration_hint,
    })
}

fn rank_preferred_nodes_for_gateway(
    cfg: &AppConfig,
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
) -> Vec<ProxyNode> {
    let enabled: Vec<&ProxyNode> = nodes.iter().filter(|n| n.enabled).collect();
    let non_info: Vec<&ProxyNode> = enabled
        .iter()
        .copied()
        .filter(|n| !is_info_proxy_node(n))
        .collect();
    let candidates = if non_info.is_empty() { enabled } else { non_info };

    let mut active_ids: HashSet<&str> = HashSet::new();
    if let Some(single_id) = cfg
        .active_single_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        active_ids.insert(single_id);
    }
    let mut member_rank: HashMap<&str, usize> = HashMap::new();
    for (g_idx, g) in groups.iter().enumerate() {
        if g.state != MultiGroupState::CircuitOpen {
            if let Some(aid) = g
                .active_node_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                active_ids.insert(aid);
            }
        }
        for (m_idx, mid) in g.member_node_ids.iter().enumerate() {
            let trimmed = mid.trim();
            if !trimmed.is_empty() {
                let rank = g_idx * 10_000 + m_idx;
                member_rank
                    .entry(trimmed)
                    .and_modify(|prev| *prev = (*prev).min(rank))
                    .or_insert(rank);
            }
        }
    }

    let mut ranked: Vec<ProxyNode> = candidates.into_iter().cloned().collect();
    ranked.sort_by(|a, b| {
        let key = |n: &ProxyNode| {
            let has_fail_tag = n.tags.iter().any(|t| {
                let l = t.trim().to_ascii_lowercase();
                matches!(l.as_str(), "failed" | "offline" | "dead" | "broken" | "timeout")
            });
            let has_healthy_tag = n.tags.iter().any(|t| {
                let l = t.trim().to_ascii_lowercase();
                matches!(
                    l.as_str(),
                    "golden" | "healthy" | "verified" | "ok" | "ai_ok" | "google_clean"
                )
            });
            let tier: u8 = if has_fail_tag {
                3
            } else if active_ids.contains(n.id.as_str()) {
                0
            } else if has_healthy_tag || member_rank.contains_key(n.id.as_str()) {
                1
            } else {
                2
            };
            let m_rank = member_rank.get(n.id.as_str()).copied().unwrap_or(usize::MAX);
            let region_pref: u8 = match n.region_code.trim().to_ascii_uppercase().as_str() {
                "TW" => 0,
                "HK" => 1,
                "SG" => 2,
                "JP" => 3,
                "US" => 4,
                "KR" => 5,
                _ => 6,
            };
            let mult_milli = if n.multiplier.is_finite() && n.multiplier >= 0.0 {
                (n.multiplier * 1000.0).round() as u64
            } else {
                u64::MAX
            };
            (tier, m_rank, region_pref, mult_milli, n.name.clone(), n.id.clone())
        };
        key(a).cmp(&key(b))
    });
    ranked
}

fn pick_non_colliding_gateway_port(used: &HashSet<u16>, preferred: u16) -> u16 {
    if preferred > 0 && !used.contains(&preferred) {
        return preferred;
    }
    for candidate in 17890u16..=60000u16 {
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    preferred
}
