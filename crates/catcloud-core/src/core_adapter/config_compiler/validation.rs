//! RFC 7396 YAML Merge Patch engine, static pre-flight validator (`validate_compiled_yaml`),
//! proxy-group cycle detection, and IPv4/IPv6 anti-loop CIDR checks.

use super::types::{
    DEFAULT_FALLBACK_GROUP_NAME, MAX_YAML_BYTES, StaticCheckIssue, StaticCheckSeverity,
    StaticValidationReport, extract_url_host, is_preaccel_group_name, push_unique,
};
use super::rules::{extract_mihomo_rule_target, extract_rule_set_provider_names, is_match_rule};
use crate::config::is_forbidden_domestic_probe_host;
use crate::error::{CatError, CatResult};
use serde_yaml_ng::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extract the missing proxy/group name from an `unknown_rule_target` static validation message.
fn parse_unknown_rule_target_from_issue(msg: &str) -> Option<&str> {
    let marker = "unknown proxy or proxy-group `";
    let rest = msg.split_once(marker)?.1;
    let target = rest.strip_suffix('`').unwrap_or_else(|| rest.split('`').next().unwrap_or(rest));
    let trimmed = target.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Aggregate static validation errors into concise, actionable Simplified Chinese prose
/// (preventing hundreds of repetitive `unknown_rule_target` lines from flooding UI or logs).
pub fn format_static_validation_summary_zh(
    report: &StaticValidationReport,
    fallback_group_hint: Option<&str>,
) -> String {
    let errors = report.errors();
    if errors.is_empty() {
        return String::new();
    }

    let mut unknown_targets: BTreeMap<String, usize> = BTreeMap::new();
    let mut other_by_code: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for issue in errors {
        if issue.code == "unknown_rule_target" {
            let target = parse_unknown_rule_target_from_issue(&issue.message)
                .unwrap_or("未知分组")
                .to_string();
            *unknown_targets.entry(target).or_insert(0) += 1;
        } else {
            other_by_code
                .entry(issue.code.clone())
                .or_default()
                .push(issue.message.clone());
        }
    }

    let mut segments: Vec<String> = Vec::new();
    if !unknown_targets.is_empty() {
        let mut sorted: Vec<(String, usize)> = unknown_targets.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total: usize = sorted.iter().map(|(_, c)| *c).sum();
        let fallback_name = fallback_group_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_FALLBACK_GROUP_NAME);
        if sorted.len() == 1 {
            let (name, count) = &sorted[0];
            segments.push(format!(
                "共有 {count} 条分流规则指向不存在的分组「{name}」（可在首页或分流页一键清理，或改为「{fallback_name}」）"
            ));
        } else {
            let shown: Vec<String> = sorted
                .iter()
                .take(3)
                .map(|(name, count)| format!("「{name}」({count} 条)"))
                .collect();
            let extra = if sorted.len() > 3 {
                format!(" 等 {} 个分组", sorted.len())
            } else {
                String::new()
            };
            segments.push(format!(
                "共有 {total} 条分流规则指向不存在的分组：{}{}（可一键清理或改为「{fallback_name}」）",
                shown.join("、"),
                extra
            ));
        }
    }

    for (code, msgs) in other_by_code {
        let count = msgs.len();
        match code.as_str() {
            "missing_relay_direct_rule" => {
                segments.push(format!(
                    "有 {count} 条国内提速中转缺少防环直连规则（{}）",
                    msgs[0]
                ));
            }
            "empty_proxy_group" => {
                segments.push(format!(
                    "有 {count} 个路线分组为空，请先导入节点或检查分组成员（{}）",
                    msgs[0]
                ));
            }
            "group_cycle" => {
                segments.push(format!("检测到代理分组循环引用：{}", msgs[0]));
            }
            _ => {
                if count <= 2 {
                    segments.push(msgs.join("；"));
                } else {
                    segments.push(format!("{} 等共 {count} 项校验异常（{code}）", msgs[0]));
                }
            }
        }
    }

    segments.join("；")
}

/// Apply a declarative RFC 7396 style YAML Merge Patch onto a cloned copy of `base`.
///
/// - Enforces `MAX_YAML_BYTES` (16 MiB) and resolves YAML `<<` anchors via `apply_merge()`.
/// - Rejects syntax errors or non-mapping top-level patches and NEVER modifies `base` on failure.
/// - Inside mappings, a patch value of `null` deletes the corresponding key from the target.
pub fn apply_yaml_merge_patch(base: &Value, patch_yaml: &str) -> CatResult<Value> {
    if patch_yaml.len() > MAX_YAML_BYTES {
        return Err(CatError::Validation(format!(
            "YAML merge patch exceeds maximum allowed size ({} > {MAX_YAML_BYTES} bytes)",
            patch_yaml.len()
        )));
    }
    let mut patch_value: Value = serde_yaml_ng::from_str(patch_yaml)?;
    patch_value.apply_merge()?;

    if !patch_value.is_mapping() {
        return Err(CatError::Validation(
            "YAML merge patch root document must be a mapping".into(),
        ));
    }

    let mut cloned = base.clone();
    merge_yaml_values(&mut cloned, patch_value);
    Ok(cloned)
}

fn merge_yaml_values(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Mapping(target_map), Value::Mapping(patch_map)) => {
            for (k, v) in patch_map {
                if v.is_null() {
                    target_map.shift_remove(&k);
                } else if let Some(existing) = target_map.get_mut(&k) {
                    if existing.is_mapping() && v.is_mapping() {
                        merge_yaml_values(existing, v);
                    } else {
                        *existing = v;
                    }
                } else {
                    target_map.insert(k, v);
                }
            }
        }
        (target_slot, patch_val) => {
            *target_slot = patch_val;
        }
    }
}

/// Perform static pre-flight checks on compiled Mihomo YAML:
/// - YAML syntax validity & 16 MiB size cap (with `<<` anchor expansion)
/// - Empty or missing `proxies` list inside any `proxy-groups` entry
/// - Cyclic references between `proxy-groups`
/// - Overseas `gstatic`/`google`/`cloudflare` URLs mistakenly assigned to domestic pre-accel groups
/// - Missing `DIRECT` loop-prevention rules for pre-acceleration relay servers
/// - Rules referencing unknown proxies or proxy-groups outside built-in actions
pub fn validate_compiled_yaml(
    yaml_str: &str,
    relay_servers: &[String],
) -> CatResult<StaticValidationReport> {
    if yaml_str.len() > MAX_YAML_BYTES {
        return Err(CatError::Validation(format!(
            "compiled YAML exceeds maximum allowed size ({} > {MAX_YAML_BYTES} bytes)",
            yaml_str.len()
        )));
    }

    let mut doc: Value = serde_yaml_ng::from_str(yaml_str)?;
    doc.apply_merge()?;

    let Some(root) = doc.as_mapping() else {
        return Err(CatError::Validation(
            "compiled Mihomo YAML root must be a mapping".into(),
        ));
    };

    let mut issues: Vec<StaticCheckIssue> = Vec::new();

    // Map proxy name -> server for discovering relay servers referenced via dialer-proxy,
    // and collect every valid proxy/proxy-group target name referenced by `rules`.
    let mut valid_rule_targets: HashSet<String> = HashSet::new();
    let mut proxy_server_map: HashMap<String, String> = HashMap::new();
    let mut dialer_targets: HashSet<String> = HashSet::new();
    if let Some(proxies) = root.get("proxies").and_then(Value::as_sequence) {
        for item in proxies {
            if let Some(map) = item.as_mapping() {
                if let Some(name) = map.get("name").and_then(Value::as_str) {
                    let trimmed_name = name.trim();
                    if !trimmed_name.is_empty() {
                        valid_rule_targets.insert(trimmed_name.to_string());
                    }
                    if let Some(server) = map.get("server").and_then(Value::as_str) {
                        proxy_server_map.insert(name.to_string(), server.to_string());
                    }
                }
                if let Some(dp) = map.get("dialer-proxy").and_then(Value::as_str) {
                    if !dp.trim().is_empty() {
                        dialer_targets.insert(dp.trim().to_string());
                    }
                }
            }
        }
    }

    // Inspect proxy-groups for empty groups, cycles, and forbidden overseas domestic probe URLs.
    let mut group_members_map: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(groups) = root.get("proxy-groups").and_then(Value::as_sequence) {
        for (idx, item) in groups.iter().enumerate() {
            let Some(map) = item.as_mapping() else {
                issues.push(StaticCheckIssue {
                    code: "invalid_proxy_group".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!("proxy-groups[{idx}] must be a YAML mapping"),
                });
                continue;
            };
            let raw_group_name = map
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(name) = raw_group_name {
                valid_rule_targets.insert(name.to_string());
            }
            let group_name = raw_group_name.unwrap_or("<unnamed>").to_string();

            let members: Vec<String> = map
                .get("proxies")
                .and_then(Value::as_sequence)
                .map(|seq| {
                    seq.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            let has_use = map
                .get("use")
                .and_then(Value::as_sequence)
                .is_some_and(|s| !s.is_empty());

            if members.is_empty() && !has_use {
                issues.push(StaticCheckIssue {
                    code: "empty_proxy_group".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!("proxy group `{group_name}` has an empty `proxies` list"),
                });
            }

            // Detect forbidden overseas probe URLs on domestic pre-acceleration groups and ensure
            // inner `load-balance` pre-acceleration groups never contain `DIRECT`.
            if is_preaccel_group_name(&group_name, &dialer_targets) {
                if let Some(probe_url) = map.get("url").and_then(Value::as_str) {
                    if let Some(host) = extract_url_host(probe_url) {
                        if is_forbidden_domestic_probe_host(&host) {
                            issues.push(StaticCheckIssue {
                                code: "forbidden_overseas_domestic_probe".to_string(),
                                severity: StaticCheckSeverity::Error,
                                message: format!(
                                    "domestic pre-acceleration group `{group_name}` must not probe overseas host `{host}`"
                                ),
                            });
                        }
                    }
                }
                if map
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.eq_ignore_ascii_case("load-balance"))
                    && members.iter().any(|m| m.eq_ignore_ascii_case("DIRECT"))
                {
                    issues.push(StaticCheckIssue {
                        code: "preaccel_lb_contains_direct".to_string(),
                        severity: StaticCheckSeverity::Error,
                        message: format!(
                            "pre-acceleration load-balance group `{group_name}` must never contain `DIRECT`"
                        ),
                    });
                }
            }

            group_members_map.insert(group_name, members);
        }
    }

    // Cycle detection across proxy-groups.
    for cycle in detect_group_cycles(&group_members_map) {
        issues.push(StaticCheckIssue {
            code: "group_cycle".to_string(),
            severity: StaticCheckSeverity::Error,
            message: format!("cyclic proxy-group reference detected: {}", cycle.join(" -> ")),
        });
    }

    // Gather all relay servers to verify DIRECT anti-loop rules:
    // explicit caller list + any proxies transitively reachable from dialer-proxy targets.
    let mut required_relay_servers: Vec<String> = Vec::new();
    for s in relay_servers {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            push_unique(&mut required_relay_servers, trimmed.to_string());
        }
    }
    for dp_target in &dialer_targets {
        let reachable = collect_transitive_proxies(dp_target, &group_members_map);
        for proxy_name in reachable {
            if let Some(server) = proxy_server_map.get(&proxy_name) {
                push_unique(&mut required_relay_servers, server.clone());
            }
        }
    }

    let rules: Vec<String> = root
        .get("rules")
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    for relay_server in &required_relay_servers {
        if !has_direct_anti_loop_rule(relay_server, &rules) {
            issues.push(StaticCheckIssue {
                code: "missing_relay_direct_rule".to_string(),
                severity: StaticCheckSeverity::Error,
                message: format!(
                    "pre-acceleration relay server `{relay_server}` is missing a top-level DIRECT loop-prevention rule"
                ),
            });
        }
    }

    // Collect top-level `rule-providers` names so `RULE-SET` rules referencing undefined
    // providers emit a clear warning instead of crashing or silently failing at runtime.
    let declared_rule_providers: HashSet<String> = root
        .get("rule-providers")
        .and_then(Value::as_mapping)
        .map(|map| {
            map.keys()
                .filter_map(Value::as_str)
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let mut warned_missing_providers: HashSet<String> = HashSet::new();

    // Verify every rule target resolves to a built-in action or an existing proxy / proxy-group,
    // and warn when `RULE-SET,<name>,...` references an undeclared `rule-providers` entry.
    for rule in &rules {
        for provider_name in extract_rule_set_provider_names(rule) {
            if !declared_rule_providers.contains(&provider_name)
                && warned_missing_providers.insert(provider_name.clone())
            {
                issues.push(StaticCheckIssue {
                    code: "missing_rule_provider".to_string(),
                    severity: StaticCheckSeverity::Warning,
                    message: format!(
                        "规则 `{rule}` 引用了规则集 `{provider_name}`，但最终配置根节点 `rule-providers` 中未定义该名称（请在内联 YAML 覆写或合并补丁中补充 `rule-providers.{provider_name}`）"
                    ),
                });
            }
        }
        if let Some(target) = extract_mihomo_rule_target(rule) {
            if !valid_rule_targets.contains(target) {
                issues.push(StaticCheckIssue {
                    code: "unknown_rule_target".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!(
                        "rule `{rule}` references unknown proxy or proxy-group `{target}`"
                    ),
                });
            }
        }
    }

    if !rules.iter().any(|r| is_match_rule(r)) {
        issues.push(StaticCheckIssue {
            code: "missing_match_rule".to_string(),
            severity: StaticCheckSeverity::Warning,
            message: "rules section does not end with a fallback MATCH rule".to_string(),
        });
    }

    if root.get("external-controller").is_some() {
        let has_secret = root
            .get("secret")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        if !has_secret {
            issues.push(StaticCheckIssue {
                code: "missing_controller_secret".to_string(),
                severity: StaticCheckSeverity::Warning,
                message: "external-controller is enabled without a non-empty secret".to_string(),
            });
        }
    }

    let ok = issues
        .iter()
        .all(|issue| issue.severity != StaticCheckSeverity::Error);

    Ok(StaticValidationReport { ok, issues })
}

fn detect_group_cycles(groups: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut in_stack: Vec<String> = Vec::new();
    let mut in_stack_set: HashSet<String> = HashSet::new();
    let mut cycles: Vec<Vec<String>> = Vec::new();

    fn dfs(
        node: &str,
        groups: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        in_stack: &mut Vec<String>,
        in_stack_set: &mut HashSet<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        in_stack.push(node.to_string());
        in_stack_set.insert(node.to_string());

        if let Some(members) = groups.get(node) {
            for next in members {
                if !groups.contains_key(next) {
                    continue;
                }
                if in_stack_set.contains(next) {
                    if let Some(pos) = in_stack.iter().position(|n| n == next) {
                        let mut cycle = in_stack[pos..].to_vec();
                        cycle.push(next.clone());
                        cycles.push(cycle);
                    }
                } else if !visited.contains(next) {
                    dfs(next, groups, visited, in_stack, in_stack_set, cycles);
                }
            }
        }

        in_stack.pop();
        in_stack_set.remove(node);
    }

    let mut keys: Vec<&String> = groups.keys().collect();
    keys.sort();
    for key in keys {
        if !visited.contains(key) {
            dfs(
                key,
                groups,
                &mut visited,
                &mut in_stack,
                &mut in_stack_set,
                &mut cycles,
            );
        }
    }

    cycles
}

fn collect_transitive_proxies(
    start: &str,
    groups: &HashMap<String, Vec<String>>,
) -> HashSet<String> {
    let mut visited_groups: HashSet<String> = HashSet::new();
    let mut leaf_proxies: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec![start.to_string()];

    while let Some(curr) = queue.pop() {
        if let Some(members) = groups.get(&curr) {
            if visited_groups.insert(curr) {
                for m in members {
                    queue.push(m.clone());
                }
            }
        } else if curr != "DIRECT" && curr != "REJECT" {
            leaf_proxies.insert(curr);
        }
    }

    leaf_proxies
}

fn has_direct_anti_loop_rule(relay_server: &str, rules: &[String]) -> bool {
    let target = relay_server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let target_ip = target.parse::<IpAddr>().ok();

    for rule in rules {
        // Stop before a catch-all MATCH rule routes the relay into a proxy loop.
        // Note: `MATCH,<target>` has only 2 segments, so this check MUST precede `parts.len() < 3`.
        if is_match_rule(rule) {
            return false;
        }
        let parts: Vec<&str> = rule.split(',').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        let rule_type = parts[0].to_ascii_uppercase();
        let payload = parts[1].to_ascii_lowercase();
        let action = parts[2].to_ascii_uppercase();

        if action != "DIRECT" {
            continue;
        }

        match (target_ip, rule_type.as_str()) {
            (Some(IpAddr::V4(v4)), "IP-CIDR") => {
                if payload == format!("{v4}/32") || ipv4_in_cidr(v4, &payload) {
                    return true;
                }
            }
            (Some(IpAddr::V6(v6)), "IP-CIDR6") => {
                if payload == format!("{v6}/128") || ipv6_in_cidr(v6, &payload) {
                    return true;
                }
            }
            (None, "DOMAIN") => {
                if payload == target {
                    return true;
                }
            }
            (None, "DOMAIN-SUFFIX") => {
                if target == payload || target.ends_with(&format!(".{payload}")) {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

fn ipv4_in_cidr(addr: Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_cidr(addr: Ipv6Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.trim().parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 0 {
        0u128
    } else {
        !0u128 << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}
