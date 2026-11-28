//! Mihomo rule grammar validation, logical/regex parsing, target rewriting, dangling-rule
//! auditing/repair, bulk rule parsing, and mandatory safety-rule pinning.

use super::types::{
    BulkRulesParseResult, DEFAULT_FALLBACK_GROUP_NAME, DanglingRuleGroupSummary,
    DanglingRuleRepairAction, DanglingRuleRepairReport, DanglingRulesAudit, SINGLE_NODE_GROUP_NAME,
    push_unique, str_val,
};
use crate::models::{AppConfig, DEFAULT_AI_ROUTING_DOMAINS, MultiGroup, ProxyNode, RouteTargetMode};
use serde_yaml_ng::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;

/// Explicit Codex / OpenAI API / Statsig endpoints guaranteed to stay pinned to the same
/// AI routing group as `chatgpt.com` / `openai.com` so long-lived streams never split routes.
const EXPLICIT_AI_CODEX_ROUTING_DOMAINS: &[&str] = &[
    "ab.chatgpt.com",
    "ios.chat.openai.com",
    "api.openai.com",
];

/// Build default `DOMAIN-SUFFIX` routing rules for CatCloud's built-in AI service domains,
/// explicitly pinning Codex / OpenAI API endpoints (`ab.chatgpt.com`, `ios.chat.openai.com`,
/// `api.openai.com`) alongside `DEFAULT_AI_ROUTING_DOMAINS`.
pub fn build_default_ai_routing_rules(target_group: &str) -> Vec<String> {
    let target = target_group.trim();
    let mut rules: Vec<String> = Vec::with_capacity(
        EXPLICIT_AI_CODEX_ROUTING_DOMAINS.len() + DEFAULT_AI_ROUTING_DOMAINS.len(),
    );
    for domain in EXPLICIT_AI_CODEX_ROUTING_DOMAINS {
        push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},{target}"));
    }
    for domain in DEFAULT_AI_ROUTING_DOMAINS {
        push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},{target}"));
    }
    rules
}

/// Built-in whitelist of standard Mihomo rule types accepted during rule expansion and validation.
const VALID_MIHOMO_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "GEOIP",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "SRC-IP-CIDR",
    "DST-PORT",
    "SRC-PORT",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "NETWORK",
    "UID",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "SUB-RULE",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "MATCH",
];

fn is_valid_mihomo_rule_type(raw: &str) -> bool {
    let upper = raw.trim().to_ascii_uppercase();
    VALID_MIHOMO_RULE_TYPES.contains(&upper.as_str())
}

fn normalize_bare_domain_candidate(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_valid_mihomo_rule_type(trimmed) {
        return None;
    }
    let candidate = trimmed
        .strip_prefix("*.")
        .or_else(|| trimmed.strip_prefix("+."))
        .unwrap_or(trimmed);
    if candidate.is_empty()
        || !candidate.contains('.')
        || candidate.starts_with('.')
        || candidate.ends_with('.')
        || candidate.starts_with('-')
        || candidate.ends_with('-')
        || candidate.contains("..")
        || candidate.parse::<Ipv4Addr>().is_ok()
    {
        return None;
    }
    if candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && candidate.chars().any(|c| c.is_ascii_alphabetic())
    {
        Some(candidate)
    } else {
        None
    }
}

pub(super) fn has_balanced_parens(expr: &str) -> bool {
    let trimmed = expr.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return false;
    }
    let mut depth: i32 = 0;
    let mut chars = trimmed.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
                // Reject juxtaposed top-level groups like `(NETWORK,UDP),(DST-PORT,443)`.
                if depth == 0 && chars.peek().is_some() {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn is_logical_rule_type(rule_type: &str) -> bool {
    let upper = rule_type.trim().to_ascii_uppercase();
    matches!(upper.as_str(), "AND" | "OR" | "NOT")
}

fn is_regex_rule_type(rule_type: &str) -> bool {
    let upper = rule_type.trim().to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "DOMAIN-REGEX" | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX"
    )
}

/// Scan from the leading `(` of `rest` until parenthesis depth first returns to 0.
///
/// Stopping at the first balanced `)` preserves targets containing parentheses
/// (such as `AI (日本)`, `Node (2)`, or unmatched `Node :)`) verbatim in the remainder.
fn split_leading_balanced_paren_expr(rest: &str) -> Option<(&str, &str)> {
    let trimmed = rest.trim();
    if !trimmed.starts_with('(') {
        return None;
    }
    let mut depth: i32 = 0;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
                if depth == 0 {
                    let end = idx + ch.len_utf8();
                    let expr = &trimmed[..end];
                    let after = trimmed[end..].trim();
                    return Some((expr, after));
                }
            }
            _ => {}
        }
    }
    None
}

/// Validate a Mihomo double-parenthesized logical condition payload `((...))` recursively.
///
/// Each top-level comma-separated clause inside the outer `(...)` must itself be a non-empty
/// balanced `(...)` expression; nested `AND`/`OR`/`NOT` clauses are validated recursively up to
/// `MAX_LOGICAL_CONDITION_DEPTH`, and leaf clauses must contain `<RULE_TYPE>,<payload>`.
fn is_valid_logical_condition_expr(rule_type: &str, expr: &str) -> bool {
    is_valid_logical_condition_expr_inner(rule_type, expr, 0)
}

fn is_valid_logical_condition_expr_inner(rule_type: &str, expr: &str, depth: usize) -> bool {
    const MAX_LOGICAL_CONDITION_DEPTH: usize = 16;
    if depth >= MAX_LOGICAL_CONDITION_DEPTH || !has_balanced_parens(expr) {
        return false;
    }
    let trimmed = expr.trim();
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return false;
    }
    let mut clauses: Vec<&str> = Vec::new();
    let mut paren_depth: i32 = 0;
    let mut start = 0usize;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return false;
                }
            }
            ',' if paren_depth == 0 => {
                clauses.push(inner[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if paren_depth != 0 {
        return false;
    }
    clauses.push(inner[start..].trim());
    if clauses.is_empty() {
        return false;
    }
    if rule_type.trim().eq_ignore_ascii_case("NOT") && clauses.len() != 1 {
        return false;
    }
    clauses.iter().all(|clause| {
        if !has_balanced_parens(clause) {
            return false;
        }
        let body = clause[1..clause.len() - 1].trim();
        let Some((sub_type, sub_rest)) = body.split_once(',') else {
            return false;
        };
        let sub_type_upper = sub_type.trim().to_ascii_uppercase();
        let sub_rest_trimmed = sub_rest.trim();
        if sub_type_upper.is_empty() || sub_rest_trimmed.is_empty() {
            return false;
        }
        if matches!(sub_type_upper.as_str(), "AND" | "OR" | "NOT") {
            is_valid_logical_condition_expr_inner(&sub_type_upper, sub_rest_trimmed, depth + 1)
        } else {
            is_valid_mihomo_rule_type(&sub_type_upper)
        }
    })
}

/// Parse `<TYPE>,((...)),<TARGET>` for Mihomo logical rules (`AND`/`OR`/`NOT`).
///
/// Matches upstream Mihomo `ParseRulePayload` strictly:
/// - Condition must be double-parenthesized `((...))`.
/// - Top-level trailing flags (`no-resolve`/`src`) are rejected (they belong inside sub-clauses).
/// - Parenthesized or asymmetric targets (`AI (日本)`, `Node (2)`, `Node :)`) are preserved verbatim.
fn parse_logical_rule_expr_and_target<'a>(
    rule_type: &str,
    rest: &'a str,
) -> Option<(&'a str, &'a str)> {
    let (expr, after) = split_leading_balanced_paren_expr(rest)?;
    if !is_valid_logical_condition_expr(rule_type, expr) {
        return None;
    }
    let after_comma = after.strip_prefix(',')?;
    let target = after_comma.trim();
    if target.is_empty() || target.contains(',') || is_mihomo_rule_flag(target) {
        return None;
    }
    Some((expr, target))
}

/// Parse `SUB-RULE,(...),<SUB_RULE_NAME>` (allowing single- or multi-layer parenthesized conditions).
fn parse_sub_rule_expr_and_target(rest: &str) -> Option<(&str, &str)> {
    let (expr, after) = split_leading_balanced_paren_expr(rest)?;
    if !has_balanced_parens(expr) {
        return None;
    }
    let inner = expr[1..expr.len() - 1].trim();
    if inner.is_empty() {
        return None;
    }
    let after_comma = after.strip_prefix(',')?;
    let target = after_comma.trim();
    if target.is_empty() || target.contains(',') {
        return None;
    }
    Some((expr, target))
}

/// Parse `<REGEX-TYPE>,<PATTERN>,<TARGET>` by splitting on the final comma so commas inside
/// regex quantifiers (`{1,3}`) and escaped parentheses (`\(bar`) are preserved verbatim.
fn parse_regex_rule_pattern_and_target(rest: &str) -> Option<(&str, &str)> {
    let (pattern, target) = rest.rsplit_once(',')?;
    let pattern = pattern.trim();
    let target = target.trim();
    if pattern.is_empty() || target.is_empty() || is_mihomo_rule_flag(target) {
        return None;
    }
    Some((pattern, target))
}

/// Parse a Mihomo catch-all `MATCH,<target>` rule tolerating ASCII whitespace around the comma
/// (e.g. `"MATCH , DIRECT"`), returning the trimmed non-empty target when valid.
fn parse_match_rule_target(rule: &str) -> Option<&str> {
    let (raw_type, rest) = rule.trim().split_once(',')?;
    if !raw_type.trim().eq_ignore_ascii_case("MATCH") {
        return None;
    }
    let target = rest.trim();
    if target.is_empty() || target.contains(',') {
        return None;
    }
    Some(target)
}

/// Return `true` when `rule` is a valid Mihomo `MATCH,<target>` rule (tolerating spaces around
/// the comma such as `"MATCH , DIRECT"`).
pub(crate) fn is_match_rule(rule: &str) -> bool {
    parse_match_rule_target(rule).is_some()
}

/// Normalize a global rule string before emitting into compiled `rules`, converting
/// whitespace-padded `MATCH , <target>` variants into canonical `MATCH,<target>`.
pub(super) fn normalize_global_rule_for_emit(rule: &str) -> String {
    if let Some(target) = parse_match_rule_target(rule) {
        format!("MATCH,{target}")
    } else {
        rule.trim().to_string()
    }
}

pub(super) fn is_plausible_global_rule(rule: &str) -> bool {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Some((raw_type, rest)) = trimmed.split_once(',') else {
        return false;
    };
    let rule_type = raw_type.trim();
    if !is_valid_mihomo_rule_type(rule_type) {
        return false;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        return is_match_rule(trimmed);
    }
    if is_logical_rule_type(rule_type) {
        return parse_logical_rule_expr_and_target(rule_type, rest).is_some();
    }
    if rule_type.eq_ignore_ascii_case("SUB-RULE") {
        return parse_sub_rule_expr_and_target(rest).is_some();
    }
    if is_regex_rule_type(rule_type) {
        return parse_regex_rule_pattern_and_target(rest).is_some();
    }
    let mut parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    while parts.len() > 2 && parts.last().is_some_and(|tok| is_mihomo_rule_flag(tok)) {
        parts.pop();
    }
    parts.len() >= 3 && !parts[1].is_empty() && !parts[parts.len() - 1].is_empty()
}

fn is_builtin_rule_action(target: &str) -> bool {
    let upper = target.trim().to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE"
    )
}

fn is_mihomo_rule_flag(token: &str) -> bool {
    token.eq_ignore_ascii_case("no-resolve") || token.eq_ignore_ascii_case("src")
}

/// Extract the raw proxy or proxy-group target from a Mihomo rule line (including built-in
/// actions such as `DIRECT`/`REJECT`). Returns `None` for blank lines, `#` comments,
/// `SUB-RULE` entries, or malformed rules without a target segment.
pub(super) fn extract_mihomo_rule_raw_target(rule: &str) -> Option<&str> {
    let trimmed = rule.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (raw_type, rest) = trimmed.split_once(',')?;
    let rule_type = raw_type.trim();
    if rule_type.is_empty() || rule_type.eq_ignore_ascii_case("SUB-RULE") {
        return None;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        return parse_match_rule_target(trimmed);
    }
    if is_logical_rule_type(rule_type) {
        return parse_logical_rule_expr_and_target(rule_type, rest).map(|(_, target)| target);
    }
    if is_regex_rule_type(rule_type) {
        return parse_regex_rule_pattern_and_target(rest).map(|(_, target)| target);
    }

    let mut parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 3 || parts[1].is_empty() {
        return None;
    }
    while parts.len() > 2 && parts.last().is_some_and(|tok| is_mihomo_rule_flag(tok)) {
        parts.pop();
    }
    if parts.len() < 3 {
        return None;
    }
    let target = *parts.last()?;
    if target.is_empty() {
        return None;
    }
    Some(target)
}

/// Extract a non-builtin proxy or proxy-group target name from a Mihomo rule line, ignoring
/// built-in actions (`DIRECT`, `REJECT`, `REJECT-DROP`, `PASS`, `COMPATIBLE`, case-insensitive).
pub fn extract_mihomo_rule_target(rule: &str) -> Option<&str> {
    extract_mihomo_rule_raw_target(rule).filter(|target| !is_builtin_rule_action(target))
}

/// Return `true` when `target` is a built-in Mihomo routing action (`DIRECT`, `REJECT`,
/// `REJECT-DROP`, `PASS`, `COMPATIBLE`, case-insensitive).
pub fn is_builtin_mihomo_rule_target(target: &str) -> bool {
    is_builtin_rule_action(target)
}

/// Rewrite the proxy/group target segment of a Mihomo rule line while preserving rule type,
/// payload/logical expression, and trailing flags (`no-resolve`, `src`).
pub fn rewrite_mihomo_rule_target(rule: &str, new_target: &str) -> Option<String> {
    let trimmed = rule.trim();
    let replacement = new_target.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || replacement.is_empty() {
        return None;
    }
    let (raw_type, rest) = trimmed.split_once(',')?;
    let rule_type = raw_type.trim();
    if rule_type.is_empty() || rule_type.eq_ignore_ascii_case("SUB-RULE") {
        return None;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        parse_match_rule_target(trimmed)?;
        return Some(format!("{rule_type},{replacement}"));
    }
    if is_logical_rule_type(rule_type) {
        let (expr, _) = parse_logical_rule_expr_and_target(rule_type, rest)?;
        return Some(format!("{rule_type},{expr},{replacement}"));
    }
    if is_regex_rule_type(rule_type) {
        let (pattern, _) = parse_regex_rule_pattern_and_target(rest)?;
        return Some(format!("{rule_type},{pattern},{replacement}"));
    }

    let mut parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 3 || parts[1].is_empty() {
        return None;
    }
    let mut trailing_flags: Vec<&str> = Vec::new();
    while parts.len() > 2 && parts.last().is_some_and(|tok| is_mihomo_rule_flag(tok)) {
        if let Some(flag) = parts.pop() {
            trailing_flags.push(flag);
        }
    }
    if parts.len() < 3 {
        return None;
    }
    let last_slot = parts.last_mut()?;
    if last_slot.is_empty() {
        return None;
    }
    *last_slot = replacement;
    trailing_flags.reverse();
    parts.extend(trailing_flags);
    Some(parts.join(","))
}

/// Collect the set of non-builtin rule targets currently valid for a given set of multi-groups
/// and proxy nodes (group names, built-in fallback/single group names, and enabled node names).
pub fn collect_valid_rule_target_names(
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
) -> HashSet<String> {
    let mut valid = HashSet::new();
    valid.insert(DEFAULT_FALLBACK_GROUP_NAME.to_string());
    valid.insert(SINGLE_NODE_GROUP_NAME.to_string());
    for g in groups {
        let name = g.name.trim();
        if !name.is_empty() {
            valid.insert(name.to_string());
        }
    }
    for n in nodes.iter().filter(|n| n.enabled) {
        let name = n.name.trim();
        if !name.is_empty() {
            valid.insert(name.to_string());
        }
    }
    valid
}

/// Resolve the most appropriate existing proxy-group name to use as a default fallback target.
pub fn resolve_default_fallback_group_name(cfg: &AppConfig, groups: &[MultiGroup]) -> String {
    if cfg.route_mode == RouteTargetMode::Single
        && cfg
            .active_single_node_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
    {
        return SINGLE_NODE_GROUP_NAME.to_string();
    }
    if let Some(active_id) = cfg.active_group_id.as_deref() {
        if let Some(found) = groups
            .iter()
            .find(|g| g.id == active_id && !g.name.trim().is_empty())
        {
            return found.name.trim().to_string();
        }
    }
    if let Some(first) = groups.iter().find(|g| !g.name.trim().is_empty()) {
        return first.name.trim().to_string();
    }
    DEFAULT_FALLBACK_GROUP_NAME.to_string()
}

/// Cascade group rename (`new_name = Some(...)`) or deletion (`new_name = None`) across
/// `cfg.rules_override.global_prepend_rules`, `global_append_rules`, and `subscription_rule_bindings`,
/// preventing `unknown_rule_target` static validation failures after renaming/deleting a group.
pub fn cascade_group_name_change_in_global_rules(
    cfg: &mut AppConfig,
    old_group_name: &str,
    new_group_name: Option<&str>,
) -> usize {
    let old_name = old_group_name.trim();
    if old_name.is_empty() {
        return 0;
    }
    let next_name = new_group_name.map(str::trim).filter(|s| !s.is_empty());
    if next_name == Some(old_name) {
        return 0;
    }
    let mut touched = 0usize;
    let mut transform = |list: &mut Vec<String>| {
        let mut out: Vec<String> = Vec::with_capacity(list.len());
        let mut seen: HashSet<String> = HashSet::new();
        for raw in list.drain(..) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if extract_mihomo_rule_target(trimmed) == Some(old_name) {
                touched += 1;
                if let Some(dest) = next_name {
                    if let Some(rebuilt) = rewrite_mihomo_rule_target(trimmed, dest) {
                        if seen.insert(rebuilt.clone()) {
                            out.push(rebuilt);
                        }
                    }
                }
            } else if seen.insert(trimmed.to_string()) {
                out.push(trimmed.to_string());
            }
        }
        *list = out;
    };
    transform(&mut cfg.rules_override.global_prepend_rules);
    transform(&mut cfg.rules_override.global_append_rules);

    if touched > 0 {
        let mut empty_keys: Vec<String> = Vec::new();
        for (sub_id, binding) in &mut cfg.rules_override.subscription_rule_bindings {
            let sync_one = |list: &mut Vec<String>| {
                let mut out: Vec<String> = Vec::with_capacity(list.len());
                let mut seen: HashSet<String> = HashSet::new();
                for raw in list.drain(..) {
                    let trimmed = raw.trim();
                    if extract_mihomo_rule_target(trimmed) == Some(old_name) {
                        if let Some(dest) = next_name {
                            if let Some(rebuilt) = rewrite_mihomo_rule_target(trimmed, dest) {
                                if seen.insert(rebuilt.clone()) {
                                    out.push(rebuilt);
                                }
                            }
                        }
                    } else if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
                        out.push(trimmed.to_string());
                    }
                }
                *list = out;
            };
            sync_one(&mut binding.prepend_rules);
            sync_one(&mut binding.append_rules);
            if binding.prepend_rules.is_empty() && binding.append_rules.is_empty() {
                empty_keys.push(sub_id.clone());
            }
        }
        for k in empty_keys {
            cfg.rules_override.subscription_rule_bindings.remove(&k);
        }
    }

    touched
}

/// Inspect `cfg.rules_override.global_prepend_rules` and `global_append_rules` for rules
/// referencing proxy/group names that do not exist in the current library.
pub fn audit_dangling_global_rules(
    cfg: &AppConfig,
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
) -> DanglingRulesAudit {
    let valid_targets = collect_valid_rule_target_names(groups, nodes);
    let mut by_target: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut total_dangling = 0usize;

    for raw in cfg
        .rules_override
        .global_prepend_rules
        .iter()
        .chain(cfg.rules_override.global_append_rules.iter())
    {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(target) = extract_mihomo_rule_target(trimmed) {
            if !valid_targets.contains(target) {
                total_dangling += 1;
                let entry = by_target
                    .entry(target.to_string())
                    .or_insert_with(|| (0, Vec::new()));
                entry.0 += 1;
                if entry.1.len() < 3 {
                    entry.1.push(trimmed.to_string());
                }
            }
        }
    }

    let mut summary_groups: Vec<DanglingRuleGroupSummary> = by_target
        .into_iter()
        .map(|(target, (count, sample_rules))| DanglingRuleGroupSummary {
            target,
            count,
            sample_rules,
        })
        .collect();
    summary_groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.target.cmp(&b.target)));

    DanglingRulesAudit {
        total_dangling,
        groups: summary_groups,
        default_fallback_group: resolve_default_fallback_group_name(cfg, groups),
    }
}

/// Repair dangling global rules in `cfg.rules_override` either by removing them or by rewriting
/// their target to a valid existing group, keeping `subscription_rule_bindings` consistent.
pub fn repair_dangling_global_rules(
    cfg: &mut AppConfig,
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    action: DanglingRuleRepairAction,
    only_targets: Option<&[String]>,
) -> DanglingRuleRepairReport {
    let valid_targets = collect_valid_rule_target_names(groups, nodes);
    let filter_set: Option<HashSet<String>> = only_targets.map(|list| {
        list.iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });
    let mut affected_set: BTreeSet<String> = BTreeSet::new();
    let mut removed_count = 0usize;
    let mut rewritten_count = 0usize;
    let rewrite_target: Option<String> = match &action {
        DanglingRuleRepairAction::Remove => None,
        DanglingRuleRepairAction::RewriteToGroup { target_group } => {
            let t = target_group.trim();
            if t.is_empty() {
                Some(resolve_default_fallback_group_name(cfg, groups))
            } else {
                Some(t.to_string())
            }
        }
    };

    let mut rewrite_map: HashMap<String, Option<String>> = HashMap::new();
    let mut process_vec = |rules: &mut Vec<String>| {
        let mut next: Vec<String> = Vec::with_capacity(rules.len());
        let mut seen: HashSet<String> = HashSet::new();
        for raw in rules.drain(..) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let is_dangling_hit = extract_mihomo_rule_target(trimmed).and_then(|target| {
                if !valid_targets.contains(target)
                    && filter_set
                        .as_ref()
                        .is_none_or(|f| f.contains(target))
                {
                    Some(target.to_string())
                } else {
                    None
                }
            });

            if let Some(dangling_target) = is_dangling_hit {
                affected_set.insert(dangling_target);
                if let Some(dest) = rewrite_target.as_deref() {
                    if let Some(rebuilt) = rewrite_mihomo_rule_target(trimmed, dest) {
                        rewritten_count += 1;
                        rewrite_map.insert(trimmed.to_string(), Some(rebuilt.clone()));
                        if seen.insert(rebuilt.clone()) {
                            next.push(rebuilt);
                        }
                    } else {
                        removed_count += 1;
                        rewrite_map.insert(trimmed.to_string(), None);
                    }
                } else {
                    removed_count += 1;
                    rewrite_map.insert(trimmed.to_string(), None);
                }
            } else if seen.insert(trimmed.to_string()) {
                next.push(trimmed.to_string());
            }
        }
        *rules = next;
    };

    process_vec(&mut cfg.rules_override.global_prepend_rules);
    process_vec(&mut cfg.rules_override.global_append_rules);

    // Keep subscription_rule_bindings synchronized so future deletes stay exact.
    if !rewrite_map.is_empty() {
        let mut empty_sub_ids: Vec<String> = Vec::new();
        for (sub_id, binding) in &mut cfg.rules_override.subscription_rule_bindings {
            let sync_list = |list: &mut Vec<String>| {
                let mut out: Vec<String> = Vec::with_capacity(list.len());
                let mut seen: HashSet<String> = HashSet::new();
                for r in list.drain(..) {
                    let key = r.trim();
                    if let Some(mapped) = rewrite_map.get(key) {
                        if let Some(rebuilt) = mapped {
                            if seen.insert(rebuilt.clone()) {
                                out.push(rebuilt.clone());
                            }
                        }
                    } else if !key.is_empty() && seen.insert(key.to_string()) {
                        out.push(key.to_string());
                    }
                }
                *list = out;
            };
            sync_list(&mut binding.prepend_rules);
            sync_list(&mut binding.append_rules);
            if binding.prepend_rules.is_empty() && binding.append_rules.is_empty() {
                empty_sub_ids.push(sub_id.clone());
            }
        }
        for id in empty_sub_ids {
            cfg.rules_override.subscription_rule_bindings.remove(&id);
        }
    }

    DanglingRuleRepairReport {
        removed_count,
        rewritten_count,
        target_group: rewrite_target,
        affected_targets: affected_set.into_iter().collect(),
    }
}

/// Expand a multi-group match rule into one or more Mihomo rule strings.
///
/// - `@ai_domains` or `PRESET:AI` expands into `DEFAULT_AI_ROUTING_DOMAINS` bound to `group_name`.
/// - Single-segment bare Mihomo rule type names (e.g. `"DOMAIN-SUFFIX"`) or malformed strings
///   are safely ignored (empty `Vec`) instead of breaking `mihomo -t`.
/// - Single-segment valid domains (e.g. `"anthropic.com"`) auto-expand to `DOMAIN-SUFFIX,<domain>,<group>`.
/// - Logical composite rules (`AND`/`OR`/`NOT`) with balanced parentheses are preserved or bound to `group_name`.
/// - 2-part shorthand rules (`DOMAIN-SUFFIX,openai.com`) with a valid non-`MATCH` rule type
///   and non-empty payload expand to `{RULE_TYPE_UPPER},{payload},{group_name}`.
/// - 3-part rules ending in `no-resolve` insert `group_name` before `no-resolve`; otherwise
///   kept only when `rule_type` is valid and all 3 segments are non-empty.
pub fn expand_group_match_rule(rule: &str, group_name: &str) -> Vec<String> {
    expand_group_match_rule_with_known_targets(rule, group_name, None)
}

pub(super) fn expand_group_match_rule_with_known_targets(
    rule: &str,
    group_name: &str,
    known_targets: Option<&HashSet<String>>,
) -> Vec<String> {
    let trimmed = rule.trim();
    let target = group_name.trim();
    if trimmed.is_empty() || target.is_empty() {
        return Vec::new();
    }
    if trimmed.eq_ignore_ascii_case("@ai_domains") || trimmed.eq_ignore_ascii_case("PRESET:AI") {
        return build_default_ai_routing_rules(target);
    }

    if let Some((raw_type, rest)) = trimmed.split_once(',') {
        let rt_raw = raw_type.trim();
        if is_logical_rule_type(rt_raw) {
            let rt = rt_raw.to_ascii_uppercase();
            let Some((expr, after)) = split_leading_balanced_paren_expr(rest) else {
                return Vec::new();
            };
            if !is_valid_logical_condition_expr(&rt, expr) {
                return Vec::new();
            }
            if after.is_empty() {
                return vec![format!("{rt},{expr},{target}")];
            }
            if let Some(after_comma) = after.strip_prefix(',') {
                let action = after_comma.trim();
                if !action.is_empty() && !action.contains(',') && !is_mihomo_rule_flag(action) {
                    return vec![format!("{rt},{expr},{action}")];
                }
            }
            return Vec::new();
        }
        if rt_raw.eq_ignore_ascii_case("SUB-RULE") {
            if let Some((expr, sub_name)) = parse_sub_rule_expr_and_target(rest) {
                return vec![format!("SUB-RULE,{expr},{sub_name}")];
            }
            return Vec::new();
        }
        if is_regex_rule_type(rt_raw) {
            let rt = rt_raw.to_ascii_uppercase();
            let rest_trimmed = rest.trim();
            if rest_trimmed.is_empty() {
                return Vec::new();
            }
            if let Some((pattern, tail)) = rest_trimmed.rsplit_once(',') {
                let pattern = pattern.trim();
                let tail = tail.trim();
                let is_explicit_target = !pattern.is_empty()
                    && !tail.is_empty()
                    && (is_builtin_rule_action(tail)
                        || tail == target
                        || known_targets.is_some_and(|set| set.contains(tail)));
                if is_explicit_target {
                    return vec![format!("{rt},{pattern},{tail}")];
                }
            }
            return vec![format!("{rt},{rest_trimmed},{target}")];
        }
    }

    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    match parts.as_slice() {
        [single] => {
            if let Some(domain) = normalize_bare_domain_candidate(single) {
                vec![format!("DOMAIN-SUFFIX,{domain},{target}")]
            } else {
                Vec::new()
            }
        }
        [rule_type, payload] => {
            if is_valid_mihomo_rule_type(rule_type)
                && !rule_type.eq_ignore_ascii_case("MATCH")
                && !payload.is_empty()
            {
                vec![format!(
                    "{},{payload},{target}",
                    rule_type.to_ascii_uppercase()
                )]
            } else {
                Vec::new()
            }
        }
        [rule_type, payload, third] => {
            if !is_valid_mihomo_rule_type(rule_type)
                || rule_type.eq_ignore_ascii_case("MATCH")
                || payload.is_empty()
                || third.is_empty()
            {
                return Vec::new();
            }
            let rt = rule_type.to_ascii_uppercase();
            if is_mihomo_rule_flag(third) {
                vec![format!("{rt},{payload},{target},{}", third.to_ascii_lowercase())]
            } else {
                vec![format!("{rt},{payload},{third}")]
            }
        }
        [rule_type, payload, third, fourth] => {
            if !is_valid_mihomo_rule_type(rule_type)
                || rule_type.eq_ignore_ascii_case("MATCH")
                || payload.is_empty()
                || third.is_empty()
                || fourth.is_empty()
            {
                return Vec::new();
            }
            let rt = rule_type.to_ascii_uppercase();
            if is_mihomo_rule_flag(third) && is_mihomo_rule_flag(fourth) {
                vec![format!(
                    "{rt},{payload},{target},{},{}",
                    third.to_ascii_lowercase(),
                    fourth.to_ascii_lowercase()
                )]
            } else {
                vec![format!("{rt},{payload},{third},{fourth}")]
            }
        }
        _ => Vec::new(),
    }
}

/// Parse pasted raw Mihomo rule text line-by-line:
/// - Ignores blank lines, `#` comment lines, and `rules:` section header lines.
/// - Strips leading YAML sequence markers (`- ` / `-\t`), paired single/double quotes,
///   and trailing unquoted `# comments`.
/// - Validates all `VALID_MIHOMO_RULE_TYPES` (including `RULE-SET`, `GEOSITE`, `GEOIP`,
///   `AND`/`OR`/`NOT`, `MATCH`, and `SUB-RULE`), deduplicating valid rules in order.
pub fn parse_bulk_rules_text(raw: &str) -> BulkRulesParseResult {
    let mut valid_rules: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut skipped_lines: Vec<String> = Vec::new();

    for raw_line in raw.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(after_rules) = trimmed
            .get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("rules:"))
            .map(|_| trimmed[6..].trim())
        {
            if after_rules.is_empty() || after_rules.starts_with('#') {
                continue;
            }
        }
        let Some(candidate) = strip_yaml_list_rule_line(trimmed) else {
            continue;
        };
        if is_plausible_global_rule(&candidate) {
            let normalized = normalize_global_rule_for_emit(&candidate);
            if seen.insert(normalized.clone()) {
                valid_rules.push(normalized);
            }
        } else {
            skipped_lines.push(trimmed.to_string());
        }
    }

    BulkRulesParseResult {
        valid_rules,
        skipped_lines,
    }
}

/// Ensure mandatory anti-loop, isolated probe core bypass, and private LAN/DNS safety rules
/// always remain deduplicated at the top of `doc["rules"]`, even when a YAML Merge Patch or
/// `inline_override_yaml` replaces `rules:` via RFC 7396 semantics.
pub(super) fn enforce_mandatory_safety_rules_at_top(doc: &mut Value, mandatory_safety_rules: &[String]) {
    let Some(root_map) = doc.as_mapping_mut() else {
        return;
    };
    let existing_rules: Vec<Value> = root_map
        .get("rules")
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();

    let mut merged: Vec<Value> =
        Vec::with_capacity(mandatory_safety_rules.len() + existing_rules.len());
    let mut seen_ci: HashSet<String> = HashSet::new();

    for rule in mandatory_safety_rules {
        let normalized = normalize_global_rule_for_emit(rule);
        if normalized.is_empty() {
            continue;
        }
        if seen_ci.insert(normalized.to_ascii_lowercase()) {
            merged.push(Value::String(normalized));
        }
    }
    for item in existing_rules {
        if let Some(raw) = item.as_str() {
            let normalized = normalize_global_rule_for_emit(raw);
            if normalized.is_empty() {
                continue;
            }
            if seen_ci.insert(normalized.to_ascii_lowercase()) {
                merged.push(Value::String(normalized));
            }
        } else {
            merged.push(item);
        }
    }
    root_map.insert(str_val("rules"), Value::Sequence(merged));
}

fn strip_unquoted_inline_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) {
            return s[..i].trim_end();
        }
    }
    s.trim_end()
}

fn strip_yaml_list_rule_line(trimmed_line: &str) -> Option<String> {
    let mut s = trimmed_line.trim();
    if s.is_empty() || s.starts_with('#') || s == "-" {
        return None;
    }
    if let Some(rest) = s.strip_prefix("- ").or_else(|| s.strip_prefix("-\t")) {
        s = rest.trim_start();
    }
    if s.is_empty() || s.starts_with('#') {
        return None;
    }

    let cleaned = if let Some(inner_rest) = s.strip_prefix('"') {
        let mut out = String::with_capacity(inner_rest.len());
        let mut chars = inner_rest.chars();
        let mut closed = false;
        let mut remainder = "";
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                } else {
                    out.push('\\');
                }
            } else if ch == '"' {
                closed = true;
                remainder = chars.as_str().trim();
                break;
            } else {
                out.push(ch);
            }
        }
        if closed && (remainder.is_empty() || remainder.starts_with('#')) {
            out
        } else {
            strip_unquoted_inline_comment(s).to_string()
        }
    } else if let Some(inner_rest) = s.strip_prefix('\'') {
        let mut out = String::with_capacity(inner_rest.len());
        let mut chars = inner_rest.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                    out.push('\'');
                } else {
                    let tail: String = chars.collect();
                    let tail_trimmed = tail.trim();
                    if tail_trimmed.is_empty() || tail_trimmed.starts_with('#') {
                        let res = out.trim();
                        return if res.is_empty() || res.starts_with('#') {
                            None
                        } else {
                            Some(res.to_string())
                        };
                    }
                    break;
                }
            } else {
                out.push(ch);
            }
        }
        strip_unquoted_inline_comment(s).to_string()
    } else {
        strip_unquoted_inline_comment(s).to_string()
    };

    let final_str = cleaned.trim();
    if final_str.is_empty() || final_str.starts_with('#') {
        None
    } else {
        Some(final_str.to_string())
    }
}

/// Extract all `RULE-SET,<provider>` provider names referenced by a top-level or logical rule line.
pub(super) fn extract_rule_set_provider_names(rule: &str) -> Vec<String> {
    let mut providers: Vec<String> = Vec::new();
    let trimmed = rule.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return providers;
    }

    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("RULE-SET") && !parts[1].is_empty() {
        push_unique(&mut providers, parts[1].to_string());
        return providers;
    }

    // Also inspect nested logical expressions such as `AND,((RULE-SET,foo),(DST-PORT,443)),DIRECT`.
    let upper = trimmed.to_ascii_uppercase();
    let needle = "(RULE-SET,";
    let mut search_from = 0usize;
    while let Some(rel) = upper[search_from..].find(needle) {
        let name_start = search_from + rel + needle.len();
        let tail = &trimmed[name_start..];
        let name_end = tail.find([',', ')']).unwrap_or(tail.len());
        let name = tail[..name_end].trim();
        if !name.is_empty() {
            push_unique(&mut providers, name.to_string());
        }
        search_from = name_start + name_end;
    }

    providers
}
