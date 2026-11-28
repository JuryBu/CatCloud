use regex::RegexBuilder;
use serde_yaml_ng::Value;
use std::net::IpAddr;

/// Maximum allowed nesting depth for recursive logical rules (`AND` / `OR` / `NOT`)
/// to guard against stack overflow on hostile or malformed rule trees.
pub const MAX_LOGICAL_RULE_DEPTH: usize = 16;

/// Upper bound on regex pattern length accepted by the offline rule matcher.
const MAX_REGEX_PATTERN_LEN: usize = 2048;

/// Upper bound on compiled regex and DFA memory budget (256 KiB).
const REGEX_SIZE_LIMIT_BYTES: usize = 256 * 1024;

/// Query inputs for offline Mihomo routing rule evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleMatchQuery {
    pub host: String,
    pub network: String, // "tcp" | "udp"
    pub port: u16,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

/// Structured outcome produced by [`evaluate_compiled_rules`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleMatchOutcome {
    pub matched: bool,
    pub matched_rule: Option<String>,
    pub matched_rule_index: Option<usize>,
    pub matched_rule_type: Option<String>,
    pub policy: Option<String>,
    pub skipped_geo_rules: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionEval {
    Matched,
    NotMatched,
    UnknownGeo,
    UnknownContext,
    Invalid,
}

#[derive(Debug, Clone)]
struct NormalizedQuery {
    host: String,
    parsed_ip: Option<IpAddr>,
    network: String,
    port: u16,
    process_name: Option<String>,
    process_path_raw: Option<String>,
    process_path_normalized: Option<String>,
}

impl NormalizedQuery {
    fn from_query(query: &RuleMatchQuery) -> Self {
        let host = query.host.trim().trim_end_matches('.').to_ascii_lowercase();
        let parsed_ip = host.parse::<IpAddr>().ok();
        let network = query.network.trim().to_ascii_lowercase();

        let process_path_raw = query
            .process_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        let process_path_normalized = process_path_raw
            .as_deref()
            .map(|p| p.replace('\\', "/"));

        let explicit_name = query
            .process_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        // Cross-platform basename derivation when `process_name` is omitted but `process_path` is provided.
        let process_name = explicit_name.or_else(|| {
            process_path_raw.as_deref().and_then(|p| {
                p.trim_end_matches(['/', '\\'])
                    .rsplit(['/', '\\'])
                    .next()
                    .filter(|seg| !seg.is_empty())
                    .map(ToString::to_string)
            })
        });

        Self {
            host,
            parsed_ip,
            network,
            port: query.port,
            process_name,
            process_path_raw,
            process_path_normalized,
        }
    }
}

/// Evaluate a query against the compiled YAML's `rules` sequence using Mihomo-aligned semantics.
///
/// Directly inspects `compiled_value.get("rules")` without manual YAML text line scanning.
pub fn evaluate_compiled_rules(
    compiled_value: &Value,
    query: &RuleMatchQuery,
) -> RuleMatchOutcome {
    let norm = NormalizedQuery::from_query(query);
    let mut outcome = RuleMatchOutcome::default();

    let Some(rules_seq) = compiled_value.get("rules").and_then(Value::as_sequence) else {
        return outcome;
    };

    for (idx, item) in rules_seq.iter().enumerate() {
        let Some(raw_rule) = item.as_str() else {
            continue;
        };
        let Some((rtype, payload, policy)) = split_compiled_rule_parts(raw_rule) else {
            continue;
        };

        match eval_condition(&rtype, payload, &norm, 0) {
            ConditionEval::Matched => {
                outcome.matched = true;
                outcome.matched_rule = Some(raw_rule.trim().to_string());
                outcome.matched_rule_index = Some(idx);
                outcome.matched_rule_type = Some(rtype);
                outcome.policy = Some(policy.to_string());
                break;
            }
            ConditionEval::UnknownGeo => {
                outcome.skipped_geo_rules.push(raw_rule.trim().to_string());
            }
            ConditionEval::NotMatched | ConditionEval::UnknownContext | ConditionEval::Invalid => {}
        }
    }

    outcome
}

/// Check whether `host` matches any entry in `compiled_value["dns"]["fake-ip-filter"]`.
pub fn matches_compiled_fake_ip_filter(compiled_value: &Value, host: &str) -> bool {
    let Some(filters) = compiled_value
        .get("dns")
        .and_then(|dns| dns.get("fake-ip-filter"))
        .and_then(Value::as_sequence)
    else {
        return false;
    };
    filters
        .iter()
        .filter_map(Value::as_str)
        .any(|pat| domain_matches_wildcard(pat, host))
}

/// Match a domain against Clash/Mihomo wildcard patterns (`+.example.com`, `*.example.com`,
/// `*`, `?`, or exact match, case-insensitive).
pub fn domain_matches_wildcard(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() || h.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix("+.") {
        return !suffix.is_empty() && (h == suffix || h.ends_with(&format!(".{suffix}")));
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        if !suffix.is_empty() && !suffix.contains('*') && !suffix.contains('?') {
            // Mihomo `*.example.com` matches exactly one subdomain label (`a.example.com`), not multi-level.
            return h
                .strip_suffix(&format!(".{suffix}"))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'));
        }
    }
    if !p.contains('*') && !p.contains('?') {
        return h == p;
    }
    glob_match(&p, &h)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_mihomo_rule_flag(token: &str) -> bool {
    let trimmed = token.trim();
    trimmed.eq_ignore_ascii_case("no-resolve") || trimmed.eq_ignore_ascii_case("src")
}

fn is_logical_rule_type(rtype: &str) -> bool {
    matches!(rtype, "AND" | "OR" | "NOT")
}

fn is_regex_rule_type(rtype: &str) -> bool {
    matches!(
        rtype,
        "DOMAIN-REGEX" | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX"
    )
}

fn has_balanced_parens(expr: &str) -> bool {
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
                if depth == 0 && chars.peek().is_some() {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

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

/// Split a compiled top-level Mihomo rule into `(RULE_TYPE_UPPER, payload, policy)`.
fn split_compiled_rule_parts(raw_rule: &str) -> Option<(String, &str, &str)> {
    let trimmed = raw_rule.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (raw_type, rest) = trimmed.split_once(',')?;
    let rtype = raw_type.trim().to_ascii_uppercase();
    if rtype.is_empty() || rtype == "SUB-RULE" {
        return None;
    }

    if rtype == "MATCH" {
        let policy = rest.trim();
        if policy.is_empty() || policy.contains(',') {
            return None;
        }
        return Some((rtype, "", policy));
    }

    if is_logical_rule_type(&rtype) {
        // Mihomo real syntax: `<TYPE>,((...)),<TARGET>` (no top-level trailing `no-resolve`/`src`).
        let (expr, after) = split_leading_balanced_paren_expr(rest)?;
        let after_comma = after.strip_prefix(',')?;
        let policy = after_comma.trim();
        if policy.is_empty() || policy.contains(',') || is_mihomo_rule_flag(policy) {
            return None;
        }
        return Some((rtype, expr, policy));
    }

    if is_regex_rule_type(&rtype) {
        // Regex payloads may contain `{1,3}` commas and escaped parens `\(bar`.
        let (pattern, policy) = rest.rsplit_once(',')?;
        let pattern = pattern.trim();
        let policy = policy.trim();
        if pattern.is_empty() || policy.is_empty() || is_mihomo_rule_flag(policy) {
            return None;
        }
        return Some((rtype, pattern, policy));
    }

    // Standard rules (strip optional trailing `no-resolve` / `src` flags).
    let mut remainder = rest.trim();
    let mut has_src_flag = false;
    loop {
        if let Some((head, tail)) = remainder.rsplit_once(',') {
            if is_mihomo_rule_flag(tail) {
                if tail.trim().eq_ignore_ascii_case("src") {
                    has_src_flag = true;
                }
                remainder = head.trim();
                continue;
            }
        }
        break;
    }

    let (payload, policy) = remainder.rsplit_once(',')?;
    let payload = payload.trim();
    let policy = policy.trim();
    if payload.is_empty() || policy.is_empty() || is_mihomo_rule_flag(policy) {
        return None;
    }
    if has_src_flag {
        return Some((format!("{rtype}:SRC"), payload, policy));
    }
    Some((rtype, payload, policy))
}

/// Split a Mihomo double-parenthesized logical payload `((...),(...))` into its inner clause bodies.
///
/// Strictly rejects:
/// - empty `()`
/// - single-parenthesized `(DOMAIN,a.com)` (including single-layer `NOT,(...)`)
/// - empty sub-clauses `((DOMAIN,a.com),())` or trailing commas `((DOMAIN,a.com),)`
/// - juxtaposed unbalanced groups `(A),(B)`
fn split_logical_children_strict(expr: &str) -> Option<Vec<&str>> {
    if !has_balanced_parens(expr) {
        return None;
    }
    let trimmed = expr.trim();
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return None;
    }

    let mut raw_clauses: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            ',' if depth == 0 => {
                raw_clauses.push(inner[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    raw_clauses.push(inner[start..].trim());
    if raw_clauses.is_empty() {
        return None;
    }

    let mut bodies = Vec::with_capacity(raw_clauses.len());
    for clause in raw_clauses {
        if !has_balanced_parens(clause) {
            return None;
        }
        let body = clause[1..clause.len() - 1].trim();
        if body.is_empty() {
            return None;
        }
        bodies.push(body);
    }
    Some(bodies)
}

/// Split one parenthesized sub-condition body (already stripped of its outer `(...)`),
/// e.g. `PROCESS-NAME,QQ.exe`, `GEOIP,CN,no-resolve`, `DOMAIN-REGEX,^a{1,3}\.com$`,
/// or nested `OR,((DST-PORT,80),(DST-PORT,443))`.
fn split_sub_condition_body(body: &str) -> Option<(String, &str)> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (raw_type, rest) = trimmed.split_once(',')?;
    let rtype = raw_type.trim().to_ascii_uppercase();
    if rtype.is_empty() {
        return None;
    }
    let rest_trimmed = rest.trim();
    if rest_trimmed.is_empty() {
        return None;
    }

    if is_logical_rule_type(&rtype) {
        if !has_balanced_parens(rest_trimmed) {
            return None;
        }
        return Some((rtype, rest_trimmed));
    }

    if is_regex_rule_type(&rtype) {
        return Some((rtype, rest_trimmed));
    }

    // Strip optional trailing `no-resolve` / `src` flags inside sub-condition clauses
    // (e.g. `GEOIP,CN,no-resolve` -> `("GEOIP", "CN")`).
    // Preserve `src` via `:SRC` suffix so `eval_condition` treats it as UnknownContext
    // (preventing `NOT,((IP-CIDR,10.0.0.0/8,src))` from falsely inverting to Matched).
    let mut payload = rest_trimmed;
    let mut has_src_flag = false;
    loop {
        if let Some((head, tail)) = payload.rsplit_once(',') {
            if is_mihomo_rule_flag(tail) {
                if tail.trim().eq_ignore_ascii_case("src") {
                    has_src_flag = true;
                }
                payload = head.trim();
                continue;
            }
        }
        break;
    }
    if payload.is_empty() {
        return None;
    }
    let effective_type = if has_src_flag {
        format!("{rtype}:SRC")
    } else {
        rtype
    };
    Some((effective_type, payload))
}

fn compile_safe_regex(pattern: &str) -> Option<regex::Regex> {
    let pat = pattern.trim();
    if pat.is_empty() || pat.len() > MAX_REGEX_PATTERN_LEN {
        return None;
    }
    RegexBuilder::new(pat)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .build()
        .ok()
}

fn ip_matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    match (ip, net_str.trim().parse::<IpAddr>()) {
        (IpAddr::V4(addr), Ok(IpAddr::V4(net))) if prefix <= 32 => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(addr) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(addr), Ok(IpAddr::V6(net))) if prefix <= 128 => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(addr) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

fn port_matches_spec(port: u16, spec: &str) -> bool {
    for part in spec.split('/') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = p.split_once('-') {
            if let (Ok(a), Ok(b)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                if a <= b && port >= a && port <= b {
                    return true;
                }
            }
        } else if let Ok(exact) = p.parse::<u16>() {
            if port == exact {
                return true;
            }
        }
    }
    false
}

fn eval_condition(
    rule_type: &str,
    payload: &str,
    query: &NormalizedQuery,
    depth: usize,
) -> ConditionEval {
    match rule_type {
        "MATCH" => ConditionEval::Matched,
        "DOMAIN" => {
            if query.parsed_ip.is_some() {
                return ConditionEval::NotMatched;
            }
            let target = payload.trim().trim_end_matches('.');
            if !target.is_empty() && query.host.eq_ignore_ascii_case(target) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-SUFFIX" => {
            if query.parsed_ip.is_some() {
                return ConditionEval::NotMatched;
            }
            let suffix = payload
                .trim()
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !suffix.is_empty()
                && (query.host == suffix || query.host.ends_with(&format!(".{suffix}")))
            {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-KEYWORD" => {
            if query.parsed_ip.is_some() {
                return ConditionEval::NotMatched;
            }
            let kw = payload.trim().to_ascii_lowercase();
            if !kw.is_empty() && query.host.contains(&kw) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-WILDCARD" => {
            if query.parsed_ip.is_some() {
                return ConditionEval::NotMatched;
            }
            if domain_matches_wildcard(payload, &query.host) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-REGEX" => {
            if query.host.is_empty() || query.parsed_ip.is_some() {
                return ConditionEval::NotMatched;
            }
            match compile_safe_regex(payload) {
                Some(re) if re.is_match(&query.host) => ConditionEval::Matched,
                Some(_) => ConditionEval::NotMatched,
                None => ConditionEval::Invalid,
            }
        }
        "IP-CIDR" | "IP-CIDR6" => match query.parsed_ip {
            Some(ip) if ip_matches_cidr(ip, payload) => ConditionEval::Matched,
            _ => ConditionEval::NotMatched,
        },
        "NETWORK" => {
            let expected = payload.trim();
            if !expected.is_empty() && query.network.eq_ignore_ascii_case(expected) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DST-PORT" => {
            if port_matches_spec(query.port, payload) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "PROCESS-NAME" => {
            let Some(ref pname) = query.process_name else {
                return ConditionEval::UnknownContext;
            };
            let target = payload.trim();
            if !target.is_empty() && pname.eq_ignore_ascii_case(target) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "PROCESS-NAME-REGEX" => {
            let Some(ref pname) = query.process_name else {
                return ConditionEval::UnknownContext;
            };
            match compile_safe_regex(payload) {
                Some(re) if re.is_match(pname) => ConditionEval::Matched,
                Some(_) => ConditionEval::NotMatched,
                None => ConditionEval::Invalid,
            }
        }
        "PROCESS-PATH" => {
            let Some(ref ppath) = query.process_path_normalized else {
                return ConditionEval::UnknownContext;
            };
            let target = payload.trim().replace('\\', "/");
            if !target.is_empty() && ppath.eq_ignore_ascii_case(&target) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "PROCESS-PATH-REGEX" => {
            let Some(ref ppath_norm) = query.process_path_normalized else {
                return ConditionEval::UnknownContext;
            };
            match compile_safe_regex(payload) {
                Some(re) => {
                    let matched = re.is_match(ppath_norm)
                        || query
                            .process_path_raw
                            .as_deref()
                            .is_some_and(|raw| re.is_match(raw));
                    if matched {
                        ConditionEval::Matched
                    } else {
                        ConditionEval::NotMatched
                    }
                }
                None => ConditionEval::Invalid,
            }
        }
        "GEOSITE" | "GEOIP" => ConditionEval::UnknownGeo,
        "AND" => {
            if depth >= MAX_LOGICAL_RULE_DEPTH {
                return ConditionEval::Invalid;
            }
            let Some(children) = split_logical_children_strict(payload) else {
                return ConditionEval::Invalid;
            };
            let mut parsed_children = Vec::with_capacity(children.len());
            for child in children {
                let Some(pair) = split_sub_condition_body(child) else {
                    return ConditionEval::Invalid;
                };
                parsed_children.push(pair);
            }
            let mut saw_unknown_geo = false;
            let mut saw_unknown_ctx = false;
            for (sub_type, sub_payload) in parsed_children {
                match eval_condition(&sub_type, sub_payload, query, depth + 1) {
                    ConditionEval::Matched => {}
                    ConditionEval::NotMatched => return ConditionEval::NotMatched,
                    ConditionEval::Invalid => return ConditionEval::Invalid,
                    ConditionEval::UnknownGeo => saw_unknown_geo = true,
                    ConditionEval::UnknownContext => saw_unknown_ctx = true,
                }
            }
            if saw_unknown_ctx {
                ConditionEval::UnknownContext
            } else if saw_unknown_geo {
                ConditionEval::UnknownGeo
            } else {
                ConditionEval::Matched
            }
        }
        "OR" => {
            if depth >= MAX_LOGICAL_RULE_DEPTH {
                return ConditionEval::Invalid;
            }
            let Some(children) = split_logical_children_strict(payload) else {
                return ConditionEval::Invalid;
            };
            let mut parsed_children = Vec::with_capacity(children.len());
            for child in children {
                let Some(pair) = split_sub_condition_body(child) else {
                    return ConditionEval::Invalid;
                };
                parsed_children.push(pair);
            }
            let mut saw_unknown_geo = false;
            let mut saw_unknown_ctx = false;
            let mut saw_invalid = false;
            for (sub_type, sub_payload) in parsed_children {
                match eval_condition(&sub_type, sub_payload, query, depth + 1) {
                    ConditionEval::Matched => return ConditionEval::Matched,
                    ConditionEval::NotMatched => {}
                    ConditionEval::Invalid => saw_invalid = true,
                    ConditionEval::UnknownGeo => saw_unknown_geo = true,
                    ConditionEval::UnknownContext => saw_unknown_ctx = true,
                }
            }
            if saw_invalid {
                ConditionEval::Invalid
            } else if saw_unknown_geo {
                ConditionEval::UnknownGeo
            } else if saw_unknown_ctx {
                ConditionEval::UnknownContext
            } else {
                ConditionEval::NotMatched
            }
        }
        "NOT" => {
            if depth >= MAX_LOGICAL_RULE_DEPTH {
                return ConditionEval::Invalid;
            }
            // Mihomo strictly requires double-parenthesized `NOT,((...)),TARGET`.
            let Some(children) = split_logical_children_strict(payload) else {
                return ConditionEval::Invalid;
            };
            if children.len() != 1 {
                return ConditionEval::Invalid;
            }
            let Some((sub_type, sub_payload)) = split_sub_condition_body(children[0]) else {
                return ConditionEval::Invalid;
            };
            match eval_condition(&sub_type, sub_payload, query, depth + 1) {
                ConditionEval::Matched => ConditionEval::NotMatched,
                ConditionEval::NotMatched => ConditionEval::Matched,
                ConditionEval::UnknownGeo => ConditionEval::UnknownGeo,
                ConditionEval::UnknownContext => ConditionEval::UnknownContext,
                ConditionEval::Invalid => ConditionEval::Invalid,
            }
        }
        other if other.ends_with(":SRC") => ConditionEval::UnknownContext,
        // Unimplemented offline rule types (RULE-SET, SRC-IP-CIDR, SRC-PORT, IP-ASN, UID, IN-*)
        // must NOT evaluate to `NotMatched`, otherwise `NOT,((RULE-SET,...))` would falsely match.
        _ => ConditionEval::UnknownContext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_with_rules(rules: &[&str]) -> Value {
        let mut seq = Vec::with_capacity(rules.len());
        for r in rules {
            seq.push(Value::String((*r).to_string()));
        }
        let mut root = serde_yaml_ng::Mapping::new();
        root.insert(Value::String("rules".to_string()), Value::Sequence(seq));
        Value::Mapping(root)
    }

    #[test]
    fn matches_standard_domain_ip_network_port_and_regex_rules() {
        let doc = yaml_with_rules(&[
            "DOMAIN,exact.example.com,Group-Exact",
            "DOMAIN-SUFFIX,codeium.com,Group-WSF",
            "DOMAIN-KEYWORD,openai,Group-AI",
            "DOMAIN-WILDCARD,*.cdn.example.net,Group-Wild",
            r"DOMAIN-REGEX,^a{1,3}\.regex\.test$,Group-Regex",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
            "AND,((NETWORK,UDP),(DST-PORT,8000-9000/15000)),Group-UDP",
            "MATCH,Fallback",
        ]);

        let q_exact = RuleMatchQuery {
            host: "EXACT.EXAMPLE.COM".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        let r_exact = evaluate_compiled_rules(&doc, &q_exact);
        assert!(r_exact.matched);
        assert_eq!(r_exact.policy.as_deref(), Some("Group-Exact"));
        assert_eq!(r_exact.matched_rule_index, Some(0));

        let q_suffix = RuleMatchQuery {
            host: "server.codeium.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_suffix).policy.as_deref(),
            Some("Group-WSF")
        );

        let q_kw = RuleMatchQuery {
            host: "api.openai.org".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_kw).policy.as_deref(),
            Some("Group-AI")
        );

        let q_wild = RuleMatchQuery {
            host: "edge.cdn.example.net".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_wild).policy.as_deref(),
            Some("Group-Wild")
        );

        let q_regex = RuleMatchQuery {
            host: "aaa.regex.test".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        let r_regex = evaluate_compiled_rules(&doc, &q_regex);
        assert_eq!(r_regex.policy.as_deref(), Some("Group-Regex"));
        assert_eq!(r_regex.matched_rule_type.as_deref(), Some("DOMAIN-REGEX"));

        let q_v4 = RuleMatchQuery {
            host: "10.20.30.40".to_string(),
            network: "tcp".to_string(),
            port: 80,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_v4).policy.as_deref(),
            Some("DIRECT")
        );

        let q_v6 = RuleMatchQuery {
            host: "fe80::1".to_string(),
            network: "tcp".to_string(),
            port: 80,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_v6).policy.as_deref(),
            Some("DIRECT")
        );

        let q_udp_range = RuleMatchQuery {
            host: "game.example".to_string(),
            network: "udp".to_string(),
            port: 8500,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_udp_range).policy.as_deref(),
            Some("Group-UDP")
        );

        let q_udp_list = RuleMatchQuery {
            host: "game.example".to_string(),
            network: "udp".to_string(),
            port: 15000,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_udp_list).policy.as_deref(),
            Some("Group-UDP")
        );
    }

    #[test]
    fn matches_process_name_path_and_composite_and_rules_with_cross_platform_basename() {
        let doc = yaml_with_rules(&[
            "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT",
            r"PROCESS-PATH,C:\Program Files\Tencent\WeChat\WeChat.exe,DIRECT",
            r"PROCESS-NAME-REGEX,^windsurf.*\.exe$,AI (日本)",
            r"PROCESS-PATH-REGEX,.*/devin/agent\.exe$,AI (日本)",
            "MATCH,Fallback",
        ]);

        // 1. Explicit process_name + matching port hits AND rule (case-insensitive)
        let q_qq = RuleMatchQuery {
            host: "203.0.113.10".to_string(),
            network: "tcp".to_string(),
            port: 15000,
            process_name: Some("qq.exe".to_string()),
            process_path: None,
        };
        let r_qq = evaluate_compiled_rules(&doc, &q_qq);
        assert!(r_qq.matched);
        assert_eq!(r_qq.policy.as_deref(), Some("DIRECT"));
        assert_eq!(r_qq.matched_rule_type.as_deref(), Some("AND"));
        assert_eq!(
            r_qq.matched_rule.as_deref(),
            Some("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT")
        );

        // 2. Cross-platform basename extraction from Windows path when process_name is None
        let q_qq_from_path = RuleMatchQuery {
            host: "203.0.113.10".to_string(),
            network: "tcp".to_string(),
            port: 15000,
            process_name: None,
            process_path: Some(r"C:\Program Files\Tencent\QQNT\QQ.exe".to_string()),
        };
        let r_qq_from_path = evaluate_compiled_rules(&doc, &q_qq_from_path);
        assert_eq!(r_qq_from_path.policy.as_deref(), Some("DIRECT"));
        assert_eq!(r_qq_from_path.matched_rule_index, Some(0));

        // 3. PROCESS-PATH normalizes `\` <-> `/` and compares case-insensitively
        let q_wechat = RuleMatchQuery {
            host: "wx.example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            process_name: None,
            process_path: Some("c:/program files/tencent/wechat/wechat.exe".to_string()),
        };
        let r_wechat = evaluate_compiled_rules(&doc, &q_wechat);
        assert_eq!(r_wechat.policy.as_deref(), Some("DIRECT"));
        assert_eq!(r_wechat.matched_rule_type.as_deref(), Some("PROCESS-PATH"));

        // 4. PROCESS-NAME-REGEX with parenthesized target `AI (日本)`
        let q_wsf = RuleMatchQuery {
            host: "api.example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            process_name: Some("WindsurfHelper.exe".to_string()),
            process_path: None,
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_wsf).policy.as_deref(),
            Some("AI (日本)")
        );

        // 5. PROCESS-PATH-REGEX matches normalized `/` path even when input used Windows `\`
        let q_devin = RuleMatchQuery {
            host: "api.example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            process_name: None,
            process_path: Some(r"C:\Program Files\Devin\agent.exe".to_string()),
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_devin).policy.as_deref(),
            Some("AI (日本)")
        );
    }

    #[test]
    fn rejects_single_layer_not_empty_and_unknown_context_not_and_excessive_depth() {
        // 1. Single-layer `NOT,(...)`, empty `AND,()`, and empty sub-clause `AND,((...),())` must NOT match.
        let doc_invalid = yaml_with_rules(&[
            "NOT,(DOMAIN,blocked.example),FALSE_POSITIVE_SINGLE_NOT",
            "AND,(),FALSE_POSITIVE_EMPTY_AND",
            "AND,((DOMAIN,ok.example),()),FALSE_POSITIVE_EMPTY_SUB",
            "OR,((DOMAIN,ok.example),()),FALSE_POSITIVE_EMPTY_OR_SUB",
            "AND,((DOMAIN,ok.example)),FALSE_POSITIVE_TOP_FLAG,no-resolve",
            "MATCH,Fallback",
        ]);
        let q = RuleMatchQuery {
            host: "ok.example".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        let res = evaluate_compiled_rules(&doc_invalid, &q);
        assert_eq!(res.policy.as_deref(), Some("Fallback"));

        // 2. Valid double-layer `NOT,((...))` works when context is known...
        let doc_not = yaml_with_rules(&[
            "NOT,((PROCESS-NAME,QQ.exe)),NOT_QQ_POLICY",
            "NOT,((DOMAIN-SUFFIX,cn)),OVERSEAS_POLICY",
            "MATCH,Fallback",
        ]);
        // ...but when BOTH process_name and process_path are None, `NOT,((PROCESS-NAME,...))`
        // evaluates to UnknownContext and MUST NOT falsely match!
        let q_no_proc = RuleMatchQuery {
            host: "example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            process_name: None,
            process_path: None,
        };
        let res_no_proc = evaluate_compiled_rules(&doc_not, &q_no_proc);
        assert_eq!(res_no_proc.policy.as_deref(), Some("OVERSEAS_POLICY"));

        // When process_name IS provided and differs from QQ.exe, `NOT` legitimately matches.
        let q_other_proc = RuleMatchQuery {
            host: "example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            process_name: Some("curl.exe".to_string()),
            process_path: None,
        };
        let res_other_proc = evaluate_compiled_rules(&doc_not, &q_other_proc);
        assert_eq!(res_other_proc.policy.as_deref(), Some("NOT_QQ_POLICY"));

        // 3. Depth limit (`MAX_LOGICAL_RULE_DEPTH = 16`) prevents stack overflow on deeply nested rules.
        let mut expr = "(DOMAIN,deep.example)".to_string();
        for _ in 0..24 {
            expr = format!("(AND,({expr}))");
        }
        let deep_rule = format!("AND,({expr}),DEEP_TARGET");
        let doc_deep = yaml_with_rules(&[&deep_rule, "MATCH,Fallback"]);
        let q_deep = RuleMatchQuery {
            host: "deep.example".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        let res_deep = evaluate_compiled_rules(&doc_deep, &q_deep);
        assert_eq!(res_deep.policy.as_deref(), Some("Fallback"));
    }

    #[test]
    fn tracks_skipped_geo_rules_and_handles_invalid_regex_gracefully() {
        let doc = yaml_with_rules(&[
            "DOMAIN-REGEX,(?=lookahead)foo,BAD_REGEX",
            "GEOSITE,cn,DIRECT",
            "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT",
            "MATCH,Main-Group",
        ]);
        let q = RuleMatchQuery {
            host: "foo.example".to_string(),
            network: "udp".to_string(),
            port: 443,
            ..Default::default()
        };
        let outcome = evaluate_compiled_rules(&doc, &q);
        assert!(outcome.matched);
        assert_eq!(outcome.policy.as_deref(), Some("Main-Group"));
        assert_eq!(
            outcome.skipped_geo_rules,
            vec![
                "GEOSITE,cn,DIRECT".to_string(),
                "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT".to_string(),
            ]
        );
    }

    #[test]
    fn guards_not_inversion_single_level_wildcard_ip_domain_skip_and_src_flags() {
        let doc = yaml_with_rules(&[
            "NOT,((AND,())),FALSE_POSITIVE_NOT_EMPTY_AND",
            "NOT,((RULE-SET,cn)),FALSE_POSITIVE_NOT_RULESET",
            "NOT,((IP-CIDR,10.0.0.0/8,src)),FALSE_POSITIVE_NOT_SRC",
            "DOMAIN-WILDCARD,*.example.com,SINGLE_LEVEL_WILD",
            "DOMAIN-KEYWORD,113,FALSE_POSITIVE_IP_DOMAIN",
            "MATCH,Fallback",
        ]);

        // 1. Multi-level subdomain must NOT match single-level `*.example.com`, and neither NOT rule may fire.
        let q_multi = RuleMatchQuery {
            host: "a.b.example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_multi).policy.as_deref(),
            Some("Fallback")
        );

        // 2. Single-level subdomain MUST match `*.example.com`.
        let q_single = RuleMatchQuery {
            host: "edge.example.com".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_single).policy.as_deref(),
            Some("SINGLE_LEVEL_WILD")
        );

        // 3. Bare IP literal must skip DOMAIN-* rules entirely.
        let q_ip = RuleMatchQuery {
            host: "203.0.113.10".to_string(),
            network: "tcp".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            evaluate_compiled_rules(&doc, &q_ip).policy.as_deref(),
            Some("Fallback")
        );
    }
}
