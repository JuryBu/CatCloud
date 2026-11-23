//! CatCloud intelligent strategy engine:
//! - [`formula`]: Safe, zero-`eval` recursive-descent AST weighting & predicate engine
//! - [`evaluator`]: Per-node evaluation context, dynamic pool filters, hard gates & ranking
//! - [`arbiter`]: Debouncing, cooldown with disconnect bypass, hysteresis, controlled load-balance
//!   pool purification, three-way below-threshold fallbacks, and cross-pool automatic recovery

pub mod arbiter;
pub mod evaluator;
pub mod formula;

pub use arbiter::{
    ArbiterAction, ArbiterDecision, ArbiterGroupMemory, BUILTIN_REJECT_TARGET,
    DEFAULT_RECOVERY_STREAK_REQUIRED, StrategyArbiter, apply_decision_to_group,
    decide_group_action, decide_group_action_with_registry, exceeds_hysteresis, format_rfc3339_ts,
    parse_rfc3339_ts,
};
pub use evaluator::{
    ActiveNodeAssessment, EvaluatedCandidate, GroupEvaluationReport, TriggerRuleHit,
    build_eval_context, build_eval_context_for_probe, evaluate_dynamic_filter,
    evaluate_group_candidates,
};
pub use formula::{
    DEFAULT_COST_EFFECTIVE_FORMULA, DEFAULT_MAX_PERF_FORMULA, DEFAULT_MISSING_PING_MS, EvalContext,
    FormulaExpr, MAX_AST_DEPTH, MAX_AST_NODES, MAX_EXPR_LEN, default_cost_effective_formula,
    default_max_perf_formula, validate_formula,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DynamicFilterSpec, FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState,
        ProbeSnapshot, ProxyNode, SwitchMode, TriggerRule,
    };
    use std::collections::HashMap;

    fn make_node(id: &str, region: &str, multiplier: f64) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-alpha".to_string(),
            name: format!("Node-{id}"),
            protocol: "trojan".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            region_code: region.to_string(),
            multiplier,
            is_443_native: true,
            enabled: true,
            ..Default::default()
        }
    }

    fn make_snapshot(
        node_id: &str,
        ok: bool,
        up_mbps: f64,
        down_mbps: f64,
        latency_ms: f64,
        google_clean: bool,
    ) -> ProbeSnapshot {
        ProbeSnapshot {
            node_id: node_id.to_string(),
            tested_at: "2026-11-22T00:00:00Z".to_string(),
            ok,
            latency_ms: Some(latency_ms),
            jitter_ms: Some(5.0),
            loss_pct: Some(if ok { 0.0 } else { 100.0 }),
            up_mbps: Some(up_mbps),
            down_mbps: Some(down_mbps),
            google_clean: Some(google_clean),
            keepalive_60s_ok: Some(ok),
            ..Default::default()
        }
    }

    // -------------------------------------------------------------------------
    // 1. AST Formula Engine tests
    // -------------------------------------------------------------------------

    #[test]
    fn formula_arithmetic_precedence_unary_comparisons_logic_and_builtins() {
        let ctx = EvalContext::default();

        let arith = FormulaExpr::parse("1 + 2 * 3 - 4 / 2").expect("parse arithmetic");
        assert!((arith.eval_f64(&ctx).unwrap() - 5.0).abs() < 1e-9);

        let unary = FormulaExpr::parse("-(3 + 2) * -2 + abs(-12.5)").expect("parse unary");
        assert!((unary.eval_f64(&ctx).unwrap() - 22.5).abs() < 1e-9);

        let minmax = FormulaExpr::parse("min(10, 4) + max(2, 7)").expect("parse min/max");
        assert!((minmax.eval_f64(&ctx).unwrap() - 11.0).abs() < 1e-9);

        let clamp_hi = FormulaExpr::parse("clamp(250, 0, 200)").expect("parse clamp hi");
        assert!((clamp_hi.eval_f64(&ctx).unwrap() - 200.0).abs() < 1e-9);

        let clamp_lo = FormulaExpr::parse("clamp(-5, 0, 200)").expect("parse clamp lo");
        assert!((clamp_lo.eval_f64(&ctx).unwrap() - 0.0).abs() < 1e-9);

        // Reversed clamp bounds must not panic.
        let clamp_swapped = FormulaExpr::parse("clamp(50, 200, 0)").expect("parse clamp swapped");
        assert!((clamp_swapped.eval_f64(&ctx).unwrap() - 50.0).abs() < 1e-9);

        let cond_true = FormulaExpr::parse("if(1 > 0, 42, 99)").expect("parse if true");
        assert!((cond_true.eval_f64(&ctx).unwrap() - 42.0).abs() < 1e-9);

        let cond_false = FormulaExpr::parse("if(0, 42, 99)").expect("parse if false");
        assert!((cond_false.eval_f64(&ctx).unwrap() - 99.0).abs() < 1e-9);

        let logic = FormulaExpr::parse(
            "!(1 == 2) && (3 >= 3) && (2 != 5) && (1 < 2) && (2 <= 2) && (0 || 1)",
        )
        .expect("parse logic");
        assert!(logic.eval_bool(&ctx).unwrap());

        let logic_false = FormulaExpr::parse("!(true && !false)").expect("parse bool literals");
        assert!(!logic_false.eval_bool(&ctx).unwrap());
    }

    #[test]
    fn formula_div_by_zero_and_safety_limits() {
        let ctx = EvalContext {
            up_mbps: 12.0,
            ..Default::default()
        };

        let div0 = FormulaExpr::parse("10 / 0").expect("parse div0");
        let val = div0.eval_f64(&ctx).unwrap();
        assert!(val.is_finite());
        assert_eq!(val, 0.0);

        let dyn_div0 = FormulaExpr::parse("100 / (up_mbps - up_mbps)").expect("parse dyn div0");
        let dyn_val = dyn_div0.eval_f64(&ctx).unwrap();
        assert!(dyn_val.is_finite());
        assert_eq!(dyn_val, 0.0);

        // Nesting beyond MAX_AST_DEPTH (64) must fail cleanly.
        let deep = format!("{}1{}", "(".repeat(MAX_AST_DEPTH + 1), ")".repeat(MAX_AST_DEPTH + 1));
        assert!(FormulaExpr::parse(&deep).is_err());

        // Length beyond MAX_EXPR_LEN (2048) must fail cleanly.
        let too_long = "1+".repeat(MAX_EXPR_LEN);
        assert!(FormulaExpr::parse(&too_long).is_err());

        // Unknown functions, unknown identifiers, malformed syntax, and bad probe args must fail.
        assert!(validate_formula("eval(\"1+1\")").is_err());
        assert!(validate_formula("unknown_metric + 1").is_err());
        assert!(validate_formula("probe_up(123)").is_err());
        assert!(validate_formula("probe_up(\"\")").is_err());
        assert!(validate_formula("min(1)").is_err());
        assert!(validate_formula("1 = 2").is_err());
        assert!(validate_formula("1 & 2").is_err());
        assert!(validate_formula("   ").is_err());
    }

    #[test]
    fn formula_per_probe_id_lookup_and_builtin_templates() {
        let mut ctx = EvalContext {
            up_mbps: 10.0,
            down_mbps: 300.0,
            ping_ms: 50.0,
            jitter_ms: 10.0,
            multiplier: 1.0,
            ok: true,
            google_clean: true,
            keepalive_ok: true,
            is_443_native: true,
            ..Default::default()
        };
        ctx.per_probe_up_mbps.insert("ai".to_string(), 18.5);
        ctx.per_probe_down_mbps.insert("dl".to_string(), 120.0);
        ctx.per_probe_ping_ms.insert("chatgpt".to_string(), 95.0);
        ctx.per_probe_ok.insert("chatgpt".to_string(), true);
        ctx.unlocked_sites.insert("windsurf".to_string(), true);

        let expr = FormulaExpr::parse(
            "probe_up(\"ai\") * 10 + probe_down('dl') * 0.5 - probe_ping(\"chatgpt\")",
        )
        .expect("parse per-probe lookup");
        assert!((expr.eval_f64(&ctx).unwrap() - 150.0).abs() < 1e-9);

        let gate = FormulaExpr::parse(
            "probe_ok(\"chatgpt\") == 1 && site_unlocked(\"Windsurf\") == true && latency_ms == 50",
        )
        .expect("parse probe gate");
        assert!(gate.eval_bool(&ctx).unwrap());

        // When a named probe ID is absent from per_probe_*, numeric lookups gracefully fall back
        // to the node's generic metrics; on an unprobed context they return 0 / >5000ms.
        let missing_fallback = FormulaExpr::parse(
            "probe_up(\"missing\") == 10 && !probe_ok(\"missing\") && probe_ping(\"missing\") == 50",
        )
        .expect("parse missing probe fallback");
        assert!(missing_fallback.eval_bool(&ctx).unwrap());

        let empty_ctx = EvalContext::default();
        let missing_empty = FormulaExpr::parse(
            "probe_up(\"missing\") == 0 && !probe_ok(\"missing\") && probe_ping(\"missing\") > 5000",
        )
        .expect("parse missing probe on empty ctx");
        assert!(missing_empty.eval_bool(&empty_ctx).unwrap());

        // Built-in templates validate and produce expected deterministic scores.
        validate_formula(DEFAULT_COST_EFFECTIVE_FORMULA).expect("validate cost-effective");
        validate_formula(DEFAULT_MAX_PERF_FORMULA).expect("validate max-perf");

        let cost_eff = default_cost_effective_formula().unwrap();
        assert!(cost_eff.uses_multiplier());
        assert!((cost_eff.eval_f64(&ctx).unwrap() - 394.5).abs() < 1e-9);

        let mut ctx_3x = ctx.clone();
        ctx_3x.multiplier = 3.0;
        assert!((cost_eff.eval_f64(&ctx_3x).unwrap() - 131.5).abs() < 1e-9);

        let max_perf = default_max_perf_formula().unwrap();
        assert!(!max_perf.uses_multiplier());
        assert!((max_perf.eval_f64(&ctx).unwrap() - 515.0).abs() < 1e-9);
    }

    // -------------------------------------------------------------------------
    // 2. Evaluator & 4 MultiGroupMode tests
    // -------------------------------------------------------------------------

    #[test]
    fn dynamic_filter_and_all_four_group_modes() {
        let mut n_jp = make_node("node-jp", "JP", 1.0);
        n_jp.sub_id = "sub-alpha".to_string();
        n_jp.protocol = "trojan".to_string();
        n_jp.is_443_native = true;

        let mut n_sg = make_node("node-sg", "SG", 0.5);
        n_sg.sub_id = "sub-beta".to_string();
        n_sg.protocol = "vless".to_string();
        n_sg.is_443_native = false;

        let mut n_dirty = make_node("node-dirty", "JP", 1.0);
        n_dirty.sub_id = "sub-alpha".to_string();

        let nodes = vec![n_jp.clone(), n_sg.clone(), n_dirty.clone()];
        let mut snaps = HashMap::new();
        snaps.insert(
            "node-jp".to_string(),
            make_snapshot("node-jp", true, 12.0, 120.0, 60.0, true),
        );
        snaps.insert(
            "node-sg".to_string(),
            make_snapshot("node-sg", true, 8.0, 100.0, 70.0, true),
        );
        snaps.insert(
            "node-dirty".to_string(),
            make_snapshot("node-dirty", true, 50.0, 200.0, 30.0, false),
        );

        let filter = DynamicFilterSpec {
            expr: Some("keepalive_ok == 1 && up_mbps >= 5".to_string()),
            sub_ids: vec!["sub-alpha".to_string()],
            region_codes: vec!["jp".to_string()],
            max_multiplier: Some(1.0),
            protocols: vec!["TROJAN".to_string()],
            require_google_clean: true,
            require_443_native: Some(true),
        };
        assert!(evaluate_dynamic_filter(&n_jp, snaps.get("node-jp"), &filter).unwrap());
        assert!(!evaluate_dynamic_filter(&n_sg, snaps.get("node-sg"), &filter).unwrap());
        assert!(!evaluate_dynamic_filter(&n_dirty, snaps.get("node-dirty"), &filter).unwrap());

        // Mode 1: StickyBest rejects dirty node via hard_gates and ranks SG (0.5x) above JP (1x).
        let sticky = MultiGroup {
            id: "grp-sticky".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "node-jp".to_string(),
                "node-sg".to_string(),
                "node-dirty".to_string(),
            ],
            hard_gates: vec!["google_clean == 1".to_string()],
            ..Default::default()
        };
        let sticky_rep = evaluate_group_candidates(&sticky, &nodes, &snaps).unwrap();
        assert_eq!(sticky_rep.gate_passed.len(), 2);
        assert_eq!(sticky_rep.gate_rejected.len(), 1);
        assert_eq!(sticky_rep.gate_rejected[0].node_id, "node-dirty");
        assert_eq!(sticky_rep.healthy_candidates[0].node_id, "node-sg");

        // Mode 2: ConditionalPool dynamically selects only `node-jp` via DynamicFilterSpec.
        let cond = MultiGroup {
            id: "grp-cond".to_string(),
            mode: MultiGroupMode::ConditionalPool,
            dynamic_filter: Some(filter),
            hard_gates: vec!["google_clean == 1".to_string()],
            ..Default::default()
        };
        let cond_rep = evaluate_group_candidates(&cond, &nodes, &snaps).unwrap();
        assert_eq!(cond_rep.pool_size, 1);
        assert_eq!(cond_rep.healthy_candidates[0].node_id, "node-jp");

        // Mode 3 & Mode 4: Controlled LoadBalance filters out region-dirty nodes cleanly.
        for mode in [
            MultiGroupMode::LoadBalanceConsistentHash,
            MultiGroupMode::LoadBalanceRoundRobin,
        ] {
            let lb_group = MultiGroup {
                id: format!("grp-{}", mode.as_str()),
                mode,
                member_node_ids: vec![
                    "node-jp".to_string(),
                    "node-sg".to_string(),
                    "node-dirty".to_string(),
                ],
                hard_gates: vec!["google_clean == 1".to_string()],
                switch_mode: SwitchMode::GracefulNewOnly,
                ..Default::default()
            };
            let mut mem = ArbiterGroupMemory::default();
            let dec = decide_group_action(&lb_group, &nodes, &snaps, None, &mut mem, 1000).unwrap();
            assert_eq!(dec.action, ArbiterAction::UpdateBalancePool);
            assert_eq!(dec.next_state, MultiGroupState::Healthy);
            assert_eq!(dec.balance_candidate_ids, vec!["node-sg", "node-jp"]);
            assert!(!dec.should_close_old_connections);
        }
    }

    // -------------------------------------------------------------------------
    // 3. Debouncing, cooldown, disconnect cooldown bypass & hysteresis
    // -------------------------------------------------------------------------

    #[test]
    fn consecutive_failures_cooldown_and_disconnect_bypass() {
        let nodes = vec![
            make_node("n1", "JP", 1.0),
            make_node("n2", "SG", 1.0),
            make_node("n3", "US", 1.0),
        ];
        let mut group = MultiGroup {
            id: "grp-ai".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into(), "n2".into(), "n3".into()],
            hard_gates: vec!["google_clean == 1".into()],
            trigger_rules: vec![TriggerRule {
                expr: "probe_up(\"ai\") < 1.0".into(),
                consecutive_failures: 2,
                bypass_cooldown_on_disconnect: true,
            }],
            formula_expr: "probe_up(\"ai\") * 10".into(),
            cooldown_sec: 60,
            hysteresis_pct: 20.0,
            switch_mode: SwitchMode::ForceCloseOld,
            active_node_id: Some("n1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut snaps = HashMap::new();
        let mut s1 = make_snapshot("n1", true, 0.5, 50.0, 60.0, true);
        s1.per_probe_up_mbps.insert("ai".into(), 0.5);
        let mut s2 = make_snapshot("n2", true, 10.0, 50.0, 60.0, true);
        s2.per_probe_up_mbps.insert("ai".into(), 10.0);
        let mut s3 = make_snapshot("n3", true, 8.0, 50.0, 60.0, true);
        s3.per_probe_up_mbps.insert("ai".into(), 8.0);
        snaps.insert("n1".into(), s1);
        snaps.insert("n2".into(), s2);
        snaps.insert("n3".into(), s3);

        let mut mem = ArbiterGroupMemory {
            last_switched_at: Some(1000),
            last_observed_active_node: Some("n1".into()),
            ..Default::default()
        };

        // Tick 1 (t=1020): 1st soft threshold breach -> debounced (needs 2 consecutive).
        let d1 = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1020).unwrap();
        assert_eq!(d1.action, ArbiterAction::KeepCurrent);
        assert_eq!(mem.consecutive_failures, 1);

        // Tick 2 (t=1030): 2nd breach reached, but cooldown (60s since t=1000) blocks switch.
        let d2 = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1030).unwrap();
        assert_eq!(d2.action, ArbiterAction::KeepCurrent);
        assert_eq!(mem.consecutive_failures, 2);

        // Tick 3 (t=1070): cooldown expired -> switch to `n2` and close old connections.
        let d3 = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1070).unwrap();
        assert_eq!(d3.action, ArbiterAction::SwitchNode);
        assert_eq!(d3.target_node_id.as_deref(), Some("n2"));
        assert!(d3.should_close_old_connections);
        apply_decision_to_group(&mut group, &d3);

        // Tick 4 (t=1080, inside 60s cooldown since t=1070): `n2` hard-disconnects (`ok=false`).
        // `bypass_cooldown_on_disconnect == true` must immediately switch to `n3`!
        let mut s2_down = make_snapshot("n2", false, 0.0, 0.0, 9999.0, true);
        s2_down.per_probe_up_mbps.insert("ai".into(), 0.0);
        snaps.insert("n2".into(), s2_down);

        let d4 = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1080).unwrap();
        assert_eq!(d4.action, ArbiterAction::SwitchNode);
        assert_eq!(d4.target_node_id.as_deref(), Some("n3"));
        assert!(d4.should_close_old_connections);
    }

    #[test]
    fn hysteresis_prevents_flapping_and_handles_negative_scores() {
        assert!(!exceeds_hysteresis(119.0, 100.0, 20.0));
        assert!(exceeds_hysteresis(120.0, 100.0, 20.0));
        assert!(!exceeds_hysteresis(-11.0, -10.0, 20.0));
        assert!(exceeds_hysteresis(-8.0, -10.0, 20.0));

        let nodes = vec![make_node("n1", "JP", 1.0), make_node("n2", "SG", 1.0)];
        let group = MultiGroup {
            id: "grp-hyst".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into(), "n2".into()],
            formula_expr: "up_mbps".into(),
            cooldown_sec: 0,
            hysteresis_pct: 20.0,
            switch_mode: SwitchMode::GracefulNewOnly,
            active_node_id: Some("n1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut snaps = HashMap::new();
        snaps.insert("n1".into(), make_snapshot("n1", true, 10.0, 100.0, 50.0, true));
        snaps.insert("n2".into(), make_snapshot("n2", true, 11.5, 100.0, 50.0, true));

        let mut mem = ArbiterGroupMemory::default();
        // +15% lead < 20% hysteresis -> keep current.
        let d_hold = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1000).unwrap();
        assert_eq!(d_hold.action, ArbiterAction::KeepCurrent);
        assert!(!d_hold.should_close_old_connections);

        // +25% lead >= 20% hysteresis -> switch gracefully (no forced old connection close).
        snaps.insert("n2".into(), make_snapshot("n2", true, 12.5, 100.0, 50.0, true));
        let d_switch = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 1010).unwrap();
        assert_eq!(d_switch.action, ArbiterAction::SwitchNode);
        assert_eq!(d_switch.target_node_id.as_deref(), Some("n2"));
        assert!(!d_switch.should_close_old_connections);
    }

    // -------------------------------------------------------------------------
    // 4. Three-way below-threshold fallback tests
    // -------------------------------------------------------------------------

    #[test]
    fn fallback_1_degrade_best_warn_emits_alerts_and_picks_best_gate_passing() {
        let nodes = vec![make_node("n1", "JP", 1.0), make_node("n2", "SG", 1.0)];
        let group = MultiGroup {
            id: "grp-degrade".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into(), "n2".into()],
            hard_gates: vec!["google_clean == 1".into()],
            trigger_rules: vec![TriggerRule {
                expr: "up_mbps < 1.0".into(),
                consecutive_failures: 1,
                bypass_cooldown_on_disconnect: true,
            }],
            formula_expr: "up_mbps * 10".into(),
            fallback_policy: FallbackPolicy::DegradeBestWarn,
            switch_mode: SwitchMode::ForceCloseOld,
            cooldown_sec: 0,
            active_node_id: Some("n1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut snaps = HashMap::new();
        snaps.insert("n1".into(), make_snapshot("n1", true, 0.2, 50.0, 80.0, true));
        snaps.insert("n2".into(), make_snapshot("n2", true, 0.8, 50.0, 80.0, true));

        let mut mem = ArbiterGroupMemory::default();
        let dec = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 2000).unwrap();
        assert_eq!(dec.action, ArbiterAction::DegradeToBest);
        assert_eq!(dec.next_state, MultiGroupState::DegradedWarn);
        assert_eq!(dec.target_node_id.as_deref(), Some("n2"));
        assert!(dec.shorten_reprobe_interval);
        assert!(dec.trigger_adapter_refresh);
        assert!(dec.should_close_old_connections);
    }

    #[test]
    fn fallback_2_cross_pool_escalate_and_auto_hysteresis_recovery() {
        let nodes = vec![
            make_node("p1", "JP", 1.0),
            make_node("p2", "SG", 1.0),
            make_node("b1", "US", 3.0),
        ];

        let mut primary = MultiGroup {
            id: "grp-primary".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["p1".into(), "p2".into()],
            hard_gates: vec!["google_clean == 1".into()],
            trigger_rules: vec![TriggerRule {
                expr: "up_mbps < 1.0".into(),
                consecutive_failures: 1,
                bypass_cooldown_on_disconnect: true,
            }],
            formula_expr: "up_mbps / max(multiplier, 0.25)".into(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            fallback_pool_id: Some("grp-3x-backup".into()),
            switch_mode: SwitchMode::ForceCloseOld,
            cooldown_sec: 60,
            hysteresis_pct: 20.0,
            active_node_id: Some("p1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let backup = MultiGroup {
            id: "grp-3x-backup".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["b1".into()],
            hard_gates: vec!["google_clean == 1".into()],
            formula_expr: "up_mbps".into(),
            ..Default::default()
        };

        let all_groups = vec![primary.clone(), backup.clone()];
        let mut snaps = HashMap::new();
        snaps.insert("p1".into(), make_snapshot("p1", true, 0.4, 50.0, 70.0, true));
        snaps.insert("p2".into(), make_snapshot("p2", true, 0.3, 50.0, 70.0, true));
        // 3x backup node has 15 Mbps => score under primary cost-effective formula = 15 / 3 = 5.0.
        snaps.insert("b1".into(), make_snapshot("b1", true, 15.0, 200.0, 60.0, true));

        let mut arbiter = StrategyArbiter::new();

        // Step 1 (t=1000): All primary nodes < 1.0 Mbps -> escalate to `b1` and stamp `escalated_since`.
        let d1 = arbiter.decide(&primary, &all_groups, &nodes, &snaps, 1000).unwrap();
        assert_eq!(d1.action, ArbiterAction::EscalateToFallbackPool);
        assert_eq!(d1.next_state, MultiGroupState::Escalated);
        assert_eq!(d1.target_node_id.as_deref(), Some("b1"));
        assert!(d1.escalated_since_rfc3339.is_some());
        assert!(d1.should_close_old_connections);
        apply_decision_to_group(&mut primary, &d1);

        // Step 2 (t=1100): `p1` barely recovers to 5.5 Mbps (score 5.5 vs 5.0 = +10% < 20% hysteresis).
        snaps.insert("p1".into(), make_snapshot("p1", true, 5.5, 100.0, 60.0, true));
        let d2 = arbiter.decide(&primary, &all_groups, &nodes, &snaps, 1100).unwrap();
        assert_eq!(d2.action, ArbiterAction::KeepCurrent);
        assert_eq!(d2.next_state, MultiGroupState::Escalated);
        assert_eq!(arbiter.memory("grp-primary").unwrap().primary_recovery_streak, 0);

        // Step 3 (t=1200): `p1` reaches 7.0 Mbps (score 7.0 >= 5.0 * 1.2 = 6.0) -> streak 1/2.
        snaps.insert("p1".into(), make_snapshot("p1", true, 7.0, 100.0, 60.0, true));
        let d3 = arbiter.decide(&primary, &all_groups, &nodes, &snaps, 1200).unwrap();
        assert_eq!(d3.action, ArbiterAction::KeepCurrent);
        assert_eq!(d3.next_state, MultiGroupState::Escalated);
        assert_eq!(arbiter.memory("grp-primary").unwrap().primary_recovery_streak, 1);

        // Step 4 (t=1320): 2nd consecutive healthy check above hysteresis -> auto recover to `p1`!
        let d4 = arbiter.decide(&primary, &all_groups, &nodes, &snaps, 1320).unwrap();
        assert_eq!(d4.action, ArbiterAction::RecoverToPrimaryPool);
        assert_eq!(d4.next_state, MultiGroupState::Healthy);
        assert_eq!(d4.target_node_id.as_deref(), Some("p1"));
        assert!(d4.escalated_since_rfc3339.is_none());
        assert!(d4.should_close_old_connections);
        apply_decision_to_group(&mut primary, &d4);
        assert!(primary.escalated_since.is_none());
        assert_eq!(arbiter.memory("grp-primary").unwrap().escalated_since, None);
    }

    #[test]
    fn fallback_3_strict_circuit_break_switches_to_reject_and_always_closes_old_connections() {
        let nodes = vec![make_node("n1", "TW", 1.0), make_node("n2", "JP", 1.0)];
        let group = MultiGroup {
            id: "grp-strict".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into(), "n2".into()],
            hard_gates: vec!["google_clean == 1".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            // Even under GracefulNewOnly, hard-gate circuit break MUST close old connections.
            switch_mode: SwitchMode::GracefulNewOnly,
            active_node_id: Some("n1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut snaps = HashMap::new();
        snaps.insert("n1".into(), make_snapshot("n1", true, 20.0, 200.0, 40.0, false));
        snaps.insert("n2".into(), make_snapshot("n2", true, 25.0, 200.0, 40.0, false));

        let mut mem = ArbiterGroupMemory::default();
        let dec = decide_group_action(&group, &nodes, &snaps, None, &mut mem, 3000).unwrap();
        assert_eq!(dec.action, ArbiterAction::CircuitBreakToReject);
        assert_eq!(dec.next_state, MultiGroupState::CircuitOpen);
        assert_eq!(dec.target_node_id.as_deref(), Some(BUILTIN_REJECT_TARGET));
        assert!(dec.should_close_old_connections);
        assert!(dec.shorten_reprobe_interval);
        assert!(dec.trigger_adapter_refresh);

        // Controlled load-balance group also enforces StrictCircuitBreak when all nodes fail gates.
        let lb_strict = MultiGroup {
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            ..group
        };
        let mut lb_mem = ArbiterGroupMemory::default();
        let lb_dec =
            decide_group_action(&lb_strict, &nodes, &snaps, None, &mut lb_mem, 3000).unwrap();
        assert_eq!(lb_dec.action, ArbiterAction::CircuitBreakToReject);
        assert_eq!(lb_dec.next_state, MultiGroupState::CircuitOpen);
        assert_eq!(lb_dec.target_node_id.as_deref(), Some(BUILTIN_REJECT_TARGET));
        assert!(lb_dec.balance_candidate_ids.is_empty());
        assert!(lb_dec.should_close_old_connections);
    }
}
