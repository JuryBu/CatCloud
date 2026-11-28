// @ts-expect-error Node 24 built-in test runner (no @types/node in frontend tsconfig)
import { describe, it } from "node:test";
// @ts-expect-error Node 24 built-in strict assert
import assert from "node:assert/strict";

import type { ProbeSnapshot, ProxyNode } from "../api/types.ts";
import {
  FORMULA_COST_EFFECTIVE,
  FORMULA_MAX_PERF,
  FORMULA_WSF_CLEAN,
  assessNodeAgainstGates,
  buildEvalContextForNode,
  checkHardGate,
  evaluateFormulaSafely,
  lookupSiteUnlockedRaw,
  tokenizeFormula,
  type EvalContext,
} from "./formulaEvaluator.ts";

function makeNode(overrides: Partial<ProxyNode> = {}): ProxyNode {
  return {
    id: "node-1",
    sub_id: "sub-1",
    name: "JP-Tokyo-01 · 1x",
    protocol: "vless",
    server: "203.0.113.10",
    port: 443,
    region_code: "JP",
    multiplier: 1.0,
    is_443_native: true,
    preaccel_override: null,
    tags: [],
    enabled: true,
    ...overrides,
  };
}

function makeSnap(overrides: Partial<ProbeSnapshot> = {}): ProbeSnapshot {
  return {
    node_id: "node-1",
    tested_at: "2026-11-28T08:00:00Z",
    ok: true,
    latency_ms: 80,
    jitter_ms: 4,
    loss_pct: 0,
    up_mbps: 20,
    down_mbps: 160,
    cf_loc: "NRT",
    yt_gl: "JP",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    ip_clean: true,
    ip_risk_level: "clean",
    ip_asn: "AS15169 Example ISP",
    ip_risk_flags: null,
    unlocked_sites: {
      chatgpt: true,
      gemini: true,
      claude: true,
      windsurf: true,
    },
    per_probe_ok: {
      builtin_latency: true,
      builtin_unlock_windsurf: true,
    },
    per_probe_up_mbps: { antigravity: 24.5 },
    per_probe_down_mbps: { dl: 190 },
    per_probe_ping_ms: { chatgpt: 92 },
    per_probe_detail: {
      builtin_unlock_windsurf: "semantic_windsurf(status=415, ip_risk=clean)",
    },
    per_probe_tested_at: { builtin_latency: "2026-11-28T08:00:00Z" },
    ...overrides,
  };
}

describe("formulaEvaluator - tokenizer & AST evaluation", () => {
  it("tokenizes valid expressions and rejects malformed operators, quotes, and numbers", () => {
    const ok = tokenizeFormula('up_mbps * 35 + site_unlocked("gemini") == 1 && !false');
    assert.equal(ok.error, null);
    assert.ok(ok.tokens.length > 0);

    assert.notEqual(tokenizeFormula("a = 1").error, null);
    assert.notEqual(tokenizeFormula("a & b").error, null);
    assert.notEqual(tokenizeFormula("a | b").error, null);
    assert.notEqual(tokenizeFormula('site_unlocked("unclosed').error, null);
    assert.notEqual(tokenizeFormula("12.").error, null);
    assert.notEqual(tokenizeFormula("up_mbps $ 2").error, null);
  });

  it("evaluates arithmetic precedence, unary ops, safe divide-by-zero, logic, and builtins", () => {
    const ctx: EvalContext = buildEvalContextForNode(makeNode(), makeSnap());

    assert.equal(evaluateFormulaSafely("2 + 3 * 4", ctx).value, 14);
    assert.equal(evaluateFormulaSafely("(2 + 3) * 4", ctx).value, 20);
    assert.equal(evaluateFormulaSafely("-5 + 12", ctx).value, 7);
    assert.equal(evaluateFormulaSafely("!0 && !false && true", ctx).value, 1);
    assert.equal(evaluateFormulaSafely("10 / 0", ctx).value, 0);
    assert.equal(evaluateFormulaSafely("min(down_mbps, 100)", ctx).value, 100);
    assert.equal(evaluateFormulaSafely("max(multiplier, 0.25)", ctx).value, 1);
    assert.equal(evaluateFormulaSafely("abs(-42.5)", ctx).value, 42.5);
    // clamp handles swapped bounds cleanly
    assert.equal(evaluateFormulaSafely("clamp(250, 200, 10)", ctx).value, 200);
    assert.equal(evaluateFormulaSafely("clamp(-5, 200, 10)", ctx).value, 10);
    assert.equal(evaluateFormulaSafely("if(ping_ms < 100, 1000, 0)", ctx).value, 1000);
    assert.equal(evaluateFormulaSafely("if(ping_ms > 100, 1000, 50)", ctx).value, 50);

    // Preset formulas compute exact expected scores
    const costRes = evaluateFormulaSafely(FORMULA_COST_EFFECTIVE, ctx);
    assert.equal(costRes.ok, true);
    // (20*35 + 160*0.25 - 80*0.08 - 4*0.15) / 1 = 700 + 40 - 6.4 - 0.6 = 733
    assert.ok(Math.abs(costRes.value - 733) < 1e-6);

    const wsfRes = evaluateFormulaSafely(FORMULA_WSF_CLEAN, ctx);
    assert.equal(wsfRes.ok, true);
    assert.ok(Math.abs(wsfRes.value - 853) < 1e-6);

    const perfRes = evaluateFormulaSafely(FORMULA_MAX_PERF, ctx);
    assert.equal(perfRes.ok, true);
    // 20*45 + 160*0.35 - 80*0.1 = 900 + 56 - 8 = 948
    assert.ok(Math.abs(perfRes.value - 948) < 1e-6);
  });

  it("handles probe/site addressing with aliases and safe fallback values", () => {
    const ctx = buildEvalContextForNode(
      makeNode(),
      makeSnap({
        unlocked_sites: { google_ai: true, ChatGPT: false },
      })
    );

    assert.equal(evaluateFormulaSafely('probe_up("antigravity")', ctx).value, 24.5);
    assert.equal(evaluateFormulaSafely('probe_up("missing")', ctx).value, 20);
    assert.equal(evaluateFormulaSafely('probe_down("dl")', ctx).value, 190);
    assert.equal(evaluateFormulaSafely('probe_ping("chatgpt")', ctx).value, 92);
    assert.equal(evaluateFormulaSafely('probe_ping("missing")', ctx).value, 80);
    assert.equal(evaluateFormulaSafely('probe_ok("builtin_unlock_windsurf")', ctx).value, 1);
    assert.equal(evaluateFormulaSafely('probe_ok("unknown")', ctx).value, 0);

    // Gemini / google_ai / gemini_aistudio aliases & case-insensitivity
    assert.equal(lookupSiteUnlockedRaw(ctx.unlockedSites, "gemini"), true);
    assert.equal(lookupSiteUnlockedRaw(ctx.unlockedSites, "gemini_aistudio"), true);
    assert.equal(lookupSiteUnlockedRaw(ctx.unlockedSites, "chatgpt"), false);
    assert.equal(lookupSiteUnlockedRaw(ctx.unlockedSites, "claude"), null);
    assert.equal(evaluateFormulaSafely('site_unlocked("gemini")', ctx).value, 1);
    assert.equal(evaluateFormulaSafely('site_unlocked("chatgpt")', ctx).value, 0);
  });

  it("returns structured errors on empty, unknown vars, bad arity, and trailing tokens", () => {
    const ctx = buildEvalContextForNode(makeNode(), makeSnap());
    assert.equal(evaluateFormulaSafely("   ", ctx).ok, false);
    assert.equal(evaluateFormulaSafely("unknown_metric + 1", ctx).ok, false);
    assert.equal(evaluateFormulaSafely("min(1)", ctx).ok, false);
    assert.equal(evaluateFormulaSafely('probe_up("")', ctx).ok, false);
    assert.equal(evaluateFormulaSafely("(1 + 2", ctx).ok, false);
    assert.equal(evaluateFormulaSafely("1 + 2 3", ctx).ok, false);
  });

  it("applies 9999 penalty when latency_ms is null/invalid in buildEvalContextForNode", () => {
    const ctx = buildEvalContextForNode(makeNode({ multiplier: 0 }), undefined);
    assert.equal(ctx.vars.ping_ms, 9999);
    assert.equal(ctx.vars.latency_ms, 9999);
    assert.equal(ctx.vars.loss_pct, 100);
    assert.equal(ctx.vars.ip_clean, 0);
    assert.equal(ctx.vars.multiplier, 0);
  });
});

describe("formulaEvaluator - hard gates & neutral untested semantics", () => {
  it("never marks untested snapshots or untested individual metrics as failed", () => {
    const node = makeNode();
    // Undefined snapshot
    assert.deepEqual(assessNodeAgainstGates(node, undefined, ["google_clean == 1", "ip_clean == 1"]), {
      hasMeasuredFailure: false,
      failedReasons: [],
      allMeasuredAndPassed: false,
    });

    // Measured ping, but google_clean / keepalive_60s_ok / ip_clean / sites are untested
    const untestedSnap = makeSnap({
      google_clean: null,
      keepalive_60s_ok: null,
      ip_clean: null,
      ip_risk_level: null,
      unlocked_sites: {},
      per_probe_ok: { builtin_latency: true },
      per_probe_detail: {},
    });
    const res = assessNodeAgainstGates(node, untestedSnap, [
      "google_clean == 1",
      "keepalive_ok == 1",
      "ip_clean == 1",
      'site_unlocked("chatgpt") == 1',
      'site_unlocked("windsurf") == 1',
    ]);
    assert.equal(res.hasMeasuredFailure, false);
    assert.deepEqual(res.failedReasons, []);
    assert.equal(res.allMeasuredAndPassed, false);
  });

  it("distinguishes ip_clean proxy_risk vs datacenter and Windsurf legacy/proxy_risk/blocked", () => {
    const node = makeNode();

    // Legacy windsurf probe result (no semantic_windsurf tag, no IP risk data) => neutrally allowed as legacy_retest
    const legacyWsSnap = makeSnap({
      ip_clean: null,
      ip_risk_level: null,
      unlocked_sites: { windsurf: true },
      per_probe_ok: { builtin_unlock_windsurf: true },
      per_probe_detail: { builtin_unlock_windsurf: "site=windsurf,status=200" },
    });
    const legacyRes = assessNodeAgainstGates(node, legacyWsSnap, ['site_unlocked("windsurf") == 1']);
    assert.equal(legacyRes.hasMeasuredFailure, false);
    assert.equal(legacyRes.allMeasuredAndPassed, false);

    // Proxy-risk IP fails both ip_clean and windsurf with distinct risk messages
    const riskSnap = makeSnap({
      ip_clean: false,
      ip_risk_level: "proxy_risk",
      unlocked_sites: { windsurf: false },
      per_probe_ok: { builtin_unlock_windsurf: false },
      per_probe_detail: {
        builtin_unlock_windsurf: "semantic_windsurf(status=415, ip_risk=proxy_risk)",
      },
    });
    const riskRes = assessNodeAgainstGates(node, riskSnap, [
      "ip_clean == 1",
      'site_unlocked("windsurf") == 1',
    ]);
    assert.equal(riskRes.hasMeasuredFailure, true);
    assert.deepEqual(riskRes.failedReasons, ["出口 IP 高危代理风控", "Windsurf 出口代理风控"]);

    // Non-residential datacenter IP (not proxy_risk)
    const dcSnap = makeSnap({
      ip_clean: false,
      ip_risk_level: "datacenter",
      unlocked_sites: { windsurf: false },
      per_probe_ok: { builtin_unlock_windsurf: false },
      per_probe_detail: {
        builtin_unlock_windsurf: "semantic_windsurf(status=403, ip_risk=datacenter)",
      },
    });
    const dcRes = assessNodeAgainstGates(node, dcSnap, [
      "ip_clean == 1",
      'site_unlocked("windsurf") == 1',
    ]);
    assert.deepEqual(dcRes.failedReasons, ["非纯净住宅 IP", "Windsurf 未解锁"]);
  });

  it("neutrally allows untested keepalive_ok & ip_clean in compound custom gates while enforcing measured checks", () => {
    const node = makeNode();
    const snap = makeSnap({
      latency_ms: 95,
      keepalive_60s_ok: null,
      ip_clean: null,
    });

    // Both keepalive_ok and ip_clean untested => neutrally treated as 1 in compound gate; ping_ms < 150 passes
    const passRes = assessNodeAgainstGates(node, snap, [
      "keepalive_ok == 1 && ip_clean == 1 && ping_ms < 150",
    ]);
    assert.equal(passRes.hasMeasuredFailure, false);
    assert.equal(passRes.allMeasuredAndPassed, true);

    // Measured ping_ms fails even though keepalive_ok & ip_clean are untested
    const failRes = assessNodeAgainstGates(node, snap, [
      "keepalive_ok == 1 && ip_clean == 1 && ping_ms < 50",
    ]);
    assert.equal(failRes.hasMeasuredFailure, true);
    assert.deepEqual(failRes.failedReasons, ["keepalive_ok == 1 && ip_clean == 1 && ping_ms < 50"]);

    // Direct checkHardGate helper
    const ctx = buildEvalContextForNode(node, makeSnap());
    assert.equal(checkHardGate("google_clean == 1 && ip_clean == 1", ctx), true);
    assert.equal(checkHardGate("ping_ms < 50", ctx), false);
  });

  it("reports allMeasuredAndPassed === true when every hard gate is measured and passes", () => {
    const res = assessNodeAgainstGates(makeNode(), makeSnap(), [
      "google_clean == 1",
      "keepalive_ok == 1",
      "ip_clean == 1",
      'site_unlocked("chatgpt") == 1',
      'site_unlocked("gemini") == 1',
      'site_unlocked("windsurf") == 1',
    ]);
    assert.deepEqual(res, {
      hasMeasuredFailure: false,
      failedReasons: [],
      allMeasuredAndPassed: true,
    });
  });
});
