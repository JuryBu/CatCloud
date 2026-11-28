// @ts-expect-error Node 24 built-in test runner (no @types/node in frontend tsconfig)
import { describe, it } from "node:test";
// @ts-expect-error Node 24 built-in strict assert
import assert from "node:assert/strict";

import {
  countTopLevelLogicalChildren,
  findBalancedParenEnd,
  formatMatchRuleChip,
  hasStrictBalancedOuterParens,
  isRuleFlagToken,
  locateMihomoRuleTarget,
  normalizeSingleMatchRule,
  parseLogicalRuleParts,
  parseUserMatchRules,
  validateInlineOverrideYamlLocal,
  validateLogicalMatchRuleRest,
  validateLogicalRuleExpr,
} from "./mihomoRuleParser.ts";

describe("mihomoRuleParser - parenthesis & logical expression validation", () => {
  it("finds balanced parenthesis end across nested groups and rejects malformed inputs", () => {
    assert.equal(findBalancedParenEnd("((A,1),(B,2))", 0), 12);
    assert.equal(findBalancedParenEnd("AND,((A,1),(B,2)),DIRECT", 4), 16);
    assert.equal(findBalancedParenEnd("((A,1),(B,2)", 0), -1);
    assert.equal(findBalancedParenEnd(")(A,1)", 0), -1);
    assert.equal(findBalancedParenEnd("abc", 0), -1);
    assert.equal(findBalancedParenEnd("(A,1)", -1), -1);
  });

  it("enforces strict single outer pair and nested double-paren structure", () => {
    assert.equal(hasStrictBalancedOuterParens("((PROCESS-NAME,QQ.exe),(DST-PORT,15000))"), true);
    assert.equal(hasStrictBalancedOuterParens("((DOMAIN-SUFFIX,cn))"), true);
    // Single-paren must be rejected
    assert.equal(hasStrictBalancedOuterParens("(PROCESS-NAME,QQ.exe)"), false);
    // Side-by-side outer parens must be rejected
    assert.equal(hasStrictBalancedOuterParens("((A,1))((B,2))"), false);
    // Unbalanced
    assert.equal(hasStrictBalancedOuterParens("((A,1)"), false);
  });

  it("validates valid AND/OR/NOT including deep nesting", () => {
    assert.equal(
      validateLogicalRuleExpr("((PROCESS-NAME,QQ.exe),(DST-PORT,15000))", "AND"),
      null
    );
    assert.equal(
      validateLogicalRuleExpr("((DOMAIN-SUFFIX,openai.com),(DOMAIN-SUFFIX,chatgpt.com))", "OR"),
      null
    );
    assert.equal(validateLogicalRuleExpr("((DOMAIN-SUFFIX,cn))", "NOT"), null);
    // Nested logical clause
    assert.equal(
      validateLogicalRuleExpr(
        "((OR,((PROCESS-NAME,QQ.exe),(PROCESS-NAME,WeChat.exe))),(NOT,((DST-PORT,80))))",
        "AND"
      ),
      null
    );
    assert.equal(
      countTopLevelLogicalChildren(
        "((OR,((PROCESS-NAME,QQ.exe),(PROCESS-NAME,WeChat.exe))),(NOT,((DST-PORT,80))))"
      ),
      2
    );
  });

  it("rejects Stage 26 dirty-character, single-paren, empty, and arity violations", () => {
    assert.notEqual(validateLogicalRuleExpr("", "AND"), null);
    assert.notEqual(validateLogicalRuleExpr("(PROCESS-NAME,QQ.exe)", "AND"), null);
    assert.notEqual(validateLogicalRuleExpr("((PROCESS-NAME,QQ.exe))((DST-PORT,443))", "AND"), null);
    // Dirty text between sibling clauses
    assert.notEqual(
      validateLogicalRuleExpr("((PROCESS-NAME,QQ.exe)junk(DST-PORT,15000))", "AND"),
      null
    );
    // Dirty text after a clause before comma
    assert.notEqual(
      validateLogicalRuleExpr("((PROCESS-NAME,QQ.exe)x,(DST-PORT,15000))", "AND"),
      null
    );
    // Empty clause or missing comma/key/value
    assert.notEqual(validateLogicalRuleExpr("(())", "AND"), null);
    assert.notEqual(validateLogicalRuleExpr("((PROCESS-NAME))", "AND"), null);
    assert.notEqual(validateLogicalRuleExpr("((,QQ.exe))", "AND"), null);
    assert.notEqual(validateLogicalRuleExpr("((PROCESS-NAME,))", "AND"), null);
    // NOT with > 1 child must fail
    assert.notEqual(
      validateLogicalRuleExpr("((DOMAIN-SUFFIX,cn),(DOMAIN-SUFFIX,jp))", "NOT"),
      null
    );
    // Malformed nested logical child (inner NOT with 2 children) must fail
    assert.notEqual(
      validateLogicalRuleExpr(
        "((NOT,((DOMAIN,a.com),(DOMAIN,b.com))),(DST-PORT,443))",
        "AND"
      ),
      null
    );
    // Malformed nested logical child (inner OR missing double parens) must fail
    assert.notEqual(
      validateLogicalRuleExpr("((OR,(DOMAIN,a.com)),(DST-PORT,443))", "AND"),
      null
    );
  });

  it("parses logical rule parts and rejects forbidden Mihomo trailing flags on AND/OR/NOT", () => {
    assert.deepEqual(
      parseLogicalRuleParts("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT"),
      {
        ruleType: "AND",
        expr: "((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
        target: "DIRECT",
      }
    );
    assert.deepEqual(parseLogicalRuleParts("NOT,((DOMAIN-SUFFIX,cn))"), {
      ruleType: "NOT",
      expr: "((DOMAIN-SUFFIX,cn))",
      target: null,
    });
    // Forbidden trailing flags or extra commas on AND/OR/NOT
    assert.equal(parseLogicalRuleParts("AND,((DOMAIN,a.com),(DST-PORT,443)),DIRECT,no-resolve"), null);
    assert.equal(parseLogicalRuleParts("AND,((DOMAIN,a.com),(DST-PORT,443)),no-resolve"), null);
    assert.equal(parseLogicalRuleParts("OR,((DOMAIN,a.com),(DST-PORT,443)),src"), null);
    // Trailing junk without comma
    assert.equal(parseLogicalRuleParts("AND,((DOMAIN,a.com),(DST-PORT,443))DIRECT"), null);
    // SUB-RULE allows sub-rule target name
    assert.deepEqual(parseLogicalRuleParts("SUB-RULE,(NETWORK,tcp),my-sub"), {
      ruleType: "SUB-RULE",
      expr: "(NETWORK,tcp)",
      target: "my-sub",
    });

    assert.equal(validateLogicalMatchRuleRest("((PROCESS-NAME,QQ.exe),(DST-PORT,15000))", "AND"), true);
    assert.equal(
      validateLogicalMatchRuleRest("((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT", "AND"),
      true
    );
    assert.equal(
      validateLogicalMatchRuleRest("((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),no-resolve", "AND"),
      false
    );
    assert.equal(
      validateLogicalMatchRuleRest("((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT,src", "AND"),
      false
    );
  });
});

describe("mihomoRuleParser - user match rules & target locator", () => {
  it("normalizes bare domains, URLs, standard rules, regex rules, and compound rules", () => {
    assert.deepEqual(normalizeSingleMatchRule("https://Codeium.com:443/path?x=1"), {
      rule: "DOMAIN-SUFFIX,codeium.com",
      invalid: false,
    });
    assert.deepEqual(normalizeSingleMatchRule(".openai.com."), {
      rule: "DOMAIN-SUFFIX,openai.com",
      invalid: false,
    });
    assert.deepEqual(normalizeSingleMatchRule("process-name, QQ.exe"), {
      rule: "PROCESS-NAME,QQ.exe",
      invalid: false,
    });
    // Regex rule preserves internal commas without splitting
    assert.deepEqual(normalizeSingleMatchRule("DOMAIN-REGEX,^[a-z]{2,5}\\.example\\.com$"), {
      rule: "DOMAIN-REGEX,^[a-z]{2,5}\\.example\\.com$",
      invalid: false,
    });
    // Logical rule validated and uppercased
    assert.deepEqual(
      normalizeSingleMatchRule("and,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))"),
      {
        rule: "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
        invalid: false,
      }
    );
    // Bare keywords rejected
    for (const kw of ["DIRECT", "REJECT", "PROXY", "DOMAIN", "MATCH", "AND", "DOMAIN,DIRECT"]) {
      assert.equal(normalizeSingleMatchRule(kw).invalid, true, `Expected invalid for ${kw}`);
    }
    // Invalid domain for DOMAIN / DOMAIN-SUFFIX rejected
    assert.equal(normalizeSingleMatchRule("DOMAIN,not_a_domain").invalid, true);
    assert.equal(normalizeSingleMatchRule("UNKNOWN-TYPE,foo").invalid, true);
  });

  it("splits multi-line and semicolon input without splitting on commas and deduplicates", () => {
    const res = parseUserMatchRules(
      [
        "codeium.com；https://windsurf.com/app",
        "DOMAIN-SUFFIX,codeium.com",
        "PROCESS-NAME,QQ.exe; AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
        "DIRECT",
        "NOT,((DOMAIN,a.com),(DOMAIN,b.com))",
      ].join("\n")
    );
    assert.deepEqual(res.rules, [
      "DOMAIN-SUFFIX,codeium.com",
      "DOMAIN-SUFFIX,windsurf.com",
      "PROCESS-NAME,QQ.exe",
      "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
    ]);
    assert.deepEqual(res.invalidTokens, ["DIRECT", "NOT,((DOMAIN,a.com),(DOMAIN,b.com))"]);
  });

  it("formats rule chips and locates targets accurately including trailing flags and regex commas", () => {
    assert.deepEqual(formatMatchRuleChip("DOMAIN-SUFFIX,openai.com"), {
      display: "openai.com",
      tag: null,
    });
    assert.deepEqual(formatMatchRuleChip("PROCESS-NAME,QQ.exe"), {
      display: "QQ.exe",
      tag: "程序",
    });
    assert.deepEqual(formatMatchRuleChip("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))"), {
      display: "((PROCESS-NAME,QQ.exe),(DST-PORT,15000))",
      tag: "复合与",
    });

    assert.equal(isRuleFlagToken("no-resolve"), true);
    assert.equal(isRuleFlagToken("SRC"), true);
    assert.equal(isRuleFlagToken("DIRECT"), false);

    const ipSpan = locateMihomoRuleTarget("IP-CIDR,10.0.0.0/8,OldGroup,no-resolve");
    assert.equal(ipSpan?.target, "OldGroup");

    const regexSpan = locateMihomoRuleTarget("DOMAIN-REGEX,^[a-z]{1,3}\\.foo\\.com$,AI_Group");
    assert.equal(regexSpan?.target, "AI_Group");

    const logicalSpan = locateMihomoRuleTarget(
      "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT"
    );
    assert.equal(logicalSpan?.target, "DIRECT");

    const matchSpan = locateMihomoRuleTarget("MATCH,FinalGroup");
    assert.equal(matchSpan?.target, "FinalGroup");

    // SUB-RULE intentionally returns null for target rewrite
    assert.equal(locateMihomoRuleTarget("SUB-RULE,(NETWORK,tcp),sub-a"), null);
  });

  it("validates inline YAML override snippets locally", () => {
    assert.equal(validateInlineOverrideYamlLocal(""), null);
    assert.equal(validateInlineOverrideYamlLocal("rules:\n  - DOMAIN,example.com,DIRECT\n"), null);
    assert.notEqual(validateInlineOverrideYamlLocal("\trules:\n  - A"), null);
    assert.notEqual(validateInlineOverrideYamlLocal("- DOMAIN,example.com,DIRECT"), null);
    assert.notEqual(validateInlineOverrideYamlLocal("not a valid yaml key"), null);
  });
});
