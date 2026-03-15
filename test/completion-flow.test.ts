// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");

const { evaluateScanDecision } = require("../dist/audit-decision.js");

test("completion flow classifies malicious findings into a bounded patch decision", () => {
  const decision = evaluateScanDecision({
    findings: [
      {
        skill: "malicious-skill",
        risk: 100,
        verdict: "MALICIOUS",
        findings: [
          {
            severity: "CRITICAL",
            id: "IOC_IP",
            cat: "malicious-code",
            desc: "Known malicious IP",
            file: "scripts/evil.js",
          },
        ],
      },
    ],
  });

  assert.equal(decision.authority_source, "guava-anti-guard");
  assert.equal(decision.guard_decision.action, "patch");
  assert.equal(decision.audit_interpretation.recommendedAction, "patch");
});

test("completion flow never promotes raw low-signal findings into durable memory", () => {
  const decision = evaluateScanDecision({
    findings: [
      {
        skill: "notes-scratch",
        risk: 8,
        verdict: "LOW RISK",
        findings: [
          {
            severity: "LOW",
            id: "LOW_SIGNAL",
            cat: "doc-example",
            desc: "Single low confidence wording match",
            file: "notes/scratch.md",
          },
        ],
      },
    ],
  });

  assert.equal(decision.guard_decision.action, "allow");
  assert.equal(decision.audit_interpretation.recommendedAction, "ignore");
  assert.equal(decision.memory_promotion.allowed, false);
});
