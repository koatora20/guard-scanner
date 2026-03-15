"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var audit_decision_exports = {};
__export(audit_decision_exports, {
  evaluateScanDecision: () => evaluateScanDecision
});
module.exports = __toCommonJS(audit_decision_exports);
function severityRank(severity) {
  switch (severity) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
    default:
      return 1;
  }
}
function evaluateScanDecision(report) {
  const target = report.findings[0];
  if (!target) {
    return {
      scan_summary: {
        target: null,
        verdict: "CLEAN",
        finding_count: 0
      },
      audit_interpretation: {
        overallSeverity: "P3",
        findingSummary: [],
        recommendedAction: "ignore",
        nextDestination: "none",
        why: "No findings were present."
      },
      guard_decision: {
        action: "allow",
        reason: "No scanner evidence requires intervention."
      },
      authority_source: "guava-anti-guard",
      memory_promotion: {
        allowed: false,
        reason: "No finding exists to promote."
      }
    };
  }
  const rawFindings = target.findings ?? [];
  const highest = rawFindings.reduce((current, finding) => {
    if (!current) return finding;
    return severityRank(finding.severity) > severityRank(current.severity) ? finding : current;
  }, rawFindings[0]);
  const highestSeverity = highest?.severity ?? "LOW";
  const findingSummary = rawFindings.map((finding) => finding.desc || finding.id);
  let overallSeverity = "P3";
  let recommendedAction = "ignore";
  let nextDestination = "none";
  let guardAction = "allow";
  let why = "Low-signal findings should not become durable institutional memory.";
  if (highestSeverity === "CRITICAL") {
    overallSeverity = "P1";
    recommendedAction = "patch";
    nextDestination = "plan";
    guardAction = "patch";
    why = "Critical scanner evidence requires a bounded fix before promotion.";
  } else if (highestSeverity === "HIGH") {
    overallSeverity = "P2";
    recommendedAction = String(target.skill).includes("guard-scanner") ? "promote-skill" : "investigate";
    nextDestination = recommendedAction === "promote-skill" ? "skill" : "plan";
    guardAction = recommendedAction === "promote-skill" ? "promote-skill" : "investigate";
    why = "High-severity findings require bounded follow-up before trust can increase.";
  } else if (highestSeverity === "MEDIUM") {
    overallSeverity = "P2";
    recommendedAction = "investigate";
    nextDestination = "plan";
    guardAction = "investigate";
    why = "Medium-severity findings need reproduction and scope clarification.";
  }
  return {
    scan_summary: {
      target: target.skill,
      verdict: target.verdict,
      finding_count: rawFindings.length
    },
    audit_interpretation: {
      overallSeverity,
      findingSummary,
      recommendedAction,
      nextDestination,
      why
    },
    guard_decision: {
      action: guardAction,
      reason: why
    },
    authority_source: "guava-anti-guard",
    memory_promotion: {
      allowed: false,
      reason: "Raw scan output must be interpreted before any durable promotion."
    }
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  evaluateScanDecision
});
//# sourceMappingURL=audit-decision.js.map