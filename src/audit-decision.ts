import type { JSONReport, ScanResult, Severity } from "./types.js";

type AuditAction = "hold" | "investigate" | "patch" | "promote-policy" | "promote-skill" | "ignore";
type GuardAction = "allow" | "investigate" | "patch" | "promote-skill";
type Priority = "P1" | "P2" | "P3";

export interface ScanDecision {
    scan_summary: {
        target: string | null;
        verdict: string;
        finding_count: number;
    };
    audit_interpretation: {
        overallSeverity: Priority;
        findingSummary: string[];
        recommendedAction: AuditAction;
        nextDestination: "memory" | "policy" | "skill" | "plan" | "none";
        why: string;
    };
    guard_decision: {
        action: GuardAction;
        reason: string;
    };
    authority_source: "guava-anti-guard";
    memory_promotion: {
        allowed: false;
        reason: string;
    };
}

type ReportLike = Pick<JSONReport, "findings"> | { findings: ScanResult[] };

function severityRank(severity: Severity): number {
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

export function evaluateScanDecision(report: ReportLike): ScanDecision {
    const target = report.findings[0];
    if (!target) {
        return {
            scan_summary: {
                target: null,
                verdict: "CLEAN",
                finding_count: 0,
            },
            audit_interpretation: {
                overallSeverity: "P3",
                findingSummary: [],
                recommendedAction: "ignore",
                nextDestination: "none",
                why: "No findings were present.",
            },
            guard_decision: {
                action: "allow",
                reason: "No scanner evidence requires intervention.",
            },
            authority_source: "guava-anti-guard",
            memory_promotion: {
                allowed: false,
                reason: "No finding exists to promote.",
            },
        };
    }

    const rawFindings = target.findings ?? [];
    const highest = rawFindings.reduce((current, finding) => {
        if (!current) return finding;
        return severityRank(finding.severity) > severityRank(current.severity) ? finding : current;
    }, rawFindings[0]);
    const highestSeverity = highest?.severity ?? "LOW";
    const findingSummary = rawFindings.map((finding) => finding.desc || finding.id);

    let overallSeverity: Priority = "P3";
    let recommendedAction: AuditAction = "ignore";
    let nextDestination: ScanDecision["audit_interpretation"]["nextDestination"] = "none";
    let guardAction: GuardAction = "allow";
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
            finding_count: rawFindings.length,
        },
        audit_interpretation: {
            overallSeverity,
            findingSummary,
            recommendedAction,
            nextDestination,
            why,
        },
        guard_decision: {
            action: guardAction,
            reason: why,
        },
        authority_source: "guava-anti-guard",
        memory_promotion: {
            allowed: false,
            reason: "Raw scan output must be interpreted before any durable promotion.",
        },
    };
}
