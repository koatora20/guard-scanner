import { J as JSONReport, d as ScanResult } from './types-DkNB1BjH.js';

type AuditAction = "hold" | "investigate" | "patch" | "promote-policy" | "promote-skill" | "ignore";
type GuardAction = "allow" | "investigate" | "patch" | "promote-skill";
type Priority = "P1" | "P2" | "P3";
interface ScanDecision {
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
type ReportLike = Pick<JSONReport, "findings"> | {
    findings: ScanResult[];
};
declare function evaluateScanDecision(report: ReportLike): ScanDecision;

export { type ScanDecision, evaluateScanDecision };
