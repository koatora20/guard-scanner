/**
 * guard-scanner v5.0.0 — Runtime Guard
 *
 * 22-pattern runtime threat detection across 4 defense layers:
 *   Layer 1: Runtime Threat Detection (13 patterns) — Payload & execution defense
 *   Layer 2: Trust Defense (5 patterns) — Memory/SOUL write protection
 *   Layer 3: Safety Judge (4 patterns) — Relational integrity checks
 *   Layer 4: Brain Behavioral Guard (1 pattern) — B-mem anomaly detection
 *
 * All patterns are deterministic regex-based checks. Zero LLM dependency.
 * Designed to block 2026-era Moltbook prompt injections and ClawHavoc RCE vectors.
 */
export interface GuardCheck {
    id: string;
    layer: 1 | 2 | 3 | 4;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    desc: string;
    test: (s: string) => boolean;
}
export interface GuardDetection {
    id: string;
    layer: number;
    severity: string;
    desc: string;
}
export declare const LAYER_1_CHECKS: GuardCheck[];
export declare const LAYER_2_CHECKS: GuardCheck[];
export declare const LAYER_3_CHECKS: GuardCheck[];
export declare const LAYER_4_CHECKS: GuardCheck[];
export interface GuardOptions {
    soulLock?: boolean;
}
export interface GuardScanResult {
    ok: boolean;
    tool: string | null;
    total_patterns: number;
    soul_lock_enabled: boolean;
    detections_count: number;
    detections: GuardDetection[];
    layers: {
        threat_detection: number;
        trust_defense: number;
        safety_judge: number;
        behavioral_guard: number;
    };
}
/**
 * Scan text against runtime guard patterns.
 * Base patterns (14) run by default.
 * Options.soulLock = true enables 9 identity/trust enforcement patterns.
 */
export declare function guardScan(text: string, toolName?: string, options?: GuardOptions): GuardScanResult;
/**
 * Convenience method that returns a JSON string, directly backwards-compatible
 * with the original GuavaSuite `guardScan` function signature.
 */
export declare function guardScanJson(text: string, toolName?: string, options?: GuardOptions): string;
//# sourceMappingURL=runtime.d.ts.map