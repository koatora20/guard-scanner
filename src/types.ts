/**
 * guard-scanner type definitions.
 */

// ── Severity & Verdict ──────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type VerdictLabel = 'MALICIOUS' | 'SUSPICIOUS' | 'LOW RISK' | 'CLEAN';
export type VerdictStat = 'malicious' | 'suspicious' | 'low' | 'clean';

export interface Verdict {
    icon: string;
    label: VerdictLabel;
    stat: VerdictStat;
}

// ── File Types ──────────────────────────────────────────────────────────────

export type FileType = 'code' | 'doc' | 'data' | 'skill-doc' | 'other';
export type ScanMode = 'auto' | 'skills' | 'repo';
export type ScanTargetKind = 'skill' | 'repo';
export type SourceLayer = 'static' | 'runtime' | 'benchmark';
export type EvidenceClass = 'code' | 'doc-example' | 'fixture' | 'generated';
export type CoexistenceMode = 'independent' | 'rampart_primary' | 'scanner_primary';
export type SyncMode = 'off' | 'local-overlay';

// ── Findings ────────────────────────────────────────────────────────────────

export interface Finding {
    severity: Severity;
    id: string;
    cat: string;
    desc: string;
    file: string;
    line?: number;
    matchCount?: number;
    sample?: string;
    source_layer?: SourceLayer;
    evidence_class?: EvidenceClass;
    confidence?: number;
    fp_suspected?: boolean;
    explainability?: string;
    suppression_reason?: string;
}

export interface ScanResult {
    skill: string;
    risk: number;
    verdict: VerdictLabel;
    findings: Finding[];
}

export type SkillResult = ScanResult;

// ── Patterns ────────────────────────────────────────────────────────────────

export interface PatternRule {
    id: string;
    cat: string;
    regex: RegExp;
    severity: Severity;
    desc: string;
    codeOnly?: boolean;
    docOnly?: boolean;
    all?: boolean;
    /** OWASP LLM Top 10 2025 mapping (e.g. 'LLM01', 'LLM06') */
    owasp?: string;
}

export interface CustomRuleInput {
    id: string;
    pattern: string;
    flags?: string;
    severity: Severity;
    cat: string;
    desc: string;
    codeOnly?: boolean;
    docOnly?: boolean;
}

export interface CustomRule extends CustomRuleInput {}

// ── IoC Database ────────────────────────────────────────────────────────────

export interface IoC_Database {
    ips: string[];
    domains: string[];
    urls: string[];
    usernames: string[];
    filenames: string[];
    typosquats: string[];
}

// ── Signature Database (hbg-scan compatible) ────────────────────────────────

export interface ThreatSignature {
    id: string;
    name: string;
    severity: Severity;
    description: string;
    hash?: string;          // SHA-256 content hash match
    patterns?: string[];    // String patterns to match
    domains?: string[];     // Suspicious domains
}

export interface SignatureDatabase {
    version: string;
    updated: string;
    signatures: ThreatSignature[];
}

// ── Scanner Options ─────────────────────────────────────────────────────────

export interface ScannerOptions {
    verbose?: boolean;
    selfExclude?: boolean;
    strict?: boolean;
    summaryOnly?: boolean;
    checkDeps?: boolean;
    rulesFile?: string;
    plugins?: string[];
    scanMode?: ScanMode;
}

export interface PluginConfig {
    mode?: 'monitor' | 'enforce' | 'strict';
    coexistenceMode?: CoexistenceMode;
    syncMode?: SyncMode;
    rampartApiBase?: string;
    syncIntervalSec?: number;
    sharedRunIdEnabled?: boolean;
    overlayExportPath?: string;
    auditLog?: boolean;
    customRules?: string;
    enableAuditLog?: boolean;
    auditDir?: string;
    suiteTokenPath?: string;
    configPath?: string;
    constitutionPath?: string;
}

export interface RuntimeDecision {
    action: 'allow' | 'warn' | 'block';
    reason?: string;
    checkId?: string;
    severity?: Severity;
}

export interface McpRequest {
    jsonrpc: '2.0';
    id?: string | number | null;
    method: string;
    params?: Record<string, unknown>;
}

// ── Scanner Stats ───────────────────────────────────────────────────────────

export interface ScanStats {
    scanned: number;
    clean: number;
    low: number;
    suspicious: number;
    malicious: number;
}

// ── Thresholds ──────────────────────────────────────────────────────────────

export interface Thresholds {
    suspicious: number;
    malicious: number;
}

// ── Reports ─────────────────────────────────────────────────────────────────

export interface JSONReport {
    timestamp: string;
    scanner: string;
    mode: 'strict' | 'normal';
    stats: ScanStats;
    thresholds: Thresholds;
    findings: SkillResult[];
    recommendations: Recommendation[];
    iocVersion: string;
    signaturesVersion?: string;
}

export interface Recommendation {
    skill: string;
    actions: string[];
}

export interface CapabilityMetrics {
    patternCount: number;
    categoryCount: number;
    runtimeCheckCount: number;
    supportedModes: ScanMode[];
}

// ── SARIF ───────────────────────────────────────────────────────────────────

export interface SARIFReport {
    version: string;
    $schema: string;
    runs: SARIFRun[];
}

export interface SARIFRun {
    tool: {
        driver: {
            name: string;
            version: string;
            informationUri: string;
            rules: SARIFRule[];
        };
    };
    results: SARIFResult[];
    invocations: Array<{ executionSuccessful: boolean; endTimeUtc: string }>;
}

export interface SARIFRule {
    id: string;
    name: string;
    shortDescription: { text: string };
    defaultConfiguration: { level: string };
    properties: { tags: string[]; 'security-severity': string };
}

export interface SARIFResult {
    ruleId: string;
    ruleIndex: number;
    level: string;
    message: { text: string };
    partialFingerprints: { primaryLocationLineHash: string };
    locations: Array<{
        physicalLocation: {
            artifactLocation: { uri: string; uriBaseId: string };
            region?: { startLine: number };
        };
    }>;
}
