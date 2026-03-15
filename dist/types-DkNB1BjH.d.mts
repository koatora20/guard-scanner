/**
 * guard-scanner type definitions.
 */
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type VerdictLabel = 'MALICIOUS' | 'SUSPICIOUS' | 'LOW RISK' | 'CLEAN';
type VerdictStat = 'malicious' | 'suspicious' | 'low' | 'clean';
interface Verdict {
    icon: string;
    label: VerdictLabel;
    stat: VerdictStat;
}
type FileType = 'code' | 'doc' | 'data' | 'skill-doc' | 'other';
type ScanMode = 'auto' | 'skills' | 'repo';
type ScanTargetKind = 'skill' | 'repo';
type SourceLayer = 'static' | 'runtime' | 'benchmark';
type EvidenceClass = 'code' | 'doc-example' | 'fixture' | 'generated';
type CoexistenceMode = 'independent' | 'rampart_primary' | 'scanner_primary';
type SyncMode = 'off' | 'local-overlay';
interface Finding {
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
interface ScanResult {
    skill: string;
    risk: number;
    verdict: VerdictLabel;
    findings: Finding[];
}
type SkillResult = ScanResult;
interface PatternRule {
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
interface CustomRuleInput {
    id: string;
    pattern: string;
    flags?: string;
    severity: Severity;
    cat: string;
    desc: string;
    codeOnly?: boolean;
    docOnly?: boolean;
}
interface CustomRule extends CustomRuleInput {
}
interface IoC_Database {
    ips: string[];
    domains: string[];
    urls: string[];
    usernames: string[];
    filenames: string[];
    typosquats: string[];
}
interface ThreatSignature {
    id: string;
    name: string;
    severity: Severity;
    description: string;
    hash?: string;
    patterns?: string[];
    domains?: string[];
}
interface SignatureDatabase {
    version: string;
    updated: string;
    signatures: ThreatSignature[];
}
interface ScannerOptions {
    verbose?: boolean;
    selfExclude?: boolean;
    strict?: boolean;
    summaryOnly?: boolean;
    checkDeps?: boolean;
    rulesFile?: string;
    plugins?: string[];
    scanMode?: ScanMode;
}
interface PluginConfig {
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
interface RuntimeDecision {
    action: 'allow' | 'warn' | 'block';
    reason?: string;
    checkId?: string;
    severity?: Severity;
}
interface McpRequest {
    jsonrpc: '2.0';
    id?: string | number | null;
    method: string;
    params?: Record<string, unknown>;
}
interface ScanStats {
    scanned: number;
    clean: number;
    low: number;
    suspicious: number;
    malicious: number;
}
interface Thresholds {
    suspicious: number;
    malicious: number;
}
interface JSONReport {
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
interface Recommendation {
    skill: string;
    actions: string[];
}
interface CapabilityMetrics {
    patternCount: number;
    categoryCount: number;
    runtimeCheckCount: number;
    supportedModes: ScanMode[];
}
interface SARIFReport {
    version: string;
    $schema: string;
    runs: SARIFRun[];
}
interface SARIFRun {
    tool: {
        driver: {
            name: string;
            version: string;
            informationUri: string;
            rules: SARIFRule[];
        };
    };
    results: SARIFResult[];
    invocations: Array<{
        executionSuccessful: boolean;
        endTimeUtc: string;
    }>;
}
interface SARIFRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    defaultConfiguration: {
        level: string;
    };
    properties: {
        tags: string[];
        'security-severity': string;
    };
}
interface SARIFResult {
    ruleId: string;
    ruleIndex: number;
    level: string;
    message: {
        text: string;
    };
    partialFingerprints: {
        primaryLocationLineHash: string;
    };
    locations: Array<{
        physicalLocation: {
            artifactLocation: {
                uri: string;
                uriBaseId: string;
            };
            region?: {
                startLine: number;
            };
        };
    }>;
}

export type { CapabilityMetrics as C, FileType as F, IoC_Database as I, JSONReport as J, McpRequest as M, PatternRule as P, Recommendation as R, SARIFReport as S, ThreatSignature as T, Verdict as V, CustomRule as a, CustomRuleInput as b, Finding as c, ScanResult as d, ScanStats as e, ScannerOptions as f, Severity as g, SignatureDatabase as h, SkillResult as i, Thresholds as j, VerdictLabel as k, ScanMode as l, PluginConfig as m, RuntimeDecision as n, ScanTargetKind as o, SourceLayer as p, VerdictStat as q };
