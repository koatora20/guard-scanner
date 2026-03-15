/**
 * guard-scanner public package index.
 */

export { GuardScanner, VERSION, THRESHOLDS } from './scanner.js';
export { evaluateScanDecision } from './audit-decision.js';
export { default as runtimeGuardPlugin } from './runtime-plugin.js';
export { default as openClawPlugin } from './plugin.js';
export { CAPABILITIES, getCapabilitySummary } from './capabilities.js';
export * from './mcp.js';
export type { PluginConfig, RuntimeDecision, RuntimePluginConfig } from './runtime-plugin.js';
export type {
    Severity, Finding, ScanResult, SkillResult, PatternRule, CustomRule, CustomRuleInput,
    ScannerOptions, ScanStats, Thresholds, Verdict, VerdictLabel, FileType,
    JSONReport, Recommendation, SARIFReport, CapabilityMetrics, McpRequest,
    IoC_Database, SignatureDatabase, ThreatSignature,
} from './types.js';
export { KNOWN_MALICIOUS, SIGNATURES_DB } from './ioc-db.js';
export { PATTERNS } from './patterns.js';
