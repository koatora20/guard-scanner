/**
 * guard-scanner v3.0.0 — Package Index
 * Re-exports all public types and the scanner class.
 */
export { GuardScanner, VERSION, THRESHOLDS } from './scanner.js';
export { default as runtimeGuardPlugin } from './runtime-plugin.js';
export { CAPABILITIES, getCapabilitySummary } from './capabilities.js';
export type { RuntimePluginConfig } from './runtime-plugin.js';
export type { Severity, Finding, SkillResult, PatternRule, CustomRuleInput, ScannerOptions, ScanStats, Thresholds, Verdict, VerdictLabel, FileType, JSONReport, Recommendation, SARIFReport, IoC_Database, SignatureDatabase, ThreatSignature, } from './types.js';
export { KNOWN_MALICIOUS, SIGNATURES_DB } from './ioc-db.js';
export { PATTERNS } from './patterns.js';
//# sourceMappingURL=index.d.ts.map