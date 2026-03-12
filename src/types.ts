export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type GuardMode = "monitor" | "enforce" | "strict";
export type RuntimeAction = "blocked" | "warned";

export interface EvidenceSpan {
  file?: string;
  start_line: number;
  end_line: number;
}

export interface FindingEvidence {
  file?: string;
  line?: number | null;
  sample?: string;
  match_count?: number;
  tool_name?: string;
  params_preview?: string;
  layer?: number;
  layer_name?: string;
}

export interface Finding {
  schema_version?: string;
  source?: "static" | "runtime";
  id: string;
  rule_id?: string;
  cat?: string;
  category: string;
  severity: Severity;
  desc?: string;
  description: string;
  file?: string;
  line?: number | null;
  matchCount?: number;
  sample?: string;
  rationale: string;
  preconditions: string;
  remediation_hint: string;
  false_positive_scenarios: string[];
  validation_state: string;
  validation_status: string;
  confidence: number;
  attack_chain_id: string | null;
  evidence: FindingEvidence;
  evidence_spans: EvidenceSpan[];
  layer?: number;
  action?: RuntimeAction;
}

export interface SkillFindingResult {
  skill: string;
  risk: number;
  verdict: string;
  findings: Finding[];
}

export interface ThresholdBand {
  suspicious: number;
  malicious: number;
}

export interface ScanStats {
  scanned: number;
  clean: number;
  low: number;
  suspicious: number;
  malicious: number;
}

export interface Recommendation {
  skill: string;
  actions: string[];
}

export interface ScanReport {
  schema_version: string;
  timestamp: string;
  scanner: string;
  finding_schema_version: string;
  mode: "normal" | "strict";
  stats: ScanStats;
  thresholds: ThresholdBand;
  findings: SkillFindingResult[];
  recommendations: Recommendation[];
  iocVersion: string;
}

export interface TextScanResult {
  safe: boolean;
  risk: number;
  detections: Finding[];
}

export interface ScannerOptions {
  verbose?: boolean;
  selfExclude?: boolean;
  strict?: boolean;
  summaryOnly?: boolean;
  quiet?: boolean;
  checkDeps?: boolean;
  soulLock?: boolean;
  plugins?: string[];
  rulesFile?: string;
}

export interface CustomRule {
  id: string;
  cat: string;
  regex: RegExp;
  severity: Severity;
  desc: string;
  codeOnly?: boolean;
  docOnly?: boolean;
  all?: boolean;
  soulLock?: boolean;
}

export interface PluginConfig {
  mode?: GuardMode;
  auditLog?: boolean;
  customRules?: string;
}

export interface RuntimeDecision {
  blocked: boolean;
  blockReason: string | null;
  detections: Finding[];
  mode: GuardMode;
  toolName?: string;
}

export interface McpRequest {
  method: string;
  params?: Record<string, unknown>;
  id?: string | number | null;
}

export interface SarifReport {
  version: string;
  $schema?: string;
  runs: Array<Record<string, unknown>>;
}

export interface CapabilityMetrics {
  static_pattern_count: number;
  runtime_check_count?: number;
  threat_category_count: number;
  runtime_layer_count?: number;
  runtime_layers?: number;
  [key: string]: unknown;
}

export interface RuntimeCheckStats {
  total: number;
  byLayer: Record<number, number>;
  bySeverity: Partial<Record<Severity, number>>;
}

export interface ThreatModel {
  timestamp: string;
  surface: Record<string, boolean>;
  summary: string;
}

export interface GuardScannerInstance {
  verbose: boolean;
  strict: boolean;
  summaryOnly: boolean;
  quiet: boolean;
  checkDeps: boolean;
  soulLock: boolean;
  thresholds: ThresholdBand;
  findings: SkillFindingResult[];
  stats: ScanStats;
  scanText(text: string): TextScanResult;
  scanDirectory(dir: string): SkillFindingResult[];
  scanTarget(targetPath: string): ScanReport;
  toJSON(): ScanReport;
  toSARIF(scanDir: string): SarifReport;
  toHTML(): string;
  generateThreatModel(findings: Finding[]): ThreatModel;
}

export interface GuardScannerConstructor {
  new (options?: ScannerOptions): GuardScannerInstance;
}

export type ScanResult = SkillFindingResult;
