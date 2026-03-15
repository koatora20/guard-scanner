import { l as ScanMode, j as Thresholds, i as SkillResult, e as ScanStats, f as ScannerOptions, c as Finding, J as JSONReport, S as SARIFReport } from './types-DkNB1BjH.mjs';

/**
 * guard-scanner core scanner.
 */

declare const VERSION: string;
declare const THRESHOLDS: Record<string, Thresholds>;
declare class GuardScanner {
    readonly verbose: boolean;
    readonly selfExclude: boolean;
    readonly strict: boolean;
    readonly summaryOnly: boolean;
    readonly checkDeps: boolean;
    readonly scanMode: ScanMode;
    readonly thresholds: Thresholds;
    findings: SkillResult[];
    stats: ScanStats;
    private scannerDir;
    private ignoredSkills;
    private ignoredPatterns;
    private customRules;
    constructor(options?: ScannerOptions);
    loadPlugin(pluginPath: string): void;
    loadCustomRules(rulesFile: string): void;
    private loadIgnoreFile;
    scanDirectory(dir: string): SkillResult[];
    scanSkill(skillPath: string, skillName: string): void;
    private scanTarget;
    private calibrateFinding;
    private enrichFinding;
    private resolveTargets;
    private safeReadDirs;
    private isSkillDir;
    private looksLikeRepo;
    private classifyFile;
    private checkIoCs;
    private checkPatterns;
    /** NEW: hbg-scan compatible signature matching (hash + pattern + domain) */
    private checkSignatures;
    /** NEW: Compaction Layer Persistence check (hbg-scan Check 5) */
    private checkCompactionPersistence;
    private checkHardcodedSecrets;
    private shannonEntropy;
    private checkStructure;
    private checkDependencies;
    private checkSkillManifest;
    private checkComplexity;
    private checkConfigImpact;
    private checkHiddenFiles;
    private checkJSDataFlow;
    private checkCrossFile;
    private getLineText;
    private getLineWindow;
    private isRepoMetadataEmailContext;
    private isBenignPromptContext;
    private isPatternCatalogContext;
    private isFirstPartyEvidenceContext;
    private isSchemaFieldContext;
    private isBenignSecretContext;
    private isBenignBase64Fragment;
    private calculateRisk;
    scoreFindings(findings: Finding[]): {
        risk: number;
        engine: 'ts' | 'rust';
    };
    private getVerdict;
    private getFiles;
    printSummary(): void;
    toJSON(): JSONReport;
    toSARIF(scanDir: string): SARIFReport;
}

export { GuardScanner, THRESHOLDS, VERSION };
