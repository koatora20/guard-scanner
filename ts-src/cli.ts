#!/usr/bin/env node
/**
 * guard-scanner v3.0.0 — CLI (TypeScript)
 *
 * Usage:
 *   guard-scanner [scan-dir] [options]           Scan all skills in directory
 *   guard-scanner install-check <skill-path>     Pre-install security check
 */

import * as fs from 'fs';
import * as path from 'path';
import { GuardScanner, VERSION } from './scanner.js';
import { PATTERNS } from './patterns.js';

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
    console.log(`
🛡️  guard-scanner v${VERSION} — Agent Skill Security Scanner (TypeScript)

Usage: guard-scanner [scan-dir] [options]

Options:
  --verbose, -v       Detailed findings with categories and samples
  --json              Write JSON report
  --sarif             Write SARIF report (GitHub Code Scanning / CI/CD)
  --self-exclude      Skip scanning the guard-scanner skill itself
  --strict            Lower detection thresholds (more sensitive)
  --summary-only      Only print the summary table
  --check-deps        Scan package.json for dependency chain risks
  --rules <file>      Load custom rules from JSON file
  --plugin <file>     Load plugin module
  --fail-on-findings  Exit code 1 if any findings (CI/CD)
  --help, -h          Show this help

New in v3.0.0:
  • TypeScript rewrite with full type safety
  • Compaction Layer Persistence detection (Feb 20 2026 attack vector)
  • Threat signature hash matching (hbg-scan compatible)
  • 7 built-in threat signatures (SIG-001 to SIG-007)
  • Enhanced risk scoring for compaction-persistence category

Examples:
  guard-scanner ./skills/ --verbose --self-exclude
  guard-scanner ./skills/ --strict --json --sarif --check-deps
  guard-scanner ./skills/ --fail-on-findings
`);
    process.exit(0);
}

// ── install-check subcommand ─────────────────────────────────────────────
if (args[0] === 'install-check') {
    const skillPath = args[1];
    if (!skillPath) {
        console.error('❌ Usage: guard-scanner install-check <skill-path>');
        process.exit(2);
    }
    const absPath = path.resolve(skillPath);
    if (!fs.existsSync(absPath)) {
        console.error(`❌ Skill path not found: ${absPath}`);
        process.exit(2);
    }

    const icStrict = args.includes('--strict');
    const icJson = args.includes('--json');
    const icVerbose = args.includes('--verbose') || args.includes('-v');

    const scanner = new GuardScanner({ strict: icStrict, verbose: icVerbose });
    const skillName = path.basename(absPath);

    console.log(`\n🛡️  guard-scanner install-check v${VERSION}`);
    console.log(`   Scanning: ${skillName} (${absPath})\n`);

    scanner.scanSkill(absPath, skillName);
    const result = scanner.findings[0];

    if (!result) {
        console.log('✅ PASS — No skill found at path');
        process.exit(0);
    }

    const { risk, verdict, findings } = result;

    if (icVerbose || findings.length > 0) {
        for (const f of findings) {
            const owaspTag = (PATTERNS.find(p => p.id === f.id) as any)?.owasp || '';
            const tag = owaspTag ? ` [${owaspTag}]` : '';
            console.log(`  ${f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡'} [${f.severity}] ${f.id}: ${f.desc}${tag}`);
            if (f.file) console.log(`    📁 ${f.file}${f.line ? `:${f.line}` : ''}`);
            if (f.sample && icVerbose) console.log(`    📝 ${f.sample.substring(0, 80)}`);
        }
        console.log('');
    }

    console.log(`Risk Score: ${risk} | Verdict: ${verdict} | Findings: ${findings.length}`);

    if (verdict === 'MALICIOUS' || verdict === 'SUSPICIOUS') {
        console.log(`\n❌ FAIL — This skill should NOT be installed.`);
        if (icJson) {
            const report = scanner.toJSON();
            const outPath = path.join(path.dirname(absPath), `${skillName}-install-check.json`);
            fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
            console.log(`📄 Report: ${outPath}`);
        }
        process.exit(1);
    } else {
        console.log(`\n✅ PASS — Skill appears safe to install.`);
        if (icJson) {
            const report = scanner.toJSON();
            const outPath = path.join(path.dirname(absPath), `${skillName}-install-check.json`);
            fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
            console.log(`📄 Report: ${outPath}`);
        }
        process.exit(0);
    }
}

const verbose = args.includes('--verbose') || args.includes('-v');
const jsonOutput = args.includes('--json');
const sarifOutput = args.includes('--sarif');
const selfExclude = args.includes('--self-exclude');
const strict = args.includes('--strict');
const summaryOnly = args.includes('--summary-only');
const checkDeps = args.includes('--check-deps');
const failOnFindings = args.includes('--fail-on-findings');

const rulesIdx = args.indexOf('--rules');
const rulesFile = rulesIdx >= 0 ? args[rulesIdx + 1] : undefined;

// Collect plugins
const plugins: string[] = [];
let idx = 0;
while (idx < args.length) {
    if (args[idx] === '--plugin' && args[idx + 1]) {
        plugins.push(args[idx + 1]);
        idx += 2;
    } else {
        idx++;
    }
}

const scanDir = args.find((a: string) =>
    !a.startsWith('-') &&
    a !== rulesFile &&
    !plugins.includes(a)
) || process.cwd();

const scanner = new GuardScanner({
    verbose, selfExclude, strict, summaryOnly, checkDeps, rulesFile, plugins,
});

scanner.scanDirectory(scanDir);

// Output reports
if (jsonOutput) {
    const report = scanner.toJSON();
    const outPath = path.join(scanDir, 'guard-scanner-report.json');
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`\n📄 JSON report: ${outPath}`);
}

if (sarifOutput) {
    const outPath = path.join(scanDir, 'guard-scanner.sarif');
    fs.writeFileSync(outPath, JSON.stringify(scanner.toSARIF(scanDir), null, 2));
    console.log(`\n📄 SARIF report: ${outPath}`);
}

// Exit codes
if (scanner.stats.malicious > 0) process.exit(1);
if (failOnFindings && scanner.findings.length > 0) process.exit(1);
process.exit(0);
