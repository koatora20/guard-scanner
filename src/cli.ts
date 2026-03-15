#!/usr/bin/env node
/**
 * guard-scanner CLI.
 */

import * as fs from 'fs';
import * as path from 'path';
import { GuardScanner, VERSION } from './scanner.js';
import { PATTERNS } from './patterns.js';
import { CAPABILITIES, getCapabilitySummary } from './capabilities.js';
import { execFileSync } from 'node:child_process';
import { handleMcpRequest } from './mcp.js';

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
    console.log(`
🛡️  guard-scanner v${VERSION} — Agent Skill Security Scanner (TypeScript-first)
${getCapabilitySummary()}

Usage: guard-scanner [scan-dir] [options]
       guard-scanner capabilities
       guard-scanner audit-baseline
       guard-scanner benchmark [scan-dir]
       guard-scanner mcp < request.json

Options:
  --verbose, -v       Detailed findings with categories and samples
  --json              Write JSON report
  --sarif             Write SARIF report (GitHub Code Scanning / CI/CD)
  --self-exclude      Skip scanning the guard-scanner skill itself
  --mode <auto|skills|repo>
                      Scan categorized skill trees correctly and avoid treating package repos as skill buckets
  --strict            Lower detection thresholds (more sensitive)
  --summary-only      Only print the summary table
  --check-deps        Scan package.json for dependency chain risks
  --rules <file>      Load custom rules from JSON file
  --plugin <file>     Load plugin module
  --fail-on-findings  Exit code 1 if any findings (CI/CD)
  --help, -h          Show this help

Current package traits:
  • TypeScript-first runtime, CLI, plugin, and MCP entrypoints
  • Dual ESM + CJS package exports with shipped declarations
  • Shared scanner engine across CLI, MCP, and OpenClaw plugin bridge

Examples:
  guard-scanner ./skills/ --verbose --self-exclude
  guard-scanner ./skills/ --mode skills
  guard-scanner ~/workspace-guard-scanner --mode repo
  guard-scanner ./skills/ --strict --json --sarif --check-deps
  guard-scanner ./skills/ --fail-on-findings
  guard-scanner mcp < request.json
`);
    process.exit(0);
}

if (args[0] === 'capabilities') {
    console.log(JSON.stringify(CAPABILITIES, null, 2));
    process.exit(0);
}

if (args[0] === 'audit-baseline') {
    const out = execFileSync(process.execPath, [path.join(__dirname, 'tools', 'audit-baseline.js')], {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    process.stdout.write(out);
    process.exit(0);
}

if (args[0] === 'benchmark') {
    const cmdArgs = [path.join(__dirname, 'tools', 'benchmark.js')];
    if (args.length > 1) {
        cmdArgs.push(...args.slice(1));
    }
    const out = execFileSync(process.execPath, cmdArgs, {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    process.stdout.write(out);
    process.exit(0);
}

if (args[0] === 'mcp') {
    const raw = fs.readFileSync(0, 'utf8');
    process.stdout.write(`${JSON.stringify(handleMcpRequest(JSON.parse(raw)), null, 2)}\n`);
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
const modeIdx = args.indexOf('--mode');
const scanMode = modeIdx >= 0 ? args[modeIdx + 1] : 'auto';
if (!['auto', 'skills', 'repo'].includes(scanMode)) {
    console.error(`❌ Invalid --mode: ${scanMode}. Use auto, skills, or repo.`);
    process.exit(2);
}

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
    verbose, selfExclude, strict, summaryOnly, checkDeps, rulesFile, plugins, scanMode: scanMode as 'auto' | 'skills' | 'repo',
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
