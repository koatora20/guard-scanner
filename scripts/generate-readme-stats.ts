import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// @ts-nocheck
/**
 * generate-readme-stats.js
 *
 * Runs `npm test` and injects actual test counts into README.md
 * Also updates the badge. Zero tolerance for hardcoded test numbers.
 *
 * Usage:
 *   node scripts/generate-readme-stats.js          # update README
 *   node scripts/generate-readme-stats.js --check   # CI mode: fail if drift detected
 */

import { execSync }  from 'child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(__dirname, '..');
const README_PATH = path.join(ROOT, 'README.md');
const TEST_FILE_COUNT_REGEX = /\.test\.(?:ts|js)$/;

function extractVitestJson(output: string): {
    numTotalTests: number;
    numPassedTests: number;
    numFailedTests: number;
    testResults: Array<{ name: string }>;
} {
    const lines = output.trim().split('\n').reverse();
    const jsonLine = lines.find((line) => line.trim().startsWith('{') && line.includes('"numTotalTests"'));
    if (!jsonLine) {
        throw new Error(`Could not find Vitest JSON payload in output:\n${output}`);
    }
    return JSON.parse(jsonLine);
}

// Run tests and capture output
let testOutput = '';
try {
    testOutput = execSync('npx vitest run --reporter=json', { cwd: ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
} catch (err) {
    testOutput = (err.stdout || '') + '\n' + (err.stderr || '');
}

let vitestReport;
try {
    vitestReport = extractVitestJson(testOutput);
} catch (err) {
    console.error(`❌ ${err.message}`);
    process.exit(1);
}

const tests = vitestReport.numTotalTests;
const pass = vitestReport.numPassedTests;
const fail = vitestReport.numFailedTests;
const suites = fs.readdirSync(path.join(ROOT, 'tests')).filter((file) => TEST_FILE_COUNT_REGEX.test(file)).length;

console.log(`📊 Parsed: tests=${tests} suites=${suites} pass=${pass} fail=${fail}`);

if (fail > 0) {
    console.error(`❌ ${fail} tests failed. Fix tests before updating README.`);
    process.exit(1);
}

// Read README
let readme = fs.readFileSync(README_PATH, 'utf8');

// 1. Update badge: tests-NNN%20passed
const badgeRe = /tests-\d+%20passed/g;
const newBadge = `tests-${pass}%20passed`;
readme = readme.replace(badgeRe, newBadge);

// 2. Update test results block
const statsBlockRe = /ℹ tests \d+\nℹ suites \d+\nℹ pass \d+\nℹ fail \d+/;
const newStatsBlock = `ℹ tests ${tests}\nℹ suites ${suites}\nℹ pass ${pass}\nℹ fail ${fail}`;
readme = readme.replace(statsBlockRe, newStatsBlock);

const isCheck = process.argv.includes('--check');

if (isCheck) {
    const current = fs.readFileSync(README_PATH, 'utf8');
    if (current !== readme) {
        console.error('❌ README test stats are out of sync! Run: node scripts/generate-readme-stats');
        process.exit(1);
    }
    console.log('✅ README test stats are in sync.');
} else {
    fs.writeFileSync(README_PATH, readme);
    console.log(`✅ README updated: ${pass} tests / ${suites} suites / ${fail} fail`);
}
