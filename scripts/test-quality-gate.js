#!/usr/bin/env node
/**
 * guard-scanner Test Quality Gate
 *
 * Prevents test quality regression by enforcing:
 * 1. Max test file count (≤ 20)
 * 2. No implementation code in test files (function declarations)
 * 3. No external skills/ dependencies in tests
 * 4. Test:implementation line ratio < 2.0
 *
 * Run: node scripts/test-quality-gate.js
 * Integrated into: npm test
 */

const fs = require('fs');
const path = require('path');

const TEST_DIR = path.join(__dirname, '..', 'test');
const SRC_DIR = path.join(__dirname, '..', 'src');
const MAX_TEST_FILES = 35;
const MAX_RATIO = 2.0;

let errors = 0;
let warnings = 0;

function fail(msg) { console.error(`  ❌ FAIL: ${msg}`); errors++; }
function warn(msg) { console.warn(`  ⚠️  WARN: ${msg}`); warnings++; }
function pass(msg) { console.log(`  ✅ PASS: ${msg}`); }

console.log('🛡️  Guard-Scanner Test Quality Gate\n');

// ── Check 1: Test file count ──
const testFiles = fs.readdirSync(TEST_DIR).filter(f => f.endsWith('.test.js'));
if (testFiles.length > MAX_TEST_FILES) {
    fail(`Test file count ${testFiles.length} exceeds max ${MAX_TEST_FILES}`);
} else {
    pass(`Test file count: ${testFiles.length}/${MAX_TEST_FILES}`);
}

// ── Check 2: No implementation code in test files ──
const IMPL_PATTERNS = [
    { regex: /^function\s+\w+\s*\(/gm, desc: 'top-level function declaration' },
    { regex: /^class\s+\w+/gm, desc: 'class declaration' },
];
// Allow helper patterns (small functions that assist testing)
const HELPER_WHITELIST = [
    'findPattern', 'matchPattern', 'testMatch', 'testPatternMatch',
    'findCheck', 'checkPatternsMatch', 'findSkillFindings',
    'hasCategory', 'hasId', 'scanFixture',
    'loadLiveData', 'httpGet', 'createMockHttpGet', 'createMockAPI',
    'buildDashEngine', 'createMockVTGet'
];

let implViolations = 0;
for (const file of testFiles) {
    const content = fs.readFileSync(path.join(TEST_DIR, file), 'utf8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funcMatch = line.match(/^function\s+(\w+)\s*\(/);
        if (funcMatch) {
            const name = funcMatch[1];
            if (!HELPER_WHITELIST.includes(name)) {
                warn(`${file}:${i + 1} — function '${name}' looks like implementation code (move to src/)`);
                implViolations++;
            }
        }
    }
}
if (implViolations === 0) {
    pass('No implementation code in test files');
} else {
    warn(`${implViolations} potential implementation function(s) in test files`);
}

// ── Check 3: No external skills/ dependencies ──
let skillDeps = 0;
for (const file of testFiles) {
    const content = fs.readFileSync(path.join(TEST_DIR, file), 'utf8');
    const matches = content.match(/require\s*\(\s*['"]\.\.\/\.\.\/skills\//g);
    if (matches) {
        fail(`${file}: ${matches.length} external skills/ require(s) — tests must be self-contained`);
        skillDeps += matches.length;
    }
}
if (skillDeps === 0) {
    pass('No external skills/ dependencies');
}

// ── Check 4: Test:implementation line ratio ──
function countLines(dir) {
    let total = 0;
    for (const f of fs.readdirSync(dir)) {
        if (f.endsWith('.js')) {
            total += fs.readFileSync(path.join(dir, f), 'utf8').split('\n').length;
        }
    }
    return total;
}

const testLines = countLines(TEST_DIR);
const srcLines = countLines(SRC_DIR);
const ratio = (testLines / srcLines).toFixed(2);

if (parseFloat(ratio) > MAX_RATIO) {
    warn(`Test:implementation ratio ${ratio}:1 exceeds max ${MAX_RATIO}:1`);
} else {
    pass(`Test:implementation ratio: ${ratio}:1 (max ${MAX_RATIO}:1)`);
}

// ── Summary ──
console.log(`\n${'═'.repeat(50)}`);
console.log(`Test files: ${testFiles.length} | Test lines: ${testLines} | Src lines: ${srcLines}`);
console.log(`Errors: ${errors} | Warnings: ${warnings}`);

if (errors > 0) {
    console.error('\n💥 Quality gate FAILED — fix errors before committing');
    process.exit(1);
}

if (warnings > 0) {
    console.warn('\n⚠️  Quality gate PASSED with warnings');
} else {
    console.log('\n✅ Quality gate PASSED');
}
