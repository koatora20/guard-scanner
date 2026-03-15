// @ts-nocheck
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { GuardScanner } = require('../dist/scanner.js');

test('v16 self-scan repo mode downgrades first-party threat intel', () => {
    const scanner = new GuardScanner({ summaryOnly: true, scanMode: 'repo' });
    scanner.scanDirectory(path.join(__dirname, '..'));
    const repo = scanner.findings.find((entry) => entry.skill.includes('workspace-guard-scanner'));
    assert.ok(repo, 'repo-mode self-scan should return a repo result');
    assert.ok(Array.isArray(repo.findings), 'repo result should carry findings');
});

test('v16 findings expose evidence metadata', () => {
    const scanner = new GuardScanner({ summaryOnly: true, checkDeps: true });
    scanner.scanDirectory(path.join(__dirname, 'fixtures'));
    const malicious = scanner.findings.find((entry) => entry.skill === 'malicious-skill');
    assert.ok(malicious);
    assert.ok(malicious.findings.every((finding) => typeof finding.confidence === 'number'));
    assert.ok(malicious.findings.every((finding) => typeof finding.evidence_class === 'string'));
    assert.ok(malicious.findings.every((finding) => finding.source_layer === 'static'));
});
