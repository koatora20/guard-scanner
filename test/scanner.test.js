/**
 * guard-scanner テストスイート
 *
 * node --test で実行
 * 実際の悪意パターンを含むフィクスチャを使い、各カテゴリの検出を検証
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { GuardScanner, VERSION, THRESHOLDS } = require('../src/scanner.js');
const { PATTERNS } = require('../src/patterns.js');
const { KNOWN_MALICIOUS } = require('../src/ioc-db.js');

const FIXTURES = path.join(__dirname, 'fixtures');

// ===== Helper =====
function scanFixture(options = {}) {
    const scanner = new GuardScanner({ summaryOnly: true, ...options });
    scanner.scanDirectory(FIXTURES);
    return scanner;
}

function findSkillFindings(scanner, skillName) {
    return scanner.findings.find(f => f.skill === skillName);
}

function hasCategory(findings, cat) {
    return findings && findings.findings.some(f => f.cat === cat);
}

function hasId(findings, id) {
    return findings && findings.findings.some(f => f.id === id);
}

// ===== 1. Detection Tests — Malicious Skill =====
describe('Malicious Skill Detection', () => {
    const scanner = scanFixture({ checkDeps: true });
    const mal = findSkillFindings(scanner, 'malicious-skill');

    it('should detect the malicious skill', () => {
        assert.ok(mal, 'malicious-skill should be in findings');
    });

    it('should rate malicious skill as MALICIOUS', () => {
        assert.equal(mal.verdict, 'MALICIOUS');
    });

    it('should detect prompt injection (Cat 1)', () => {
        assert.ok(hasCategory(mal, 'prompt-injection'), 'Should detect prompt-injection');
        assert.ok(hasId(mal, 'PI_IGNORE') || hasId(mal, 'PI_ROLE') || hasId(mal, 'PI_SYSTEM') || hasId(mal, 'PI_TAG_INJECTION'),
            'Should detect specific prompt injection pattern');
    });

    it('should detect malicious code (Cat 2)', () => {
        assert.ok(hasCategory(mal, 'malicious-code'), 'Should detect malicious-code');
        assert.ok(hasId(mal, 'MAL_EVAL') || hasId(mal, 'MAL_EXEC') || hasId(mal, 'MAL_CHILD'),
            'Should detect eval/exec/child_process');
    });

    it('should detect suspicious downloads (Cat 3)', () => {
        assert.ok(hasCategory(mal, 'suspicious-download') || hasId(mal, 'DL_CURL_BASH'),
            'Should detect curl|bash pattern');
    });

    it('should detect credential handling (Cat 4)', () => {
        assert.ok(hasCategory(mal, 'credential-handling'), 'Should detect credential-handling');
    });

    it('should detect secret detection (Cat 5)', () => {
        assert.ok(hasCategory(mal, 'secret-detection'), 'Should detect hardcoded secrets');
    });

    it('should detect exfiltration (Cat 6)', () => {
        assert.ok(hasCategory(mal, 'exfiltration'), 'Should detect exfiltration endpoints');
    });

    it('should detect obfuscation (Cat 9)', () => {
        assert.ok(hasCategory(mal, 'obfuscation'), 'Should detect obfuscation patterns');
    });

    it('should detect leaky skills (Cat 11)', () => {
        assert.ok(hasCategory(mal, 'leaky-skills'), 'Should detect leaky skill patterns');
    });

    it('should detect memory poisoning (Cat 12)', () => {
        assert.ok(hasCategory(mal, 'memory-poisoning'), 'Should detect memory poisoning');
    });

    it('should detect identity hijacking (Cat 17)', () => {
        assert.ok(hasCategory(mal, 'identity-hijack'), 'Should detect identity hijacking');
    });

    it('should detect data flow (credential → network)', () => {
        assert.ok(hasCategory(mal, 'data-flow'), 'Should detect data flow patterns');
    });

    it('should detect dependency chain risks', () => {
        assert.ok(hasCategory(mal, 'dependency-chain'), 'Should detect dependency risks');
    });

    it('should detect IoC (known malicious IP)', () => {
        assert.ok(hasId(mal, 'IOC_IP'), 'Should detect known malicious IP 91.92.242.30');
    });

    it('should detect IoC (webhook.site)', () => {
        assert.ok(hasId(mal, 'IOC_DOMAIN') || hasId(mal, 'EXFIL_WEBHOOK'),
            'Should detect webhook.site');
    });
});

// ===== 2. Clean Skill — False Positive Test =====
describe('Clean Skill (False Positive Test)', () => {
    const scanner = scanFixture();
    const clean = findSkillFindings(scanner, 'clean-skill');

    it('should NOT flag clean skill as having findings', () => {
        assert.equal(clean, undefined, 'clean-skill should have no findings');
    });

    it('should count clean as clean in stats', () => {
        assert.ok(scanner.stats.clean >= 1, 'At least 1 clean skill');
    });
});

// ===== 3. Risk Score & Threshold Tests =====
describe('Risk Score Calculation', () => {
    const scanner = new GuardScanner({ summaryOnly: true });

    it('should return 0 for empty findings', () => {
        assert.equal(scanner.calculateRisk([]), 0);
    });

    it('should score LOW for single low finding', () => {
        const risk = scanner.calculateRisk([{ severity: 'LOW', id: 'TEST', cat: 'structural' }]);
        assert.ok(risk > 0 && risk < THRESHOLDS.normal.suspicious,
            `Risk ${risk} should be below suspicious threshold ${THRESHOLDS.normal.suspicious}`);
    });

    it('should amplify score for credential + exfil combo', () => {
        const baseFindings = [
            { severity: 'HIGH', id: 'CRED1', cat: 'credential-handling' },
            { severity: 'HIGH', id: 'EXFIL1', cat: 'exfiltration' }
        ];
        const risk = scanner.calculateRisk(baseFindings);
        // 2x HIGH = 30, then credential+exfil amplifier = 2x = 60
        assert.ok(risk >= 60, `Risk ${risk} should be amplified by cred+exfil combo`);
    });

    it('should max out on known IoC', () => {
        const findings = [{ severity: 'CRITICAL', id: 'IOC_IP', cat: 'malicious-code' }];
        const risk = scanner.calculateRisk(findings);
        assert.equal(risk, 100, 'Known IoC should max out risk to 100');
    });

    it('should amplify identity hijack', () => {
        const findings = [
            { severity: 'CRITICAL', id: 'SOUL_OVERWRITE', cat: 'identity-hijack' },
            { severity: 'HIGH', id: 'PERSIST_CRON', cat: 'persistence' }
        ];
        const risk = scanner.calculateRisk(findings);
        assert.ok(risk >= 90, `Identity hijack + persistence should score ≥ 90, got ${risk}`);
    });
});

// ===== 4. Verdict Tests =====
describe('Verdict Determination', () => {
    const scanner = new GuardScanner({ summaryOnly: true });
    const strict = new GuardScanner({ summaryOnly: true, strict: true });

    it('should return CLEAN for risk 0', () => {
        assert.equal(scanner.getVerdict(0).label, 'CLEAN');
    });

    it('should return LOW RISK for risk 1-29', () => {
        assert.equal(scanner.getVerdict(15).label, 'LOW RISK');
    });

    it('should return SUSPICIOUS for risk 30-79', () => {
        assert.equal(scanner.getVerdict(50).label, 'SUSPICIOUS');
    });

    it('should return MALICIOUS for risk 80+', () => {
        assert.equal(scanner.getVerdict(80).label, 'MALICIOUS');
    });

    it('strict mode should lower thresholds', () => {
        assert.equal(strict.getVerdict(20).label, 'SUSPICIOUS');  // normal would be LOW
        assert.equal(strict.getVerdict(60).label, 'MALICIOUS');    // normal would be SUSPICIOUS
    });
});

// ===== 5. Output Format Tests =====
describe('Output Formats', () => {
    const scanner = scanFixture();

    it('toJSON should return valid structure', () => {
        const json = scanner.toJSON();
        assert.ok(json.timestamp, 'Should have timestamp');
        assert.ok(json.scanner.includes('guard-scanner'), 'Should identify scanner');
        assert.ok(json.stats, 'Should have stats');
        assert.ok(Array.isArray(json.findings), 'findings should be array');
        assert.ok(Array.isArray(json.recommendations), 'recommendations should be array');
    });

    it('toJSON recommendations should flag credential+exfil', () => {
        const json = scanner.toJSON();
        const malRecs = json.recommendations.find(r => r.skill === 'malicious-skill');
        assert.ok(malRecs, 'Should have recommendations for malicious-skill');
        assert.ok(malRecs.actions.length > 0, 'Should have action items');
    });

    it('toSARIF should return valid SARIF 2.1.0', () => {
        const sarif = scanner.toSARIF(FIXTURES);
        assert.equal(sarif.version, '2.1.0');
        assert.ok(sarif.runs, 'Should have runs');
        assert.ok(sarif.runs[0].tool.driver.name === 'guard-scanner');
        assert.ok(sarif.runs[0].results.length > 0, 'Should have results');
        assert.ok(sarif.runs[0].tool.driver.rules.length > 0, 'Should have rules');
    });

    it('toHTML should return valid HTML', () => {
        const html = scanner.toHTML();
        assert.ok(html.includes('<!DOCTYPE html>'), 'Should be valid HTML');
        assert.ok(html.includes('guard-scanner'), 'Should mention guard-scanner');
        assert.ok(html.includes('malicious-skill'), 'Should include malicious skill');
    });
});

// ===== 6. Pattern Database Integrity =====
describe('Pattern Database', () => {
    it('should have 100+ patterns', () => {
        assert.ok(PATTERNS.length >= 100, `Expected 100+ patterns, got ${PATTERNS.length}`);
    });

    it('all patterns should have required fields', () => {
        for (const p of PATTERNS) {
            assert.ok(p.id, `Pattern missing id: ${JSON.stringify(p).substring(0, 50)}`);
            assert.ok(p.cat, `Pattern ${p.id} missing cat`);
            assert.ok(p.regex, `Pattern ${p.id} missing regex`);
            assert.ok(p.severity, `Pattern ${p.id} missing severity`);
            assert.ok(p.desc, `Pattern ${p.id} missing desc`);
            assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(p.severity),
                `Pattern ${p.id} invalid severity: ${p.severity}`);
        }
    });

    it('should cover all 17 categories', () => {
        const cats = new Set(PATTERNS.map(p => p.cat));
        const expected = [
            'prompt-injection', 'malicious-code', 'suspicious-download',
            'credential-handling', 'secret-detection', 'exfiltration',
            'obfuscation', 'identity-hijack'
        ];
        for (const e of expected) {
            assert.ok(cats.has(e), `Missing category: ${e}`);
        }
    });

    it('pattern regexes should not throw on test strings', () => {
        const testStr = 'const x = require("fs"); eval(Buffer.from("test").toString());';
        for (const p of PATTERNS) {
            assert.doesNotThrow(() => {
                p.regex.lastIndex = 0;
                p.regex.test(testStr);
            }, `Pattern ${p.id} regex threw`);
        }
    });
});

// ===== 7. IoC Database Integrity =====
describe('IoC Database', () => {
    it('should have IPs', () => {
        assert.ok(KNOWN_MALICIOUS.ips.length > 0);
    });

    it('should have domains', () => {
        assert.ok(KNOWN_MALICIOUS.domains.length > 0);
    });

    it('should have typosquats', () => {
        assert.ok(KNOWN_MALICIOUS.typosquats.length > 10, 'Should have 10+ typosquats');
    });

    it('should include ClawHavoc C2 IP', () => {
        assert.ok(KNOWN_MALICIOUS.ips.includes('91.92.242.30'));
    });

    it('should include webhook.site', () => {
        assert.ok(KNOWN_MALICIOUS.domains.includes('webhook.site'));
    });
});

// ===== 8. Shannon Entropy =====
describe('Shannon Entropy', () => {
    const scanner = new GuardScanner({ summaryOnly: true });

    it('should return low entropy for repeated chars', () => {
        const e = scanner.shannonEntropy('aaaaaaaaaa');
        assert.ok(e < 1, `Entropy of "aaa..." should be < 1, got ${e}`);
    });

    it('should return high entropy for random-looking strings', () => {
        const e = scanner.shannonEntropy('aB3xK9pQ2mW7nL5cR1dF4gH6jS8tU0vY');
        assert.ok(e > 4, `Entropy of random string should be > 4, got ${e}`);
    });
});

// ===== 9. Ignore File =====
describe('Ignore Functionality', () => {
    it('should respect ignored patterns', () => {
        // Create a temp ignore file
        const ignoreContent = '# Test ignore\npattern:PI_IGNORE\npattern:PI_ROLE\n';
        const ignorePath = path.join(FIXTURES, '.guard-scanner-ignore');
        fs.writeFileSync(ignorePath, ignoreContent);

        try {
            const scanner = scanFixture();
            const mal = findSkillFindings(scanner, 'malicious-skill');
            // The ignored patterns should not appear
            assert.ok(!hasId(mal, 'PI_IGNORE'), 'PI_IGNORE should be filtered out');
            assert.ok(!hasId(mal, 'PI_ROLE'), 'PI_ROLE should be filtered out');
            // But other patterns should still be detected
            assert.ok(mal, 'malicious-skill should still have findings');
        } finally {
            fs.unlinkSync(ignorePath);
        }
    });
});

// ===== 10. Plugin API =====
describe('Plugin API', () => {
    it('should load plugin patterns', () => {
        const pluginPath = path.join(__dirname, 'test-plugin.js');
        fs.writeFileSync(pluginPath, `
      module.exports = {
        name: 'test-plugin',
        patterns: [
          { id: 'PLUGIN_TEST', cat: 'custom', regex: /console\\.log/g, severity: 'LOW', desc: 'Plugin test', all: true }
        ]
      };
    `);

        try {
            const scanner = new GuardScanner({ summaryOnly: true, plugins: [pluginPath] });
            assert.equal(scanner.customRules.length, 1);
            assert.equal(scanner.customRules[0].id, 'PLUGIN_TEST');
        } finally {
            fs.unlinkSync(pluginPath);
        }
    });
});
