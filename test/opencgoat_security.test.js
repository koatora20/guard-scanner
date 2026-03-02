/**
 * OpenCGoat (GuavaGoat) Autonomous Security Integration Tests
 * 
 * Target: Validate B2B Autonomy against 2026 Moltbook/Claude Code Vulnerabilities
 * Tests resilience to PromptPwnd (Prompt Injection) and Cognitive Worm (Memory Poisoning).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { GuardScanner, THRESHOLDS } = require('../src/scanner.js');

const SKILLS_DIR = '/Users/ishikawaryuuta/.openclaw/workspace/skills';
const TARGET_SKILLS = [
    'bug-bounty-scan',
    'opencrabs-swarm-bounty',
    'og-board-manager',
    'og-board-individual'
];

function findSkillFindings(scanner, skillName) {
    return scanner.findings.find(f => f.skill === skillName);
}

function hasCategory(findings, cat) {
    return findings && findings.findings.some(f => f.cat === cat);
}

describe('OpenCGoat B2B Autonomous Registry Audit', () => {
    // strict mode lower thresholds, soulLock prevents memory tampering
    const scanner = new GuardScanner({ summaryOnly: true, strict: true, soulLock: true });

    // Process target skills directory
    TARGET_SKILLS.forEach(skill => {
        const skillPath = path.join(SKILLS_DIR, skill);
        scanner.scanSkill(skillPath, skill);
    });

    TARGET_SKILLS.forEach(skillName => {
        describe(`Skill: ${skillName}`, () => {
            const skillData = findSkillFindings(scanner, skillName);

            it('should not contain any findings (CLEAN status)', () => {
                // Assert no findings were generated.
                // If it fails, Guard-Scanner caught something.
                const findingsLength = skillData ? skillData.findings.length : 0;
                assert.equal(findingsLength, 0, `Skill ${skillName} has vulnerabilities! \n${JSON.stringify(skillData, null, 2)}`);
            });

            if (skillData && skillData.findings.length > 0) {
                it('should be immune to PromptPwnd (No prompt injection allowed)', () => {
                    assert.ok(!hasCategory(skillData, 'prompt-injection'), 'FAILED: Prompt Injection (PromptPwnd vector) detected.');
                });

                it('should be immune to Moltbook Cognitive Worm (No memory poisoning)', () => {
                    assert.ok(!hasCategory(skillData, 'memory-poisoning'), 'FAILED: Memory Poisoning (Cognitive Worm vector) detected.');
                });

                it('should not contain structural RCE or Exec bindings', () => {
                    assert.ok(!hasCategory(skillData, 'malicious-code'), 'FAILED: Malicious Code (RCE) detected.');
                });

                it('should survive rigorous enterprise metrics', () => {
                    const risk = scanner.calculateRisk(skillData.findings);
                    const verdict = scanner.getVerdict(risk);
                    // In strict mode, MUST be CLEAN
                    assert.equal(verdict.label, 'CLEAN', `VERDICT FAILED: ${verdict.label}`);
                });
            }
        });
    });
});
