// @ts-nocheck
import { describe, it, assert, beforeEach, afterEach, vi } from 'vitest';

import { PolicyEngine  } from '../src/policy-engine';

describe('P1: Runtime Guard Policy Engine', () => {
    it('Should evaluate tool calls against strict sensitivity profiles', () => {
        const engine = new PolicyEngine({ mode: 'strict' });
        
        const decision1 = engine.evaluate('run_shell_command', { command: 'rm -rf /' });
        assert.equal(decision1.action, 'block', 'Should block destructive FS ops in strict mode');
        
        const decision2 = engine.evaluate('read_file', { file_path: '.env' });
        assert.equal(decision2.action, 'block', 'Should block credential reads in strict mode');
        
        const decision3 = engine.evaluate('read_file', { file_path: 'README.md' });
        assert.equal(decision3.action, 'allow', 'Should allow normal reads');
    });

    it('respects capability-scoped policy contracts', () => {
        const engine = new PolicyEngine({
            mode: 'strict',
            policy: {
                id: 'review-only',
                allowed_tools: ['read_file'],
                max_network_scope: 'none',
                memory_write_permission: false,
                secret_bearing_context: true,
            },
        });

        const blockedTool = engine.evaluate('shell', { command: 'echo hi' });
        assert.equal(blockedTool.action, 'block');
        assert.equal(blockedTool.policyId, 'review-only');

        const blockedMemory = engine.evaluate('read_file', { path: 'memory/episodes/2026-03-13.md', action: 'write' });
        assert.equal(blockedMemory.action, 'block');
    });
});
