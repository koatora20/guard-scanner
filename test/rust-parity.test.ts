// @ts-nocheck
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

describe('Rust parity harness', () => {
    it('matches TypeScript risk scoring fixtures', () => {
        const root = path.join(__dirname, '..');
        const output = execFileSync('npx', ['tsx', 'scripts/rust-parity.ts'], {
            cwd: root,
            encoding: 'utf8',
        });
        assert.match(output, /Rust parity: 3\/3 matched/);
    });
});
