const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const CLI = path.join(process.cwd(), 'dist', 'cli.js');

test('capabilities subcommand exposes source of truth', () => {
    const raw = execFileSync(process.execPath, [CLI, 'capabilities'], {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    const parsed = JSON.parse(raw);
    assert.equal(parsed.product.version, '16.0.0');
    assert.ok(parsed.capabilities.subcommands.includes('benchmark'));
});

test('audit-baseline reports legacy drift signals', () => {
    const raw = execFileSync(process.execPath, [CLI, 'audit-baseline'], {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    const parsed = JSON.parse(raw);
    assert.ok(Array.isArray(parsed.drifts));
});

test('benchmark subcommand returns parity report', () => {
    const raw = execFileSync(process.execPath, [CLI, 'benchmark', path.join(process.cwd(), 'test', 'fixtures')], {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    const parsed = JSON.parse(raw);
    assert.ok(Array.isArray(parsed.parity));
    assert.ok(parsed.parity.length > 0);
});
