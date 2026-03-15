// @ts-nocheck
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
    assert.equal(parsed.product.version, '17.0.0');
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
    const raw = execFileSync(process.execPath, [CLI, 'benchmark', path.join(process.cwd(), 'test', 'fixtures'), '--runs', '3'], {
        cwd: process.cwd(),
        encoding: 'utf8',
    });
    const parsed = JSON.parse(raw);
    assert.equal(parsed.run_count, 3);
    assert.equal(parsed.cold_runs, 1);
    assert.equal(parsed.warm_runs, 2);
    assert.ok(Array.isArray(parsed.stage_samples));
    assert.equal(parsed.stage_samples.length, 3);
    assert.equal(parsed.fixture_id, 'fixtures');
    assert.equal(parsed.aggregates.total_ms.all.count, 3);
    assert.ok(typeof parsed.aggregates.scan_ms.all.p95 === 'number');
    assert.ok(typeof parsed.aggregates.ts_score_ms.all.p95 === 'number');
    assert.ok(typeof parsed.aggregates.rust_score_ms.all.p95 === 'number');
    assert.ok(typeof parsed.aggregates.total_ms.all.p95 === 'number');
    assert.ok(typeof parsed.aggregates.throughput_items_per_sec.all.mean === 'number');
    assert.equal(parsed.environment.node, process.version);
    assert.ok(Array.isArray(parsed.parity));
    assert.ok(parsed.parity.length > 0);
});
