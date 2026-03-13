// @ts-nocheck
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
    buildBenchmarkLedger,
    buildFalsePositiveLedger,
    loadQualityContract,
} = require('../src/benchmark-runner');

describe('Benchmark ledger contracts', () => {
    it('builds three benchmark layers and aggregate metrics', () => {
        const ledger = buildBenchmarkLedger(loadQualityContract());

        assert.equal(ledger.layers.length, 3);
        assert.ok(typeof ledger.aggregate.metrics.precision === 'number');
        assert.ok(typeof ledger.aggregate.metrics.recall === 'number');
        assert.ok(typeof ledger.explainability.rate === 'number');
    });

    it('emits a false-positive ledger with stable structure', () => {
        const ledger = buildBenchmarkLedger(loadQualityContract());
        const fpLedger = buildFalsePositiveLedger(ledger);

        assert.ok(Array.isArray(fpLedger.entries));
        assert.equal(fpLedger.benchmark_version, ledger.benchmark_version);
    });
});
