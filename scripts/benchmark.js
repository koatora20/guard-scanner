const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { GuardScanner } = require('../dist/scanner.js');
const { scoreWithRust } = require('../dist/rust-bridge.js');

function main() {
    const target = process.argv[2] ? path.resolve(process.argv[2]) : path.join(process.cwd(), 'test', 'fixtures');
    const scanner = new GuardScanner({ summaryOnly: true, checkDeps: true });

    const scanStarted = performance.now();
    const originalLog = console.log;
    console.log = () => {};
    scanner.scanDirectory(target);
    console.log = originalLog;
    const scanElapsedMs = Number((performance.now() - scanStarted).toFixed(3));

    const tsStarted = performance.now();
    const tsResults = scanner.findings.map((entry) => ({
        skill: entry.skill,
        risk: scanner.scoreFindings(entry.findings).risk,
    }));
    const tsElapsedMs = Number((performance.now() - tsStarted).toFixed(3));

    const rustStarted = performance.now();
    const rustResults = scanner.findings.map((entry) => {
        const rust = scoreWithRust(entry.findings);
        return {
            skill: entry.skill,
            risk: rust ? rust.risk : null,
            engine: rust ? rust.engine : 'fallback',
        };
    });
    const rustElapsedMs = Number((performance.now() - rustStarted).toFixed(3));

    const parity = tsResults.map((entry, index) => ({
        skill: entry.skill,
        tsRisk: entry.risk,
        rustRisk: rustResults[index].risk,
        parity: rustResults[index].risk === null ? 'missing-rust-core' : entry.risk === rustResults[index].risk ? 'match' : 'drift',
    }));

    console.log(JSON.stringify({
        target,
        scanElapsedMs,
        tsElapsedMs,
        rustElapsedMs,
        parity,
    }, null, 2));
}

main();
