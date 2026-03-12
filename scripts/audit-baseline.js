const fs = require('node:fs');
const path = require('node:path');

function readJson(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function summarizeText(text) {
    const matches = [...text.matchAll(/\b(\d+)\s+(?:patterns?|categories?|runtime checks?)\b/gi)];
    return matches.map((m) => m[0]);
}

function main() {
    const root = process.cwd();
    const capabilities = readJson(path.join(root, 'docs', 'spec', 'capabilities.json'));
    const pkg = readJson(path.join(root, 'package.json'));
    const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
    const skill = fs.readFileSync(path.join(root, 'SKILL.md'), 'utf8');
    const status = fs.readFileSync(path.join(root, 'STATUS.md'), 'utf8');
    const roadmap = fs.readFileSync(path.join(root, 'ROADMAP.md'), 'utf8');

    const report = {
        scannerVersion: pkg.version,
        sourceOfTruthVersion: capabilities.product.version,
        sourceOfTruth: capabilities.capabilities,
        documentSignals: {
            README: summarizeText(readme),
            SKILL: summarizeText(skill),
            STATUS: summarizeText(status),
            ROADMAP: summarizeText(roadmap),
        },
        drifts: [],
    };

    if (pkg.version !== capabilities.product.version) {
        report.drifts.push(`package.json version (${pkg.version}) != capabilities version (${capabilities.product.version})`);
    }

    for (const [docName, entries] of Object.entries(report.documentSignals)) {
        if (entries.length === 0) continue;
        const compact = entries.join(', ');
        if (/129 patterns|21 categories|186\+ threat patterns|20 categories/i.test(compact)) {
            report.drifts.push(`${docName} contains legacy marketing counts: ${compact}`);
        }
    }

    console.log(JSON.stringify(report, null, 2));
}

main();

