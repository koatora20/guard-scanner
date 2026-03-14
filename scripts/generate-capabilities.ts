// @ts-nocheck
const fs = require('fs');
const path = require('path');
const { PATTERNS } = require('../src/patterns');
const { RUNTIME_CHECKS } = require('../src/runtime-guard');
const { TOOLS } = require('../src/mcp-server');
const { computeExplainabilityCompletenessRate } = require('../src/benchmark-runner');
const { normalizeFinding } = require('../src/finding-schema');
const { V16_LAYER_NAMES, buildAsiCoverage } = require('../src/v16-taxonomy');
const packageJson = require('../package.json');
const pluginJson = require('../openclaw.plugin.json');

const specDir = path.join(__dirname, '../docs/spec');
const capabilitiesPath = path.join(specDir, 'capabilities.json');
const testDir = path.join(__dirname, '../test');
const dataDir = path.join(__dirname, '../docs/data');
const qualityContractPath = path.join(dataDir, 'quality-contract.json');
const benchmarkLedgerPath = path.join(dataDir, 'benchmark-ledger.json');

if (!fs.existsSync(specDir)) {
    fs.mkdirSync(specDir, { recursive: true });
}

// Calculate true values from source code — single source of truth
const categories = new Set(PATTERNS.map(p => p.cat));
const testFiles = fs.readdirSync(testDir).filter(f => f.endsWith('.test.ts'));
const qualityContract = JSON.parse(fs.readFileSync(qualityContractPath, 'utf8'));
const benchmarkLedger = fs.existsSync(benchmarkLedgerPath)
    ? JSON.parse(fs.readFileSync(benchmarkLedgerPath, 'utf8'))
    : null;
const explainability = computeExplainabilityCompletenessRate();
const normalizedSample = PATTERNS.slice(0, 64).map((pattern) => normalizeFinding(pattern, { source: 'static' }));

const spec = {
    package_version: packageJson.version,
    plugin_version: pluginJson.version,
    static_pattern_count: PATTERNS.length,
    threat_category_count: categories.size,
    runtime_check_count: RUNTIME_CHECKS.length,
    test_file_count: testFiles.length,
    dependencies_runtime: Object.keys(packageJson.dependencies || {}).length,
    dependencies_dev: Object.keys(packageJson.devDependencies || {}).length,
    mcp_tools: TOOLS.map(t => t.name),
    cli_commands: ["scan", "benchmark", "serve", "watch", "audit", "crawl", "patrol"],
    supported_outputs: ["json", "sarif", "html", "terminal"],
    supported_integrations: ["openclaw", "mcp", "virustotal", "github", "npm"],
    benchmark_corpus_version: qualityContract.benchmark_version,
    benchmark_layers: benchmarkLedger ? benchmarkLedger.layers.map((layer) => ({
        id: layer.layer,
        benign: layer.counts.benign,
        malicious: layer.counts.malicious,
        precision: layer.metrics.precision,
        recall: layer.metrics.recall,
        false_positive_rate: layer.metrics.false_positive_rate,
        false_negative_rate: layer.metrics.false_negative_rate,
    })) : [],
    analysis_layers: Object.entries(V16_LAYER_NAMES).map(([layer, name]) => ({ layer: Number(layer), name })),
    owasp_asi_coverage: buildAsiCoverage(normalizedSample),
    capability_flags: {
        protocol_analysis: true,
        runtime_evidence: true,
        cognitive_detection: true,
        threat_intelligence: true,
    },
    compliance_modes: ['owasp-asi'],
    explainability_completeness_rate: explainability.rate,
    runtime_check_latency_budget_ms: qualityContract.quality_targets.runtime_check_latency_budget_ms,
    quality_targets: qualityContract.quality_targets,
};

fs.writeFileSync(capabilitiesPath, JSON.stringify(spec, null, 2));
console.log(`✅ Generated SSoT at ${capabilitiesPath}`);
console.log(JSON.stringify(spec, null, 2));
