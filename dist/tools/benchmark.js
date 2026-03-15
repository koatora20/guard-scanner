"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var import_node_path = __toESM(require("node:path"));
var import_node_os = __toESM(require("node:os"));
var import_node_perf_hooks = require("node:perf_hooks");
const { GuardScanner } = require("../scanner.js");
const { scoreWithRust } = require("../rust-bridge.js");
function round(value) {
  return Number(value.toFixed(3));
}
function parseArgs(argv) {
  let target;
  let runCount = 5;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--runs" && argv[index + 1]) {
      runCount = Math.max(1, Number.parseInt(argv[index + 1], 10) || 5);
      index += 1;
      continue;
    }
    if (!arg.startsWith("-") && target === void 0) {
      target = import_node_path.default.resolve(arg);
    }
  }
  return {
    target: target ?? import_node_path.default.join(process.cwd(), "test", "fixtures"),
    runCount
  };
}
function nearestPercentile(values, percentile) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const rank = Math.max(0, Math.ceil(percentile / 100 * sorted.length) - 1);
  return sorted[Math.min(rank, sorted.length - 1)];
}
function summarize(values) {
  if (values.length === 0) {
    return {
      count: 0,
      min: 0,
      max: 0,
      mean: 0,
      stddev: 0,
      p50: 0,
      p95: 0,
      p99: 0
    };
  }
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return {
    count: values.length,
    min: round(Math.min(...values)),
    max: round(Math.max(...values)),
    mean: round(mean),
    stddev: round(Math.sqrt(variance)),
    p50: round(nearestPercentile(values, 50)),
    p95: round(nearestPercentile(values, 95)),
    p99: round(nearestPercentile(values, 99))
  };
}
function aggregateByWarmth(samples, field) {
  const all = samples.map((sample) => Number(sample[field] ?? 0));
  const cold = samples.filter((sample) => Boolean(sample.cold)).map((sample) => Number(sample[field] ?? 0));
  const warm = samples.filter((sample) => !Boolean(sample.cold)).map((sample) => Number(sample[field] ?? 0));
  return {
    all: summarize(all),
    cold: summarize(cold),
    warm: summarize(warm)
  };
}
function runSample(target, runIndex) {
  const scanner = new GuardScanner({ summaryOnly: true, checkDeps: true });
  const scanStarted = import_node_perf_hooks.performance.now();
  const originalLog = console.log;
  console.log = () => {
  };
  scanner.scanDirectory(target);
  console.log = originalLog;
  const scanElapsedMs = round(import_node_perf_hooks.performance.now() - scanStarted);
  const tsStarted = import_node_perf_hooks.performance.now();
  const tsResults = scanner.findings.map((entry) => ({
    skill: entry.skill,
    risk: scanner.scoreFindings(entry.findings).risk
  }));
  const tsElapsedMs = round(import_node_perf_hooks.performance.now() - tsStarted);
  const rustStarted = import_node_perf_hooks.performance.now();
  const rustResults = scanner.findings.map((entry) => {
    const rust = scoreWithRust(entry.findings);
    return {
      skill: entry.skill,
      risk: rust ? rust.risk : null,
      engine: rust ? rust.engine : "fallback"
    };
  });
  const rustElapsedMs = round(import_node_perf_hooks.performance.now() - rustStarted);
  const reportStarted = import_node_perf_hooks.performance.now();
  const parity = tsResults.map((entry, index) => ({
    skill: entry.skill,
    tsRisk: entry.risk,
    rustRisk: rustResults[index]?.risk ?? null,
    parity: rustResults[index]?.risk === null ? "missing-rust-core" : entry.risk === rustResults[index]?.risk ? "match" : "drift"
  }));
  const reportElapsedMs = round(import_node_perf_hooks.performance.now() - reportStarted);
  const totalElapsedMs = round(scanElapsedMs + tsElapsedMs + rustElapsedMs + reportElapsedMs);
  const findingCount = scanner.findings.reduce((sum, entry) => sum + entry.findings.length, 0);
  const throughputItemsPerSec = round(scanner.findings.length / Math.max(totalElapsedMs / 1e3, 1e-3));
  return {
    run_index: runIndex,
    cold: runIndex === 1,
    scan_ms: scanElapsedMs,
    ts_score_ms: tsElapsedMs,
    rust_score_ms: rustElapsedMs,
    report_ms: reportElapsedMs,
    total_ms: totalElapsedMs,
    throughput_items_per_sec: throughputItemsPerSec,
    skills_scanned: scanner.findings.length,
    finding_count: findingCount,
    parity
  };
}
function main() {
  const { target, runCount } = parseArgs(process.argv.slice(2));
  const samples = Array.from({ length: runCount }, (_, index) => runSample(target, index + 1));
  const parity = samples[samples.length - 1]?.parity ?? [];
  console.log(JSON.stringify({
    target,
    fixture_id: import_node_path.default.basename(target),
    run_count: runCount,
    cold_runs: samples.filter((sample) => Boolean(sample.cold)).length,
    warm_runs: samples.filter((sample) => !Boolean(sample.cold)).length,
    stage_samples: samples.map((sample) => ({
      run_index: sample.run_index,
      cold: sample.cold,
      scan_ms: sample.scan_ms,
      ts_score_ms: sample.ts_score_ms,
      rust_score_ms: sample.rust_score_ms,
      report_ms: sample.report_ms,
      total_ms: sample.total_ms,
      throughput_items_per_sec: sample.throughput_items_per_sec,
      skills_scanned: sample.skills_scanned,
      finding_count: sample.finding_count
    })),
    aggregates: {
      scan_ms: aggregateByWarmth(samples, "scan_ms"),
      ts_score_ms: aggregateByWarmth(samples, "ts_score_ms"),
      rust_score_ms: aggregateByWarmth(samples, "rust_score_ms"),
      report_ms: aggregateByWarmth(samples, "report_ms"),
      total_ms: aggregateByWarmth(samples, "total_ms"),
      throughput_items_per_sec: aggregateByWarmth(samples, "throughput_items_per_sec")
    },
    parity,
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpu_count: import_node_os.default.cpus().length,
      cwd: process.cwd()
    }
  }, null, 2));
}
main();
//# sourceMappingURL=benchmark.js.map