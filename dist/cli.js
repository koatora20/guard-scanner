#!/usr/bin/env node
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
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));
var import_scanner = require("./scanner.js");
var import_patterns = require("./patterns.js");
var import_capabilities = require("./capabilities.js");
var import_node_child_process = require("node:child_process");
var import_mcp = require("./mcp.js");
const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log(`
\u{1F6E1}\uFE0F  guard-scanner v${import_scanner.VERSION} \u2014 Agent Skill Security Scanner (TypeScript-first)
${(0, import_capabilities.getCapabilitySummary)()}

Usage: guard-scanner [scan-dir] [options]
       guard-scanner capabilities
       guard-scanner audit-baseline
       guard-scanner benchmark [scan-dir]
       guard-scanner mcp < request.json

Options:
  --verbose, -v       Detailed findings with categories and samples
  --json              Write JSON report
  --sarif             Write SARIF report (GitHub Code Scanning / CI/CD)
  --self-exclude      Skip scanning the guard-scanner skill itself
  --mode <auto|skills|repo>
                      Scan categorized skill trees correctly and avoid treating package repos as skill buckets
  --strict            Lower detection thresholds (more sensitive)
  --summary-only      Only print the summary table
  --check-deps        Scan package.json for dependency chain risks
  --rules <file>      Load custom rules from JSON file
  --plugin <file>     Load plugin module
  --fail-on-findings  Exit code 1 if any findings (CI/CD)
  --help, -h          Show this help

Current package traits:
  \u2022 TypeScript-first runtime, CLI, plugin, and MCP entrypoints
  \u2022 Dual ESM + CJS package exports with shipped declarations
  \u2022 Shared scanner engine across CLI, MCP, and OpenClaw plugin bridge

Examples:
  guard-scanner ./skills/ --verbose --self-exclude
  guard-scanner ./skills/ --mode skills
  guard-scanner ~/workspace-guard-scanner --mode repo
  guard-scanner ./skills/ --strict --json --sarif --check-deps
  guard-scanner ./skills/ --fail-on-findings
  guard-scanner mcp < request.json
`);
  process.exit(0);
}
if (args[0] === "capabilities") {
  console.log(JSON.stringify(import_capabilities.CAPABILITIES, null, 2));
  process.exit(0);
}
if (args[0] === "audit-baseline") {
  const out = (0, import_node_child_process.execFileSync)(process.execPath, [path.join(__dirname, "tools", "audit-baseline.js")], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
  process.stdout.write(out);
  process.exit(0);
}
if (args[0] === "benchmark") {
  const cmdArgs = [path.join(__dirname, "tools", "benchmark.js")];
  if (args.length > 1) {
    cmdArgs.push(...args.slice(1));
  }
  const out = (0, import_node_child_process.execFileSync)(process.execPath, cmdArgs, {
    cwd: process.cwd(),
    encoding: "utf8"
  });
  process.stdout.write(out);
  process.exit(0);
}
if (args[0] === "mcp") {
  const raw = fs.readFileSync(0, "utf8");
  process.stdout.write(`${JSON.stringify((0, import_mcp.handleMcpRequest)(JSON.parse(raw)), null, 2)}
`);
  process.exit(0);
}
if (args[0] === "install-check") {
  const skillPath = args[1];
  if (!skillPath) {
    console.error("\u274C Usage: guard-scanner install-check <skill-path>");
    process.exit(2);
  }
  const absPath = path.resolve(skillPath);
  if (!fs.existsSync(absPath)) {
    console.error(`\u274C Skill path not found: ${absPath}`);
    process.exit(2);
  }
  const icStrict = args.includes("--strict");
  const icJson = args.includes("--json");
  const icVerbose = args.includes("--verbose") || args.includes("-v");
  const scanner2 = new import_scanner.GuardScanner({ strict: icStrict, verbose: icVerbose });
  const skillName = path.basename(absPath);
  console.log(`
\u{1F6E1}\uFE0F  guard-scanner install-check v${import_scanner.VERSION}`);
  console.log(`   Scanning: ${skillName} (${absPath})
`);
  scanner2.scanSkill(absPath, skillName);
  const result = scanner2.findings[0];
  if (!result) {
    console.log("\u2705 PASS \u2014 No skill found at path");
    process.exit(0);
  }
  const { risk, verdict, findings } = result;
  if (icVerbose || findings.length > 0) {
    for (const f of findings) {
      const owaspTag = import_patterns.PATTERNS.find((p) => p.id === f.id)?.owasp || "";
      const tag = owaspTag ? ` [${owaspTag}]` : "";
      console.log(`  ${f.severity === "CRITICAL" ? "\u{1F534}" : f.severity === "HIGH" ? "\u{1F7E0}" : "\u{1F7E1}"} [${f.severity}] ${f.id}: ${f.desc}${tag}`);
      if (f.file) console.log(`    \u{1F4C1} ${f.file}${f.line ? `:${f.line}` : ""}`);
      if (f.sample && icVerbose) console.log(`    \u{1F4DD} ${f.sample.substring(0, 80)}`);
    }
    console.log("");
  }
  console.log(`Risk Score: ${risk} | Verdict: ${verdict} | Findings: ${findings.length}`);
  if (verdict === "MALICIOUS" || verdict === "SUSPICIOUS") {
    console.log(`
\u274C FAIL \u2014 This skill should NOT be installed.`);
    if (icJson) {
      const report = scanner2.toJSON();
      const outPath = path.join(path.dirname(absPath), `${skillName}-install-check.json`);
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      console.log(`\u{1F4C4} Report: ${outPath}`);
    }
    process.exit(1);
  } else {
    console.log(`
\u2705 PASS \u2014 Skill appears safe to install.`);
    if (icJson) {
      const report = scanner2.toJSON();
      const outPath = path.join(path.dirname(absPath), `${skillName}-install-check.json`);
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      console.log(`\u{1F4C4} Report: ${outPath}`);
    }
    process.exit(0);
  }
}
const verbose = args.includes("--verbose") || args.includes("-v");
const jsonOutput = args.includes("--json");
const sarifOutput = args.includes("--sarif");
const selfExclude = args.includes("--self-exclude");
const strict = args.includes("--strict");
const summaryOnly = args.includes("--summary-only");
const checkDeps = args.includes("--check-deps");
const failOnFindings = args.includes("--fail-on-findings");
const modeIdx = args.indexOf("--mode");
const scanMode = modeIdx >= 0 ? args[modeIdx + 1] : "auto";
if (!["auto", "skills", "repo"].includes(scanMode)) {
  console.error(`\u274C Invalid --mode: ${scanMode}. Use auto, skills, or repo.`);
  process.exit(2);
}
const rulesIdx = args.indexOf("--rules");
const rulesFile = rulesIdx >= 0 ? args[rulesIdx + 1] : void 0;
const plugins = [];
let idx = 0;
while (idx < args.length) {
  if (args[idx] === "--plugin" && args[idx + 1]) {
    plugins.push(args[idx + 1]);
    idx += 2;
  } else {
    idx++;
  }
}
const scanDir = args.find(
  (a) => !a.startsWith("-") && a !== rulesFile && !plugins.includes(a)
) || process.cwd();
const scanner = new import_scanner.GuardScanner({
  verbose,
  selfExclude,
  strict,
  summaryOnly,
  checkDeps,
  rulesFile,
  plugins,
  scanMode
});
scanner.scanDirectory(scanDir);
if (jsonOutput) {
  const report = scanner.toJSON();
  const outPath = path.join(scanDir, "guard-scanner-report.json");
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`
\u{1F4C4} JSON report: ${outPath}`);
}
if (sarifOutput) {
  const outPath = path.join(scanDir, "guard-scanner.sarif");
  fs.writeFileSync(outPath, JSON.stringify(scanner.toSARIF(scanDir), null, 2));
  console.log(`
\u{1F4C4} SARIF report: ${outPath}`);
}
if (scanner.stats.malicious > 0) process.exit(1);
if (failOnFindings && scanner.findings.length > 0) process.exit(1);
process.exit(0);
//# sourceMappingURL=cli.js.map