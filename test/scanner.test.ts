// @ts-nocheck
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { GuardScanner, THRESHOLDS } = require("../dist/scanner.js");
const { PATTERNS } = require("../dist/patterns.js");
const capabilities = require("../docs/spec/capabilities.json");

const FIXTURES = path.join(process.cwd(), "test", "fixtures");

function scanFixture(options = {}) {
  const scanner = new GuardScanner({ summaryOnly: true, checkDeps: true, ...options });
  scanner.scanDirectory(FIXTURES);
  return scanner;
}

function findSkill(scanner, name) {
  return scanner.findings.find((entry) => entry.skill === name);
}

describe("Scanner Fixtures", () => {
  const scanner = scanFixture();
  const malicious = findSkill(scanner, "malicious-skill");

  it("classifies malicious fixture as MALICIOUS", () => {
    assert.ok(malicious);
    assert.equal(malicious.verdict, "MALICIOUS");
    assert.ok(malicious.risk >= THRESHOLDS.normal.malicious);
  });

  it("detects core malicious categories on the fixture corpus", () => {
    const categories = new Set(malicious.findings.map((finding) => finding.cat));
    assert.ok(categories.has("prompt-injection"));
    assert.ok(categories.has("malicious-code"));
    assert.ok(categories.has("credential-handling"));
    assert.ok(categories.has("exfiltration"));
  });

  it("keeps clean fixture out of findings", () => {
    assert.equal(findSkill(scanner, "clean-skill"), undefined);
    assert.ok(scanner.stats.clean >= 1);
  });

  it("flags config-impact on the config changer fixture", () => {
    const configChanger = findSkill(scanner, "config-changer");
    assert.ok(configChanger);
    assert.ok(configChanger.findings.some((finding) => finding.id === "CFG_WRITE_DETECTED"));
  });
});

describe("Scanner Public Methods", () => {
  const scanner = new GuardScanner({ summaryOnly: true });

  it("calculates risk for empty and critical findings", () => {
    assert.equal(scanner.calculateRisk([]), 0);
    assert.equal(scanner.calculateRisk([{ severity: "CRITICAL", id: "IOC_IP", cat: "malicious-code" }]), 100);
  });

  it("returns verdict labels across threshold bands", () => {
    assert.equal(scanner.getVerdict(0).label, "CLEAN");
    assert.equal(scanner.getVerdict(15).label, "LOW RISK");
    assert.equal(scanner.getVerdict(50).label, "SUSPICIOUS");
    assert.equal(scanner.getVerdict(90).label, "MALICIOUS");
  });

  it("serializes JSON and SARIF reports", () => {
    const populated = scanFixture();
    const json = populated.toJSON();
    const sarif = populated.toSARIF(FIXTURES);

    assert.equal(json.stats.malicious >= 1, true);
    assert.equal(Array.isArray(json.findings), true);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(Array.isArray(sarif.runs[0].results), true);
  });
});

describe("Pattern Source Of Truth", () => {
  it("matches the capabilities manifest counts", () => {
    const categoryCount = new Set(PATTERNS.map((pattern) => pattern.cat)).size;
    assert.equal(PATTERNS.length, capabilities.capabilities.pattern_count);
    assert.equal(categoryCount, capabilities.capabilities.category_count);
  });

  it("keeps every pattern structurally valid", () => {
    for (const pattern of PATTERNS) {
      assert.ok(pattern.id);
      assert.ok(pattern.cat);
      assert.ok(pattern.regex instanceof RegExp);
      assert.ok(pattern.severity);
      assert.ok(pattern.desc);
    }
  });
});

describe("Ignore File Support", () => {
  it("skips ignored targets and pattern ids", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-scanner-ignore-"));
    const fixtureDir = path.join(tempDir, "malicious-skill");
    fs.cpSync(path.join(FIXTURES, "malicious-skill"), fixtureDir, { recursive: true });
    fs.writeFileSync(
      path.join(tempDir, ".guard-scanner-ignore"),
      "malicious-skill\npattern:IOC_IP\n",
      "utf8",
    );

    try {
      const scanner = new GuardScanner({ summaryOnly: true, checkDeps: true });
      scanner.scanDirectory(tempDir);
      assert.equal(scanner.findings.length, 0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
