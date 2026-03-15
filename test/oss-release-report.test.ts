// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");

test("oss release report emits passing artifact, surface, compat, and completion sections", () => {
    const raw = execFileSync("node", ["dist/tools/oss-release-report.js"], {
        cwd: process.cwd(),
        encoding: "utf8",
    });
    const report = JSON.parse(raw);

    assert.equal(report.releaseArtifactReport.status, "PASS");
    assert.equal(report.releaseArtifactReport.package_name, "guard-scanner");
    assert.equal(report.releaseArtifactReport.package_version, "17.0.0");
    assert.equal(report.releaseArtifactReport.packed_files.includes("docs/public-safe-boundary.md"), true);

    assert.equal(report.publicSurfaceReport.status, "PASS");
    assert.ok(report.publicSurfaceReport.mcp_tools.includes("guard_scan_path"));
    assert.equal(report.publicSurfaceReport.plugin_manifest.version, "17.0.0");
    assert.equal(report.publicSurfaceReport.plugin_manifest.hook_only, true);
    assert.equal(report.publicSurfaceReport.runtime_skills.authority_source, "guava-anti-guard");
    assert.equal(report.publicSurfaceReport.clawhub_wrapper.status, "PASS");

    assert.equal(report.compatReport.status, "PASS");
    assert.equal(report.compatReport.openclaw_baseline, "2026.3.13");
    assert.ok(report.compatReport.tested_versions.includes("2026.3.13"));

    const statuses = Object.fromEntries(report.ossCompletionReport.results.map((entry) => [entry.test_id, entry.status]));
    assert.deepEqual(statuses, {
        R1: "PASS",
        R2: "PASS",
        R3: "PASS",
        R4: "PASS",
        R5: "PASS",
        R6: "PASS",
    });
});
