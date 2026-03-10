const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");

test("release gate validates lean packed artifact", () => {
    const output = execFileSync("node", ["scripts/release-gate.js"], {
        cwd: process.cwd(),
        encoding: "utf8",
    });
    const report = JSON.parse(output);

    assert.equal(report.ok, true);
    assert.equal(report.packageName, "guard-scanner");
    assert.equal(report.pluginId, "guava-guard-scanner");
    assert.equal(report.packedFiles.includes("dist/index.js"), true);
    assert.equal(report.packedFiles.includes("dist/runtime-plugin.js"), true);
    assert.equal(report.packedFiles.includes("docs/html-report-preview.png"), false);
    assert.equal(report.packedFiles.includes("ts-src/cli.ts"), false);
});
