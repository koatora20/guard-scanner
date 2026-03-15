// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("plugin manifest points to compiled runtime guard entry", () => {
    const manifestPath = path.join(process.cwd(), "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8"));

    assert.equal(manifest.id, "guava-guard-scanner");
    assert.equal(manifest.kind, "security");
    assert.equal(manifest.version, pkg.version);
    assert.equal(
        manifest.hooks.before_tool_call.handler,
        "./dist/plugin.js",
    );
    assert.equal(
        manifest.hooks.before_tool_call.export,
        "default",
    );
    assert.equal(
        manifest.configSchema.properties.auditLog.default,
        true,
    );
    assert.deepEqual(
        manifest.configSchema.properties.mode.enum,
        ["monitor", "enforce", "strict"],
    );
});
