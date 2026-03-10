const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("plugin manifest points to compiled runtime guard entry", () => {
    const manifestPath = path.join(process.cwd(), "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

    assert.equal(manifest.id, "guava-guard-scanner");
    assert.equal(manifest.kind, "security");
    assert.equal(
        manifest.hooks.before_tool_call.handler,
        "./dist/runtime-plugin.js",
    );
    assert.equal(
        manifest.hooks.before_tool_call.export,
        "default",
    );
    assert.equal(
        manifest.configSchema.properties.mode.default,
        "enforce",
    );
    assert.deepEqual(
        manifest.configSchema.properties.mode.enum,
        ["monitor", "enforce", "strict"],
    );
});
