const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("plugin manifest stays hook-only and public-safe", () => {
    const manifest = JSON.parse(
        fs.readFileSync(path.join(process.cwd(), "openclaw.plugin.json"), "utf8"),
    );

    assert.ok(manifest.hooks.before_tool_call, "before_tool_call hook is required");
    assert.equal(manifest.hooks.before_tool_call.handler, "./dist/runtime-plugin.js");
    assert.ok(!manifest.tools, "runtime plugin must not expose tool handlers directly");
    assert.ok(!manifest.mcpServers, "runtime plugin must not expose MCP servers");
});

test("boundary doc records runtime vs repo surface split", () => {
    const boundaryDoc = fs.readFileSync(
        path.join(process.cwd(), "docs", "public-safe-boundary.md"),
        "utf8",
    );

    assert.match(boundaryDoc, /runtime-plugin/);
    assert.match(boundaryDoc, /scanner-core/);
    assert.match(boundaryDoc, /runtime_payload_scan/);
    assert.match(boundaryDoc, /repo_surface_scan/);
    assert.match(boundaryDoc, /shell escalation/);
});
