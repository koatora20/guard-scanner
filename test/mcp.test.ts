// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { handleMcpRequest } = require("../dist/mcp.js");

test("mcp tools/list exposes guard_scan_path", () => {
  const response = handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
  });

  assert.equal(response.error, undefined);
  assert.equal(response.result.tools[0].name, "guard_scan_path");
});

test("mcp tools/call returns structured scan content", () => {
  const response = handleMcpRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "guard_scan_path",
      arguments: {
        path: path.join(process.cwd(), "test", "fixtures"),
        scanMode: "auto",
        summaryOnly: true,
        checkDeps: true,
      },
    },
  });

  assert.equal(response.error, undefined);
  assert.equal(Array.isArray(response.result.content), true);
  assert.equal(response.result.structuredContent.stats.malicious >= 1, true);
});
