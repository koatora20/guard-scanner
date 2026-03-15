"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var mcp_exports = {};
__export(mcp_exports, {
  handleMcpRequest: () => handleMcpRequest,
  runMcpScan: () => runMcpScan
});
module.exports = __toCommonJS(mcp_exports);
var import_scanner = require("./scanner.js");
function runMcpScan(params) {
  const scanner = new import_scanner.GuardScanner({
    verbose: params.verbose,
    selfExclude: params.selfExclude,
    strict: params.strict,
    summaryOnly: params.summaryOnly ?? true,
    checkDeps: params.checkDeps,
    rulesFile: params.rulesFile,
    plugins: params.plugins,
    scanMode: params.scanMode
  });
  scanner.scanDirectory(params.path);
  return scanner.toJSON();
}
function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function jsonRpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}
function handleMcpRequest(request) {
  if (request.method === "initialize") {
    return jsonRpcResult(request.id ?? null, {
      protocolVersion: "2026-03-26",
      serverInfo: {
        name: "guard-scanner",
        version: "17.0.0"
      },
      capabilities: {
        tools: {}
      }
    });
  }
  if (request.method === "tools/list") {
    return jsonRpcResult(request.id ?? null, {
      tools: [
        {
          name: "guard_scan_path",
          description: "Scan a skill tree or repository path with guard-scanner and return the typed JSON report.",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              path: { type: "string", description: "Absolute or relative path to scan." },
              scanMode: { type: "string", enum: ["auto", "skills", "repo"] },
              strict: { type: "boolean" },
              checkDeps: { type: "boolean" },
              summaryOnly: { type: "boolean" },
              selfExclude: { type: "boolean" }
            },
            required: ["path"]
          }
        }
      ]
    });
  }
  if (request.method === "tools/call") {
    const params = request.params;
    if (params?.name !== "guard_scan_path" || !params.arguments?.path) {
      return jsonRpcError(request.id ?? null, -32602, "guard_scan_path requires a path argument");
    }
    const report = runMcpScan(params.arguments);
    return jsonRpcResult(request.id ?? null, {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            stats: report.stats,
            recommendations: report.recommendations
          }, null, 2)
        }
      ],
      structuredContent: report
    });
  }
  return jsonRpcError(request.id ?? null, -32601, `Unsupported MCP method: ${request.method}`);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handleMcpRequest,
  runMcpScan
});
//# sourceMappingURL=mcp.js.map