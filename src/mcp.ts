import { GuardScanner } from "./scanner.js";
import type { JSONReport, McpRequest, ScannerOptions } from "./types.js";

type JsonRpcId = string | number | null;

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
};

type ScanParams = ScannerOptions & {
  path: string;
};

export function runMcpScan(params: ScanParams): JSONReport {
  const scanner = new GuardScanner({
    verbose: params.verbose,
    selfExclude: params.selfExclude,
    strict: params.strict,
    summaryOnly: params.summaryOnly ?? true,
    checkDeps: params.checkDeps,
    rulesFile: params.rulesFile,
    plugins: params.plugins,
    scanMode: params.scanMode,
  });

  scanner.scanDirectory(params.path);
  return scanner.toJSON();
}

function jsonRpcResult(id: JsonRpcId, result: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

function jsonRpcError(id: JsonRpcId, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export function handleMcpRequest(request: McpRequest): JsonRpcResponse {
  if (request.method === "initialize") {
    return jsonRpcResult(request.id ?? null, {
      protocolVersion: "2026-03-26",
      serverInfo: {
        name: "guard-scanner",
        version: "17.0.0",
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
    const params = request.params as {
      name?: string;
      arguments?: ScanParams;
    };

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
            recommendations: report.recommendations,
          }, null, 2)
        }
      ],
      structuredContent: report,
    });
  }

  return jsonRpcError(request.id ?? null, -32601, `Unsupported MCP method: ${request.method}`);
}
