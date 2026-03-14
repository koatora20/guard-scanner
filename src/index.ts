import type {
  GuardScannerConstructor,
  GuardScannerInstance,
  RuntimeCheckStats,
  RuntimeDecision,
  ScannerOptions,
  } from "./types.js";


const scanner = require("./scanner") as {
  GuardScanner: GuardScannerConstructor;
  VERSION: string;
  THRESHOLDS: Record<string, unknown>;
  SEVERITY_WEIGHTS: Record<string, number>;
  scanToolCall: (
    toolName: string,
    params: Record<string, unknown> | string,
    options?: Record<string, unknown>,
  ) => RuntimeDecision;
  RUNTIME_CHECKS: Array<Record<string, unknown>>;
  getCheckStats: () => RuntimeCheckStats;
  LAYER_NAMES: Record<number, string>;
};
const mcpServer = require("./mcp-server") as {
  MCPServer: new () => unknown;
  startServer: () => void;
  TOOLS: Array<Record<string, unknown>>;
};

export const GuardScanner = scanner.GuardScanner;
export const VERSION = scanner.VERSION;
export const THRESHOLDS = scanner.THRESHOLDS;
export const SEVERITY_WEIGHTS = scanner.SEVERITY_WEIGHTS;
export const scanToolCall = scanner.scanToolCall;
export const RUNTIME_CHECKS = scanner.RUNTIME_CHECKS;
export const getCheckStats = scanner.getCheckStats;
export const LAYER_NAMES = scanner.LAYER_NAMES;
export const MCPServer = mcpServer.MCPServer;
export const startServer = mcpServer.startServer;
export const TOOLS = mcpServer.TOOLS;

export function createScanner(options: ScannerOptions = {}): GuardScannerInstance {
  return new scanner.GuardScanner(options);
}

export type {
  CapabilityMetrics,
  CustomRule,
  Finding,
  GuardMode,
  GuardScannerConstructor,
  GuardScannerInstance,
  McpRequest,
  PluginConfig,
  RuntimeDecision,
  RuntimeCheckStats,
  ScanReport,
  SarifReport,
  ScanResult,
  ScannerOptions,
  Severity,
} from "./types.js";
