"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var src_exports = {};
__export(src_exports, {
  CAPABILITIES: () => import_capabilities.CAPABILITIES,
  GuardScanner: () => import_scanner.GuardScanner,
  KNOWN_MALICIOUS: () => import_ioc_db.KNOWN_MALICIOUS,
  PATTERNS: () => import_patterns.PATTERNS,
  SIGNATURES_DB: () => import_ioc_db.SIGNATURES_DB,
  THRESHOLDS: () => import_scanner.THRESHOLDS,
  VERSION: () => import_scanner.VERSION,
  evaluateScanDecision: () => import_audit_decision.evaluateScanDecision,
  getCapabilitySummary: () => import_capabilities.getCapabilitySummary,
  openClawPlugin: () => import_plugin.default,
  runtimeGuardPlugin: () => import_runtime_plugin.default
});
module.exports = __toCommonJS(src_exports);
var import_scanner = require("./scanner.js");
var import_audit_decision = require("./audit-decision.js");
var import_runtime_plugin = __toESM(require("./runtime-plugin.js"));
var import_plugin = __toESM(require("./plugin.js"));
var import_capabilities = require("./capabilities.js");
__reExport(src_exports, require("./mcp.js"), module.exports);
var import_ioc_db = require("./ioc-db.js");
var import_patterns = require("./patterns.js");
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CAPABILITIES,
  GuardScanner,
  KNOWN_MALICIOUS,
  PATTERNS,
  SIGNATURES_DB,
  THRESHOLDS,
  VERSION,
  evaluateScanDecision,
  getCapabilitySummary,
  openClawPlugin,
  runtimeGuardPlugin,
  ...require("./mcp.js")
});
//# sourceMappingURL=index.js.map