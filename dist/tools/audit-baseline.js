"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var import_node_fs = require("node:fs");
var import_node_path = __toESM(require("node:path"));
function readJson(file) {
  return JSON.parse((0, import_node_fs.readFileSync)(file, "utf8"));
}
function summarizeText(text) {
  const matches = [...text.matchAll(/\b(\d+)\s+(?:patterns?|categories?|runtime checks?)\b/gi)];
  return matches.map((match) => match[0]);
}
function main() {
  const root = process.cwd();
  const capabilities = readJson(
    import_node_path.default.join(root, "docs", "spec", "capabilities.json")
  );
  const pkg = readJson(import_node_path.default.join(root, "package.json"));
  const readme = (0, import_node_fs.readFileSync)(import_node_path.default.join(root, "README.md"), "utf8");
  const skill = (0, import_node_fs.readFileSync)(import_node_path.default.join(root, "SKILL.md"), "utf8");
  const status = (0, import_node_fs.readFileSync)(import_node_path.default.join(root, "STATUS.md"), "utf8");
  const roadmap = (0, import_node_fs.readFileSync)(import_node_path.default.join(root, "ROADMAP.md"), "utf8");
  const report = {
    scannerVersion: pkg.version,
    sourceOfTruthVersion: capabilities.product.version,
    sourceOfTruth: capabilities.capabilities,
    documentSignals: {
      README: summarizeText(readme),
      SKILL: summarizeText(skill),
      STATUS: summarizeText(status),
      ROADMAP: summarizeText(roadmap)
    },
    drifts: []
  };
  if (pkg.version !== capabilities.product.version) {
    report.drifts.push(`package.json version (${pkg.version}) != capabilities version (${capabilities.product.version})`);
  }
  for (const [docName, entries] of Object.entries(report.documentSignals)) {
    if (entries.length === 0) continue;
    const compact = entries.join(", ");
    if (/129 patterns|21 categories|186\+ threat patterns|20 categories/i.test(compact)) {
      report.drifts.push(`${docName} contains legacy marketing counts: ${compact}`);
    }
  }
  console.log(JSON.stringify(report, null, 2));
}
main();
//# sourceMappingURL=audit-baseline.js.map