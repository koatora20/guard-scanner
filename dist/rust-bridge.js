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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var rust_bridge_exports = {};
__export(rust_bridge_exports, {
  scoreWithRust: () => scoreWithRust
});
module.exports = __toCommonJS(rust_bridge_exports);
var fs = __toESM(require("node:fs"));
var os = __toESM(require("node:os"));
var path = __toESM(require("node:path"));
var import_node_child_process = require("node:child_process");
function candidateBinaryPaths() {
  const envPath = process.env.GUARD_SCANNER_RUST_CORE;
  const candidates = [
    envPath,
    path.join(process.cwd(), "rust", "guard-scan-core", "target", "release", "guard-scan-core"),
    path.join(process.cwd(), "rust", "guard-scan-core", "target", "debug", "guard-scan-core"),
    path.join(process.cwd(), "rust", "guard-scan-core", "target", "release", "guard-scan-core.exe"),
    path.join(process.cwd(), "rust", "guard-scan-core", "target", "debug", "guard-scan-core.exe")
  ].filter((value) => Boolean(value));
  return [...new Set(candidates)];
}
function scoreWithRust(findings) {
  for (const binaryPath of candidateBinaryPaths()) {
    if (!fs.existsSync(binaryPath)) continue;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-scanner-rust-"));
    const inputPath = path.join(tmpDir, "input.json");
    try {
      fs.writeFileSync(inputPath, JSON.stringify({ findings }));
      const proc = (0, import_node_child_process.spawnSync)(binaryPath, ["score", "--input", inputPath], {
        cwd: process.cwd(),
        encoding: "utf8",
        timeout: 5e3
      });
      if (proc.status !== 0) {
        continue;
      }
      const parsed = JSON.parse(proc.stdout);
      if (typeof parsed?.risk === "number") {
        return parsed;
      }
    } catch {
      continue;
    } finally {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
      }
    }
  }
  return null;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  scoreWithRust
});
//# sourceMappingURL=rust-bridge.js.map