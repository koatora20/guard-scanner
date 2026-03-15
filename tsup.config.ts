import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
    scanner: "src/scanner.ts",
    "audit-decision": "src/audit-decision.ts",
    patterns: "src/patterns.ts",
    "ioc-db": "src/ioc-db.ts",
    capabilities: "src/capabilities.ts",
    "rust-bridge": "src/rust-bridge.ts",
    "runtime-plugin": "src/runtime-plugin.ts",
    plugin: "src/plugin.ts",
    mcp: "src/mcp.ts",
    "public-types": "src/public-types.ts",
    "tools/audit-baseline": "scripts/audit-baseline.ts",
    "tools/benchmark": "scripts/benchmark.ts",
    "tools/release-gate": "scripts/release-gate.ts",
    "tools/oss-release-report": "scripts/oss-release-report.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  bundle: false,
  target: "node18",
  splitting: false,
  shims: false,
  outDir: "dist",
  outExtension({ format }) {
    return {
      js: format === "esm" ? ".mjs" : ".js",
    };
  },
});
