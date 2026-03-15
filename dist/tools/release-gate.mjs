import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
function run(cmd, args, cwd) {
  return execFileSync(cmd, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}
function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}
function smokeInstall(tarballPath, pkgName) {
  const tempDir = mkdtempSync(join(tmpdir(), "guard-scanner-pack-"));
  try {
    writeFileSync(
      join(tempDir, "package.json"),
      JSON.stringify({ name: "guard-scanner-smoke", private: true }, null, 2)
    );
    run("npm", ["install", "--no-package-lock", tarballPath], tempDir);
    run("node", [
      "-e",
      [
        `const mod = require(${JSON.stringify(pkgName)});`,
        "if (typeof mod.GuardScanner !== 'function') throw new Error('missing GuardScanner require export');",
        "if (!mod.VERSION) throw new Error('missing VERSION require export');"
      ].join(" ")
    ], tempDir);
    run("node", [
      "--input-type=module",
      "-e",
      [
        `const mod = await import(${JSON.stringify(pkgName)});`,
        "if (typeof mod.GuardScanner !== 'function') throw new Error('missing GuardScanner import export');",
        "if (!mod.VERSION) throw new Error('missing VERSION import export');"
      ].join(" ")
    ], tempDir);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}
function main() {
  const root = process.cwd();
  const pkg = loadJson(join(root, "package.json"));
  const manifest = loadJson(join(root, "openclaw.plugin.json"));
  const capabilities = loadJson(join(root, "docs", "spec", "capabilities.json"));
  const compatibility = loadJson(join(root, "docs", "compatibility.json"));
  const readme = readFileSync(join(root, "README.md"), "utf8");
  const skill = readFileSync(join(root, "SKILL.md"), "utf8");
  const wrapperSkill = readFileSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "SKILL.md"), "utf8");
  const wrapperReadme = readFileSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "README.md"), "utf8");
  const npmLatest = JSON.parse(run("npm", ["view", "openclaw", "version", "--json"], root));
  assert(pkg.name === "guard-scanner", `package name drift: ${pkg.name}`);
  assert(pkg.version === capabilities.product.version, "package version must match capabilities source of truth");
  assert(manifest.id === "guava-guard-scanner", `plugin id drift: ${manifest.id}`);
  assert(manifest.name === "guava-guard-scanner", `plugin name drift: ${manifest.name}`);
  assert(manifest.version === pkg.version, "plugin manifest version must match package version");
  assert(manifest.license === pkg.license, "license mismatch between package and plugin manifest");
  assert(manifest.hooks.before_tool_call?.handler === "./dist/plugin.js", "runtime handler drift");
  assert(manifest.hooks.before_tool_call?.export === "default", "runtime handler export drift");
  assert(!manifest.tools, "runtime plugin must stay hook-only");
  assert(!manifest.mcpServers, "runtime plugin must not expose MCP servers");
  assert(existsSync(join(root, "README.md")), "missing README.md");
  assert(existsSync(join(root, "LICENSE")), "missing LICENSE");
  assert(existsSync(join(root, "SKILL.md")), "missing SKILL.md");
  assert(existsSync(join(root, "SECURITY.md")), "missing SECURITY.md");
  assert(existsSync(join(root, "docs", "public-safe-boundary.md")), "missing public-safe boundary doc");
  assert(existsSync(join(root, "docs", "spec", "capabilities.json")), "missing capabilities source of truth");
  assert(existsSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "SKILL.md")), "missing ClawHub thin wrapper skill");
  assert(existsSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "README.md")), "missing ClawHub thin wrapper README");
  assert(readme.includes("Source of truth"), "README must mention the source of truth");
  assert(skill.includes("Source of truth"), "SKILL.md must mention the source of truth");
  assert(!/--html|HTML dashboard|warn-only|legacy Internal Hook|v2\.1\.0|v3\.0\.0/.test(readme), "README contains stale public claims");
  assert(!/--html|HTML dashboard|warn-only|legacy Internal Hook|v2\.1\.0|v3\.0\.0/.test(skill), "SKILL contains stale public claims");
  assert(/thin wrapper/i.test(wrapperSkill), "thin wrapper SKILL must state wrapper role");
  assert(/guard_scan_path/.test(wrapperSkill), "thin wrapper SKILL must point to guard_scan_path");
  assert(/guava-anti-guard/.test(wrapperSkill), "thin wrapper SKILL must keep guava-anti-guard as final authority");
  assert(/must not introduce a second authority surface/i.test(wrapperReadme), "thin wrapper README must prohibit a second authority surface");
  assert(!/crypto|blockchain|token gating/i.test(wrapperSkill), "thin wrapper SKILL must stay crypto-free");
  assert(pkg.exports?.["."], "package exports must define root entry");
  assert(pkg.exports?.["./plugin"], "package exports must define ./plugin entry");
  assert(pkg.exports?.["./mcp"], "package exports must define ./mcp entry");
  assert(pkg.exports?.["./audit-decision"], "package exports must define ./audit-decision entry");
  assert(pkg.exports?.["./capabilities"], "package exports must define ./capabilities entry");
  assert(pkg.exports?.["./types"], "package exports must define ./types entry");
  assert(compatibility.openclaw.latestStable === npmLatest, "compatibility latestStable is stale");
  assert(compatibility.openclaw.testedVersions.includes(compatibility.openclaw.baseline), "compatibility baseline missing from testedVersions");
  assert(compatibility.openclaw.testedVersions.includes(compatibility.openclaw.latestStable), "compatibility latest stable missing from testedVersions");
  const packDir = mkdtempSync(join(tmpdir(), "guard-scanner-pack-gate-"));
  const packReport = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", packDir], root));
  const tarballName = packReport[0]?.filename;
  assert(tarballName, "npm pack did not produce a tarball");
  const tarballPath = join(packDir, tarballName);
  const packedFiles = new Set((packReport[0]?.files || []).map((entry) => entry.path));
  for (const required of [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "SKILL.md",
    "openclaw.plugin.json",
    "package.json",
    "docs/compatibility.json",
    "docs/public-safe-boundary.md",
    "docs/spec/capabilities.json",
    "docs/THREAT_TAXONOMY.md",
    "dist/index.js",
    "dist/index.mjs",
    "dist/index.d.ts",
    "dist/plugin.js",
    "dist/plugin.mjs",
    "dist/plugin.d.ts",
    "dist/mcp.js",
    "dist/mcp.mjs",
    "dist/mcp.d.ts",
    "dist/public-types.js",
    "dist/public-types.mjs",
    "dist/public-types.d.ts",
    "dist/cli.js",
    "dist/tools/audit-baseline.js",
    "dist/tools/benchmark.js",
    "dist/runtime-plugin.js",
    "dist/tools/release-gate.js",
    "dist/tools/oss-release-report.js"
  ]) {
    assert(packedFiles.has(required), `pack missing required file: ${required}`);
  }
  for (const forbidden of [
    "docs/html-report-preview.png",
    "ts-src/cli.ts",
    "dist/__tests__/scanner.test.js"
  ]) {
    assert(!packedFiles.has(forbidden), `pack should exclude file: ${forbidden}`);
  }
  try {
    smokeInstall(tarballPath, pkg.name);
  } finally {
    rmSync(tarballPath, { force: true });
    rmSync(packDir, { recursive: true, force: true });
  }
  const ossReport = JSON.parse(run("node", [join(root, "dist", "tools", "oss-release-report.js")], root));
  assert(ossReport.ossCompletionReport.ok, "oss release report must pass");
  console.log(JSON.stringify({
    ok: true,
    packageName: pkg.name,
    pluginId: manifest.id,
    packedFiles: [...packedFiles].sort(),
    ossCompletionOk: ossReport.ossCompletionReport.ok
  }, null, 2));
}
main();
//# sourceMappingURL=release-gate.mjs.map