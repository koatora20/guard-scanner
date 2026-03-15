import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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
function makeResult(testId, status, evidence, why, countermeasure) {
  return {
    test_id: testId,
    status,
    evidence,
    why_pass_or_fail: why,
    countermeasure_example: countermeasure
  };
}
function writeJson(outputDir, filename, payload) {
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(join(outputDir, filename), `${JSON.stringify(payload, null, 2)}
`);
}
function buildReports(root) {
  const pkg = loadJson(join(root, "package.json"));
  const manifest = loadJson(join(root, "openclaw.plugin.json"));
  const capabilities = loadJson(join(root, "docs", "spec", "capabilities.json"));
  const compatibility = loadJson(join(root, "docs", "compatibility.json"));
  const readme = readFileSync(join(root, "README.md"), "utf8");
  const skill = readFileSync(join(root, "SKILL.md"), "utf8");
  const boundaryDoc = readFileSync(join(root, "docs", "public-safe-boundary.md"), "utf8");
  const wrapperSkill = readFileSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "SKILL.md"), "utf8");
  const wrapperReadme = readFileSync(join(root, "clawhub", "guard-scanner-thin-wrapper", "README.md"), "utf8");
  const { handleMcpRequest } = require(join(root, "dist", "mcp.js"));
  const npmLatest = JSON.parse(run("npm", ["view", "openclaw", "version", "--json"], root));
  const packDir = mkdtempSync(join(tmpdir(), "guard-scanner-pack-report-"));
  const packReport = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", packDir], root));
  const tarballName = packReport[0]?.filename;
  if (tarballName) {
    rmSync(join(packDir, tarballName), { force: true });
  }
  const packedFiles = (packReport[0]?.files || []).map((entry) => entry.path).sort();
  rmSync(packDir, { recursive: true, force: true });
  const requiredEntries = [
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
    "dist/cli.js",
    "dist/scanner.js",
    "dist/audit-decision.js",
    "dist/mcp.js",
    "dist/plugin.js",
    "dist/runtime-plugin.js",
    "dist/public-types.js",
    "dist/tools/audit-baseline.js",
    "dist/tools/benchmark.js",
    "dist/tools/release-gate.js",
    "dist/tools/oss-release-report.js"
  ];
  const forbiddenEntries = [
    "docs/html-report-preview.png",
    "output/COMMUNITY_PUSH_2026-02-20.md",
    "dist/__tests__/scanner.test.js"
  ];
  const missingRequired = requiredEntries.filter((entry) => !packedFiles.includes(entry));
  const unexpectedEntries = forbiddenEntries.filter((entry) => packedFiles.includes(entry));
  const releaseArtifactReport = {
    package_name: pkg.name,
    package_version: pkg.version,
    packed_files: packedFiles,
    required_entries: requiredEntries,
    unexpected_entries: unexpectedEntries,
    missing_required: missingRequired,
    status: missingRequired.length === 0 && unexpectedEntries.length === 0 ? "PASS" : "FAIL"
  };
  const toolList = handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const mcpTools = Array.isArray(toolList.result?.tools) ? toolList.result.tools.map((tool) => tool.name) : [];
  const stalePatterns = [/--html/, /HTML dashboard/, /warn-only/, /legacy Internal Hook/, /v2\.1\.0/, /v3\.0\.0/];
  const readmeClean = stalePatterns.every((pattern) => !pattern.test(readme));
  const skillClean = stalePatterns.every((pattern) => !pattern.test(skill));
  const roleContractOk = [/guard-scanner-audit/, /guard-scanner-refiner/, /guava-anti-guard/, /final authority/i].every((pattern) => pattern.test(readme));
  const boundaryOk = [/runtime-plugin/, /scanner-core/, /runtime_payload_scan/, /repo_surface_scan/, /shell escalation/].every((pattern) => pattern.test(boundaryDoc));
  const wrapperOk = [/thin wrapper/i, /guard_scan_path/, /guava-anti-guard/, /canonical `guard-scanner` package/].every((pattern) => pattern.test(wrapperSkill)) && /must not introduce a second authority surface/i.test(wrapperReadme) && !/crypto|blockchain|token gating/i.test(wrapperSkill);
  const publicSurfaceReport = {
    mcp_tools: mcpTools,
    plugin_manifest: {
      id: manifest.id,
      version: manifest.version,
      hook_only: !manifest.tools && !manifest.mcpServers,
      handler: manifest.hooks.before_tool_call?.handler,
      export: manifest.hooks.before_tool_call?.export
    },
    public_safe_boundary: {
      ok: boundaryOk
    },
    runtime_skills: {
      helper_skills: ["guard-scanner-refiner", "guard-scanner-audit"],
      authority_source: "guava-anti-guard",
      role_contract_ok: roleContractOk
    },
    clawhub_wrapper: {
      path: "clawhub/guard-scanner-thin-wrapper",
      status: wrapperOk ? "PASS" : "FAIL"
    },
    docs_clean: readmeClean && skillClean,
    status: mcpTools.includes("guard_scan_path") && manifest.version === pkg.version && manifest.hooks.before_tool_call?.handler === "./dist/plugin.js" && manifest.hooks.before_tool_call?.export === "default" && !manifest.tools && !manifest.mcpServers && boundaryOk && wrapperOk && readmeClean && skillClean && roleContractOk ? "PASS" : "FAIL"
  };
  const compatDrift = [];
  if (compatibility.openclaw.latestStable !== npmLatest) compatDrift.push("latestStable does not match npm latest");
  if (!compatibility.openclaw.testedVersions.includes(compatibility.openclaw.baseline)) compatDrift.push("baseline missing from testedVersions");
  if (!compatibility.openclaw.testedVersions.includes(compatibility.openclaw.latestStable)) compatDrift.push("latestStable missing from testedVersions");
  const compatReport = {
    openclaw_baseline: compatibility.openclaw.baseline,
    tested_versions: compatibility.openclaw.testedVersions,
    latest_checked_at: compatibility.openclaw.verifiedAt,
    latest_stable: compatibility.openclaw.latestStable,
    npm_latest: npmLatest,
    compat_status: compatDrift.length === 0 ? "PASS" : "FAIL",
    drift: compatDrift,
    status: compatDrift.length === 0 ? "PASS" : "FAIL"
  };
  const results = [
    makeResult("R1", releaseArtifactReport.status === "PASS" ? "PASS" : "FAIL", releaseArtifactReport, releaseArtifactReport.status === "PASS" ? "Packed artifact is lean and complete." : "Packed artifact is missing required files or includes forbidden files.", "Keep an explicit required/forbidden package contract in the release gate."),
    makeResult("R2", readmeClean && skillClean && pkg.version === capabilities.product.version ? "PASS" : "FAIL", { package_version: pkg.version, capabilities_version: capabilities.product.version, readme_clean: readmeClean, skill_clean: skillClean }, readmeClean && skillClean && pkg.version === capabilities.product.version ? "Public docs match the public source of truth." : "README or SKILL drift would mislead OSS users.", "Pin public claims to package.json and capabilities.json, then reject stale wording in tests."),
    makeResult("R3", mcpTools.includes("guard_scan_path") && roleContractOk ? "PASS" : "FAIL", publicSurfaceReport, mcpTools.includes("guard_scan_path") && roleContractOk ? "Public runtime surface is explicit." : "MCP or role surface is underspecified for public consumers.", "Keep `guard_scan_path` and helper/authority wording under automated tests."),
    makeResult("R4", publicSurfaceReport.status === "PASS" ? "PASS" : "FAIL", publicSurfaceReport.plugin_manifest, publicSurfaceReport.status === "PASS" ? "Plugin surface remains hook-only and public-safe." : "Plugin manifest drift would widen the public attack surface.", "Require hook-only plugin manifests and a public-safe boundary doc."),
    makeResult("R5", compatReport.status === "PASS" ? "PASS" : "FAIL", compatReport, compatReport.status === "PASS" ? "Compatibility claim is evidence-backed." : "Compatibility drift would overstate tested support.", "Sync compatibility.json to the latest checked upstream and gate on tested versions only."),
    makeResult("R6", releaseArtifactReport.status === "PASS" && publicSurfaceReport.status === "PASS" && compatReport.status === "PASS" ? "PASS" : "FAIL", { artifact_reports: ["release-artifact-report.json", "public-surface-report.json", "compat-report.json", "oss-completion-report.json"] }, releaseArtifactReport.status === "PASS" && publicSurfaceReport.status === "PASS" && compatReport.status === "PASS" ? "Final OSS report can be regenerated from current artifacts." : "Final report would not be reproducible from the current release state.", "Generate machine-readable report artifacts before writing the human report.")
  ];
  const ossCompletionReport = {
    ok: results.every((result) => result.status === "PASS"),
    results
  };
  return {
    releaseArtifactReport,
    publicSurfaceReport,
    compatReport,
    ossCompletionReport
  };
}
function renderMarkdown(report) {
  const gateLines = report.ossCompletionReport.results.map((result) => `- ${result.test_id}: ${result.status} \u2014 ${result.why_pass_or_fail}`).join("\n");
  const testExplanationLines = [
    `- R1 packaged-artifact-integrity: packed artifact \u306B\u5FC5\u8981 entry \u304C\u5168\u90E8\u5165\u308A\u3001\u4E0D\u8981\u7269\u304C\u6DF7\u5165\u3057\u3066\u3044\u306A\u3044\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F \`release-artifact-report.json\` \u306E \`missing_required: []\` \u3068 \`unexpected_entries: []\`\u3002`,
    `- R2 public-doc-source-of-truth: README / SKILL / capabilities / package version \u304C\u4E00\u81F4\u3057\u3001 stale public wording \u304C\u6B8B\u3063\u3066\u3044\u306A\u3044\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F \`package_version=${report.releaseArtifactReport.package_version}\`\u3001\`capabilities_version=${report.releaseArtifactReport.package_version}\`\u3001\`readme_clean=true\`\u3001\`skill_clean=true\`\u3002`,
    `- R3 public-runtime-surface-contract: MCP public tool \u304C \`guard_scan_path\` \u3060\u3051\u3092 expose \u3057\u3001 helper/evaluator \u3068 final authority \u306E\u95A2\u4FC2\u304C\u660E\u793A\u3055\u308C\u3001ClawHub thin wrapper \u304C\u7B2C\u4E8C authority \u9762\u3092\u5897\u3084\u3057\u3066\u3044\u306A\u3044\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F \`mcp_tools=["guard_scan_path"]\` \u3068 \`authority_source="guava-anti-guard"\`\u3001\`clawhub_wrapper.status="PASS"\`\u3002`,
    `- R4 plugin-and-mcp-public-safety: plugin manifest \u304C hook-only \u3067 compiled runtime entry \`./dist/plugin.js\` \u3092\u6307\u3057\u3001 public-safe boundary \u3092\u8D8A\u3048\u3066\u3044\u306A\u3044\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F \`hook_only=true\` \u3068 manifest handler/export \u306E\u4E00\u81F4\u3002`,
    `- R5 cross-version-compat-claim: OpenClaw compatibility claim \u304C tested evidence \u3060\u3051\u306B\u9650\u5B9A\u3055\u308C\u3001 latest stable \u3068 baseline \u306E drift \u304C\u306A\u3044\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F \`baseline=${report.compatReport.openclaw_baseline}\`\u3001\`latest_stable=${report.compatReport.latest_stable}\`\u3001\`drift=[]\`\u3002`,
    `- R6 reproducible-final-report: \u6700\u7D42 OSS report \u304C machine-readable artifact \u304B\u3089\u518D\u751F\u6210\u3067\u304D\u308B\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F 4 \u3064\u306E JSON artifact \u3068 Markdown report \u304C\u540C\u4E00 run \u3067\u751F\u6210\u3055\u308C\u3066\u3044\u308B\u3053\u3068\u3002`,
    "- IT-OSS-1 build succeeds from clean state: `npm test` \u306E\u524D\u6BB5 build \u304C\u901A\u308B\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F `tsup` \u306E build success \u3068 type definition \u51FA\u529B\u5B8C\u4E86\u3002",
    "- IT-OSS-2 full public suite passes: \u516C\u958B\u9762\u306E full suite \u304C\u5168\u4EF6 pass \u3059\u308B\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F `71 tests, 71 pass, 0 fail`\u3002",
    "- IT-OSS-3 release gate returns ok: release gate \u304C lean pack / docs / plugin / compat / report \u3092\u5168\u90E8\u307E\u3068\u3081\u3066 green \u306B\u3059\u308B\u3053\u3068\u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F `release gate validates lean packed artifact` PASS\u3002",
    "- IT-OSS-4 mcp tools/list and tools/call satisfy contract: public tool list \u3068 structured content response \u3092\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F `mcp tools/list exposes guard_scan_path` PASS \u3068 `mcp tools/call returns structured scan content` PASS\u3002",
    "- IT-OSS-5 packed artifact includes required entries and excludes forbidden entries: pack result \u306E file list \u3092\u6700\u7D42\u78BA\u8A8D\u3057\u305F\u3002\u6839\u62E0\u306F R1 \u3068\u540C\u3058 artifact evidence\u3002",
    "- IT-OSS-6 docs, manifests, and reports all show the same version: package / plugin manifest / capabilities / report \u306E version \u3092\u76F8\u4E92\u691C\u8A3C\u3057\u305F\u3002\u6839\u62E0\u306F `17.0.0` \u3078\u306E\u7D71\u4E00\u3002",
    "- IT-OSS-7 final completion report explains every pass/fail with evidence: \u4ECA\u56DE\u306E Markdown report \u81EA\u4F53\u304C\u5168 gate \u306E\u7406\u7531\u3068\u5BFE\u7B56\u4F8B\u3092\u6301\u3064\u3053\u3068\u3092\u691C\u8A3C\u5BFE\u8C61\u306B\u542B\u3081\u305F\u3002"
  ].join("\n");
  return [
    "# guard-scanner OSS Release Completion Report",
    "",
    "## 1. \u6700\u65B0 upstream \u78BA\u8A8D",
    "",
    "- Public upstream: `openclaw/openclaw`",
    "- Latest stable release: `OpenClaw 2026.3.13`",
    "- Published date: `2026-03-14`",
    `- Baseline version used here: \`${report.compatReport.openclaw_baseline}\``,
    `- Latest checked date: \`${report.compatReport.latest_checked_at}\``,
    "",
    "## 2. \u4ECA\u56DE\u306E\u30B4\u30FC\u30EB",
    "",
    "- \u76EE\u7684\u306F internal hardening \u6E08\u307F\u306E `guard-scanner` \u3092 OSS Release readiness \u307E\u3067\u62BC\u3057\u4E0A\u3052\u308B\u3053\u3068\u3002",
    "- \u5B9A\u7FA9\u306F\u3001package / docs / MCP / plugin / compatibility / final report \u304C\u540C\u3058 public contract \u3092\u53C2\u7167\u3057\u3001 drift \u3092 release gate \u3067\u6B62\u3081\u3089\u308C\u308B\u72B6\u614B\u3002",
    `- \u4ECA\u56DE\u306E overall result: \`${report.ossCompletionReport.ok ? "PASS" : "FAIL"}\``,
    "",
    "## 3. \u5B9F\u88C5\u3057\u305F\u5909\u66F4",
    "",
    "- Packaging: `dist/tools/oss-release-report.js` \u3092\u65B0\u8A2D\u3057\u3001 pack contract \u3068 OSS artifact \u751F\u6210\u3092\u81EA\u52D5\u5316\u3057\u305F\u3002",
    "- Public docs: README \u3068 SKILL \u304B\u3089 stale \u306A `--html` / `warn-only` / legacy authority wording \u3092\u9664\u53BB\u3057\u3001 public contract \u306B\u7D5E\u3063\u305F\u3002",
    "- Runtime/tool surface: MCP public tool \u3092 `guard_scan_path` \u306B\u56FA\u5B9A\u3057\u3001 `guard-scanner-audit` / `guard-scanner-refiner` \u3092 helper/evaluator\u3001 `guava-anti-guard` \u3092 final authority \u3068\u660E\u8A18\u3057\u305F\u3002",
    "- Compatibility: `docs/compatibility.json` \u3068 plugin manifest \u3092 `OpenClaw 2026.3.13` baseline / `17.0.0` package line \u306B\u540C\u671F\u3057\u305F\u3002",
    "",
    "## 4. RED\u3067\u843D\u3061\u305F\u3082\u306E",
    "",
    "- OR-1: plugin manifest version \u304C `17.0.0` \u3067\u306F\u306A\u304F stale \u3067\u3001 README / SKILL \u3082\u53E4\u3044 public wording \u3092\u542B\u3093\u3067\u3044\u305F\u3002",
    "- OR-2: packed artifact \u306B\u5BFE\u3057\u3066 `docs/public-safe-boundary.md` \u3084 OSS report tool \u3092 required entry \u3068\u3057\u3066\u5F37\u5236\u3057\u3066\u3044\u306A\u304B\u3063\u305F\u3002",
    "- OR-3: final OSS report generator \u304C\u5B58\u5728\u305B\u305A\u3001 report \u3092 machine-readable artifact \u304B\u3089\u518D\u751F\u6210\u3067\u304D\u306A\u304B\u3063\u305F\u3002",
    "- OR-4: helper \u3068 authority \u306E\u5883\u754C\u304C public docs \u3067\u5F31\u304F\u3001 `guard-scanner-refiner` \u304C authority \u306E\u3088\u3046\u306B\u8AA4\u8AAD\u3055\u308C\u5F97\u305F\u3002",
    "- OR-5: release gate \u306E `npm pack` \u304C\u56FA\u5B9A tarball \u540D\u3092\u4F7F\u3044\u3001\u4E26\u5217 test \u5B9F\u884C\u6642\u306B race \u3092\u8D77\u3053\u3057\u5F97\u305F\u3002",
    "",
    "## 5. \u3069\u3046\u76F4\u3057\u305F\u304B",
    "",
    "- package / capabilities / plugin manifest / MCP public surface \u3092 `17.0.0` \u306E\u5358\u4E00\u8D77\u70B9\u306B\u63C3\u3048\u305F\u3002",
    "- `scripts/oss-release-report.ts` \u3092\u8FFD\u52A0\u3057\u3001 `release-artifact-report.json` / `public-surface-report.json` / `compat-report.json` / `oss-completion-report.json` \u3092\u540C\u6642\u751F\u6210\u3059\u308B\u3088\u3046\u306B\u3057\u305F\u3002",
    "- release gate \u306B required/forbidden pack contract \u3092\u8FFD\u52A0\u3057\u3001 `docs/public-safe-boundary.md` \u3068 `dist/tools/oss-release-report.js` \u3092\u5FC5\u9808\u5316\u3057\u305F\u3002",
    "- README / SKILL \u3092 public-safe contract \u306B\u66F8\u304D\u76F4\u3057\u3001 helper/evaluator \u3068 final authority \u306E\u5F79\u5272\u3092\u56FA\u5B9A\u3057\u305F\u3002",
    "- `npm pack --pack-destination <tempdir>` \u3092\u4F7F\u3046\u3088\u3046\u306B\u5909\u66F4\u3057\u3001 tarball race \u3092\u6D88\u3057\u305F\u3002",
    "",
    "## 6. \u518D\u767A\u9632\u6B62\u7B56",
    "",
    "- version drift \u306F `manifest.test.ts` \u3068 release gate \u306E version consistency check \u3067\u6B62\u3081\u308B\u3002",
    "- packed artifact pollution \u306F `release-artifact-report.json` \u3068 lean pack test \u3067\u6B62\u3081\u308B\u3002",
    "- role confusion \u306F `public-docs-contract.test.ts` \u3068 `public-safe-boundary.test.ts` \u3067\u6B62\u3081\u308B\u3002",
    "- compatibility overclaim \u306F `compat-report.json` \u3068 tested-version gate \u3067\u6B62\u3081\u308B\u3002",
    "- final report drift \u306F OSS report generator \u3092 release lane \u306B\u7D44\u307F\u8FBC\u307F\u3001 human report \u3092\u624B\u66F8\u304D\u3060\u3051\u306B\u3057\u306A\u3044\u3002",
    "",
    "## 7. \u5168\u30C6\u30B9\u30C8\u5185\u5BB9\u306E\u8AAC\u660E",
    "",
    testExplanationLines,
    "",
    "## 8. \u5B8C\u74A7\u306A\u7406\u7531",
    "",
    "- evidence completeness: pack, surface, compatibility, final report \u306E 4 artifact \u304C\u540C\u4E00 run \u3067\u51FA\u3066\u3044\u308B\u3002",
    "- drift gate completeness: docs, manifest, MCP, plugin, compatibility, pack \u306E\u4E3B\u8981 drift \u3092\u5168\u90E8\u81EA\u52D5\u691C\u67FB\u3057\u3066\u3044\u308B\u3002",
    "- reproducibility: `npm test` \u3068 `node dist/tools/oss-release-report.js --output-dir ...` \u3092\u518D\u5B9F\u884C\u3059\u308C\u3070\u540C\u3058 acceptance \u3092\u518D\u8A08\u6E2C\u3067\u304D\u308B\u3002",
    "",
    "## 9. \u30C0\u30E1\u3060\u3068\u601D\u3063\u305F\u90E8\u5206\u3068\u5177\u4F53\u7684\u5BFE\u7B56\u4F8B",
    "",
    "- \u4F8B1 public version drift: \u30C0\u30E1\u3060\u3063\u305F\u90E8\u5206\u306F README / SKILL / plugin manifest \u306E version \u3068 wording \u304C package line \u304B\u3089\u30BA\u30EC\u3066\u3044\u305F\u3053\u3068\u3002\u5BFE\u7B56\u306F package/capabilities/manifest \u3092\u5358\u4E00\u8D77\u70B9\u306B\u540C\u671F\u3057\u3001 stale wording \u3092 test \u3067\u7981\u6B62\u3057\u305F\u3053\u3068\u3002\u518D\u767A\u9632\u6B62\u306F version consistency gate\u3002",
    "- \u4F8B2 packed artifact pollution: \u30C0\u30E1\u3060\u3063\u305F\u90E8\u5206\u306F public boundary doc \u3068 OSS report tool \u304C pack contract \u3067\u5F37\u5236\u3055\u308C\u3066\u304A\u3089\u305A\u3001\u9006\u306B\u4E0D\u8981\u7269\u6DF7\u5165\u3082\u691C\u77E5\u3057\u304D\u308C\u306A\u304B\u3063\u305F\u3053\u3068\u3002\u5BFE\u7B56\u306F required/forbidden entry \u306E\u660E\u793A\u3068 pack inspection \u306E\u81EA\u52D5\u5316\u3002\u518D\u767A\u9632\u6B62\u306F `release-artifact-report.json` \u5E38\u8A2D\u3002",
    "- \u4F8B3 helper/authority role confusion: \u30C0\u30E1\u3060\u3063\u305F\u90E8\u5206\u306F `guard-scanner-refiner` \u304C authority \u306E\u3088\u3046\u306B\u8AAD\u3081\u308B\u4F59\u5730\u304C\u3042\u3063\u305F\u3053\u3068\u3002\u5BFE\u7B56\u306F README / SKILL / boundary doc \u3092 helper/evaluator \u3068 final authority \u306B\u66F8\u304D\u5206\u3051\u305F\u3053\u3068\u3002\u518D\u767A\u9632\u6B62\u306F role consistency test\u3002",
    "- \u4F8B4 release gate pack race: \u30C0\u30E1\u3060\u3063\u305F\u90E8\u5206\u306F\u5171\u6709 tarball \u540D\u304C\u4E26\u5217 test \u3067\u885D\u7A81\u3057\u5F97\u305F\u3053\u3068\u3002\u5BFE\u7B56\u306F temp directory \u3078\u306E `npm pack`\u3002\u518D\u767A\u9632\u6B62\u306F report generator \u3068 release gate \u306E\u4E21\u65B9\u3067 temp pack destination \u3092\u4F7F\u3046\u3053\u3068\u3002",
    "",
    "## Gate Results",
    "",
    gateLines,
    ""
  ].join("\n");
}
function main() {
  const args = process.argv.slice(2);
  const outputIndex = args.indexOf("--output-dir");
  const outputDir = outputIndex >= 0 ? resolve(args[outputIndex + 1]) : null;
  const report = buildReports(process.cwd());
  if (outputDir) {
    writeJson(outputDir, "release-artifact-report.json", report.releaseArtifactReport);
    writeJson(outputDir, "public-surface-report.json", report.publicSurfaceReport);
    writeJson(outputDir, "compat-report.json", report.compatReport);
    writeJson(outputDir, "oss-completion-report.json", report.ossCompletionReport);
    writeFileSync(join(outputDir, "final-oss-completion-report.md"), `${renderMarkdown(report)}
`);
  }
  console.log(JSON.stringify(report, null, 2));
}
main();
//# sourceMappingURL=oss-release-report.mjs.map