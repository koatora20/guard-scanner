import { readFileSync } from "node:fs";
import path from "node:path";
function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}
function summarizeText(text) {
  const matches = [...text.matchAll(/\b(\d+)\s+(?:patterns?|categories?|runtime checks?)\b/gi)];
  return matches.map((match) => match[0]);
}
function main() {
  const root = process.cwd();
  const capabilities = readJson(
    path.join(root, "docs", "spec", "capabilities.json")
  );
  const pkg = readJson(path.join(root, "package.json"));
  const readme = readFileSync(path.join(root, "README.md"), "utf8");
  const skill = readFileSync(path.join(root, "SKILL.md"), "utf8");
  const status = readFileSync(path.join(root, "STATUS.md"), "utf8");
  const roadmap = readFileSync(path.join(root, "ROADMAP.md"), "utf8");
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
//# sourceMappingURL=audit-baseline.mjs.map