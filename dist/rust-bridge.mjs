import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
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
      const proc = spawnSync(binaryPath, ["score", "--input", inputPath], {
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
export {
  scoreWithRust
};
//# sourceMappingURL=rust-bridge.mjs.map