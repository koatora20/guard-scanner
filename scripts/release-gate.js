const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const root = process.cwd();
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "openclaw.plugin.json"), "utf8"));
    const capabilities = JSON.parse(fs.readFileSync(path.join(root, "docs", "spec", "capabilities.json"), "utf8"));
    const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
    const skill = fs.readFileSync(path.join(root, "SKILL.md"), "utf8");

    assert(pkg.name === "guard-scanner", `package name drift: ${pkg.name}`);
    assert(pkg.version === capabilities.product.version, "package version must match capabilities source of truth");
    assert(manifest.id === "guava-guard-scanner", `plugin id drift: ${manifest.id}`);
    assert(manifest.name === "guava-guard-scanner", `plugin name drift: ${manifest.name}`);
    assert(manifest.license === pkg.license, "license mismatch between package and plugin manifest");
    assert(manifest.hooks.before_tool_call.handler === "./dist/runtime-plugin.js", "runtime handler drift");
    assert(!manifest.tools, "runtime plugin must stay hook-only");
    assert(!manifest.mcpServers, "runtime plugin must not expose MCP servers");
    assert(fs.existsSync(path.join(root, "README.md")), "missing README.md");
    assert(fs.existsSync(path.join(root, "LICENSE")), "missing LICENSE");
    assert(fs.existsSync(path.join(root, "SKILL.md")), "missing SKILL.md");
    assert(fs.existsSync(path.join(root, "SECURITY.md")), "missing SECURITY.md");
    assert(fs.existsSync(path.join(root, "docs", "public-safe-boundary.md")), "missing public-safe boundary doc");
    assert(fs.existsSync(path.join(root, "docs", "spec", "capabilities.json")), "missing capabilities source of truth");
    assert(readme.includes("Source of truth"), "README must mention the source of truth");
    assert(skill.includes("Source of truth"), "SKILL.md must mention the source of truth");

    const packRaw = execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: root,
        encoding: "utf8",
    });
    const packReport = JSON.parse(packRaw);
    const packedFiles = new Set((packReport[0]?.files || []).map((entry) => entry.path));

    for (const required of [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "SKILL.md",
        "openclaw.plugin.json",
        "package.json",
        "docs/spec/capabilities.json",
        "dist/index.js",
        "dist/cli.js",
        "dist/runtime-plugin.js",
        "docs/THREAT_TAXONOMY.md",
    ]) {
        assert(packedFiles.has(required), `pack missing required file: ${required}`);
    }

    for (const forbidden of [
        "docs/html-report-preview.png",
        "ts-src/cli.ts",
        "dist/__tests__/scanner.test.js",
    ]) {
        assert(!packedFiles.has(forbidden), `pack should exclude file: ${forbidden}`);
    }

    console.log(JSON.stringify({
        ok: true,
        packageName: pkg.name,
        pluginId: manifest.id,
        packedFiles: [...packedFiles].sort(),
    }, null, 2));
}

main();
