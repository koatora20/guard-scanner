// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("ClawHub thin wrapper stays aligned with the canonical package contract", () => {
    const wrapperRoot = path.join(process.cwd(), "clawhub", "guard-scanner-thin-wrapper");
    const skill = fs.readFileSync(path.join(wrapperRoot, "SKILL.md"), "utf8");
    const readme = fs.readFileSync(path.join(wrapperRoot, "README.md"), "utf8");

    assert.match(skill, /thin wrapper/i);
    assert.match(skill, /canonical `guard-scanner` package/);
    assert.match(skill, /guard_scan_path/);
    assert.match(skill, /guava-anti-guard/);
    assert.match(skill, /tested OpenClaw baseline: `2026\.3\.13`/);
    assert.doesNotMatch(skill, /final authority surface/i);
    assert.doesNotMatch(skill, /crypto|blockchain|token gating/i);

    assert.match(readme, /ClawHub-facing thin wrapper/);
    assert.match(readme, /must not introduce a second authority surface/);
    assert.match(readme, /Final authority remains `guava-anti-guard`/);
});
