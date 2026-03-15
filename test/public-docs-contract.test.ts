// @ts-nocheck
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("README and SKILL stay aligned with the public OSS contract", () => {
    const readme = fs.readFileSync(path.join(process.cwd(), "README.md"), "utf8");
    const skill = fs.readFileSync(path.join(process.cwd(), "SKILL.md"), "utf8");
    const wrapperSkill = fs.readFileSync(path.join(process.cwd(), "clawhub", "guard-scanner-thin-wrapper", "SKILL.md"), "utf8");

    for (const doc of [readme, skill]) {
        assert.doesNotMatch(doc, /--html|HTML dashboard|warn-only|legacy Internal Hook|v2\.1\.0|v3\.0\.0/);
    }

    assert.match(readme, /Source of truth: `docs\/spec\/capabilities\.json`/);
    assert.match(readme, /guard-scanner-audit/);
    assert.match(readme, /guard-scanner-refiner/);
    assert.match(readme, /guava-anti-guard/);
    assert.match(readme, /final authority/i);
    assert.match(readme, /Terminal.*JSON.*SARIF/s);
    assert.match(readme, /clawhub\/guard-scanner-thin-wrapper/);
    assert.match(wrapperSkill, /thin wrapper/i);
    assert.match(wrapperSkill, /guard_scan_path/);
    assert.match(wrapperSkill, /guava-anti-guard/);
});

test("GitHub-facing docs stay free of stale crypto marketing and legacy output claims", () => {
    const security = fs.readFileSync(path.join(process.cwd(), "SECURITY.md"), "utf8");
    const changelog = fs.readFileSync(path.join(process.cwd(), "CHANGELOG.md"), "utf8");
    const communityPush = fs.readFileSync(path.join(process.cwd(), "output", "COMMUNITY_PUSH_2026-02-20.md"), "utf8");

    assert.doesNotMatch(security, /--html|src\/patterns\.js|src\/ioc-db\.js/);
    assert.doesNotMatch(changelog, /SoulChain|blockchain integration/i);
    assert.doesNotMatch(communityPush, /\$GUAVA token gating|wallet.*dependency|chain dependency/i);
    assert.match(communityPush, /archive marker/i);
    assert.match(communityPush, /Current public source of truth is \[`README\.md`\]/);
});
