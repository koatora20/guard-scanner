import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { computeSha256Hex, verifyPluginTrustChain, type PluginTrustPolicy } from '../scripts/lib/plugin-trust.ts';

const ROOT = path.join(__dirname, '..');

test('verifyPluginTrustChain passes for current dist plugin and policy', () => {
  const policyPath = path.join(ROOT, 'docs', 'spec', 'plugin-trust.json');
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8')) as PluginTrustPolicy;
  const errors = verifyPluginTrustChain(ROOT, ['./dist/openclaw-plugin.mjs'], policy);
  assert.deepEqual(errors, []);
});

test('verifyPluginTrustChain fails when extension is missing from policy', () => {
  const policy: PluginTrustPolicy = {
    version: 1,
    enforce: true,
    entries: [],
  };

  const errors = verifyPluginTrustChain(ROOT, ['./dist/openclaw-plugin.mjs'], policy);
  assert.ok(errors.some((e) => /not present in plugin trust policy/.test(e)));
});

test('computeSha256Hex is deterministic', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'plugin-hash-'));
  const file = path.join(dir, 'sample.txt');
  fs.writeFileSync(file, 'guard-scanner');

  const first = computeSha256Hex(file);
  const second = computeSha256Hex(file);
  assert.equal(first, second);
  assert.match(first, /^[a-f0-9]{64}$/);
});
