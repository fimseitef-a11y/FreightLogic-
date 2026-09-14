import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/rollback-verifier-current.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPT = path.join(ROOT, 'scripts/verify-rollback.mjs');
const source = readFileSync(SCRIPT, 'utf8');

test('B5 verifier is pinned to v24.0.9 runtime candidate and Worker v15', () => {
  ok(source.includes("5446b097fe8791f3d7c79b5a5833a0930ee83cf2"), 'exact v24.0.9 runtime SHA must be named');
  ok(source.includes("EXPECTED_APP_VERSION = '24.0.9'"), 'app generation must be v24.0.9');
  ok(source.includes("EXPECTED_WORKER_VERSION = '15'"), 'Worker generation must be v15');
});

test('stale production candidate / Worker-v14 expectations cannot return', () => {
  ok(!source.includes('8d5b82b8cfaf9d2264d0220d49e598e7ce705eec'), 'old production candidate must not be authoritative');
  ok(!source.includes("srcWorkerVer === '14'"), 'Worker v14 must not be treated as current');
  ok(!source.includes('expected 14'), 'no current expectation may name Worker v14');
});

test('B5 verifier executes successfully and records fix-forward-only policy', () => {
  const output = execFileSync(process.execPath, [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  ok(/B5 verdict[\s\S]*PASS/.test(output), 'verifier must finish with PASS');
  ok(output.includes('Safe rollback target: NONE PROVEN.'), 'must not manufacture a safe rollback SHA');
  ok(output.includes('Approved recovery action: FIX FORWARD.'), 'fix-forward must be the approved recovery action');
  ok(output.includes('v24.0.8 demonstrably lacks the pickup-feasibility gate'), 'unsafe immediate predecessor must be proven, not merely asserted');
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
