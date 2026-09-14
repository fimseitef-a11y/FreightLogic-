// B5 rollback/fix-forward verifier regression coverage.
// Prevents the certification tool itself from silently drifting back to an old
// release candidate or Worker generation.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/rollback-verifier.spec.mjs');

const SCRIPT = read('scripts/verify-rollback.mjs');
const PARITY = read('scripts/verify-cloudflare-parity.mjs');
const WORKER = read('cloud-backup-worker.js');

function parityWorkerVersion() {
  return PARITY.match(/workerVersion:\s*"(\d+)"/)?.[1] || null;
}
function healthWorkerVersion() {
  return WORKER.match(/path === '\/health'[\s\S]{0,400}?version:\s*'(\d+)'/)?.[1] || null;
}

test('[RB-01] candidate is derived from first-parent release history or explicitly overridden', () => {
  ok(/--first-parent/.test(SCRIPT),
    'default candidate must derive from first-parent main history, not a topic-branch implementation SHA');
  ok(/--candidate/.test(SCRIPT) && /FL_RELEASE_SHA/.test(SCRIPT),
    'operator/CI must be able to pin an exact candidate without editing source');
  ok(!/8d5b82b8cfaf9d2264d0220d49e598e7ce705eec/.test(SCRIPT),
    'the stale pre-v24.0.9 production-candidate literal must never return');
});

test('[RB-02] Worker generation comes from the live-parity contract, not a second literal', () => {
  const expected = parityWorkerVersion();
  const health = healthWorkerVersion();
  ok(expected, 'live parity verifier must declare a Worker generation');
  eq(health, expected, 'Worker /health source must match the live-parity generation');
  ok(/expectedWorkerVersion/.test(SCRIPT) && /verify-cloudflare-parity\.mjs/.test(SCRIPT),
    'rollback verifier must derive Worker generation from the parity verifier');
  ok(!/expected 14/.test(SCRIPT) && !/source is v14/.test(SCRIPT),
    'stale Worker-v14 assertions must not recur');
});

test('[RB-03] frozen runtime drift is checked explicitly', () => {
  ok(/runtimeDrift/.test(SCRIPT), 'verifier must compare the frozen candidate to HEAD');
  for (const rel of ['app.js', 'service-worker.js', 'manifest.json', 'sw-bridge.js', 'modern-shell.js', 'cloud-backup-worker.js']) {
    ok(SCRIPT.includes(`'${rel}'`), `runtime drift set must include ${rel}`);
  }
});

test('[RB-04] known-regression builds are classified unsafe, never approved', () => {
  ok(/UNSAFE_APP_TARGETS/.test(SCRIPT), 'known prior app targets must be classified explicitly');
  ok(/NO SAFE WORKER ROLLBACK TARGET IS APPROVED/.test(SCRIPT),
    'the v7 Worker must never be described as a normal rollback target');
  ok(/Approved rollback SHA:\s+NONE/.test(SCRIPT),
    'successful B5 output must state that no regression-safe rollback SHA is approved');
  ok(/Approved recovery policy:\s+FIX FORWARD/.test(SCRIPT),
    'fix-forward must be the explicit approved policy');
});

test('[RB-05] fix-forward executability is proved from real repository paths', () => {
  for (const rel of [
    '.github/workflows/tests.yml',
    '.github/workflows/verify-live-parity.yml',
    '.github/workflows/deploy-backup-worker.yml',
    'scripts/deploy-backup-worker.sh',
    'scripts/verify-live-authority.mjs',
    'scripts/verify-live-backup.mjs',
    'wrangler.jsonc',
    'scripts/wrangler.backup-worker.jsonc',
  ]) {
    ok(SCRIPT.includes(`'${rel}'`), `B5 executability check must include ${rel}`);
  }
});

export async function runSpec() { return await run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
