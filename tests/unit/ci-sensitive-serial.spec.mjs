// CI stability contract: sensitive browser lifecycle specs are serialized once,
// after the bounded parallel pool. This changes scheduling only — never assertions,
// timeouts, retries, production code, or whether a failing spec fails the gate.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const runAll = () => readFileSync(path.join(REPO_ROOT, 'tests/run-all.mjs'), 'utf8');

const { test, run } = createSuite('unit/ci-sensitive-serial.spec.mjs');

test('[CISS-01] only the two observed lifecycle-sensitive specs are pulled from the parallel queue', () => {
  const s = runAll();
  const m = s.match(/const SERIAL_SPECS = new Set\(\[([\s\S]*?)\]\);/);
  ok(m, 'SERIAL_SPECS contract must exist');
  const names = [...m[1].matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*,/g)].map(x => x[1]).sort();
  eq(JSON.stringify(names), JSON.stringify(['backupRestoreParity','productIASliceD']),
    'serialization must stay narrowly scoped to the two empirically failing lifecycle-sensitive specs');
});

test('[CISS-02] sensitive specs execute after the parallel pool and still run exactly once', () => {
  const s = runAll();
  ok(s.includes('const serialJobs = allJobs.filter(job => SERIAL_SPECS.has(job.fn));'),
    'serial jobs must be selected explicitly');
  ok(s.includes('const queue = allJobs.filter(job => !SERIAL_SPECS.has(job.fn));'),
    'serial jobs must be excluded from the parallel queue');
  const pool = s.indexOf('await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));');
  const serial = s.indexOf('for (const job of serialJobs) await runJob(job);');
  ok(pool >= 0 && serial > pool, 'serial jobs must execute only after the parallel pool drains');
});

test('[CISS-03] the stabilization is not a retry, skip, quarantine, or timeout weakening', () => {
  const s = runAll();
  const start = s.indexOf('const SERIAL_SPECS = new Set([');
  const end = s.indexOf('console.log = realLog;', start);
  ok(start >= 0 && end > start, 'scheduler region must be locatable');
  const region = s.slice(start, end);
  ok(!/while\s*\([^)]*fail/i.test(region), 'failed specs must never be looped/retried');
  ok(!/filter\s*\([^)]*fail/i.test(region), 'failed specs must never be filtered out of the result');
  ok(!/timeout\s*=|setTimeout\s*\(/i.test(region), 'scheduler stabilization must not change test timeouts');
  ok(region.includes('results[job.i] = r;'), 'serial results must feed the same aggregate result array');
});

export async function runSpec(){ return run(); }
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
