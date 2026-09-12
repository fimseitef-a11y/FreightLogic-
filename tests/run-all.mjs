// Runs every spec file in this suite against a real headless Chromium instance
// of the app (Playwright) and prints an aggregate summary.
//
// Usage:  node tests/run-all.mjs
//         FL_TEST_CONCURRENCY=1 node tests/run-all.mjs    (serial, for debugging)
// (Requires the sibling node_modules/playwright symlink — see tests/README.md)
//
// PARALLEL. This previously awaited 41 specs one at a time, each launching its
// own Chromium process, which took roughly 20 minutes and made the full suite
// something you avoided running — and a suite you avoid running is a suite that
// stops catching things. Specs now execute in separate child processes behind a
// bounded worker pool.
//
// Process isolation is what makes that safe, and it was verified before the
// change rather than assumed:
//
//   * The shared HTTP server in harness.mjs is a per-PROCESS singleton, so
//     parallel specs each get their own and cannot tear down a peer's. Specs
//     only call stopServer() from their own standalone branch, never inside
//     runSpec(), so the runner path never tore it down mid-suite either.
//   * `sw-subresource-semantics` deliberately KILLS its origin mid-test. It
//     already ran a private server for exactly that reason, and now does so in
//     a private process as well.
//   * Every spec already launched its own browser and context, so browser-level
//     isolation was never the constraint — only the shared module registry was,
//     and separate processes remove it.
//
// Output is buffered per spec and printed in DECLARED order, so a parallel run
// reads exactly like a serial one. Execution order is not guaranteed; printed
// order is.
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const RUN_ONE = path.join(__dirname, 'lib', 'run-one.mjs');

// Declared order. This is the printed order regardless of completion order.
const SPECS = [
  'tests/unit/pure-functions.spec.mjs',
  'tests/unit/service-worker-shell.spec.mjs',
  'tests/unit/release-hygiene.spec.mjs',
  'tests/unit/cache-generation.spec.mjs',
  'tests/integration/sw-subresource-semantics.spec.mjs',
  'tests/integration/v2404-fail-closed.spec.mjs',
  'tests/unit/lane-guard.spec.mjs',
  'tests/integration/dz-exit-grade-cap.spec.mjs',
  'tests/integration/tax-export-csv-corruption.spec.mjs',
  'tests/integration/pin-lockout.spec.mjs',
  'tests/integration/fl-tests-exposure.spec.mjs',
  'tests/integration/toctou-concurrent-edit.spec.mjs',
  'tests/integration/field-resilience.spec.mjs',
  'tests/integration/insurance-migration.spec.mjs',
  'tests/integration/export-checksum-integrity.spec.mjs',
  'tests/integration/backup-restore-parity.spec.mjs',
  'tests/integration/dz-gate-parity.spec.mjs',
  'tests/integration/xlsx-bundled-vendor.spec.mjs',
  'tests/integration/van-fit-precheck.spec.mjs',
  'tests/integration/pickup-feasibility.spec.mjs',
  'tests/integration/m1-doctrine-integrity.spec.mjs',
  'tests/integration/m2-expense-fuel-concurrency.spec.mjs',
  'tests/integration/m3-confidence-evidence.spec.mjs',
  'tests/integration/m4-load-lifecycle.spec.mjs',
  'tests/integration/m5-opportunity-ingestion.spec.mjs',
  'tests/integration/m6-historical-import.spec.mjs',
  // Issue #119 Batch A — release-integrity hotfix regressions
  'tests/integration/batch-a-release-integrity.spec.mjs',
  'tests/integration/m3-real-evidence-wiring.spec.mjs',
  'tests/integration/batch-b-m6-reconciliation.spec.mjs',
  // v24.0.2 exact-candidate blockers 1-8
  'tests/integration/blockers-exact-candidate.spec.mjs',
  'tests/unit/worker-canonical-absence.spec.mjs',
  'tests/unit/m7-runner-semantics.spec.mjs',
  'tests/unit/live-authority-runner.spec.mjs',
  'tests/integration/sw-update-handshake.spec.mjs',
  'tests/integration/diagnostics-install-identity.spec.mjs',
  'tests/integration/merge-restore-concurrency.spec.mjs',
  'tests/integration/same-millisecond-concurrency.spec.mjs',
  'tests/unit/pre-v24-integrity.spec.mjs',
  'tests/unit/v24-unified-decision.spec.mjs',
  'tests/integration/v24-authority-boundaries.spec.mjs',
  'tests/integration/v24-economics-bid.spec.mjs',
];

// Each child drives a real browser, so this is bounded by cores, not by I/O.
const CONCURRENCY = Math.max(1, Number(process.env.FL_TEST_CONCURRENCY) || Math.min(4, os.cpus().length));

// Longest-first scheduling. With a bounded pool the total time cannot beat the
// slowest single spec, so the slow ones must START first or the pool finishes
// its short work and then sits waiting on a straggler it began late.
//
// `field-resilience` dominates at ~290s and that is INHERENT, not waste: its
// F-7 assertions exercise real GeolocationPositionError streaks, and
// watchPosition only re-fires its error callback on the production 15s timeout.
// Waiting is the thing under test. Measured with the "Slowest specs" readout
// below — refresh this list from it if the balance shifts, or drop a spec from
// it once it is genuinely fast; being wrong here costs ordering, never
// correctness.
const SLOW_FIRST = new Set([
  'tests/integration/field-resilience.spec.mjs',
  'tests/integration/toctou-concurrent-edit.spec.mjs',
  'tests/integration/diagnostics-install-identity.spec.mjs',
  'tests/integration/pin-lockout.spec.mjs',
  'tests/integration/same-millisecond-concurrency.spec.mjs',
]);

// Indices into SPECS, ordered for EXECUTION. Printing stays in declared order.
const SCHEDULE = [
  ...SPECS.map((f, i) => [f, i]).filter(([f]) => SLOW_FIRST.has(f)).map(([, i]) => i),
  ...SPECS.map((f, i) => [f, i]).filter(([f]) => !SLOW_FIRST.has(f)).map(([, i]) => i),
];

const SUMMARY_RE = /--\s+(.+?):\s+(\d+)\s+passed,\s+(\d+)\s+failed\s+--/;
const ANSI_RE = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');
const stripAnsi = (s) => s.replace(ANSI_RE, '');

function runSpecFile(file) {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [RUN_ONE, file], {
      cwd: REPO_ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });

    child.on('error', (err) => {
      resolve({
        file, pass: 0, fail: 1, ms: Date.now() - started, output: out,
        failures: [{ name: '(child process could not start)', error: String(err) }],
      });
    });

    child.on('close', (code) => {
      const ms = Date.now() - started;
      const plain = stripAnsi(out);
      const m = plain.match(SUMMARY_RE);

      // No summary line means the spec never reported. That is a FAILURE, never
      // a silent skip — the X-06 rule: a suite that did not run is not a pass.
      if (!m) {
        resolve({
          file, pass: 0, fail: 1, ms, output: out,
          failures: [{ name: '(spec did not report a result)', error: `child exited ${code}` }],
        });
        return;
      }

      const pass = Number(m[2]);
      const reported = Number(m[3]);
      const failures = [...plain.matchAll(/^\s+✗\s+(.+?)\s*$/gm)].map((x) => ({ name: x[1], error: '' }));

      // Trust the exit code over a green summary: a child that died after
      // printing its line must never read as passing.
      const fail = (code !== 0 && reported === 0) ? 1 : reported;
      resolve({
        file: m[1], pass, fail, ms, output: out,
        failures: fail > reported
          ? [...failures, { name: '(child exited non-zero despite reporting no failures)', error: `exit ${code}` }]
          : failures,
      });
    });
  });
}

const started = Date.now();
const results = new Array(SPECS.length);
let next = 0;

async function worker() {
  for (;;) {
    const slot = next++;
    if (slot >= SCHEDULE.length) return;
    const i = SCHEDULE[slot];           // execution order
    results[i] = await runSpecFile(SPECS[i]); // stored by declared index
  }
}

await Promise.all(Array.from({ length: Math.min(CONCURRENCY, SPECS.length) }, worker));

// Print in declared order so a parallel run reads like a serial one.
for (const r of results) process.stdout.write(r.output.replace(/\n?$/, '\n'));

const totalPass = results.reduce((s, r) => s + r.pass, 0);
const totalFail = results.reduce((s, r) => s + r.fail, 0);
const wallSec = ((Date.now() - started) / 1000).toFixed(1);

console.log('\n' + '='.repeat(60));
console.log(`TOTAL: ${totalPass} passed, ${totalFail} failed across ${results.length} spec files`);
console.log(`       ${wallSec}s wall clock at concurrency ${CONCURRENCY}`);
console.log('='.repeat(60));

// Slowest specs, so suite time is a visible number rather than folklore.
const slowest = [...results].sort((a, b) => b.ms - a.ms).slice(0, 5);
console.log('\nSlowest specs:');
for (const r of slowest) console.log(`  ${(r.ms / 1000).toFixed(1)}s  ${r.file}`);

const failing = results.flatMap((r) => r.failures.map((f) => `${r.file} :: ${f.name}`));
if (failing.length) {
  console.log('\nFailing:');
  for (const f of failing) console.log('  - ' + f);
}

// X-06 (v23.9 Phase 2): every finding this suite covers is FIXED, so there is no
// longer a legitimate reason for a spec here to fail and the aggregate exit code
// is a real signal CI can gate on.
process.exit(totalFail ? 1 : 0);
