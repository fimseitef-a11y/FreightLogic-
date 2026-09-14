// B5 rollback/fix-forward evidence generator — contract regression.
//
// The earlier version of this spec pinned the verifier to one release
// (`5446b09…` / `24.0.9` / Worker `16`), which meant the verifier AND this spec
// both needed a hand edit every release, and the gate reported PASS while
// describing a superseded candidate whenever that edit was missed. The verifier
// now DERIVES the candidate, the previous generation and the Worker generation
// from the tree and from git history, so this spec asserts the derivation
// instead of a snapshot — it stays correct at the next release with no edit.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/rollback-verifier-current.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPT = path.join(ROOT, 'scripts/verify-rollback.mjs');
const source = readFileSync(SCRIPT, 'utf8');

const appVersion = readFileSync(path.join(ROOT, 'app.js'), 'utf8')
  .match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];
const workerGeneration = readFileSync(path.join(ROOT, 'cloud-backup-worker.js'), 'utf8')
  .match(/Cloud Backup Worker v(\d+)/)?.[1];

const output = execFileSync(process.execPath, [SCRIPT], {
  cwd: ROOT,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
});

test('[RBV-01] no release identity is pinned into the verifier', () => {
  // Code only — the header comment explains the defect and may name it.
  const code = source.split('\n').filter((l) => !/^\s*\*|^\s*\/\*|^\s*\/\//.test(l)).join('\n');
  ok(!/\b[0-9a-f]{40}\b/.test(code), 'no 40-hex candidate SHA may be hardcoded');
  ok(!/EXPECTED_APP_VERSION\s*=\s*'/.test(code), 'the app generation must be derived, not assigned a literal');
  ok(!/EXPECTED_WORKER_VERSION\s*=\s*'/.test(code), 'the Worker generation must be derived, not assigned a literal');
  ok(!/PREVIOUS_APP_(CANDIDATE|VERSION)\s*=\s*'/.test(code), 'the previous generation must be derived from history');
});

test('[RBV-02] the verifier reports the tree it was actually run against', () => {
  ok(appVersion, 'app.js must declare APP_VERSION');
  ok(workerGeneration, 'cloud-backup-worker.js must declare its generation');
  ok(output.includes(`app generation:    v${appVersion}`), `must report the current app generation v${appVersion}`);
  ok(output.includes(`Worker generation: v${workerGeneration}`), `must report the current Worker generation v${workerGeneration}`);
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  ok(output.includes(head), 'must name the exact HEAD it verified');
});

test('[RBV-03] the previous generation is identified and is a real ancestor', () => {
  ok(/previous generation derived from history: [0-9a-f]{12} \(v[\d.]+\)/.test(output),
    'the previous generation must be derived and named');
  ok(/is a true ancestor of v/.test(output), 'the previous generation must be proven an ancestor');
  const previous = output.match(/previous generation derived from history: [0-9a-f]{12} \(v([\d.]+)\)/)?.[1];
  ok(previous && previous !== appVersion, 'the previous generation must differ from the current one');
});

test('[RBV-04] every named safety gate is present in the candidate', () => {
  for (const ident of ['checkPickupFeasibility', 'checkVanFit', 'isDeadZoneEligible', 'knownNum']) {
    ok(output.includes(`candidate contains ${ident}`), `${ident} must be proven present in the candidate`);
  }
});

test('[RBV-05] the verifier can never manufacture a safe rollback target', () => {
  ok(/B5 verdict[\s\S]*PASS/.test(output), 'verifier must finish with PASS on a healthy tree');
  ok(output.includes('Safe rollback target: NONE PROVEN.'), 'must not manufacture a safe rollback SHA');
  ok(output.includes('Approved recovery action: FIX FORWARD.'), 'fix-forward must be the approved recovery action');
  ok(output.includes('no older app SHA is approved as a safe rollback target'),
    'the policy note must survive regardless of what the safety-gate comparison found');
  const verdict = output.split('== B5 verdict ==')[1] || '';
  const targetLines = verdict.split('\n').filter((l) => /rollback target:/i.test(l));
  ok(targetLines.length === 1 && targetLines[0].trim() === 'Safe rollback target: NONE PROVEN.',
    `the verdict may name no rollback target but NONE PROVEN (saw: ${JSON.stringify(targetLines)})`);
});

test('[RBV-06] the Worker generation is one number, agreed by source and parity gate', () => {
  ok(output.includes(`repository Worker source is v${workerGeneration}`), 'Worker source generation must be reported');
  ok(output.includes(`live-parity verifier expects the same Worker generation (v${workerGeneration})`),
    'the parity verifier must be aligned to the repository Worker source');
  ok(output.includes('manual Worker fix-forward workflow is present'), 'an executable fix-forward path must exist');
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
