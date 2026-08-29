// Issue #119 Batch A / A7 — M7 certification-runner semantics.
//
// The merged runner could print "AUTOMATED CERTIFICATION PASSED. Freeze the
// release after the operator gates pass." on a fast run that had SKIPPED the
// entire Playwright suite, while the canonical certification state was HOLD
// with uncovered source defects. A skipped gate was being scored as a pass, and
// a preflight was calling itself a certification.
//
// These tests EXECUTE the runner rather than grepping it, so they test the
// behaviour the operator actually sees.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('unit/m7-runner-semantics.spec.mjs');

// The certifier shells out to scripts/verify-cloudflare-parity.mjs, whose live
// half reaches the deployed Pages/Worker origins. Invoking the certifier once
// per test meant up to five rounds of that on every CI run — enough to stall
// the whole suite on a runner whose network reaches those origins slowly. It is
// run ONCE and the output shared; every assertion below is about that one run.
let _cached = null;
function runCertifyFresh(args = []){
  try {
    return { code: 0, out: execFileSync('node', ['scripts/m7-certify.mjs', ...args], { cwd: ROOT, encoding: 'utf8', timeout: 180000 }) };
  } catch (e) {
    return { code: e.status ?? 1, out: String(e.stdout || '') + String(e.stderr || '') };
  }
}
function runCertify(args = []){
  if (args.length === 0 && _cached) return _cached;
  let result;
  try {
    result = { code: 0, out: execFileSync('node', ['scripts/m7-certify.mjs', ...args], { cwd: ROOT, encoding: 'utf8', timeout: 180000 }) };
  } catch (e) {
    result = { code: e.status ?? 1, out: String(e.stdout || '') + String(e.stderr || '') };
  }
  if (args.length === 0) _cached = result;
  return result;
}

// The canonical state this repo is actually in right now. Read from docs so the
// expectation tracks the real governance document, not a hardcoded guess.
function canonicalIsHeld(){
  const dir = path.join(ROOT, 'docs');
  return readdirSync(dir)
    .filter(f => /^COMPLETION_RELEASE_CERTIFICATION_(STATE|ADDENDUM)_\d{4}-\d{2}-\d{2}\.md$/.test(f))
    .some(f => /HOLD|NOT\s+CERTIFIED|BLOCKED/i.test(
      (readFileSync(path.join(dir, f), 'utf8').match(/^Status:\s*(.+)$/m) || [,''])[1]));
}

test('[M7-01] the default run is a preflight and never calls itself a certification', () => {
  const { out } = runCertify();
  ok(/RELEASE PREFLIGHT/.test(out), 'the default run must be labelled a release preflight');
  ok(!/CERTIFICATION PASSED/.test(out), 'a preflight must never announce that certification passed');
  ok(!/Freeze the release after the operator gates/.test(out),
     'a run that skipped the suite must never tell the operator to freeze');
});

test('[M7-02] a skipped suite is reported SKIP, not counted as a pass', () => {
  const { out } = runCertify();
  ok(/SKIP\s+full Playwright suite/.test(out), 'the un-run suite must be reported as SKIP');
  ok(/NOT RUN/.test(out), 'and explicitly described as not run');
  const m = out.match(/AUTOMATED GATES: (\d+) passed, (\d+) failed, (\d+) not run/);
  ok(!!m, 'the summary must report passed / failed / not-run separately');
  eq(Number(m[3]), 1, 'exactly the suite gate is counted as not run');
});

test('[M7-03] while the canonical state is HOLD the runner reports NOT CERTIFIABLE', () => {
  if (!canonicalIsHeld()){
    // If the release state is genuinely cleared, the correct assertion flips —
    // the runner must then NOT claim a hold that no document declares.
    const { out } = runCertify();
    ok(!/canonical release state is HOLD/.test(out), 'no hold may be reported once no document declares one');
    return;
  }
  const { out } = runCertify();
  ok(/NOT CERTIFIABLE/.test(out), 'a held release cannot be certified by any set of green automated gates');
  ok(/canonical release state is HOLD/.test(out), 'and the runner must name the hold as the blocker');
  ok(/Do not freeze/.test(out), 'and must say so plainly');
});

test('[M7-04] the four gate classes stay visibly separate', () => {
  const { out } = runCertify();
  ok(/AUTOMATED GATES:/.test(out), 'automated preflight gates are their own class');
  ok(/full Playwright suite/.test(out), 'the full suite is its own gate, not folded into the preflight');
  ok(/LIVE DEPLOYMENT GATES/.test(out), 'live Cloudflare checks are their own class');
  ok(/PHYSICAL DEVICE GATES/.test(out), 'physical iPhone checks are their own class');
});

test('[M7-05] a clean preflight on a held release still exits 0, and the verdict carries the meaning', () => {
  const { code, out } = runCertify();
  // Exit status reports GATE FAILURE. Conflating "this release is not
  // certifiable" with "this script failed" would make every preflight on a
  // correctly-held release look like a broken tool.
  const failed = Number((out.match(/AUTOMATED GATES: \d+ passed, (\d+) failed/) || [,'0'])[1]);
  eq(code, failed ? 1 : 0, 'the exit code tracks failed gates, not the certification verdict');
});

/* ── blocker 5: a historical HOLD is immutable evidence, not a permanent state ── */

test('[M7-06] a later authoritative state supersedes a historical HOLD without rewriting history', () => {
  const dir = path.join(ROOT, 'docs');
  const held = readdirSync(dir).filter(f =>
    /^COMPLETION_RELEASE_CERTIFICATION_(STATE|ADDENDUM)_\d{4}-\d{2}-\d{2}\.md$/.test(f));

  // Today's real state must block. This is not a hypothetical: the repository
  // is on HOLD right now and the runner has to say so.
  ok(/NOT CERTIFIABLE/.test(runCertify().out), 'the real current HOLD blocks certification');

  // Now add a synthetic LATER document that explicitly supersedes every
  // currently-held one. Nothing on disk is edited — the historical files stay
  // exactly as they are, as evidence.
  const synthetic = path.join(dir, 'COMPLETION_RELEASE_CERTIFICATION_STATE_2099-01-01.md');
  const before = held.map(f => readFileSync(path.join(dir, f), 'utf8'));
  writeFileSync(synthetic, [
    '# Synthetic certification state (test fixture)',
    '',
    'Date: 2099-01-01',
    `Supersedes: ${held.join(', ')}`,
    'Status: **CERTIFIED — completion release approved**',
    '',
  ].join('\n'));
  let out;
  try { out = runCertifyFresh().out; }
  finally { unlinkSync(synthetic); }

  ok(!/canonical release state is HOLD/.test(out),
     'an explicitly superseding authoritative state clears the historical hold');
  ok(/CERTIFIED/.test(out), 'and the runner reports the current state, not an archived one');

  // The historical evidence is untouched.
  held.forEach((f, i) => {
    eq(readFileSync(path.join(dir, f), 'utf8'), before[i],
       `${f} must not be edited to clear a hold — history stays immutable`);
  });
  // And the real state blocks again the moment the fixture is gone.
  ok(/NOT CERTIFIABLE/.test(runCertifyFresh().out), 'removing the superseding state restores the hold');
});

test('[M7-07] a superseding document that itself declares a hold still holds', () => {
  const dir = path.join(ROOT, 'docs');
  const held = readdirSync(dir).filter(f =>
    /^COMPLETION_RELEASE_CERTIFICATION_(STATE|ADDENDUM)_\d{4}-\d{2}-\d{2}\.md$/.test(f));
  const synthetic = path.join(dir, 'COMPLETION_RELEASE_CERTIFICATION_STATE_2099-01-02.md');
  writeFileSync(synthetic, [
    '# Synthetic certification state (test fixture)', '', 'Date: 2099-01-02',
    `Supersedes: ${held.join(', ')}`,
    'Status: **HOLD — blockers remain**', '',
  ].join('\n'));
  let out;
  try { out = runCertifyFresh().out; } finally { unlinkSync(synthetic); }
  ok(/NOT CERTIFIABLE/.test(out), 'supersession is not a way to clear a hold — only a CLEAR state clears it');
});

test('[M7-08] a state document with no parseable Status fails closed', () => {
  const dir = path.join(ROOT, 'docs');
  const synthetic = path.join(dir, 'COMPLETION_RELEASE_CERTIFICATION_STATE_2099-01-03.md');
  writeFileSync(synthetic, '# Synthetic fixture with no Status line\n\nDate: 2099-01-03\n');
  let out;
  try { out = runCertifyFresh().out; } finally { unlinkSync(synthetic); }
  ok(/NOT CERTIFIABLE/.test(out), 'an unparseable state document must never read as permission to proceed');
});

export async function runSpec(){ return await run(); }
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
