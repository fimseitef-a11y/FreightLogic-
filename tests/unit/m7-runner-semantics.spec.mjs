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
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('unit/m7-runner-semantics.spec.mjs');

function runCertify(args = []){
  try {
    return { code: 0, out: execFileSync('node', ['scripts/m7-certify.mjs', ...args], { cwd: ROOT, encoding: 'utf8' }) };
  } catch (e) {
    return { code: e.status ?? 1, out: String(e.stdout || '') + String(e.stderr || '') };
  }
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

export async function runSpec(){ return await run(); }
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
