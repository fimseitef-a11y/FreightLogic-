// Production service-worker / offline gate — shape and safety contract.
//
// The gate itself needs a live origin and a real browser, so this spec does not
// re-run it. What it pins is the part that must never regress silently: the
// workflow's authority (read-only, no secrets, no deploy), the three-verdict
// semantics, and the specific assertions that exist because a real defect got
// past a green check before.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/production-sw-gate.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(path.join(ROOT, p), 'utf8');

const wf = read('.github/workflows/verify-production-sw.yml');
const gate = read('scripts/verify-production-sw.mjs');

test('[PSW-01] the workflow is read-only and holds no deploy authority', () => {
  ok(/permissions:\s*\n\s*contents:\s*read/.test(wf), 'permissions must be contents: read');
  ok(!/contents:\s*write/.test(wf), 'the workflow may never request write access');
  // Match an actual expression, not the word in a comment explaining its absence.
  ok(!/\$\{\{\s*secrets\./.test(wf), 'the workflow must use no secrets — it verifies only unauthenticated surface');
  // Assert the real property rather than scrubbing prose: no deploy tooling, and
  // no executable line that deploys. Comments may (and should) say it never does.
  ok(!/wrangler/i.test(wf), 'a verification workflow must not invoke wrangler');
  const runLines = wf.split('\n').filter((l) => !/^\s*#/.test(l));
  ok(!runLines.some((l) => /\bdeploy\b/i.test(l) && !/::error::|echo |description:/.test(l)),
    'no executable line in a verification workflow may deploy');
});

test('[PSW-02] a dispatch input can never reach the shell as code', () => {
  // The origin arrives through the environment and is expanded as a quoted argv
  // element. Interpolating ${{ }} straight into a run: block would let a
  // dispatcher inject shell.
  ok(/APP_ORIGIN:\s*\$\{\{\s*github\.event\.inputs\.app_origin\s*\}\}/.test(wf),
    'the input must be bound to an env var, not interpolated into the command');
  ok(/node scripts\/verify-production-sw\.mjs \$\{APP_ORIGIN:\+"\$APP_ORIGIN"\}/.test(wf),
    'the origin must be passed as a quoted argv element');
});

test('[PSW-03] the gate runs the real verifier and honours all three verdicts', () => {
  ok(/node scripts\/verify-production-sw\.mjs/.test(wf), 'the workflow must execute the real gate');
  for (const verdict of ['PASS', 'UNOBSERVED', 'FAILURE']) {
    ok(wf.includes(verdict), `the workflow must distinguish ${verdict}`);
  }
  ok(/steps\.gate\.outputs\.verdict != 'PASS'/.test(wf),
    'anything other than PASS must fail the job — an unobserved gate is not a passed gate');
});

test('[PSW-04] the gate reports UNOBSERVED rather than inventing a verdict', () => {
  ok(/VERDICT: UNOBSERVED/.test(gate), 'UNOBSERVED must be a real outcome');
  ok(/return 2;/.test(gate), 'UNOBSERVED must exit 2 — non-zero, so callers still fail closed');
  ok(/if \(failures\)[\s\S]{0,200}VERDICT: FAILURE/.test(gate),
    'a real failure must outrank unobservability');
});

test('[PSW-05] the 2026-09-13 injected-asset defect is specifically covered', () => {
  // The injected overlay is reachable ONLY through the tag the service worker
  // injects, so no markup-based check could ever see it 404. The gate must
  // assert both that the tag is injected and that the file actually loads.
  // #231 Phase C deleted admin-driver-ui.js; the gate must now FAIL if the
  // worker still injects it.
  ok(gate.includes('midwest-stack-authority.js'), 'the injected overlay asset must be named');
  ok(/admin-driver-ui\.js is still injected[\s\S]{0,120}\(#231\)/.test(gate),
    'a worker still injecting the deleted admin module must fail the gate (#231 Phase C)');
  ok(/injected AND fetchable/.test(gate), 'a present tag pointing at a 404 is the defect — fetchability must be asserted');
  ok(/missing from the precache/.test(gate), 'a declared asset absent from the precache must fail');
});

test('[PSW-06] the v24.0.4 HTML-masquerade defect is specifically covered', () => {
  ok(/answered with HTML/.test(gate), 'an HTML body for a subresource request must fail');
  ok(/never existed was answered with the app shell/.test(gate),
    'the effectiveness probe must itself catch a worker that answers any miss with the shell');
  ok(/self-heals/.test(gate), 'a drifted ?v= on a known asset must self-heal rather than poison the response');
});

test('[PSW-07] the gate is non-destructive and says what it did not observe', () => {
  ok(!/caches\.delete|unregister\(\)|clearSiteData/.test(gate),
    'the gate must never clear caches or unregister a worker');
  ok(/NOT observed here: the offline navigation itself/.test(gate),
    'the one thing this gate cannot observe must be stated, not implied');
  ok(/FIELD_TEST_CHECKLIST/.test(gate), 'it must point at where that evidence does come from');
});

test('[PSW-08] the provenance step fails closed instead of recording nothing', () => {
  // The first production run recorded `app:` with nothing after it: escaped
  // double quotes inside the run: block were eaten by the shell, grep read `=`
  // as a filename, and the step still exited 0. A step whose only job is naming
  // WHICH candidate the evidence belongs to must never succeed having named none.
  const step = wf.slice(wf.indexOf('Record the exact source being verified'), wf.indexOf('Run the production service-worker gate'));
  ok(!/\\"/.test(step), 'no escaped double quotes — that is what broke it the first time');
  ok(/if \[ -z "\$app" \] \|\| \[ -z "\$sw" \]; then/.test(step),
    'the step must check that it actually read both versions');
  ok(/exit 1/.test(step), 'an unidentified candidate must fail the job, not be recorded as blank');
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await runSpec();
  process.exit(result.fail ? 1 : 0);
}
