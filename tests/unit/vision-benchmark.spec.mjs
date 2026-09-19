// Vision provider benchmark (Issue #252's measurement half) — scoring rules and
// the runner's refusals. Static, in-process, and network-free: the one
// subprocess case talks to a server on 127.0.0.1 that this file starts.
//
// WHY A BENCHMARK NEEDS A REGRESSION AT ALL. This script's output is what picks
// the default vision provider, and a scoring bug does not announce itself — it
// prints a confident percentage either way. Two specific ways it could lie:
//
//   1. By flattering. If correctly-left-absent fields counted toward accuracy, a
//      provider that read nothing would score well on a sparse corpus, and if
//      place comparison were fuzzy, "Chicago" would pass for "Chicago Heights".
//      VB-05 and VB-04 pin both.
//   2. By averaging away the one error that matters. An unstated deadhead
//      arriving as 0 is not an inaccuracy — it is a VERIFIED ZERO the operator
//      never supplied, reaching canonical economics as fact. It is the defect
//      class v24.0.1/.4/.5/.21 each closed one layer at a time, and VB-02 keeps
//      it as its own counter that no accuracy figure can absorb.
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFile } from 'node:child_process';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';
import {
  SCORED_FIELDS, CRITICAL_FIELDS, classifyField, scoreCase, accuracy,
  silentCriticalErrorRate, summarizeProvider, stability, truthIsUsable, workerFieldKeys,
} from '../../scripts/lib/vision-bench.mjs';

const { test, run } = createSuite('unit/vision-benchmark.spec.mjs');
const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const RUNNER = 'scripts/benchmark-vision-providers.mjs';

const TINY_JPEG = Buffer.from(
  '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a' +
  'HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA' +
  'AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==', 'base64');

const truth = (fields) => {
  const f = Object.fromEntries(SCORED_FIELDS.map(k => [k, null]));
  return { ...f, ...fields };
};
const meta = (states) => Object.fromEntries(SCORED_FIELDS.map(k => [k, { state: states[k] || 'ABSENT', confidence: null }]));

// ─────────────────────────────────────────────────────────────────────────────

test('[VB-01] the scored field list is checked against the Worker, not asserted', () => {
  // The benchmark claims to mirror VISION_FIELD_SPEC. A stale copy would measure
  // a contract the endpoint no longer has, and it would keep printing a
  // percentage while doing it — the failure this whole suite exists to catch.
  const wk = workerFieldKeys(read('cloud-backup-worker.js'));
  eq(wk.length, SCORED_FIELDS.length, 'field count must match the Worker contract');
  for (const k of wk) ok(SCORED_FIELDS.includes(k), `Worker field "${k}" is not scored by the benchmark`);
  for (const k of SCORED_FIELDS) ok(wk.includes(k), `benchmark scores "${k}", which the Worker does not extract`);

  // And the runner must actually perform that comparison at run time, not rely
  // on this test having been run at some point — the DAC-04/DAC-08 convention,
  // with comment lines stripped so a call inside a `//` cannot satisfy it.
  const runnerExec = read(RUNNER).split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  ok(/workerFieldKeys\(/.test(runnerExec), 'the runner must read the Worker field list at run time');
  ok(/SCORED_FIELDS has drifted/.test(read(RUNNER)), 'the runner must fail on drift rather than score a stale contract');
});

test('[VB-02] an unstated deadhead read as 0 is FABRICATED and separately counted', () => {
  const invented = classifyField('deadheadMiles', null, 0, 'OBSERVED');
  eq(invented.outcome, 'fabricated', 'null ground truth + a returned 0 is a fabricated value, not a miss');
  ok(invented.fabricatedZeroDeadhead === true, 'a fabricated deadhead zero must carry its own flag');
  ok(invented.silent === true, 'an OBSERVED fabrication reaches the evaluator unflagged');

  // Every neighbouring case must NOT trip it, or the counter is noise.
  ok(classifyField('deadheadMiles', 0, 0, 'OBSERVED').outcome === 'correct',
    'a STATED zero read as zero is correct — a verified zero is a real fact');
  ok(!classifyField('deadheadMiles', 0, 0, 'OBSERVED').fabricatedZeroDeadhead,
    'a stated zero read as zero is not a fabrication');
  ok(!classifyField('deadheadMiles', null, null, 'ABSENT').fabricatedZeroDeadhead,
    'correctly leaving an unstated deadhead absent is not a fabrication');
  ok(!classifyField('loadedMiles', null, 0, 'OBSERVED').fabricatedZeroDeadhead,
    'the deadhead counter must not fire on another field');
});

test('[VB-03] a wrong value the review step flags is not counted as a silent error', () => {
  const silent = classifyField('pay', 950, 900, 'OBSERVED');
  const flagged = classifyField('pay', 950, 900, 'UNCERTAIN');
  eq(silent.outcome, 'wrong', 'a mismatched value is wrong regardless of state');
  eq(flagged.outcome, 'wrong', 'a mismatched value is wrong regardless of state');
  ok(silent.silent === true, 'an OBSERVED wrong value reaches the driver unchallenged');
  ok(flagged.silent === false,
    'an UNCERTAIN wrong value is surfaced by the review step — a provider honest about shaky reads is the safer default, and that only shows up if these are counted apart');
});

test('[VB-04] place comparison is a token rule, not a fuzzy matcher', () => {
  eq(classifyField('destination', 'Toledo, OH', 'Toledo OH', 'OBSERVED').outcome, 'correct',
    'punctuation is not a difference');
  eq(classifyField('destination', 'Toledo', 'Toledo, OH', 'OBSERVED').outcome, 'near',
    'one extra trailing state token is a qualification of a less specific value, reported as near rather than silently accepted');
  eq(classifyField('destination', 'Chicago', 'Chicago Heights, IL', 'OBSERVED').outcome, 'wrong',
    'a different place is wrong however similar the prefix — the v24.0.2 rule');
  eq(classifyField('destination', 'Chicago, IL', 'Chicago, MO', 'OBSERVED').outcome, 'wrong',
    'the same city name in a different state is a different place');
  eq(classifyField('loadedMiles', 345, 845, 'OBSERVED').outcome, 'wrong',
    'no tolerance band on numbers: OCR-confusable digits are the corpus case #252 names');
});

test('[VB-05] accuracy excludes correctly-absent fields from its denominator', () => {
  // A provider that reads nothing at all must not score well on a sparse corpus.
  const gt = truth({ pay: 1450, loadedMiles: 380 });
  const readNothing = scoreCase(gt, { fields: truth({}), fieldMeta: meta({}) });
  eq(accuracy(readNothing.all), 0, 'reading nothing is 0% accurate, not 88% for the sixteen fields it correctly left alone');
  eq(readNothing.all.absentOk, 16, 'the correctly-absent fields are still counted, just not in the denominator');

  const readBoth = scoreCase(gt, {
    fields: truth({ pay: 1450, loadedMiles: 380 }),
    fieldMeta: meta({ pay: 'OBSERVED', loadedMiles: 'OBSERVED' }),
  });
  eq(accuracy(readBoth.all), 1, 'reading both stated fields is 100%');
});

test('[VB-06] malformed-JSON rate is a share of calls, not of scored cases', () => {
  // Denominated on scored cases, a provider would look BETTER the more often it
  // failed, because every failure removes itself from the denominator.
  const s = summarizeProvider([
    { requestBytes: 10, latencyMs: 5, failure: 'malformedJson' },
    { requestBytes: 10, latencyMs: 5, failure: 'malformedJson' },
    { requestBytes: 10, latencyMs: 5, failure: 'malformedJson' },
    { requestBytes: 10, latencyMs: 5, score: scoreCase(truth({ pay: 100 }), { fields: truth({ pay: 100 }), fieldMeta: meta({ pay: 'OBSERVED' }) }) },
  ]);
  eq(s.calls, 4, 'every attempt is a call');
  eq(s.scoredCases, 1, 'only one produced a scoreable extraction');
  eq(s.malformedJsonRate, 0.75, 'three of four CALLS were unparseable');
  eq(s.failures.malformedJson, 3, 'failure modes are counted separately, not merged into one error rate');
  eq(s.accuracyAll, 1, 'accuracy describes the extractions that happened and does not silently absorb the failures');
});

test('[VB-07] ground truth seeded from a model scores nothing until a human verifies it', () => {
  // --init pre-fills a sidecar from one provider's reading so the operator
  // corrects values instead of typing eighteen fields. That biases truth toward
  // the seeding model, and this gate is the mitigation.
  const seeded = { verified: false, seededBy: 'workers-ai / moondream', fields: truth({ pay: 1 }) };
  ok(!truthIsUsable(seeded).usable, 'an unverified sidecar must not be scored against');
  ok(/workers-ai/.test(truthIsUsable(seeded).why), 'the refusal names which model seeded it, so the bias is visible');
  ok(!truthIsUsable(null).usable, 'a missing sidecar is not ground truth');
  ok(!truthIsUsable({ verified: true }).usable, 'a verified sidecar with no fields is not ground truth');
  ok(truthIsUsable({ verified: true, fields: truth({}) }).usable, 'a verified sidecar with fields is usable');
});

test('[VB-08] critical fields are the ones that reach economics or a blocking gate', () => {
  for (const k of ['pay', 'loadedMiles', 'deadheadMiles', 'origin', 'destination', 'pickupDate', 'pickupTime']) {
    ok(CRITICAL_FIELDS.includes(k), `${k} feeds canonical economics, market classification or the v24.0.9 feasibility gate`);
  }
  for (const k of ['notes', 'commodity', 'dimensions']) {
    ok(!CRITICAL_FIELDS.includes(k), `${k} is observational colour; grading it as critical would dilute the metric that picks a provider`);
  }
  const gt = truth({ pay: 950, notes: 'team required' });
  const s = scoreCase(gt, { fields: truth({ pay: 900, notes: 'solo' }), fieldMeta: meta({ pay: 'OBSERVED', notes: 'OBSERVED' }) });
  eq(s.critical.wrong, 1, 'only the critical mismatch lands in the critical tally');
  eq(s.all.wrong, 2, 'both mismatches land in the overall tally');
  ok(silentCriticalErrorRate(s.critical) > 0, 'an unflagged critical mismatch shows up as a silent critical error');
});

test('[VB-09] stability needs two comparable runs and reads values, not confidences', () => {
  const ext = (pay, conf) => ({ extraction: { fields: truth({ pay }), fieldMeta: { pay: { state: 'OBSERVED', confidence: conf } } } });
  eq(stability([ext(100, 0.9)]), null, 'one run cannot describe stability');
  eq(stability([ext(100, 0.9), ext(100, 0.4)]), 1,
    'a confidence that wobbles while the value holds is a stable extraction — it is the value that reaches the evaluator');
  eq(stability([ext(100, 0.9), ext(200, 0.9)]), 0.5, 'a value that changes between runs is not stable');
  // A failed call has no extraction to compare, so it is excluded from the
  // denominator rather than counted as instability — but excluding it can leave
  // only one comparable run, and one sample is not evidence of stability. It
  // reports UNKNOWN rather than a flattering 100%, the same refusal the
  // live-parity runner makes with UNOBSERVED.
  eq(stability([ext(100, 0.9), { failure: 'providerError' }]), null,
    'one surviving run cannot evidence stability and must not report as perfect');
  eq(stability([ext(100, 0.9), ext(100, 0.9), { failure: 'providerError' }]), 1,
    'with two comparable runs the failed call is excluded from the denominator, not counted against stability');
});

test('[VB-10] the runner refuses to run without an explicit corpus path', async () => {
  // There is deliberately no in-repo default. Real load screenshots carry broker
  // names, rates and lanes, and `wrangler.jsonc` publishes this repository's root
  // as a document origin — an in-repo corpus is the #228 defect with pictures.
  const r = await execNode([RUNNER]);
  eq(r.code, 64, '--corpus is required');
  ok(/--corpus <dir> is required/.test(r.out), 'it must say what is missing');
  const src = read(RUNNER);
  ok(!/corpus\s*[:=]\s*['"`][^'"`]*(?:fixtures|corpus|screenshots)/.test(src.replace(/--corpus <dir>/g, '')),
    'no default corpus path may be baked in');
});

test('[VB-11] a provider that fabricates a deadhead zero fails the run, end to end', async () => {
  // The only subprocess case that runs the whole thing: real runner, real
  // exported Worker fetch handler, real invite/claim credential, real adapter —
  // only the model is a local server on 127.0.0.1, reached through the
  // `deepseek` adapter's configurable base URL, so nothing leaves this machine.
  const dir = mkdtempSync(path.join(os.tmpdir(), 'fl-vision-bench-'));
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({
        fields: { orderNo: '1079999', origin: 'Gary, IN', destination: 'Toledo, OH', pay: 900, loadedMiles: 250, deadheadMiles: 0 },
        confidence: { orderNo: 1, origin: 1, destination: 1, pay: 1, loadedMiles: 1, deadheadMiles: 1 },
      }) } }] }));
    });
  });
  try {
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    writeFileSync(path.join(dir, 'quote.jpg'), TINY_JPEG);
    writeFileSync(path.join(dir, 'quote.expected.json'), JSON.stringify({
      verified: true,
      // The posting does not state a deadhead. null, not 0 — that is the fact
      // under test.
      fields: truth({ orderNo: '1079999', origin: 'Gary, IN', destination: 'Toledo, OH', pay: 900, loadedMiles: 250, deadheadMiles: null }),
    }));
    const outFile = path.join(dir, 'report.json');
    const r = await execNode([RUNNER, '--corpus', dir, '--providers', 'deepseek', '--out', outFile], {
      DEEPSEEK_API_KEY: 'local-stub-not-a-credential',
      DEEPSEEK_BASE_URL: `http://127.0.0.1:${port}`,
      NO_PROXY: '*', no_proxy: '*', HTTPS_PROXY: '', HTTP_PROXY: '', https_proxy: '', http_proxy: '',
    });
    eq(r.code, 1, 'fabricating an unstated deadhead as 0 must fail the run at any accuracy');
    ok(/fabricated an unstated deadhead as 0: deepseek/.test(r.out), 'the failure must name the provider and the reason');

    const report = JSON.parse(readFileSync(outFile, 'utf8'));
    eq(report.summaries.deepseek.fabricatedZeroDeadhead, 1, 'the report records the fabrication');
    // The report is written to disk and shared; a credential must never be in it.
    const flat = JSON.stringify(report);
    for (const secret of ['local-stub-not-a-credential', 'DEEPSEEK_API_KEY', 'Bearer', 'X-Admin-Token']) {
      ok(!flat.includes(secret), `the written report must not contain "${secret}"`);
    }
  } finally {
    await new Promise(r => server.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});

function execNode(args, extraEnv = {}) {
  return new Promise(resolve => {
    execFile('node', args, { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120000, env: { ...process.env, ...extraEnv } },
      (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, out: `${stdout || ''}${stderr || ''}` }));
  });
}

run();
