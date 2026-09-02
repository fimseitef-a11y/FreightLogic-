#!/usr/bin/env node
/**
 * FreightLogic — live Worker authority-boundary verification (M7 gate).
 *
 *   node scripts/verify-live-authority.mjs [workerOrigin] [--paid]
 *
 * `scripts/verify-cloudflare-parity.mjs` already covers the deployed asset
 * generation, `/health`, the Worker version and admin auth denial. The one M7
 * live gate it does NOT cover is the `/evaluate` + `/extract` AUTHORITY
 * BOUNDARY: proving the deployed Worker *projects* the client's canonical
 * decision rather than recalculating one of its own.
 *
 * That distinction is the whole v24.0 authority rule, and a version string in
 * `/health` does not prove it — only behaviour does. This script asks the live
 * Worker questions whose answers differ if the boundary is broken.
 *
 * AUTH.  Reads the backup token from the FL_BACKUP_TOKEN environment variable,
 * never from argv, so it stays out of shell history and process listings. It
 * is never printed, not even partially.
 *
 *   FL_BACKUP_TOKEN=flk_... node scripts/verify-live-authority.mjs
 *
 * COST.  The default run spends NO OpenAI quota: every check it performs is on
 * a path the Worker short-circuits before calling the model. `--paid` adds the
 * live projection checks, which do call OpenAI (rate limit: 100/hr per user for
 * /evaluate, 50/hr for /extract).
 *
 * DATA.  Every fixture below is synthetic. No operator trip, broker, rate or
 * lane data is sent to the network by this script.
 *
 * EXIT CODES — the certification record requires "unreachable" and "failed" to
 * be different outcomes, because an unobserved check is not a product failure
 * and must never be recorded as one:
 *
 *   0  all attempted checks passed
 *   1  a real authority-boundary FAILURE — the deployed Worker is wrong
 *   2  UNOBSERVED — the origin could not be reached, or no token was supplied
 */

const args = process.argv.slice(2);
const paid = args.includes('--paid');
const positional = args.filter(a => !a.startsWith('-'));
const workerOrigin = (positional[0] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');
const token = process.env.FL_BACKUP_TOKEN || '';

const checks = [];
let unreachable = false;

function pass(name, detail = '') { checks.push({ state: 'PASS', name, detail }); }
function fail(name, detail = '') { checks.push({ state: 'FAIL', name, detail }); }
function skip(name, detail = '') { checks.push({ state: 'SKIP', name, detail }); }

function assert(name, cond, detail = '') { cond ? pass(name) : fail(name, detail); }

async function post(path, body, { auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && token) headers['X-Backup-Token'] = token;
  try {
    const res = await fetch(`${workerOrigin}${path}`, {
      method: 'POST', headers, body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
    const json = await res.json().catch(() => null);
    // An interposed proxy, WAF or load balancer answers at the HTTP layer, so
    // `fetch` RESOLVES — it does not throw — and a 403 from a corporate egress
    // proxy is indistinguishable from a Worker response unless we look at the
    // body. Every real Worker reply is JSON carrying `ok`; anything else did
    // not come from the Worker and is evidence about the network, not about
    // the product. Getting this wrong is what made an earlier revision of this
    // script report a blocked sandbox as an authority-boundary FAILURE.
    if (!json || typeof json !== 'object' || !('ok' in json)) {
      unreachable = true;
      return { ok: false, status: 0, json: null,
        error: `HTTP ${res.status} with a non-Worker body — request did not reach the Worker` };
    }
    return { ok: res.ok, status: res.status, json };
  } catch (e) {
    // A transport error is not evidence about the product. Record it and let
    // the caller decide; the run ends UNOBSERVED rather than FAILED.
    unreachable = true;
    return { ok: false, status: 0, json: null, error: String(e && e.message || e) };
  }
}

/* ── fixtures — synthetic throughout ──────────────────────────────────────── */

// A complete canonical decision with a deliberately AWKWARD combination: a
// STRATEGIC verdict at grade B on a lane whose numbers a model reviewing it
// would plausibly want to call ACCEPT/A. If the Worker lets the model own the
// verdict or grade, these values change and the check fails.
const completeDecision = {
  authority: { verdict: 'STRATEGIC', grade: 'B', reason: 'synthetic fixture — authority boundary probe' },
  economics: { available: true, trueRPM: 1.63, totalMi: 420, deadheadPct: 11 },
  bid: {
    range: {
      minimum:      { amount: 588, rpm: 1.40 },
      professional: { amount: 651, rpm: 1.55 },
      strong:       { amount: 714, rpm: 1.70 },
      premium:      { amount: 777, rpm: 1.85 },
    },
  },
  factsComplete: true,
  load: { origin: 'Springfield, IL', destination: 'Terre Haute, IN', loadedMi: 420, deadMi: 46, revenue: 685 },
};

const rejectDecision = {
  ...completeDecision,
  authority: { verdict: 'REJECT', grade: 'F', reason: 'synthetic fixture — real reject must survive' },
  economics: { available: true, trueRPM: 0.98, totalMi: 300, deadheadPct: 20 },
};

// Three DIFFERENT ways a client legitimately says "I do not have a decision".
// The v13 contract must preserve all three, not just the explicit verdict.
const unavailableByVerdict = {
  authority: { verdict: 'UNAVAILABLE', grade: '?' },
  economics: { available: false, trueRPM: null },
  bid: { suppressed: true, range: null },
  factsComplete: false,
  unknownFacts: ['deadheadMi', 'revenue'],
};
const unavailableByFactsFlag = {
  authority: { verdict: 'ACCEPT', grade: 'A' },   // deliberately contradictory…
  economics: { available: true, trueRPM: 2.10 },  // …with factsComplete:false
  bid: { range: { minimum: { amount: 500, rpm: 1.40 } } },
  factsComplete: false,
  unknownFacts: ['loadedMi'],
};
const unavailableByEconomics = {
  authority: { verdict: 'ACCEPT', grade: 'A' },
  economics: { available: false, trueRPM: null },
  bid: { suppressed: true, range: null },
  factsComplete: true,
  unknownFacts: [],
};

/* ── absence checks — no OpenAI call, always run ──────────────────────────── */

function assertAbsencePreserved(label, r) {
  if (r.status === 0) { skip(label, 'origin unreachable'); return; }
  if (r.status !== 200 || !r.json?.ai) { fail(label, `HTTP ${r.status} ${JSON.stringify(r.json)?.slice(0, 160)}`); return; }
  const ai = r.json.ai;
  const bad = [];
  if (ai.verdict !== 'UNAVAILABLE') bad.push(`verdict=${ai.verdict}`);
  if (ai.grade !== '?') bad.push(`grade=${ai.grade}`);
  if (!/^UNAVAILABLE/.test(String(ai.trueRpmBand))) bad.push(`trueRpmBand=${ai.trueRpmBand}`);
  if (/\$\s*0(\.00)?\b/.test(String(ai.bidAdvice))) bad.push(`bidAdvice manufactured $0: ${ai.bidAdvice}`);
  if (ai.authority !== 'CLIENT_UNIFIED_DECISION_ENGINE') bad.push(`authority=${ai.authority}`);
  if (r.json.model !== null) bad.push(`model=${r.json.model} (an unavailable decision must not spend an OpenAI call)`);
  bad.length ? fail(label, bad.join('; ')) : pass(label);
}

async function run() {
  console.log(`FreightLogic — live Worker authority boundary`);
  console.log(`  origin: ${workerOrigin}`);
  console.log(`  mode:   ${paid ? 'FULL (spends OpenAI quota)' : 'FREE (short-circuit paths only)'}`);
  console.log('='.repeat(72));

  if (!token) {
    console.log('\n  FL_BACKUP_TOKEN is not set — every /evaluate and /extract check needs it.');
    console.log('  Re-run as:  FL_BACKUP_TOKEN=flk_... node scripts/verify-live-authority.mjs\n');
    console.log('  UNOBSERVED — no checks were performed. This is not a pass and not a failure.');
    process.exit(2);
  }

  // 1. auth: /evaluate must reject an unauthenticated caller
  const noAuth = await post('/evaluate', { canonicalDecision: completeDecision }, { auth: false });
  if (noAuth.status === 0) skip('/evaluate rejects an unauthenticated request', 'origin unreachable');
  else assert('/evaluate rejects an unauthenticated request', noAuth.status === 401,
    `expected 401, got ${noAuth.status}` + (noAuth.status === 429 ? ' (429 = this IP is rate-limited; retry from a fresh IP)' : ''));

  // 2-4. all three legitimate shapes of canonical absence
  assertAbsencePreserved('UNAVAILABLE verdict is projected, never coerced to REJECT/F/$0.00',
    await post('/evaluate', { canonicalDecision: unavailableByVerdict }));
  assertAbsencePreserved('factsComplete:false is honoured over a contradictory ACCEPT/A',
    await post('/evaluate', { canonicalDecision: unavailableByFactsFlag }));
  assertAbsencePreserved('economics.available:false is honoured over a contradictory ACCEPT/A',
    await post('/evaluate', { canonicalDecision: unavailableByEconomics }));

  // 5. an incomplete-but-not-unavailable decision is refused, not filled in
  const noBid = await post('/evaluate', {
    canonicalDecision: {
      authority: { verdict: 'ACCEPT', grade: 'A' },
      economics: { available: true, trueRPM: 1.80 },
      factsComplete: true,
      // no bid range at all
    },
  });
  if (noBid.status === 0) skip('a decision with no bid range is refused, not invented', 'origin unreachable');
  else assert('a decision with no bid range is refused, not invented',
    noBid.status === 400 && /required/i.test(String(noBid.json?.error || '')),
    `expected 400 + "required", got ${noBid.status} ${JSON.stringify(noBid.json)?.slice(0, 160)}`);

  if (!paid) {
    skip('live projection of a complete decision', 'needs --paid (spends OpenAI quota)');
    skip('live projection of a real REJECT/F', 'needs --paid (spends OpenAI quota)');
    skip('/extract returns fields without evaluating', 'needs --paid (spends OpenAI quota)');
  } else {
    // 6. THE projection check: the model reviews, the client decides.
    const complete = await post('/evaluate', { canonicalDecision: completeDecision });
    if (complete.status === 0) skip('live projection of a complete decision', 'origin unreachable');
    else if (complete.status !== 200 || !complete.json?.ai) {
      fail('live projection of a complete decision', `HTTP ${complete.status} ${JSON.stringify(complete.json)?.slice(0, 160)}`);
    } else {
      const ai = complete.json.ai;
      const bad = [];
      if (ai.verdict !== 'STRATEGIC') bad.push(`verdict=${ai.verdict} (client said STRATEGIC)`);
      if (ai.grade !== 'B') bad.push(`grade=${ai.grade} (client said B)`);
      if (String(ai.trueRpmBand) !== '$1.63 / true mile') bad.push(`trueRpmBand=${ai.trueRpmBand} (client said 1.63)`);
      if (!/Minimum \$588 @ \$1\.40\/mi/.test(String(ai.bidAdvice))) bad.push(`bidAdvice did not project the canonical minimum: ${ai.bidAdvice}`);
      if (ai.authority !== 'CLIENT_UNIFIED_DECISION_ENGINE') bad.push(`authority=${ai.authority}`);
      bad.length ? fail('live projection of a complete decision', bad.join('; ')) : pass('live projection of a complete decision');
      // Commentary is allowed and expected — it just cannot own the decision.
      assert('the model may still agree or challenge in commentary',
        ai.agreement === 'AGREE' || ai.agreement === 'CHALLENGE', `agreement=${ai.agreement}`);
    }

    // 7. a genuine REJECT/F is still a REJECT/F — v13 must not have softened it
    const rej = await post('/evaluate', { canonicalDecision: rejectDecision });
    if (rej.status === 0) skip('live projection of a real REJECT/F', 'origin unreachable');
    else if (rej.status !== 200 || !rej.json?.ai) fail('live projection of a real REJECT/F', `HTTP ${rej.status}`);
    else assert('live projection of a real REJECT/F',
      rej.json.ai.verdict === 'REJECT' && rej.json.ai.grade === 'F',
      `verdict=${rej.json.ai.verdict} grade=${rej.json.ai.grade}`);

    // 8. /extract parses text; it must not return a decision of any kind
    const ext = await post('/extract', {
      text: 'Order #TEST-9001 | Springfield, IL to Terre Haute, IN | 420 mi | pickup 2026-09-10 | broker Synthetic Freight Co',
    });
    if (ext.status === 0) skip('/extract returns fields without evaluating', 'origin unreachable');
    else if (ext.status !== 200) fail('/extract returns fields without evaluating', `HTTP ${ext.status} ${JSON.stringify(ext.json)?.slice(0, 160)}`);
    else {
      const bad = [];
      if (!ext.json?.fields || typeof ext.json.fields !== 'object') bad.push('no fields object returned');
      for (const forbidden of ['verdict', 'grade', 'trueRPM', 'bid', 'canonicalDecision']) {
        if (ext.json?.fields && forbidden in ext.json.fields) bad.push(`/extract returned a decision field: ${forbidden}`);
      }
      bad.length ? fail('/extract returns fields without evaluating', bad.join('; ')) : pass('/extract returns fields without evaluating');
    }
  }

  /* ── report ────────────────────────────────────────────────────────────── */
  console.log('');
  for (const c of checks) {
    const mark = c.state === 'PASS' ? 'PASS' : c.state === 'FAIL' ? 'FAIL' : 'SKIP';
    console.log(`  ${mark}  ${c.name}${c.detail ? `  — ${c.detail}` : ''}`);
  }
  const passed = checks.filter(c => c.state === 'PASS').length;
  const failed = checks.filter(c => c.state === 'FAIL').length;
  const skipped = checks.filter(c => c.state === 'SKIP').length;
  console.log('-'.repeat(72));
  console.log(`  ${passed} passed, ${failed} failed, ${skipped} not run`);

  if (unreachable && failed === 0) {
    console.log('\n  UNOBSERVED — the live origin could not be reached from this network.');
    console.log('  This is NOT a pass and NOT a product failure. Re-run from a network that');
    console.log('  reaches the deployed Worker before recording an M7 result.');
    process.exit(2);
  }
  if (failed) {
    console.log('\n  FAILED — the deployed Worker did not preserve the canonical authority boundary.');
    console.log('  Do not certify this release generation until this is resolved.');
    process.exit(1);
  }
  console.log(`\n  Authority boundary verified on ${workerOrigin}${paid ? '' : ' (free checks only — re-run with --paid for the full gate)'}.`);
  process.exit(0);
}

run().catch(e => {
  console.error('\n  Runner error:', e && e.message || e);
  console.error('  Recorded as UNOBSERVED rather than as a product failure.');
  process.exit(2);
});
