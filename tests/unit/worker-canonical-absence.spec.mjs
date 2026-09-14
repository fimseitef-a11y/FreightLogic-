// Issue #119 Batch A, item 6 — Worker compatibility with canonical ABSENCE.
//
// Drives the REAL exported Worker handler (cloud-backup-worker.js's default
// export) over an in-memory KV stand-in. The M3 addendum called this out
// explicitly: the existing v24 coverage proved only that the AI projection
// echoes a COMPLETE hand-built decision, so nothing caught the Worker turning
// an UNAVAILABLE / grade `?` / trueRPM null / suppressed-bid decision into a
// confident REJECT / F / $0.00 answer the client never issued.
//
// No network is used: the unavailable decision short-circuits before OpenAI is
// called, which is itself part of the contract under test.
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('unit/worker-canonical-absence.spec.mjs');

const worker = (await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href)).default;

// Minimal KV stand-in: enough for token auth + the rate-limit counter. The
// Worker's own storage layer is external infrastructure, not the logic under
// test (same rationale as tests/lib/mock-worker.mjs).
function makeEnv({ configured = false } = {}){
  const store = new Map();
  return {
    ...(configured ? { OPENAI_API_KEY: 'test-key-not-used-outside-the-mocked-model-path' } : {}),
    ALLOWED_ORIGIN: 'http://localhost',
    BACKUPS: {
      async get(key){
        if (key.startsWith('tokh:')) return JSON.stringify({ userId: 'usr_test', name: 'Test Driver', active: true });
        return store.has(key) ? store.get(key) : null;
      },
      async put(key, value){ store.set(key, value); },
      async delete(key){ store.delete(key); },
      async list(){ return { keys: [] }; },
    },
  };
}

const TOKEN = 'flk_' + '0'.repeat(32);

async function evaluate(canonicalDecision, options){
  const req = new Request('https://worker.test/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Backup-Token': TOKEN, 'X-Device-Id': 'test-device' },
    body: JSON.stringify({ canonicalDecision }),
  });
  const res = await worker.fetch(req, makeEnv(options));
  return { status: res.status, body: await res.json() };
}

test('[W-01] /health reports the version the parity verifier expects', async () => {
  // DERIVED, not pinned. This asserts source self-consistency: whatever
  // generation the release machinery expects, the Worker's own /health must
  // report. Hardcoding the number here made it the FOURTH hand-synced copy of
  // one value (with the parity verifier, the deploy script and the deploy
  // workflow), and it went stale on the very next Worker bump — which is how
  // this assertion was found.
  //
  // The accidental-bump guard is a different job and still pinned by hand, in
  // cache-generation.spec.mjs CG-09: that one exists to make an unintended
  // Worker change visible during an app-generation bump, so it must NOT derive.
  const expected = readFileSync(path.join(ROOT, 'scripts/verify-cloudflare-parity.mjs'), 'utf8')
    .match(/workerVersion:\s*"(\d+)"/)?.[1];
  ok(expected, 'could not read workerVersion from scripts/verify-cloudflare-parity.mjs');

  const res = await worker.fetch(new Request('https://worker.test/health'), makeEnv());
  const body = await res.json();
  eq(res.status, 200, 'health is reachable');
  eq(body.version, expected,
    `cloud-backup-worker.js /health must report v${expected}, matching the parity verifier`);
});

test('[W-01b] production app origin is the default and explicitly allowed by CORS', async () => {
  const prod = 'https://freightlogic-v2.fimseitef.workers.dev';
  const env = makeEnv();
  const defaultRes = await worker.fetch(new Request('https://worker.test/health'), env);
  eq(defaultRes.headers.get('Access-Control-Allow-Origin'), prod, 'no-Origin fallback targets the real production app');

  const originRes = await worker.fetch(new Request('https://worker.test/health', { headers: { Origin: prod } }), env);
  eq(originRes.status, 200, 'production-origin health remains unauthenticated');
  eq(originRes.headers.get('Access-Control-Allow-Origin'), prod, 'production app receives an exact CORS allow-origin');
});

test('[W-02] an UNAVAILABLE canonical decision is preserved, never turned into REJECT/F/$0.00', async () => {
  const { status, body } = await evaluate({
    schemaVersion: '24.0.0',
    factsComplete: false,
    unknownFacts: ['deadheadMi', 'revenue'],
    authority: { source: 'CLIENT_UNIFIED_DECISION_ENGINE', verdict: 'UNAVAILABLE', grade: '?', reason: 'required facts missing' },
    economics: { available: false, trueRPM: null, totalMi: null, deadMi: null },
    bid: { authority: 'CLIENT_UNIFIED_DECISION_ENGINE', suppressed: true, range: null },
  });
  eq(status, 200, 'a canonically unavailable decision is a valid request, not a 400');
  eq(body.ok, true, 'and is answered, not rejected');
  eq(body.ai.verdict, 'UNAVAILABLE', 'the verdict is projected verbatim — never REJECT');
  eq(body.ai.grade, '?', 'the unknown grade is projected verbatim — never F');
  eq(body.ai.authority, 'CLIENT_UNIFIED_DECISION_ENGINE', 'the client remains the authority');
  ok(/UNAVAILABLE/.test(body.ai.trueRpmBand), 'an absent True RPM is reported as unavailable, not $0.00');
  ok(!/\$\s*0\.00/.test(body.ai.trueRpmBand), 'and never as a dollar figure');
  ok(/suppressed/i.test(body.ai.bidAdvice), 'a suppressed bid range is reported as suppressed');
  ok(!/\$\d/.test(body.ai.bidAdvice), 'and no dollar figure is manufactured to fill it');
  ok(/deadheadMi/.test(body.ai.primaryReason), 'the missing facts are named back to the driver');
  eq(body.model, null, 'no AI call is made for a decision that does not exist');
});

test('[W-03] a decision whose economics are unavailable is also treated as absent', async () => {
  const { status, body } = await evaluate({
    authority: { verdict: 'ACCEPT', grade: 'B' },
    economics: { available: false, trueRPM: null },
    bid: { suppressed: true, range: null },
  });
  eq(status, 200, 'answered rather than 400');
  eq(body.ai.verdict, 'UNAVAILABLE', 'economics that are not available cannot support an ACCEPT projection');
  eq(body.ai.grade, '?', 'nor a letter grade');
});

test('[W-04] a genuinely complete decision still fails closed when required fields are missing', async () => {
  // Not "unavailable" — just malformed. This must still be refused, so the
  // absence path cannot become a way to smuggle an incomplete payload through.
  const { status, body } = await evaluate({
    authority: { verdict: 'ACCEPT', grade: 'B' },
    economics: { available: true, trueRPM: 1.72 },
    bid: { suppressed: false, range: null },
  });
  eq(status, 400, 'a malformed complete decision is still refused');
  eq(body.ok, false, 'and reports failure');
  ok(/Local evaluation remains authoritative/.test(body.error), 'with the client authority restated');
});

test('[W-05] a real REJECT and a real F still project verbatim', async () => {
  // The complete-decision path calls OpenAI. Stub the outbound call so this
  // test is hermetic (no network) and so the assertion is about PROJECTION,
  // which is the only part of that response the Worker owns.
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    choices: [{ message: { content: JSON.stringify({
      summary: 'model text', agreement: 'AGREE', primaryReason: 'model reason',
      // The model TRIES to publish its own verdict/grade/bid. None of it may land.
      verdict: 'ACCEPT', grade: 'A', bidAdvice: '$9,999', trueRpmBand: '$9.99 / true mile',
      risks: [], positives: [], nextMove: 'model move',
    }) } }],
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  let body;
  try { ({ body } = await evaluate({
    factsComplete: true,
    authority: { verdict: 'REJECT', grade: 'F', reason: 'below the $1.40 normal floor' },
    economics: { available: true, trueRPM: 1.02, totalMi: 400, deadMi: 40 },
    bid: { suppressed: false, range: { minimum: { amount: 560, rpm: 1.40 } } },
  }, { configured: true })); } finally { globalThis.fetch = realFetch; }

  eq(body.ok, true, 'a complete decision is reviewed, not short-circuited as absent');
  eq(body.ai.verdict, 'REJECT', 'a real REJECT projects verbatim — the model cannot upgrade it');
  eq(body.ai.grade, 'F', 'a real F projects verbatim — the absence fix did not soften real grades');
  ok(/\$1\.02 \/ true mile/.test(body.ai.trueRpmBand), 'the True RPM band comes from canonical economics, not the model');
  ok(/Minimum \$560/.test(body.ai.bidAdvice), 'the bid advice comes from the canonical range, not the model');
  ok(!/9,?999/.test(body.ai.bidAdvice + body.ai.trueRpmBand), "the model's competing figures are discarded");
});

test('[W-06] factsComplete:false wins without AI configuration and never calls a model', async () => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('unexpected model request'); };
  try {
    const { status, body } = await evaluate({
      factsComplete: false,
      authority: { verdict: 'ACCEPT', grade: 'A' },
      economics: { available: true, trueRPM: 2.1 },
      bid: { range: { minimum: { amount: 500, rpm: 1.4 } } },
    });
    eq(status, 200, 'the model-free path works with no OpenAI key');
    eq(body.ai.verdict, 'UNAVAILABLE', 'missing facts outrank contradictory ACCEPT');
    eq(body.ai.grade, '?', 'unknown grade is preserved');
    ok(/^UNAVAILABLE/.test(String(body.ai.trueRpmBand)),
      'factsComplete:false suppresses a contradictory numeric True RPM');
    ok(!/\$\s*2\.10/.test(String(body.ai.trueRpmBand)),
      'factsComplete:false never leaks the contradictory $2.10 True RPM');
    eq(body.model, null, 'no model is used');
    eq(calls, 0, 'no outbound request is attempted');
  } finally { globalThis.fetch = realFetch; }
});

test('[W-07] a complete decision still requires AI configuration', async () => {
  const { status, body } = await evaluate({
    factsComplete: true,
    authority: { verdict: 'ACCEPT', grade: 'B' },
    economics: { available: true, trueRPM: 1.72 },
    bid: { range: { minimum: { amount: 560, rpm: 1.4 } } },
  });
  eq(status, 500, 'a real model request fails closed without a key');
  eq(body.ok, false, 'AI configuration failure is explicit');
  ok(/not configured/.test(body.error), 'configuration remains required on the paid path');
});

test('[W-08] malformed JSON and oversized requests are rejected before AI configuration', async () => {
  for (const [body, extraHeaders, expected] of [
    ['{', {}, 400],
    ['{}', { 'Content-Length': String(65537) }, 413],
  ]) {
    const res = await worker.fetch(new Request('https://worker.test/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Backup-Token': TOKEN, ...extraHeaders },
      body,
    }), makeEnv());
    eq(res.status, expected, 'request validation must not depend on an AI key');
  }
});

test('[W-09] canonical absence still requires driver authentication', async () => {
  const res = await worker.fetch(new Request('https://worker.test/evaluate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ canonicalDecision: { factsComplete: false } }),
  }), makeEnv());
  eq(res.status, 401, 'the model-free path does not bypass driver authentication');
});

export async function runSpec(){ return await run(); }
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
