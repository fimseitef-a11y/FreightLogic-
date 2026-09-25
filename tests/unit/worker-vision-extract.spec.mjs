// Worker v21 — POST /extract-image, the screenshot intake path (Issue #252).
//
// WHAT THESE ARE REALLY GUARDING. #252 hands a vision model the one input that
// reaches this operator most often — a screenshot of a load posting — and the
// standing risk is not that extraction is imperfect. It is that an imperfect
// extraction arrives looking CERTAIN. Two failure shapes matter more than
// accuracy, and neither is caught by measuring accuracy:
//
//   1. An absent deadhead arriving as 0. The whole app is built on the
//      distinction between a stated zero and an unstated one (v24.0.1 canonical
//      economics, v24.0.4's four intake paths, v24.0.5's persistence layer), and
//      the Worker's own `intPositive` CANNOT express it — it maps an explicit 0
//      to null. VEX-04/05 assert both directions on the same endpoint.
//   2. The model volunteering a verdict. The v24.0 authority rule already
//      constrains /evaluate to PROJECT the canonical decision rather than
//      recalculate it; a vision endpoint that passed through a `grade` or a
//      `ratePerMile` would be a second evaluator arriving by a new door.
//      VEX-06 dumps the entire response and requires those keys to be absent.
//
// These drive the REAL exported fetch handler from cloud-backup-worker.js with
// a stub provider injected through the same `env` Cloudflare supplies, so the
// route, the auth gate, the ceilings and the normalizer under test are the
// shipped ones. Only the model call is stubbed — there is no network here and
// no provider key.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-vision-extract.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';

function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  return {
    _map: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) };
    },
    dump() { return [...m.entries()].map(([k, v]) => k + '=' + v).join('\n'); },
  };
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  return mod.default;
}

const REQ = (url, opts = {}) => new Request('https://worker.test' + url, opts);

/** Mint a REAL driver credential through the real invite/claim path, so these
 *  tests exercise the same auth gate production does rather than a seeded
 *  fixture that could drift from it. */
async function seedDriver(worker, env) {
  const inv = await (await worker.fetch(REQ('/admin/invites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN },
    body: JSON.stringify({ name: 'Screenshot Driver' }),
  }), env)).json();
  const claimed = await (await worker.fetch(REQ('/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: JSON.stringify({ code: inv.code }),
  }), env)).json();
  return claimed.token;
}

// A 1x1 JPEG. The bytes are never looked at by the stub provider; what matters
// is that the route's decode/mime path accepts a real image the way the app's
// canvas re-encode produces one.
const TINY_JPEG_B64 =
  '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a' +
  'HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA' +
  'AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==';

/** Exact-host match for the OpenAI endpoint the adapter calls (a substring
 *  test would also match an unrelated host that merely contains the name). */
function isOpenAIUrl(u) {
  try { return new URL(String(u)).hostname === 'api.openai.com'; } catch { return false; }
}

/** Build an env whose vision provider is a stub returning `raw`.
 *
 *  `VISION_PROVIDER: 'openai'` plus a stubbed global fetch is deliberate: it
 *  exercises a REAL adapter in the shipped table rather than a test-only
 *  provider branch that production never takes. */
function visionEnv(kv, raw, { fail = false } = {}) {
  const realFetch = globalThis.fetch;
  const restore = () => { globalThis.fetch = realFetch; };
  globalThis.fetch = async (url) => {
    if (isOpenAIUrl(url)) {
      if (fail) return new Response('upstream boom', { status: 500 });
      return new Response(JSON.stringify({ choices: [{ message: { content: raw } }] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return realFetch(url);
  };
  return {
    env: { BACKUPS: kv, ADMIN_TOKEN: ADMIN, OPENAI_API_KEY: 'sk-test', VISION_PROVIDER: 'openai' },
    restore,
  };
}

function imageReq(token, body) {
  return REQ('/extract-image', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-Id': 'dev-1', 'X-Backup-Token': token },
    body: JSON.stringify(body),
  });
}

/** Run one extraction with a stubbed provider output and return the parsed body. */
async function extract(rawModelOutput, { image, opts } = {}) {
  const kv = makeKV();
  const worker = await loadWorker();
  const bootEnv = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const token = await seedDriver(worker, bootEnv);
  const { env, restore } = visionEnv(kv, rawModelOutput, opts);
  try {
    const res = await worker.fetch(
      imageReq(token, image || { image: TINY_JPEG_B64, mime: 'image/jpeg' }), env);
    return { res, body: await res.json().catch(() => ({})), kv, token, worker, env };
  } finally { restore(); }
}

const FULL = JSON.stringify({
  fields: {
    orderNo: '1079840', broker: 'DispatchLand', origin: 'Columbus, OH',
    destination: 'Chicago, IL', pay: 1250, loadedMiles: 355, deadheadMiles: 42,
    pickupDate: '2026-09-19', pickupTime: '19:00', weight: 1800,
  },
  confidence: {
    orderNo: 0.98, broker: 0.95, origin: 0.97, destination: 0.96,
    pay: 0.99, loadedMiles: 0.94, deadheadMiles: 0.92, pickupDate: 0.9,
    pickupTime: 0.88, weight: 0.85,
  },
});

// ── Auth and configuration boundaries ────────────────────────────────────────

const APP_ORIGIN = 'https://freightlogic-v2.fimseitef.workers.dev';
function anonReq(headers = {}, body = { image: TINY_JPEG_B64, mime: 'image/jpeg' }) {
  return REQ('/extract-image', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

// v25 (operator-approved 2026-09-25): a request with NO driver token is served
// only from the FreightLogic app origin, 20/hr per IP and 300/day in total.
test('[VEX-01] a no-login request from any other origin is rejected, and calls no provider', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  let providerCalled = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => { if (isOpenAIUrl(u)) providerCalled = true; return realFetch(u); };
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN, OPENAI_API_KEY: 'sk-test', VISION_PROVIDER: 'openai' };
  try {
    const none = await worker.fetch(anonReq({}), env);
    ok(none.status === 401 || none.status === 403, `no Origin must be refused, got ${none.status}`);
    const foreign = await worker.fetch(anonReq({ Origin: 'https://evil.example' }), env);
    ok(foreign.status === 401 || foreign.status === 403, `a foreign Origin must be refused, got ${foreign.status}`);
  } finally { globalThis.fetch = realFetch; }
  ok(!providerCalled, 'a refused request must never spend provider allocation');
});

test('[VEX-18] a no-login request from the app origin is read, through the same normalizer', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const { env, restore } = visionEnv(kv, JSON.stringify({ fields: { origin: 'Mobile, AL', loadedMiles: 380, grade: 'A' }, confidence: { origin: 0.9, loadedMiles: 0.9 } }));
  try {
    const res = await worker.fetch(anonReq({ Origin: APP_ORIGIN, 'CF-Connecting-IP': '198.51.100.7' }), env);
    eq(res.status, 200, `expected 200, got ${res.status}`);
    const body = await res.json();
    eq(body.fields.origin, 'Mobile, AL', 'fields come back');
    ok(!('grade' in body.fields), 'a volunteered grade is still dropped');
    eq(body.fields.deadheadMiles, null, 'an unstated deadhead is still null');
  } finally { restore(); }
});

test('[VEX-19] the no-login route stops at 20 reads per IP per hour', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const { env, restore } = visionEnv(kv, JSON.stringify({ fields: { origin: 'Mobile, AL' }, confidence: { origin: 0.9 } }));
  try {
    const statuses = [];
    for (let i = 0; i < 21; i++) statuses.push((await worker.fetch(anonReq({ Origin: APP_ORIGIN, 'CF-Connecting-IP': '198.51.100.8' }), env)).status);
    eq(statuses.slice(0, 20).every(x => x === 200), true, 'the first 20 are served');
    eq(statuses[20], 429, 'the 21st in the hour is refused');
    const other = await worker.fetch(anonReq({ Origin: APP_ORIGIN, 'CF-Connecting-IP': '198.51.100.9' }), env);
    eq(other.status, 200, 'another IP is unaffected');
  } finally { restore(); }
});

test('[VEX-20] the no-login route stops at 300 reads per day in total', async () => {
  const day = Math.floor(Date.now() / 86400000);
  const kv = makeKV({ ['rlday:anon-image:' + day]: '300' });
  const worker = await loadWorker();
  let providerCalled = false;
  const { env, restore } = visionEnv(kv, '{}');
  const inner = globalThis.fetch;
  globalThis.fetch = async (u, o) => { if (isOpenAIUrl(u)) providerCalled = true; return inner(u, o); };
  try {
    const res = await worker.fetch(anonReq({ Origin: APP_ORIGIN, 'CF-Connecting-IP': '198.51.100.10' }), env);
    eq(res.status, 429, 'past the daily total every no-login read is refused');
  } finally { globalThis.fetch = inner; restore(); }
  ok(!providerCalled, 'and no provider call is made');
});

test('[VEX-21] a request WITH a token still uses the authenticated route', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const { env, restore } = visionEnv(kv, FULL);
  try {
    const bad = await worker.fetch(REQ('/extract-image', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Origin: APP_ORIGIN, 'X-Backup-Token': 'flk_' + '0'.repeat(32) },
      body: JSON.stringify({ image: TINY_JPEG_B64 }),
    }), env);
    ok(bad.status === 401 || bad.status === 403, `a bad token is refused, not downgraded to no-login, got ${bad.status}`);
  } finally { restore(); }
});

test('[VEX-02] an unconfigured provider reports NOT CONFIGURED, not a failed extraction', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const bootEnv = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const token = await seedDriver(worker, bootEnv);
  // No OPENAI_API_KEY. The operator can act on "not configured" and cannot act
  // on "AI error", so these must not be the same answer.
  const res = await worker.fetch(imageReq(token, { image: TINY_JPEG_B64 }),
    { BACKUPS: kv, ADMIN_TOKEN: ADMIN, VISION_PROVIDER: 'openai' });
  eq(res.status, 501, `expected 501 for unconfigured provider, got ${res.status}`);
  const body = await res.json();
  eq(body.ok, false, 'an unconfigured provider is not a successful extraction');
  ok(/not configured/i.test(body.error), `error must name configuration, got: ${body.error}`);
});

// ── The contract that matters ────────────────────────────────────────────────

test('[VEX-03] a clean extraction returns tri-state fieldMeta and the observed values', async () => {
  const { res, body } = await extract(FULL);
  eq(res.status, 200, `expected 200, got ${res.status}`);
  eq(body.ok, true, 'a clean extraction must report ok');
  eq(body.fields.orderNo, '1079840', 'orderNo must survive');
  eq(body.fields.pay, 1250, 'pay must survive as a number');
  eq(body.fields.loadedMiles, 355, 'loadedMiles must survive');
  eq(body.fields.deadheadMiles, 42, 'a stated deadhead must survive');
  eq(body.fieldMeta.pay.state, 'OBSERVED', 'a high-confidence field is OBSERVED');
  eq(body.fieldMeta.deliveryDate.state, 'ABSENT', 'a field not in the image is ABSENT');
  eq(body.fields.deliveryDate, null, 'an ABSENT field must be null, never a placeholder');
});

test('[VEX-04] an ABSENT deadhead stays null — it never becomes a verified zero', async () => {
  // The single most consequential assertion in this file. A fabricated 0 here
  // overstates True RPM on every load whose posting omits the deadhead, and it
  // does so INVISIBLY, because the number looks like a real one all the way
  // through the evaluator.
  const raw = JSON.stringify({
    fields: { origin: 'Columbus, OH', destination: 'Chicago, IL', pay: 900, loadedMiles: 300 },
    confidence: { origin: 0.95, destination: 0.95, pay: 0.97, loadedMiles: 0.93 },
  });
  const { body } = await extract(raw);
  eq(body.ok, true, 'extraction should still succeed with a missing deadhead');
  eq(body.fields.deadheadMiles, null, 'an unstated deadhead MUST be null, not 0');
  eq(body.fieldMeta.deadheadMiles.state, 'ABSENT', 'and must be reported as ABSENT');
});

test('[VEX-05] an EXPLICIT zero deadhead survives as a verified zero', async () => {
  // The other half, and the one `intPositive` cannot express: a driver already
  // sitting on the pickup has a real, verified 0. Collapsing it to UNKNOWN sends
  // the evaluator back to ask for a figure the posting already gave.
  const raw = JSON.stringify({
    fields: { origin: 'Columbus, OH', destination: 'Chicago, IL', pay: 900, loadedMiles: 300, deadheadMiles: 0 },
    confidence: { deadheadMiles: 0.96 },
  });
  const { body } = await extract(raw);
  eq(body.fields.deadheadMiles, 0, 'an explicit 0 deadhead MUST survive as 0');
  eq(body.fieldMeta.deadheadMiles.state, 'OBSERVED', 'a stated zero is an observation, not an absence');
});

test('[VEX-06] a volunteered verdict, grade or rate-per-mile is DROPPED, not passed through', async () => {
  // AI extracts; FreightLogic decides. A provider that helpfully offers a grade
  // must not be able to introduce a second evaluator through a new door.
  const raw = JSON.stringify({
    fields: {
      origin: 'Columbus, OH', destination: 'Chicago, IL', pay: 900, loadedMiles: 300,
      grade: 'A', verdict: 'ACCEPT', ratePerMile: 3.0, trueRpm: 3.0,
      recommendation: 'TAKE IT', bidRange: '900-1100', profit: 400,
    },
    confidence: { origin: 0.95, pay: 0.99, grade: 0.99, verdict: 0.99 },
  });
  const { body } = await extract(raw);
  eq(body.ok, true, 'the observational fields should still extract');
  const serialized = JSON.stringify(body);
  for (const banned of ['grade', 'verdict', 'ratePerMile', 'trueRpm', 'recommendation', 'bidRange', 'profit']) {
    ok(!Object.prototype.hasOwnProperty.call(body.fields, banned),
      `fields must not carry an AI-authored "${banned}"`);
    ok(!Object.prototype.hasOwnProperty.call(body.fieldMeta, banned),
      `fieldMeta must not carry an AI-authored "${banned}"`);
  }
  ok(!/"ACCEPT"|"TAKE IT"/.test(serialized), 'no AI verdict string may reach the client');
});

test('[VEX-07] a field with no reported confidence is UNCERTAIN, not assumed good', async () => {
  // Silence is not confidence. A provider that omits the block must still send
  // the driver to the review step rather than past it.
  const raw = JSON.stringify({ fields: { origin: 'Toledo, OH', pay: 700, loadedMiles: 210 } });
  const { body } = await extract(raw);
  eq(body.fieldMeta.origin.state, 'UNCERTAIN', 'unscored field must be UNCERTAIN');
  eq(body.fieldMeta.pay.state, 'UNCERTAIN', 'unscored money must be UNCERTAIN');
});

test('[VEX-08] a low-confidence field is reported UNCERTAIN so review can flag it', async () => {
  const raw = JSON.stringify({
    fields: { origin: 'Columbus, OH', pay: 845, loadedMiles: 300 },
    confidence: { origin: 0.95, pay: 0.41, loadedMiles: 0.93 },
  });
  const { body } = await extract(raw);
  eq(body.fieldMeta.pay.state, 'UNCERTAIN', 'a 0.41-confidence read must be UNCERTAIN');
  eq(body.fields.pay, 845, 'but the value is still reported — flagged, not discarded');
  eq(body.fieldMeta.origin.state, 'OBSERVED', 'a clean read stays OBSERVED');
});

// ── Fail closed ──────────────────────────────────────────────────────────────

test('[VEX-09] unparseable provider output FAILS CLOSED rather than returning an empty load', async () => {
  const { res, body } = await extract('I could not read that image, sorry!');
  eq(res.status, 422, `expected 422, got ${res.status}`);
  eq(body.ok, false, 'garbage must not report success');
  ok(!body.fields, 'a failed extraction must carry no fields at all');
});

test('[VEX-10] output with NO readable field fails closed, not as a blank success', async () => {
  // The dangerous shape: valid JSON, every field null. Reported as ok:true it
  // would open the review step on an empty form that looks like a real read.
  const { res, body } = await extract(JSON.stringify({ fields: { pay: null, origin: null }, confidence: {} }));
  eq(res.status, 422, `expected 422, got ${res.status}`);
  eq(body.ok, false, 'an all-null extraction is not a success');
});

test('[VEX-11] a provider transport failure is 502 and never a partial result', async () => {
  const { res, body } = await extract(FULL, { opts: { fail: true } });
  eq(res.status, 502, `expected 502, got ${res.status}`);
  eq(body.ok, false, 'a provider failure must not report ok');
});

test('[VEX-12] a non-image mime is refused before any provider call', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const token = await seedDriver(worker, { BACKUPS: kv, ADMIN_TOKEN: ADMIN });
  let providerCalled = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => { if (isOpenAIUrl(u)) providerCalled = true; return realFetch(u); };
  try {
    const res = await worker.fetch(
      imageReq(token, { image: TINY_JPEG_B64, mime: 'application/pdf' }),
      { BACKUPS: kv, ADMIN_TOKEN: ADMIN, OPENAI_API_KEY: 'sk-test', VISION_PROVIDER: 'openai' });
    eq(res.status, 415, `expected 415, got ${res.status}`);
  } finally { globalThis.fetch = realFetch; }
  ok(!providerCalled, 'an unsupported type must be refused before spending provider allocation');
});

test('[VEX-13] a data: URL image is accepted and its mime honoured', async () => {
  const { res, body } = await extract(FULL, {
    image: { image: 'data:image/png;base64,' + TINY_JPEG_B64 },
  });
  eq(res.status, 200, `a data: URL must be accepted, got ${res.status}`);
  eq(body.ok, true, 'and extract normally');
});

test('[VEX-14] the response carries no provider secret', async () => {
  const { body } = await extract(FULL);
  const serialized = JSON.stringify(body);
  ok(!serialized.includes('sk-test'), 'a provider key must never reach the client');
});

// ── The DEFAULT provider — the adapter production actually takes ─────────────
//
// Every test above drives `VISION_PROVIDER: 'openai'`, which is a real adapter
// in the shipped table but is NOT the one production runs: `VISION_PROVIDER` is
// deliberately unset on the deployed Worker, so `VISION_DEFAULT_PROVIDER`
// ('workers-ai') is the live path. That left the live path with no coverage at
// all, and it was wrong: it called Moondream 3.1 with `image` as a byte ARRAY
// and the prompt under `prompt`, which is the OLDER Workers AI vision
// convention (llava/uform). Moondream 3.1's documented schema takes `image` as
// a STRING — a public HTTPS URL or a base64 data URI — and puts the query
// prompt in `question`; it answers in `answer`, not `description`/`response`/
// `text`. So `env.AI.run` threw on every call, the route's catch returned
// HTTP 502, and screenshot intake could never have worked in production.
//
// Observed, not deduced: the authenticated live gate (Verify Authenticated
// Worker, run 35756559469 against the deployed v21) reported
// `FAIL live /extract-image provider path — HTTP 502` while all five canonical
// authority-boundary checks in the same run passed.
//
// These two assert the CALL SHAPE and the READ, because those are what was
// wrong. Asserting the response body alone cannot catch it — a stub that
// answers whatever it is asked passes either way.

/** An env whose `AI` binding records the payload it was handed and answers the
 *  way the documented Moondream `query` task does. */
function workersAiEnv(kv, answer) {
  const seen = [];
  return {
    seen,
    env: {
      BACKUPS: kv,
      ADMIN_TOKEN: ADMIN,
      AI: {
        async run(model, payload) {
          seen.push({ model, payload });
          return { answer, caption: null, points: null, objects: null, reasoning: null };
        },
      },
    },
  };
}

test('[VEX-16] the DEFAULT provider calls Workers AI with the schema that model documents', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const { seen, env } = workersAiEnv(kv, FULL);
  const token = await seedDriver(worker, env);

  const res = await worker.fetch(imageReq(token, { image: TINY_JPEG_B64, mime: 'image/jpeg' }), env);
  const body = await res.json();

  eq(res.status, 200, `the default provider path must reach normalization, got ${res.status} ${JSON.stringify(body).slice(0, 200)}`);
  eq(seen.length, 1, 'the default provider must invoke the AI binding exactly once');

  const { model, payload } = seen[0];
  ok(/^@cf\//.test(model), `a Workers AI model id is expected, got ${model}`);

  // `image` is a STRING. A byte array is the older convention and is exactly
  // what the deployed v21 sent, so this is the assertion that fails on it.
  eq(typeof payload.image, 'string', `image must be a string (URL or base64 data URI), got ${Array.isArray(payload.image) ? 'array' : typeof payload.image}`);
  ok(/^data:image\/jpeg;base64,/.test(payload.image), `image must be a base64 data URI carrying the request's mime, got ${String(payload.image).slice(0, 40)}`);

  // The prompt rides `question`, not `prompt`.
  ok(typeof payload.question === 'string' && payload.question.length > 0,
    `the query prompt must ride 'question', got keys ${Object.keys(payload).join(',')}`);
  ok(payload.prompt === undefined, "`prompt` is not a parameter this model accepts — sending it is the defect, not a harmless extra");

  // Bounded generation, within the documented range.
  ok(Number.isInteger(payload.max_tokens) && payload.max_tokens >= 1 && payload.max_tokens <= 28672,
    `max_tokens must stay inside the documented 1..28672 range, got ${payload.max_tokens}`);

  // The extraction wants the JSON answer, not a reasoning trace competing for
  // the same token budget.
  eq(payload.reasoning, false, 'the reasoning trace must be off for structured extraction');

  ok(body.ok === true && body.fields && typeof body.fields === 'object',
    'and the normalized fields must come back as usual');
});

test('[VEX-17] the DEFAULT provider reads the field that model answers in', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  // `answer` is the ONLY key the documented `query` task fills. A reader that
  // looks at description/response/text finds nothing, returns '', and the route
  // fails closed with 422 — a silent dead feature rather than a visible error.
  const { env } = workersAiEnv(kv, FULL);
  const token = await seedDriver(worker, env);
  const body = await (await worker.fetch(imageReq(token, { image: TINY_JPEG_B64, mime: 'image/jpeg' }), env)).json();

  eq(body.ok, true, `the adapter must read the model's answer field — got ${JSON.stringify(body).slice(0, 200)}`);
  eq(body.fields.orderNo, '1079840', 'and the answer must reach the normalizer intact');
  eq(body.provider, 'workers-ai', 'provenance must name the default provider');
});

// ── Generation ───────────────────────────────────────────────────────────────

test('[VEX-15] /health names the generation this endpoint shipped in', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const health = await (await worker.fetch(REQ('/health'), { BACKUPS: kv })).json();
  const src = await (await import('node:fs/promises')).readFile(path.join(ROOT, 'cloud-backup-worker.js'), 'utf8');
  const headerVersion = /FreightLogic Cloud Backup Worker v(\d+)/.exec(src)?.[1];
  ok(headerVersion, 'could not read the Worker generation from its own header');
  eq(String(health.version), headerVersion, `/health must match the header, got ${health.version} vs ${headerVersion}`);
  ok(/\/extract-image/.test(src), 'the vision route must exist in the shipped Worker');
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
