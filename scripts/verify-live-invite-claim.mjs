#!/usr/bin/env node
/**
 * FreightLogic — live invite/claim contract verification (Worker v18+).
 *
 *   node scripts/verify-live-invite-claim.mjs [workerOrigin]
 *
 * WHY THIS EXISTS. v24.0.13 shipped zero-token driver onboarding: an invite
 * claim code replaces the permanent `flk_` bearer token that used to be mailed
 * to a driver. `tests/unit/worker-invite-claim.spec.mjs` proves the contract
 * against the real fetch handler with an in-memory KV, and that is a strong
 * source gate — but it is not evidence about the DEPLOYED Worker. The existing
 * authenticated gate (`verify-live-authority.mjs`, `verify-live-backup.mjs`)
 * predates these endpoints and does not touch them, so at the moment the
 * onboarding path went live it had ZERO production verification.
 *
 * That gap matters more here than almost anywhere else in the app: this is the
 * only flow that MINTS a credential, and the failure mode of getting it wrong
 * is a driver who cannot onboard or, worse, a re-claim that mints a second
 * `userId` and orphans every backup the driver has made.
 *
 * WHAT IT DOES, AND WHAT IT DELIBERATELY DOES NOT.
 *
 * `POST /admin/invites` needs the real ADMIN_TOKEN, which this gate does not
 * have and must not have. So the invite half is verified only at its AUTH
 * BOUNDARY (no token and a wrong token must both be 401), and the claim half is
 * exercised in full by seeding an `inv:<sha256(code)>` record straight into the
 * production KV namespace — exactly the way the existing authenticated gate
 * seeds its synthetic driver identity, with the same short TTL and the same
 * best-effort cleanup.
 *
 * DATA. Every value is synthetic and randomly generated per run. No operator
 * data and no real driver credential is read or written. The seeded invite
 * carries a TTL so it expires even if cleanup fails; the `user:`/`tokh:`
 * records the Worker mints during a claim carry NO TTL of their own, which is
 * exactly why cleanup here is mandatory rather than tidy — see cleanup().
 *
 * RATE LIMIT. `/claim` is 10 requests per hour per IP on the deployed Worker.
 * This script spends at most 6, and deliberately does NOT test the 429: proving
 * the limit live would consume the remaining budget and make every later check
 * in the same run report a rate limit instead of its real answer. The limit is
 * covered offline by WIC-11.
 *
 * If the Worker DOES answer 429, that is this gate's own budget being spent and
 * is reported as UNOBSERVED, never FAILURE. GitHub runners share egress ranges,
 * so a legitimate re-run inside the hour can land on it through no fault of the
 * Worker — and a gate that cries FAILURE on its own second run is a gate people
 * learn to ignore.
 *
 * EXIT CODES — "unreachable" and "failed" must stay different outcomes, because
 * an unobserved check is not a product failure and must never be recorded as
 * one:
 *
 *   0  PASS       — live evidence observed, the contract holds
 *   1  FAILURE    — the deployed Worker got the contract wrong
 *   2  UNOBSERVED — origin unreachable, or no KV credential to seed with
 */

import crypto from 'node:crypto';

const args = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith('--'));
const workerOrigin = (positional[0] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');

const CF_TOKEN = process.env.FL_CF_API_TOKEN || '';
const CF_ACCOUNT = process.env.FL_CF_ACCOUNT_ID || '';
const KV_NS = process.env.FL_KV_NAMESPACE_ID || '';

/** The name every synthetic record this gate creates carries, so a residue is
 *  identifiable in GET /admin/users instead of hiding among real drivers. */
const CERT_NAME = 'FreightLogic Certification';

const checks = [];
let unreachable = false;
/** Set only once a SEEDED invite has actually been claimed against the live
 *  Worker. Without it this gate could return PASS having exercised only the
 *  four checks that need no seeded state — a credential-minting contract
 *  reported as verified when its minting half never ran. A verdict is a claim
 *  about what was observed, so PASS has to require the observation. */
let roundTripObserved = false;
/** Set when the deployed Worker answers a /claim probe with 429.
 *
 *  That is the per-IP budget being spent, NOT a broken contract — and the two
 *  must not be conflated, because a gate that cries FAILURE on its own second
 *  run in an hour is a gate people learn to ignore. The budget is 10/hr per IP
 *  and GitHub runners share egress ranges, so a legitimate re-run, or an
 *  unrelated run from the same range, can land on it through no fault of the
 *  Worker. It reads as UNOBSERVED: the contract was not disproved, it was not
 *  reachable. */
let rateLimited = false;
/** Every KV key this run created, so cleanup can remove all of them. */
const created = new Set();

function record(name, state, detail) {
  checks.push({ name, state, detail });
  const mark = state === 'PASS' ? 'PASS' : state === 'FAIL' ? 'FAIL' : 'SKIP';
  console.log(`  ${mark}  ${name}${detail ? ` — ${detail}` : ''}`);
}
const pass = (n, d) => record(n, 'PASS', d);
const fail = (n, d) => record(n, 'FAIL', d);
const skip = (n, d) => record(n, 'SKIP', d);

function assert(name, cond, detail) {
  if (cond) pass(name, detail); else fail(name, detail);
  return cond;
}

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** Base32 over the same alphabet the Worker's b32() uses, so a generated code
 *  is indistinguishable in shape from one /admin/invites would mint. */
function b32(bytes) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, val = 0, out = '';
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += A[(val << (5 - bits)) & 31];
  return out;
}

/** Bounded fetch. A transport error sets `unreachable` rather than counting as
 *  a product failure — the distinction the exit codes above exist for. */
async function req(path, opts = {}, timeoutMs = 20000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), timeoutMs);
  try {
    const res = await fetch(workerOrigin + path, { ...opts, signal: c.signal });
    clearTimeout(t);
    let json = null;
    try { json = await res.json(); } catch { /* not every response is JSON */ }
    return { ok: true, status: res.status, json };
  } catch (e) {
    clearTimeout(t);
    unreachable = true;
    return { ok: false, status: 0, json: null, error: e && e.message };
  }
}

async function claim(code) {
  const r = await req('/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (r.ok && r.status === 429) rateLimited = true;
  return r;
}

// ── Cloudflare KV, used only to seed and to clean up ────────────────────────

const kvBase = () => `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/storage/kv/namespaces/${KV_NS}`;
const kvAuth = () => ({ Authorization: `Bearer ${CF_TOKEN}` });

async function kvPut(key, value, ttlSeconds) {
  const url = `${kvBase()}/values/${encodeURIComponent(key)}?expiration_ttl=${ttlSeconds}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { ...kvAuth(), 'Content-Type': 'text/plain' },
    body: value,
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body || body.success !== true) {
    throw new Error(`KV write rejected for ${key} (HTTP ${res.status})`);
  }
  created.add(key);
}

async function kvDelete(key) {
  try {
    const res = await fetch(`${kvBase()}/values/${encodeURIComponent(key)}`, { method: 'DELETE', headers: kvAuth() });
    return res.ok;
  } catch {
    return false;
  }
}

/** MANDATORY, not tidy. A claim makes the Worker write `user:<id>` and
 *  `tokh:<hash>` with NO expiry of their own, so anything this run mints would
 *  otherwise be a synthetic driver account living in production KV forever.
 *
 *  Deletion is best effort — a Cloudflare API blip during cleanup must not turn
 *  a good run into a failure — but it is NOT SILENT. A residue that nobody is
 *  told about is a residue nobody removes, so anything still standing is named
 *  here, with the fact that it is findable in the admin listing under the
 *  certification name rather than hiding among real drivers. */
async function cleanup() {
  if (!created.size) return;
  const stuck = [];
  for (const key of created) {
    if (!(await kvDelete(key))) stuck.push(key);
  }
  if (stuck.length) {
    console.log('\n  CLEANUP INCOMPLETE — these synthetic keys could not be deleted:');
    for (const k of stuck) console.log(`    ${k}`);
    console.log('  They are this gate\'s, not an operator\'s. The driver records carry');
    console.log(`  name "${CERT_NAME}" and are visible in GET /admin/users; the invite key`);
    console.log('  expires on its own TTL. Remove them before the next certification run.');
  }
}

async function run() {
  console.log(`\nFreightLogic live invite/claim contract — ${workerOrigin}\n${'-'.repeat(72)}`);

  // ── 1. The invite endpoint's auth boundary. Needs no secret. ──────────────
  const noTok = await req('/admin/invites', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Cert' }),
  });
  if (noTok.ok) {
    assert('POST /admin/invites without an admin token is 401', noTok.status === 401, `HTTP ${noTok.status}`);
  } else {
    skip('POST /admin/invites without an admin token is 401', 'origin unreachable');
  }

  const badTok = await req('/admin/invites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': 'definitely-not-the-admin-token' },
    body: JSON.stringify({ name: 'Cert' }),
  });
  if (badTok.ok) {
    assert('POST /admin/invites with a wrong admin token is 401', badTok.status === 401, `HTTP ${badTok.status}`);
  } else {
    skip('POST /admin/invites with a wrong admin token is 401', 'origin unreachable');
  }

  // ── 2. Claim input validation. Needs no seeded state. ────────────────────
  const malformed = await claim('nope');
  if (malformed.ok && !rateLimited) {
    assert('POST /claim with a malformed code is 400', malformed.status === 400, `HTTP ${malformed.status}`);
  } else if (rateLimited) {
    skip('POST /claim with a malformed code is 400', 'HTTP 429 — per-IP claim budget spent');
  } else {
    skip('POST /claim with a malformed code is 400', 'origin unreachable');
  }

  // A well-formed code that was never issued. 410 rather than 404 is deliberate
  // in the Worker: a distinct 404 would be an oracle confirming which codes
  // were once real.
  const unknown = await claim(b32(crypto.randomBytes(15)));
  if (unknown.ok && !rateLimited) {
    assert('POST /claim with an unknown code is 410, not 404', unknown.status === 410, `HTTP ${unknown.status}`);
  } else if (rateLimited) {
    skip('POST /claim with an unknown code is 410, not 404', 'HTTP 429 — per-IP claim budget spent');
  } else {
    skip('POST /claim with an unknown code is 410, not 404', 'origin unreachable');
  }

  if (unreachable) return report();
  if (rateLimited) {
    skip('seeded claim round trip', 'per-IP claim budget already spent — not seeding');
    return report();
  }

  // ── 3. The full claim path, against a seeded invite. ─────────────────────
  if (!CF_TOKEN || !CF_ACCOUNT || !KV_NS) {
    skip('seeded claim round trip', 'no KV credential supplied — cannot seed an invite');
    return report();
  }

  const code = b32(crypto.randomBytes(15));
  const codeKey = 'inv:' + sha256(code);
  const ttl = 900;
  const invite = {
    name: CERT_NAME,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
    claims: 0,
    maxClaims: 3,
    userId: null,
  };

  try {
    await kvPut(codeKey, JSON.stringify(invite), ttl);
  } catch (e) {
    // A credential that cannot write is an UNOBSERVED condition, not a product
    // failure: it says nothing about whether the deployed Worker is correct.
    skip('seeded claim round trip', `KV seed failed: ${e.message}`);
    unreachable = true;
    return report();
  }

  // KV is eventually consistent; wait for the deployed Worker to see the seed
  // rather than turning propagation delay into a failure.
  let first = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    first = await claim(code);
    if (!first.ok) break;
    if (first.status !== 410) break;
    await new Promise(r => setTimeout(r, 5000));
  }

  if (!first || !first.ok) { skip('seeded claim round trip', 'origin unreachable'); return report(); }
  if (first.status === 410) {
    skip('seeded claim round trip', 'seeded invite never became visible to the Worker (KV propagation)');
    unreachable = true;
    return report();
  }

  const okFirst = assert('a seeded invite claims successfully', first.status === 200 && first.json?.ok === true, `HTTP ${first.status}`);
  if (!okFirst) return report();
  roundTripObserved = true;

  const t1 = first.json.token, u1 = first.json.userId;
  if (t1) created.add('tokh:' + sha256(t1));
  if (u1) created.add('user:' + u1);

  assert('the minted token matches the flk_ format', /^flk_[a-f0-9]{32}$/.test(t1 || ''), t1 ? 'shape ok' : 'absent');
  assert('the minted userId matches the u_ format', /^u_/.test(u1 || ''), u1 || 'absent');

  // The credential is real end to end, not just well-shaped: it authenticates.
  const asDriver = await req('/status', { headers: { 'X-Backup-Token': t1, 'X-Device-Id': 'fl-cert-invite' } });
  if (asDriver.ok) {
    assert('the minted token actually authenticates against the live Worker', asDriver.status === 200, `HTTP ${asDriver.status}`);
  } else {
    skip('the minted token actually authenticates against the live Worker', 'origin unreachable');
  }

  // ── 4. Re-claim identity. THE assertion that matters most. ───────────────
  const second = await claim(code);
  if (second.ok && second.status === 200 && second.json?.ok) {
    const t2 = second.json.token, u2 = second.json.userId;
    if (t2) created.add('tokh:' + sha256(t2));
    if (u2) created.add('user:' + u2);

    // Backups are keyed user:<userId>:device:<id>:..., so a second userId here
    // would orphan every backup the driver had already made — silently, while
    // looking like it worked.
    assert('a re-claim returns the SAME userId (a new one would orphan every backup)', u2 === u1, `${u1} vs ${u2}`);
    assert('a re-claim issues a different token', !!t2 && t2 !== t1, 'fresh credential');

    // A re-claim is a rotation, not an accumulation of live credentials.
    const oldTok = await req('/status', { headers: { 'X-Backup-Token': t1, 'X-Device-Id': 'fl-cert-invite' } });
    if (oldTok.ok) {
      assert('the previous token is revoked by the re-claim', oldTok.status === 403, `HTTP ${oldTok.status}`);
    } else {
      skip('the previous token is revoked by the re-claim', 'origin unreachable');
    }

    // ── 5. Exhaustion. maxClaims is 3; the 4th must be refused. ────────────
    const third = await claim(code);
    if (third.ok && third.status === 200 && third.json?.token) {
      created.add('tokh:' + sha256(third.json.token));
      if (third.json.userId) created.add('user:' + third.json.userId);
    }
    const fourth = await claim(code);
    if (fourth.ok) {
      assert('the 4th claim of one invite is refused with 410', fourth.status === 410, `HTTP ${fourth.status}`);
    } else {
      skip('the 4th claim of one invite is refused with 410', 'origin unreachable');
    }
  } else if (second.ok) {
    fail('a re-claim returns the SAME userId (a new one would orphan every backup)', `re-claim returned HTTP ${second.status}`);
  } else {
    skip('a re-claim returns the SAME userId (a new one would orphan every backup)', 'origin unreachable');
  }

  return report();
}

function report() {
  const passed = checks.filter(c => c.state === 'PASS').length;
  const failed = checks.filter(c => c.state === 'FAIL').length;
  const skipped = checks.filter(c => c.state === 'SKIP').length;
  console.log('-'.repeat(72));
  console.log(`  ${passed} passed, ${failed} failed, ${skipped} not run`);

  // A real failure outranks unreachability: evidence of a broken contract is
  // evidence regardless of whether some later check could not be attempted.
  if (failed) {
    console.log('\n  VERDICT: FAILURE — the deployed Worker got the invite/claim contract wrong.');
    console.log('  Do not certify this release generation until this is resolved.');
    return 1;
  }
  if (rateLimited) {
    console.log('\n  VERDICT: UNOBSERVED — the deployed Worker answered /claim with 429.');
    console.log('  That is the per-IP budget (10/hr) being spent, NOT a broken contract. This');
    console.log('  gate spends up to 6 per run and GitHub runners share egress ranges, so a');
    console.log('  second run inside the hour can land here through no fault of the Worker.');
    console.log('  Re-run after the hour rolls over. Do NOT record this as a failure.');
    return 2;
  }
  if (unreachable || !roundTripObserved) {
    console.log('\n  VERDICT: UNOBSERVED — the live origin could not be reached, or the seeded');
    console.log('  claim round trip never ran. This is NOT a pass and NOT a product failure.');
    if (!unreachable && !roundTripObserved) {
      console.log('  The no-state checks above passed, but they do not cover the half of this');
      console.log('  contract that MINTS a credential, so this run cannot report PASS.');
    }
    return 2;
  }
  console.log(`\n  VERDICT: PASS — invite/claim contract verified on ${workerOrigin}.`);
  return 0;
}

let code = 2;
try {
  code = await run();
} catch (e) {
  console.error('\n  Runner error:', (e && e.message) || e);
  console.error('  Recorded as UNOBSERVED rather than as a product failure.');
  code = 2;
} finally {
  // Runs on every path, including a thrown error, so a partial run never leaves
  // a synthetic driver account behind in production KV.
  await cleanup();
}
process.exit(code);
