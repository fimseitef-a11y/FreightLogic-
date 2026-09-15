// Worker v18 — zero-token driver onboarding (POST /admin/invites, POST /claim).
//
// WHAT THESE ARE REALLY GUARDING. Before v18 the only way to onboard a driver
// was POST /admin/users, which returns a permanent `flk_` bearer token that then
// had to be carried to the driver's phone by a human — so the credential came to
// rest in an inbox or an iMessage thread and stayed there indefinitely, readable
// by anyone who later picked up either device, long after that driver had been
// onboarded or even revoked.
//
// A claim code is the opposite trade: spent on redemption, dead in 72 hours on
// its own, stored only as a SHA-256 hash, and the token it produces is delivered
// straight to the claiming device. WIC-11 is the assertion that actually says
// so — it dumps the whole KV namespace and greps it for the plaintext code and
// every issued token.
//
// These drive the REAL exported fetch handler from cloud-backup-worker.js
// against an in-memory KV, not a reimplementation of its logic. The only thing
// swapped is Cloudflare's KV binding — and unlike the KV stand-in in
// worker-token-rotation.spec.mjs, this one honours `expirationTtl`, because
// three of the properties below (72h expiry, the re-put not extending it, and
// the rate-limit window) are invisible without it.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-invite-claim.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';

/** KV stand-in WITH expiry support. `now()` is injectable so a test can move
 *  the clock forward without sleeping — an expiry test that really waited 72
 *  hours is not a test anyone runs. */
function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  const exp = new Map();
  const api = {
    _map: m,
    _exp: exp,
    now: () => Date.now(),
    _live(k) {
      if (!m.has(k)) return false;
      const e = exp.get(k);
      if (e !== undefined && api.now() >= e) { m.delete(k); exp.delete(k); return false; }
      return true;
    },
    async get(k) { return api._live(k) ? m.get(k) : null; },
    async put(k, v, opts) {
      m.set(k, v);
      // Cloudflare resets the TTL on every put. That is exactly why the Worker
      // has to re-derive the ORIGINAL expiry when it writes an invite back.
      if (opts && opts.expirationTtl) exp.set(k, api.now() + opts.expirationTtl * 1000);
      else exp.delete(k);
    },
    async delete(k) { m.delete(k); exp.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => api._live(k) && k.startsWith(prefix)).map(name => ({ name })) };
    },
    /** Everything currently stored, as one string — for the no-plaintext sweep. */
    dump() {
      return [...m.entries()].filter(([k]) => api._live(k)).map(([k, v]) => k + '=' + v).join('\n');
    },
  };
  return api;
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  return mod.default;
}

const REQ = (url, opts = {}) => new Request('https://worker.test' + url, opts);

function adminInvite(name = 'Dana', token = ADMIN) {
  const headers = { 'Content-Type': 'application/json' };
  if (token !== null) headers['X-Admin-Token'] = token;
  return REQ('/admin/invites', { method: 'POST', headers, body: JSON.stringify({ name }) });
}

function claimReq(code, ip = '203.0.113.7') {
  return REQ('/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
    body: JSON.stringify({ code }),
  });
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Mint an invite and hand back the parsed body. */
async function mintInvite(worker, env, name = 'Dana') {
  const res = await worker.fetch(adminInvite(name), env);
  const body = await res.json();
  return { res, body };
}

// ── Admin auth on the invite endpoint ────────────────────────────────────────

test('[WIC-01] POST /admin/invites with NO admin token is 401', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const res = await worker.fetch(adminInvite('Dana', null), { BACKUPS: kv, ADMIN_TOKEN: ADMIN });
  eq(res.status, 401, `expected 401, got ${res.status}`);
  ok(!kv.dump().includes('inv:'), 'an unauthenticated request must not create an invite');
});

test('[WIC-02] POST /admin/invites with the WRONG admin token is 401', async () => {
  const kv = makeKV(); const worker = await loadWorker();
  const res = await worker.fetch(adminInvite('Dana', 'not-the-admin-token'), { BACKUPS: kv, ADMIN_TOKEN: ADMIN });
  eq(res.status, 401, `expected 401, got ${res.status}`);
  ok(!kv.dump().includes('inv:'), 'a rejected request must not create an invite');
});

test('[WIC-03] a valid invite returns a 24-char base32 code and stores only its hash', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { res, body } = await mintInvite(worker, env, 'Dana');

  eq(res.status, 201, `expected 201, got ${res.status}`);
  eq(body.ok, true, 'invite must report ok');
  ok(/^[A-Z2-7]{24}$/.test(body.code), `code must be 24 base32 chars, got ${body.code}`);
  // 15 random bytes is exactly 120 bits and exactly 24 chars with no padding,
  // which is why the /claim validator can be exact rather than lenient.
  eq(body.code.length, 24, 'code length must be exactly 24');
  ok(!/[018]/.test(body.code), 'alphabet must omit 0/1/8 — the characters misread off a phone screen');

  const hash = await sha256Hex(body.code);
  ok(kv._map.has('inv:' + hash), 'the invite must be stored under the SHA-256 of the code');
  ok(!kv.dump().includes(body.code), 'the PLAINTEXT code must never be written to KV');

  const expMs = new Date(body.expiresAt).getTime() - Date.now();
  ok(expMs > 71 * 3600 * 1000 && expMs <= 72 * 3600 * 1000, `expiry should be ~72h, got ${expMs}ms`);
});

// ── Claim validation ─────────────────────────────────────────────────────────

test('[WIC-04] a malformed code is 400 and is never hashed into a lookup', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  for (const bad of ['', 'short', 'AAAA', 'AAAAAAAAAAAAAAAAAAAAAAAAA', 'AAAAAAAAAAAAAAAAAAAAAA01', 'aaaaaaaaaaaaaaaaaaaaaaa!']) {
    const res = await worker.fetch(claimReq(bad), env);
    eq(res.status, 400, `"${bad}" should be 400, got ${res.status}`);
  }
});

test('[WIC-05] an unknown but well-formed code is 410, not 404', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const res = await worker.fetch(claimReq('AAAAAAAAAAAAAAAAAAAAAAAA'), env);
  // 410 for "never existed", "expired" and "already spent" alike. A distinct
  // 404 would be an oracle confirming which codes were once real.
  eq(res.status, 410, `expected 410, got ${res.status}`);
});

test('[WIC-06] a valid claim returns a well-formed token and a u_ userId', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');

  const res = await worker.fetch(claimReq(inv.code), env);
  const body = await res.json();
  eq(res.status, 200, `expected 200, got ${res.status}`);
  eq(body.ok, true, 'claim must report ok');
  ok(/^flk_[a-f0-9]{32}$/.test(body.token), `token must match flk_[a-f0-9]{32}, got ${body.token}`);
  ok(/^u_/.test(body.userId), `userId must start with u_, got ${body.userId}`);
  eq(body.name, 'Dana', 'the invited name must carry through to the account');

  const rec = JSON.parse(await kv.get('user:' + body.userId));
  eq(rec.active, true, 'a claimed driver must be active');
  eq(rec.tokenHash, await sha256Hex(body.token), 'the record must store the token HASH');
  ok(!('token' in rec), 'the record must carry no plaintext token field');
});

test('[WIC-07] claims 2 and 3 return the SAME userId with a fresh token, and revoke the old one', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');

  const c1 = await (await worker.fetch(claimReq(inv.code), env)).json();
  const c2 = await (await worker.fetch(claimReq(inv.code), env)).json();
  const c3 = await (await worker.fetch(claimReq(inv.code), env)).json();

  // Same identity is the whole point: backups are keyed user:<userId>:..., so a
  // second userId would orphan everything the first one had already stored.
  // This is what makes the iOS Safari -> Home Screen storage split recoverable.
  eq(c2.userId, c1.userId, 'a re-claim MUST keep the same userId or it orphans every backup');
  eq(c3.userId, c1.userId, 'the third claim must keep the same userId too');
  ok(c2.token !== c1.token, 'each claim must issue a fresh token');
  ok(c3.token !== c2.token, 'the third token must differ from the second');

  // A re-claim is a rotation, not an accumulation of live credentials.
  eq(await kv.get('tokh:' + await sha256Hex(c1.token)), null, 'the first token must be revoked');
  eq(await kv.get('tokh:' + await sha256Hex(c2.token)), null, 'the second token must be revoked');
  ok(await kv.get('tokh:' + await sha256Hex(c3.token)), 'the newest token must be live');
});

test('[WIC-08] the 4th claim is 410 and the invite key is deleted', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');
  const hash = await sha256Hex(inv.code);

  for (let i = 0; i < 3; i++) {
    const r = await worker.fetch(claimReq(inv.code), env);
    eq(r.status, 200, `claim ${i + 1} should succeed, got ${r.status}`);
  }
  const fourth = await worker.fetch(claimReq(inv.code), env);
  eq(fourth.status, 410, `the 4th claim should be 410, got ${fourth.status}`);
  eq(await kv.get('inv:' + hash), null, 'a spent invite must be deleted, not merely refused');
});

test('[WIC-09] re-putting the invite does NOT extend its original expiry', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');
  const hash = await sha256Hex(inv.code);
  const originalExpiry = kv._exp.get('inv:' + hash);
  const originalIso = inv.expiresAt;

  // Move 71 hours in — still inside the window, so the claim must succeed.
  //
  // BOTH clocks have to move. The Worker derives the remaining TTL from
  // Date.now(); the KV stand-in applies that TTL against its own now(). An
  // earlier version of this test advanced only the KV clock and "failed",
  // reporting a three-day extension that was really just two clocks 71 hours
  // apart. A time test that leaves a second clock behind measures the gap
  // between them, not the behaviour under test.
  const realNow = Date.now;
  let clock = realNow() + 71 * 3600 * 1000;
  kv.now = () => clock;
  Date.now = () => clock;
  try {
    const r = await worker.fetch(claimReq(inv.code), env);
    eq(r.status, 200, `a claim at 71h should still work, got ${r.status}`);

    // Cloudflare resets the TTL on every put, so without the Worker re-deriving
    // the remaining TTL this re-put would push the deadline 72h further out and
    // a repeatedly-claimed invite would never expire at all.
    const afterExpiry = kv._exp.get('inv:' + hash);
    ok(afterExpiry <= originalExpiry + 1000,
      `expiry must not be extended: was ${new Date(originalExpiry).toISOString()}, now ${new Date(afterExpiry).toISOString()}`);
    eq(JSON.parse(kv._map.get('inv:' + hash)).expiresAt, originalIso, 'the recorded expiresAt must be unchanged');

    // Past the original deadline the invite is simply gone.
    clock = new Date(originalIso).getTime() + 1000;
    const late = await worker.fetch(claimReq(inv.code), env);
    eq(late.status, 410, `a claim past the original expiry should be 410, got ${late.status}`);
  } finally {
    Date.now = realNow;
  }
});

test('[WIC-10] a claim after the driver is revoked is 403', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');
  const first = await (await worker.fetch(claimReq(inv.code), env)).json();

  const del = await worker.fetch(REQ('/admin/users/' + first.userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env);
  eq(del.status, 200, `revoke should succeed, got ${del.status}`);

  // Revoking someone must not be undone by an invite link they still hold.
  const res = await worker.fetch(claimReq(inv.code), env);
  eq(res.status, 403, `a claim against a revoked driver should be 403, got ${res.status}`);
  const body = await res.json();
  ok(!body.token, 'a refused claim must not return a token');
});

test('[WIC-11] the 11th claim attempt from one IP within the hour is 429', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const IP = '198.51.100.22';
  // Ten malformed guesses still consume the allowance — the limit is checked
  // BEFORE the code is parsed, which is what makes it a brute-force defence
  // rather than a defence against well-formed guesses only.
  for (let i = 0; i < 10; i++) {
    const r = await worker.fetch(claimReq('AAAAAAAAAAAAAAAAAAAAAAAA', IP), env);
    ok(r.status !== 429, `attempt ${i + 1} should not be rate limited, got ${r.status}`);
  }
  const res = await worker.fetch(claimReq('AAAAAAAAAAAAAAAAAAAAAAAA', IP), env);
  eq(res.status, 429, `the 11th attempt should be 429, got ${res.status}`);

  // A different IP is unaffected — the limit is per-IP, not global.
  const other = await worker.fetch(claimReq('AAAAAAAAAAAAAAAAAAAAAAAA', '198.51.100.23'), env);
  ok(other.status !== 429, `a different IP should not be limited, got ${other.status}`);
});

test('[WIC-12] KV never contains a plaintext code or a plaintext token, at any point', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');

  const seen = [inv.code];
  ok(!kv.dump().includes(inv.code), 'after minting: the code must not be in KV');

  for (let i = 0; i < 3; i++) {
    const c = await (await worker.fetch(claimReq(inv.code), env)).json();
    seen.push(c.token);
    const dump = kv.dump();
    for (const secret of seen) {
      ok(!dump.includes(secret), `after claim ${i + 1}: KV must not contain the plaintext value ${secret.slice(0, 6)}...`);
    }
  }
  // And the flk_ prefix must appear nowhere at all — the strongest form of the
  // claim, since it would catch a token stored under any key name.
  ok(!kv.dump().includes('flk_'), 'no plaintext flk_ token may exist anywhere in KV');
});

// ── Re-invite binds to an existing driver ────────────────────────────────────

test('[WIC-16] a re-invite claims into the SAME account and keeps its backup history', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const first = await (await worker.fetch(claimReq((await mintInvite(worker, env, 'Dana')).body.code), env)).json();

  // Give the driver real history, so orphaning it would be visible.
  const push = await worker.fetch(REQ('/backup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Backup-Token': first.token, 'X-Device-Id': 'oldphone' },
    body: JSON.stringify({ encrypted: 'DANA-HISTORY', iv: 'i', salt: 's' }),
  }), env);
  eq(push.status, 200, `the first device should be able to back up, got ${push.status}`);

  // Re-invite: a NEW code, bound to the EXISTING userId.
  const res = await worker.fetch(REQ('/admin/invites', {
    method: 'POST',
    headers: { 'X-Admin-Token': ADMIN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Dana', userId: first.userId }),
  }), env);
  const inv2 = await res.json();
  eq(res.status, 201, `a bound invite should be created, got ${res.status}`);
  eq(inv2.userId, first.userId, 'the invite must record the account it is bound to');
  eq(inv2.reinvite, true, 'the response must say this is a re-invite');

  const second = await (await worker.fetch(claimReq(inv2.code), env)).json();

  // THE ASSERTION THAT MATTERS. A second userId would leave DANA-HISTORY in KV
  // with nothing able to address it — the exact failure in-place rotation
  // exists to prevent, reintroduced through a button labelled "Re-invite".
  eq(second.userId, first.userId, 'a re-invite MUST claim into the same account, or every backup is orphaned');
  ok(second.token !== first.token, 'a re-invite must issue a fresh token');
  eq(await kv.get('tokh:' + await sha256Hex(first.token)), null, 'the old token must be revoked');

  const read = await (await worker.fetch(REQ('/backup', { headers: { 'X-Backup-Token': second.token, 'X-Device-Id': 'oldphone' } }), env)).json();
  eq(read.encrypted, 'DANA-HISTORY', 'the new token must reach the history made under the old one');

  const users = await (await worker.fetch(REQ('/admin/users', { headers: { 'X-Admin-Token': ADMIN } }), env)).json();
  eq(users.users.length, 1, `a re-invite must not create a second driver, saw ${users.users.length}`);
});

test('[WIC-17] a re-invite is refused for an unknown or revoked driver', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const bind = (userId) => worker.fetch(REQ('/admin/invites', {
    method: 'POST',
    headers: { 'X-Admin-Token': ADMIN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Dana', userId }),
  }), env);

  eq((await bind('not-a-user-id')).status, 400, 'a malformed userId must be 400');
  eq((await bind('u_deadbeefdeadbeef')).status, 404, 'an unknown userId must be 404');

  const c = await (await worker.fetch(claimReq((await mintInvite(worker, env, 'Dana')).body.code), env)).json();
  await worker.fetch(REQ('/admin/users/' + c.userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env);
  // Claiming would be refused anyway (403), so issuing the link would only hand
  // the operator something that cannot work.
  eq((await bind(c.userId)).status, 409, 'a revoked driver must not be re-invitable');
});

// ── Isolation ────────────────────────────────────────────────────────────────

test('[WIC-13] driver A cannot read driver B\'s backup', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const a = await (await worker.fetch(claimReq((await mintInvite(worker, env, 'Ana')).body.code), env)).json();
  const b = await (await worker.fetch(claimReq((await mintInvite(worker, env, 'Ben')).body.code, '203.0.113.8'), env)).json();
  ok(a.userId !== b.userId, 'two separate invites must produce two separate accounts');

  const push = (tok, payload) => worker.fetch(REQ('/backup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Backup-Token': tok, 'X-Device-Id': 'dev1' },
    body: JSON.stringify(payload),
  }), env);

  eq((await push(a.token, { encrypted: 'AAA-ana', iv: 'i', salt: 's' })).status, 200, 'A should be able to back up');
  eq((await push(b.token, { encrypted: 'BBB-ben', iv: 'i', salt: 's' })).status, 200, 'B should be able to back up');

  const readA = await (await worker.fetch(REQ('/backup', { headers: { 'X-Backup-Token': a.token, 'X-Device-Id': 'dev1' } }), env)).json();
  const readB = await (await worker.fetch(REQ('/backup', { headers: { 'X-Backup-Token': b.token, 'X-Device-Id': 'dev1' } }), env)).json();
  eq(readA.encrypted, 'AAA-ana', 'A must read A\'s own backup');
  eq(readB.encrypted, 'BBB-ben', 'B must read B\'s own backup');
  ok(readA.encrypted !== readB.encrypted, 'the two drivers must not share a payload');
});

test('[WIC-14] a revoked driver\'s token is 403 on /backup', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const c = await (await worker.fetch(claimReq((await mintInvite(worker, env, 'Dana')).body.code), env)).json();

  const before = await worker.fetch(REQ('/status', { headers: { 'X-Backup-Token': c.token, 'X-Device-Id': 'dev1' } }), env);
  eq(before.status, 200, `a live token should work, got ${before.status}`);

  await worker.fetch(REQ('/admin/users/' + c.userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env);

  const after = await worker.fetch(REQ('/backup', { headers: { 'X-Backup-Token': c.token, 'X-Device-Id': 'dev1' } }), env);
  eq(after.status, 403, `a revoked token should be 403 on /backup, got ${after.status}`);
});

// ── Endpoint placement ───────────────────────────────────────────────────────

test('[WIC-15] /claim requires NO backup token, and /health reports v18', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const { body: inv } = await mintInvite(worker, env, 'Dana');

  // The request carries no X-Backup-Token at all. If /claim were placed below
  // the driver-token gate this would be 401 "Missing token" — which would be
  // circular, since /claim is how a device gets its first token.
  const res = await worker.fetch(claimReq(inv.code), env);
  eq(res.status, 200, `/claim must not require a backup token, got ${res.status}`);

  const health = await (await worker.fetch(REQ('/health'), env)).json();
  eq(String(health.version), '18', `health should report v18, got ${health.version}`);
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
