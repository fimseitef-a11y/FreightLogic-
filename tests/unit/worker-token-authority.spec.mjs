// Worker v20 — canonical-user token authority (Issue #221).
//
// THE DEFECT. Driver authentication resolved the presented bearer token through
// the `tokh:<sha256(token)>` index and then trusted whatever it found:
//
//     tokenRaw = await env.BACKUPS.get('tokh:' + driverTokenHash);
//     ...
//     if (!tokenData.active) return 403;
//     const driverUserId = tokenData.userId;        // authenticated. done.
//
// It never asked the account itself whether that was still its token.
//
// `POST /claim` (and `POST /admin/users/:id/rotate`) re-key in place: they write
// a fresh `tokh:<newHash>` plus `user:<userId>` and delete the hash they
// OBSERVED. Cloudflare KV has no transaction and no compare-and-swap, so two
// overlapping claims can each read the same prior state and each write a token
// record. The last `user:` write wins — but the losing writer's `tokh:` entry
// survives, because the winner deleted a different hash.
//
// The consequence is not cosmetic residue: it is TWO SIMULTANEOUSLY LIVE BEARER
// CREDENTIALS for one driver account, one of which the account does not name and
// nobody can see, valid indefinitely — including after a rotation performed
// specifically to retire it. Every backup is keyed by `userId`, so the stale
// credential reads and writes the live driver's real data.
//
// THE FIX these assertions pin: after the index resolves, load `user:<userId>`,
// require it to be active AND to name the exact hash presented, delete that
// superseded index entry, and 403. This does not make KV atomic — the
// claim-count increment is still a race and is still documented as one. It makes
// the canonical user record the only authority on which hash is current, so a
// losing index entry authenticates nothing.
//
// These drive the REAL exported fetch handler against an in-memory KV. The stale
// entry is SEEDED DIRECTLY rather than produced by racing two claims: the race
// is real but not deterministically reproducible in a single-threaded test, and
// a regression that only fails on an unlucky interleaving is the kind of green
// check this repository has recorded four times over. Seeding the exact residue
// state the race produces is the stronger assertion.
//
// NEGATIVE CONTROL, verified to fire: removing the canonical-user block from
// `cloud-backup-worker.js` makes WTA-01, WTA-02, WTA-03 and WTA-06 pass the
// stale token straight through — WTA-01 returns 200 and the stale credential
// reads the live driver's backup list.

import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-token-authority.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';

function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  const api = {
    _map: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) };
    },
    keys() { return [...m.keys()]; },
  };
  return api;
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  return mod.default;
}

const REQ = (url, opts = {}) => new Request('https://worker.test' + url, opts);

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

const LIVE_TOKEN  = 'flk_' + 'a'.repeat(32);
const STALE_TOKEN = 'flk_' + 'b'.repeat(32);
const USER_ID     = 'u_canonicalauthority01';

/** The exact KV state an interrupted re-key leaves behind: the account names the
 *  live hash, and BOTH index entries exist. */
async function seedRacedRekey({ userActive = true, userHasTokenHash = true } = {}) {
  const liveHash  = await sha256Hex(LIVE_TOKEN);
  const staleHash = await sha256Hex(STALE_TOKEN);

  const canonical = {
    userId: USER_ID, name: 'Dana',
    createdAt: '2026-09-01T00:00:00.000Z',
    active: userActive, backupCount: 3,
  };
  if (userHasTokenHash) canonical.tokenHash = liveHash;

  // The losing writer's record: same userId, its own (now superseded) hash.
  const stale = { ...canonical, tokenHash: staleHash };

  const kv = makeKV({
    ['user:' + USER_ID]: JSON.stringify(canonical),
    ['tokh:' + liveHash]: JSON.stringify(canonical),
    ['tokh:' + staleHash]: JSON.stringify(stale),
    // A real backup belonging to this driver, so "did the stale token reach the
    // live driver's data" is answerable rather than theoretical.
    [`user:${USER_ID}:device:dev_x:backup:2026-09-01T00-00-00-000Z`]: JSON.stringify({ payload: 'ciphertext' }),
    [`user:${USER_ID}:device:dev_x:ptr`]: JSON.stringify({
      keys: [`user:${USER_ID}:device:dev_x:backup:2026-09-01T00-00-00-000Z`], totalCreated: 1,
    }),
  });
  return { kv, liveHash, staleHash };
}

const env = kv => ({ BACKUPS: kv, ADMIN_TOKEN: ADMIN });

function driverReq(pathname, token, method = 'GET') {
  return REQ(pathname, {
    method,
    headers: { 'X-Backup-Token': token, 'X-Device-Id': 'dev_x' },
  });
}

// ── The defect itself ────────────────────────────────────────────────────────

test('[WTA-01] a stale token-index entry for the same user cannot authenticate', async () => {
  const { kv } = await seedRacedRekey();
  const worker = await loadWorker();

  const res = await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));
  eq(res.status, 403,
    `a superseded bearer token must be refused, got ${res.status} — it is a second live credential for one account`);

  const body = await res.json().catch(() => ({}));
  eq(body.ok, false, 'the refusal must not report success');
});

test('[WTA-02] the stale token cannot read the live driver\'s backups', async () => {
  // The property that actually matters. A 403 on /list is only meaningful if no
  // other driver endpoint accepts the same credential.
  const { kv } = await seedRacedRekey();
  const worker = await loadWorker();

  for (const [pathname, method] of [['/list', 'GET'], ['/status', 'GET'], ['/backup', 'GET'], ['/backup/delta', 'GET']]) {
    const res = await worker.fetch(driverReq(pathname, STALE_TOKEN, method), env(kv));
    eq(res.status, 403, `${method} ${pathname} must refuse a superseded token, got ${res.status}`);
    const text = await res.text();
    ok(!text.includes('ciphertext'),
      `${method} ${pathname} leaked the live driver's backup payload to a superseded token`);
  }
});

test('[WTA-03] the live token still works, and is unaffected by the cleanup', async () => {
  // A pass earned by refusing everything would be worthless.
  const { kv, liveHash } = await seedRacedRekey();
  const worker = await loadWorker();

  // Spend the stale token first, so its cleanup has already run.
  await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));

  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 200, `the canonical token must still authenticate, got ${res.status}`);
  ok(kv.keys().includes('tokh:' + liveHash),
    'the live index entry must survive a stale token being refused — one holder must not be able to evict another');
});

test('[WTA-04] presenting the stale token deletes only its own index entry', async () => {
  const { kv, liveHash, staleHash } = await seedRacedRekey();
  const worker = await loadWorker();

  ok(kv.keys().includes('tokh:' + staleHash), 'sanity: the stale entry is seeded');
  await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));

  ok(!kv.keys().includes('tokh:' + staleHash),
    'the superseded index entry must be cleaned by the first request that presents it, not left to linger');
  ok(kv.keys().includes('tokh:' + liveHash), 'the canonical entry must be untouched');
  ok(kv.keys().includes('user:' + USER_ID), 'the account record must be untouched');
});

test('[WTA-05] a second attempt with the stale token is still refused after cleanup', async () => {
  const { kv } = await seedRacedRekey();
  const worker = await loadWorker();

  await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));
  const again = await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));
  eq(again.status, 403, 'the now-absent index entry must still be a refusal, not a different outcome');
});

// ── Fail-closed shapes ───────────────────────────────────────────────────────

test('[WTA-06] a token index entry naming a revoked account is refused', async () => {
  // Revoke writes `active:false` to the user record; an index entry left saying
  // `active:true` must not be able to contradict it.
  const { kv, liveHash } = await seedRacedRekey({ userActive: false });
  // Make the index entry lie, which is exactly the residue case.
  const lying = JSON.parse(kv._map.get('tokh:' + liveHash));
  lying.active = true;
  kv._map.set('tokh:' + liveHash, JSON.stringify(lying));

  const worker = await loadWorker();
  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 403, 'the user record is the authority on revocation, not the token index');
});

test('[WTA-07] a token index entry with no account record at all is refused', async () => {
  const liveHash = await sha256Hex(LIVE_TOKEN);
  const kv = makeKV({
    ['tokh:' + liveHash]: JSON.stringify({ userId: USER_ID, name: 'Dana', active: true, tokenHash: liveHash }),
    // no `user:` record
  });
  const worker = await loadWorker();
  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 403, 'an index entry is not an account — with no user record this must fail closed');
});

test('[WTA-08] a legacy v7 account with plaintext token and no tokenHash still authenticates', async () => {
  // The one place a naive "require user.tokenHash" rule would have locked a real
  // driver out. v7 wrote `token` in plaintext and no hash; the canonical hash is
  // DERIVED from it rather than waved through, so there is no fail-open branch.
  const kv = makeKV({
    ['user:' + USER_ID]: JSON.stringify({
      userId: USER_ID, name: 'Dana', token: LIVE_TOKEN, active: true, backupCount: 0,
    }),
    ['tokh:' + await sha256Hex(LIVE_TOKEN)]: JSON.stringify({
      userId: USER_ID, name: 'Dana', tokenHash: await sha256Hex(LIVE_TOKEN), active: true,
    }),
  });
  const worker = await loadWorker();
  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 200, `a legacy plaintext account must still work, got ${res.status}`);

  // ...and the same legacy record must not accept a DIFFERENT token.
  const res2 = await worker.fetch(driverReq('/list', STALE_TOKEN), env(kv));
  eq(res2.status, 403, 'deriving the legacy hash must not become a way in for any other token');
});

test('[WTA-09] an account record carrying neither tokenHash nor token is refused', async () => {
  const liveHash = await sha256Hex(LIVE_TOKEN);
  const kv = makeKV({
    ['user:' + USER_ID]: JSON.stringify({ userId: USER_ID, name: 'Dana', active: true }),
    ['tokh:' + liveHash]: JSON.stringify({ userId: USER_ID, name: 'Dana', tokenHash: liveHash, active: true }),
  });
  const worker = await loadWorker();
  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 403, 'a malformed account must fail closed rather than fall back to trusting the index');
});

test('[WTA-10] an index entry with no userId is refused', async () => {
  const liveHash = await sha256Hex(LIVE_TOKEN);
  const kv = makeKV({
    ['tokh:' + liveHash]: JSON.stringify({ name: 'Dana', active: true, tokenHash: liveHash }),
  });
  const worker = await loadWorker();
  const res = await worker.fetch(driverReq('/list', LIVE_TOKEN), env(kv));
  eq(res.status, 403, 'a token that names no account cannot be resolved to one');
});

// ── Rotation and claim end to end ────────────────────────────────────────────

test('[WTA-11] after an in-place rotation the previous token is dead', async () => {
  // Drives the REAL rotate endpoint rather than seeding its result, so this also
  // covers rotation continuing to delete the hash it observed.
  const kv = makeKV(); const worker = await loadWorker();

  const created = await worker.fetch(REQ('/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN },
    body: JSON.stringify({ name: 'Dana' }),
  }), env(kv));
  const { userId, token: first } = await created.json();

  eq((await worker.fetch(driverReq('/list', first), env(kv))).status, 200,
    'sanity: the freshly minted token works');

  const rotated = await worker.fetch(REQ(`/admin/users/${userId}/rotate`, {
    method: 'POST', headers: { 'X-Admin-Token': ADMIN },
  }), env(kv));
  const { token: second } = await rotated.json();
  ok(second && second !== first, 'rotation must mint a different token');

  eq((await worker.fetch(driverReq('/list', second), env(kv))).status, 200,
    'the rotated token must work');
  eq((await worker.fetch(driverReq('/list', first), env(kv))).status, 403,
    'the pre-rotation token must be dead — that is what rotation is for');
});

// ── CORS authority (Issue #221, related cleanup) ─────────────────────────────

test('[WTA-12] the retired Pages origins are no longer echoed by CORS', async () => {
  const worker = await loadWorker();
  const kv = makeKV();
  const live = 'https://freightlogic-v2.fimseitef.workers.dev';

  for (const stale of ['https://freightlogic.pages.dev', 'https://www.freightlogic.pages.dev']) {
    const res = await worker.fetch(REQ('/health', { headers: { Origin: stale } }), env(kv));
    const echoed = res.headers.get('Access-Control-Allow-Origin');
    ok(echoed !== stale,
      `a retired origin must not be echoed as allowed (got ${echoed}) — an origin nobody deploys to is one nobody can vouch for`);
    eq(echoed, live, 'an unrecognised origin falls back to the production app origin');
  }

  const good = await worker.fetch(REQ('/health', { headers: { Origin: live } }), env(kv));
  eq(good.headers.get('Access-Control-Allow-Origin'), live, 'the live app origin is still allowed');
});

test('[WTA-13] env.ALLOWED_ORIGIN remains the configuration hook', async () => {
  // Removing the hardcoded legacy origins must not remove the ability to add an
  // origin later — otherwise the cleanup becomes a reason to re-add code.
  const worker = await loadWorker();
  const configured = 'https://freightlogic.example';
  const res = await worker.fetch(REQ('/health', { headers: { Origin: configured } }),
    { BACKUPS: makeKV(), ADMIN_TOKEN: ADMIN, ALLOWED_ORIGIN: configured });
  eq(res.headers.get('Access-Control-Allow-Origin'), configured,
    'an exact-match configured origin is still honoured');
});

test('[WTA-14] /health reports the Worker generation this candidate ships', async () => {
  const worker = await loadWorker();
  const res = await worker.fetch(REQ('/health'), env(makeKV()));
  const body = await res.json();
  eq(res.status, 200, 'health must be reachable');
  // Read the generation out of the source rather than pinning a literal, so a
  // future Worker bump needs no edit here (the CG-09 convention).
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(path.join(ROOT, 'cloud-backup-worker.js'), 'utf8');
  const headerVersion = src.match(/Cloud Backup Worker v(\d+)/)?.[1];
  ok(headerVersion, 'could not read the Worker generation from its own header');
  eq(String(body.version), headerVersion,
    'the reported version and the header must name the same generation');
});

export async function runSpec() { return run(); }
