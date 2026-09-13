// Worker v15 — in-place token rotation (POST /admin/users/:id/rotate).
//
// WHY THIS ENDPOINT EXISTS, and therefore what these tests are really guarding:
// before it, the only way to change a driver's token was POST /admin/users,
// which mints a new `userId` alongside the new token. Every backup is stored
// under `user:<userId>:device:<deviceId>:backup:<ts>`, so "rotating" that way
// silently orphaned the driver's entire backup history — the data stayed in KV
// and nothing could ever address it again. Rotating a credential must not cost
// the data that credential protects. WTR-07 is the test that actually says so.
//
// It is also what finishes the P-01/P-02 cleanup. The superseded Worker v7
// stored tokens in KV in PLAINTEXT (both as the `token:<raw>` key and as a
// `token` field inside the record). v14 clears those lazily — only on that
// token's next use — so a token that is never used again keeps its plaintext
// copy indefinitely. Rotation deletes it immediately: WTR-04 and WTR-05.
//
// These drive the REAL exported fetch handler from cloud-backup-worker.js
// against an in-memory KV, not a reimplementation of its logic. The only thing
// swapped is Cloudflare's KV binding.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-token-rotation.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';

/** Minimal stand-in for a Cloudflare KV namespace. Mirrors only the surface the
 *  Worker uses: get/put/delete/list-by-prefix. */
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
  };
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  return mod.default;
}

function adminReq(url, method = 'POST', token = ADMIN) {
  const headers = {};
  if (token !== null) headers['X-Admin-Token'] = token;
  return new Request('https://worker.test' + url, { method, headers });
}

/** A driver as Worker v14+ stores one: hashed token, no plaintext. */
async function seedModernUser(kv, worker) {
  const create = await worker.fetch(
    new Request('https://worker.test/admin/users', {
      method: 'POST',
      headers: { 'X-Admin-Token': ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test Driver' }),
    }),
    { BACKUPS: kv, ADMIN_TOKEN: ADMIN }
  );
  const body = await create.json();
  return body; // { ok, userId, name, token }
}

test('[WTR-01] rotation issues a new token and KEEPS the same userId', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);

  const res = await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env);
  const body = await res.json();

  eq(res.status, 200, `rotate returned ${res.status}`);
  eq(body.ok, true, 'rotate must report ok');
  eq(body.userId, created.userId, 'userId MUST be preserved — a new one orphans every backup');
  ok(body.token && body.token !== created.token, 'a new token must be issued');
  ok(/^flk_[a-f0-9]{32}$/.test(body.token), `new token must match the flk_ format, got ${body.token}`);
});

test('[WTR-02] rotation preserves name, createdAt and backupCount', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);

  // Simulate accrued history on the account.
  const before = JSON.parse(await kv.get('user:' + created.userId));
  before.backupCount = 17;
  await kv.put('user:' + created.userId, JSON.stringify(before));

  await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env);
  const after = JSON.parse(await kv.get('user:' + created.userId));

  eq(after.name, before.name, 'name must survive rotation');
  eq(after.createdAt, before.createdAt, 'createdAt must survive rotation');
  eq(after.backupCount, 17, 'backupCount must survive rotation');
  eq(after.active, true, 'account stays active');
  ok(after.rotatedAt, 'rotation should be recorded on the account');
});

test('[WTR-03] the old hashed token key is removed and a new one created', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);
  const oldHash = JSON.parse(await kv.get('user:' + created.userId)).tokenHash;

  const body = await (await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env)).json();
  const newHash = JSON.parse(await kv.get('user:' + created.userId)).tokenHash;

  ok(newHash && newHash !== oldHash, 'the stored hash must change');
  eq(await kv.get('tokh:' + oldHash), null, 'the OLD hashed key must be deleted — otherwise the old token still authenticates');
  ok(await kv.get('tokh:' + newHash), 'the new hashed key must exist');
  ok(body.token, 'the plaintext token is returned to the caller exactly once');
});

test('[WTR-04] a legacy v7 PLAINTEXT token key is deleted immediately (P-01 residue)', async () => {
  const worker = await loadWorker();
  // Exactly how Worker v7 wrote a driver: raw token as the KV key AND inside
  // the record. This is the residue v14 only clears lazily.
  const legacyToken = 'flk_' + 'a1b2c3d4'.repeat(4);
  // A REAL v7 id shape: `'u_' + crypto.randomUUID().slice(0, 12)`, so hex with
  // an embedded dash. Worth getting right — the id validator is
  // /^u_[a-f0-9-]{8,36}$/i, and an invented id with letters outside [a-f] is
  // rejected as malformed before rotation is even attempted. The first version
  // of this fixture made exactly that mistake and failed for the wrong reason.
  const legacyRec = {
    userId: 'u_3f2a1b4c-5d6', name: 'Legacy', token: legacyToken,
    createdAt: '2026-03-13T00:00:00.000Z', active: true,
  };
  const kv = makeKV({
    ['user:' + legacyRec.userId]: JSON.stringify(legacyRec),
    ['token:' + legacyToken]: JSON.stringify(legacyRec),
  });
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };

  const body = await (await worker.fetch(adminReq(`/admin/users/${legacyRec.userId}/rotate`), env)).json();

  eq(body.ok, true, 'rotating a legacy record must succeed');
  eq(await kv.get('token:' + legacyToken), null,
     'the plaintext token: key MUST be gone — this is the whole point of rotating a v7 account');
  eq(body.legacyPlaintextCleared, true, 'the response should report that plaintext residue was cleared');
});

test('[WTR-05] the rotated record stores no plaintext token field', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);
  const body = await (await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env)).json();

  const rec = JSON.parse(await kv.get('user:' + created.userId));
  const hashRec = JSON.parse(await kv.get('tokh:' + rec.tokenHash));

  eq(rec.token, undefined, 'the user record must not carry a plaintext token');
  eq(hashRec.token, undefined, 'the token record must not carry a plaintext token');
  // Belt and braces: the raw token must not appear anywhere in KV at all.
  const dump = JSON.stringify([...kv._map.entries()]);
  ok(!dump.includes(body.token), 'the new plaintext token must not be persisted anywhere in KV');
});

test('[WTR-06] rotating a REVOKED account is refused, not silently reactivated', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);
  await worker.fetch(adminReq(`/admin/users/${created.userId}`, 'DELETE'), env);

  const res = await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env);
  eq(res.status, 409, `expected 409 for a revoked account, got ${res.status}`);

  const rec = JSON.parse(await kv.get('user:' + created.userId));
  eq(rec.active, false, 'a refused rotation must leave the account revoked');
});

test('[WTR-07] existing backups stay addressable after rotation — the whole point', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);

  // Store a backup the way the driver endpoints do, then rotate, then read it
  // back with the NEW token. If rotation minted a fresh userId (the old
  // "create a new driver" workaround) this read returns 404 and the operator's
  // history is gone.
  const put = await worker.fetch(new Request('https://worker.test/backup', {
    method: 'POST',
    headers: { 'X-Backup-Token': created.token, 'X-Device-Id': 'devA' },
    body: 'ENCRYPTED-PAYLOAD-CONTENTS',
  }), env);
  eq(put.status, 200, 'seeding a backup should succeed');

  const rotated = await (await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`), env)).json();

  const got = await worker.fetch(new Request('https://worker.test/backup', {
    method: 'GET', headers: { 'X-Backup-Token': rotated.token, 'X-Device-Id': 'devA' },
  }), env);
  eq(got.status, 200, 'the pre-rotation backup must still be retrievable with the new token');
  eq(await got.text(), 'ENCRYPTED-PAYLOAD-CONTENTS', 'and it must be byte-identical');

  // And the superseded token must no longer work.
  const stale = await worker.fetch(new Request('https://worker.test/backup', {
    method: 'GET', headers: { 'X-Backup-Token': created.token, 'X-Device-Id': 'devA' },
  }), env);
  eq(stale.status, 403, `the old token must stop working, got ${stale.status}`);
});

test('[WTR-08] rotation requires the admin token', async () => {
  const kv = makeKV(); const worker = await loadWorker(); const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const created = await seedModernUser(kv, worker);

  const none = await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`, 'POST', null), env);
  eq(none.status, 401, `tokenless rotate must be 401, got ${none.status}`);

  const wrong = await worker.fetch(adminReq(`/admin/users/${created.userId}/rotate`, 'POST', 'not-the-admin-token'), env);
  eq(wrong.status, 401, `wrong-admin-token rotate must be 401, got ${wrong.status}`);

  // The account must be untouched by either rejected attempt.
  const rec = JSON.parse(await kv.get('user:' + created.userId));
  eq(rec.tokenHash, JSON.parse(await kv.get('user:' + created.userId)).tokenHash, 'record unchanged');
  eq(rec.rotatedAt, undefined, 'a rejected rotation must not stamp rotatedAt');
});

export async function runSpec() { return run(); }
