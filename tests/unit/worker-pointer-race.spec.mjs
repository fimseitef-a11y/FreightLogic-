// Worker backup/delta key-integrity regressions.
//
// WPR-01/02 (v16): first-write pointer discovery must not index the just-written
// key twice. WPR-03 (v17): two writes inside one millisecond must not share a
// key at all — they did, and the second silently overwrote the first.
//
// Cloudflare KV can make a put visible to list() while the Worker is doing
// Promise.all([put(newKey), getPtr(...)]) on a device with no pointer yet. The
// old code then appended newKey after getPtr() had already discovered it,
// producing duplicate pointers such as [delta1, delta1, delta2]. This spec
// drives the REAL Worker with an in-memory KV whose put() is immediately visible
// to list(), reproducing the exact production failure deterministically.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-pointer-race.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';

function makeKV() {
  const m = new Map();
  return {
    _map: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) {
      // Deliberately visible synchronously before this async function resolves.
      // That is the race shape observed in production: list() can see the new
      // data key while getPtr() is performing its first lazy migration.
      m.set(k, v);
    },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) };
    },
  };
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href + `?ptr-race=${Date.now()}-${Math.random()}`);
  return mod.default;
}

async function seedDriver(worker, kv) {
  const res = await worker.fetch(new Request('https://worker.test/admin/users', {
    method: 'POST',
    headers: { 'X-Admin-Token': ADMIN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Pointer Race Driver' }),
  }), { BACKUPS: kv, ADMIN_TOKEN: ADMIN });
  eq(res.status, 201, 'test driver creation must succeed');
  return res.json();
}

function driverReq(pathname, method, token, device, body) {
  const headers = {
    'X-Backup-Token': token,
    'X-Device-Id': device,
  };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  return new Request('https://worker.test' + pathname, { method, headers, body });
}

test('[WPR-01] first delta write is indexed exactly once when list() already sees it', async () => {
  const kv = makeKV();
  const worker = await loadWorker();
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const driver = await seedDriver(worker, kv);
  const device = 'ptr-race-delta';
  const payloads = [1, 2].map(seq => JSON.stringify({ kind: 'delta', seq, filler: 'x'.repeat(32) }));

  for (const payload of payloads) {
    const res = await worker.fetch(driverReq('/backup/delta', 'POST', driver.token, device, payload), env);
    eq(res.status, 200, `delta POST must succeed, got ${res.status}`);
  }

  const res = await worker.fetch(driverReq('/backup/delta', 'GET', driver.token, device), env);
  const body = await res.json();
  eq(res.status, 200, 'delta GET must succeed');
  eq(body.deltas.length, 2, `exactly two deltas must be returned, got ${body.deltas.length}`);
  eq(body.retainedCount, 2, 'retainedCount must count unique delta keys');
  eq(body.totalCreated, 2, 'totalCreated must count real delta writes once each');

  const seqs = body.deltas.map(d => JSON.parse(d.payload).seq);
  eq(JSON.stringify(seqs), JSON.stringify([1, 2]), `delta order must be [1,2], got ${JSON.stringify(seqs)}`);

  const userId = driver.userId;
  const ptr = JSON.parse(await kv.get(`user:${userId}:device:${device}:dptr`));
  eq(ptr.keys.length, 2, 'delta pointer must contain exactly two keys');
  eq(new Set(ptr.keys).size, 2, 'delta pointer must not contain duplicate keys');
});

test('[WPR-02] first full-backup write is also indexed exactly once', async () => {
  const kv = makeKV();
  const worker = await loadWorker();
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const driver = await seedDriver(worker, kv);
  const device = 'ptr-race-full';
  const payloads = [
    JSON.stringify({ kind: 'full', seq: 1, filler: 'a'.repeat(32) }),
    JSON.stringify({ kind: 'full', seq: 2, filler: 'b'.repeat(32) }),
  ];

  for (const payload of payloads) {
    const res = await worker.fetch(driverReq('/backup', 'POST', driver.token, device, payload), env);
    eq(res.status, 200, `backup POST must succeed, got ${res.status}`);
  }

  const ptr = JSON.parse(await kv.get(`user:${driver.userId}:device:${device}:bptr`));
  eq(ptr.keys.length, 2, 'full-backup pointer must contain exactly two keys');
  eq(new Set(ptr.keys).size, 2, 'full-backup pointer must not contain duplicate keys');
  eq(ptr.count, 2, 'full-backup pointer count must reflect unique keys');

  const got = await worker.fetch(driverReq('/backup', 'GET', driver.token, device), env);
  eq(got.status, 200, 'latest full backup must remain readable');
  eq(await got.text(), payloads[1], 'latest full backup must be the second payload byte-for-byte');
});

test('[WPR-03] writes inside one frozen millisecond still get unique, ordered keys', async () => {
  // The WPR-01/02 reproduction depends on the host being fast enough to land two
  // requests in the same millisecond. Freezing the clock makes the property the
  // fix actually guarantees — key uniqueness under a shared millisecond — the
  // thing under test, so this cannot pass by timing luck on a slower runner.
  const kv = makeKV();
  const worker = await loadWorker();
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const driver = await seedDriver(worker, kv);
  const device = 'ptr-race-frozen';

  const realNow = Date.now;
  Date.now = () => 1_800_000_000_000;
  try {
    for (const seq of [1, 2, 3, 4]) {
      const res = await worker.fetch(
        driverReq('/backup/delta', 'POST', driver.token, device, JSON.stringify({ kind: 'delta', seq, filler: 'z'.repeat(32) })),
        env,
      );
      eq(res.status, 200, `delta ${seq} must be stored, got ${res.status}`);
    }
  } finally {
    Date.now = realNow;
  }

  const ptr = JSON.parse(await kv.get(`user:${driver.userId}:device:${device}:dptr`));
  eq(ptr.keys.length, 4, `four same-millisecond deltas must produce four keys, got ${ptr.keys.length}`);
  eq(new Set(ptr.keys).size, 4, 'no two keys may collide inside one millisecond');
  eq(JSON.stringify(ptr.keys), JSON.stringify([...ptr.keys].sort()),
    'keys must stay lexically sorted so a plain sort is still chronological');

  const res = await worker.fetch(driverReq('/backup/delta', 'GET', driver.token, device), env);
  const body = await res.json();
  eq(body.deltas.length, 4, 'every same-millisecond delta must survive and be readable');
  eq(JSON.stringify(body.deltas.map(d => JSON.parse(d.payload).seq)), JSON.stringify([1, 2, 3, 4]),
    'restore order must still be chronological');
  body.deltas.forEach((d) => {
    ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(d.ts),
      `key shape must stay parseable into a real ISO instant, got ${d.ts}`);
  });
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
