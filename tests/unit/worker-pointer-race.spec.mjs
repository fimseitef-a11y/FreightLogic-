// Worker v16 production-certification regression: first-write pointer discovery
// must not index the just-written backup/delta key twice.
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

function freezeClock(iso = '2026-09-14T07:40:00.123Z') {
  const RealDate = globalThis.Date;
  const fixedMs = RealDate.parse(iso);
  class FrozenDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [fixedMs])); }
    static now() { return fixedMs; }
  }
  globalThis.Date = FrozenDate;
  return () => { globalThis.Date = RealDate; };
}

test('[WPR-01] first delta writes stay unique under a frozen same-millisecond clock while list() already sees them', async () => {
  const kv = makeKV();
  const worker = await loadWorker();
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const driver = await seedDriver(worker, kv);
  const device = 'ptr-race-delta';
  const payloads = [1, 2].map(seq => JSON.stringify({ kind: 'delta', seq, filler: 'x'.repeat(32) }));

  const restoreClock = freezeClock();
  try {
    for (const payload of payloads) {
      const res = await worker.fetch(driverReq('/backup/delta', 'POST', driver.token, device, payload), env);
      eq(res.status, 200, `delta POST must succeed, got ${res.status}`);
    }
  } finally {
    restoreClock();
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

test('[WPR-02] full-backup writes stay unique under a frozen same-millisecond clock', async () => {
  const kv = makeKV();
  const worker = await loadWorker();
  const env = { BACKUPS: kv, ADMIN_TOKEN: ADMIN };
  const driver = await seedDriver(worker, kv);
  const device = 'ptr-race-full';
  const payloads = [
    JSON.stringify({ kind: 'full', seq: 1, filler: 'a'.repeat(32) }),
    JSON.stringify({ kind: 'full', seq: 2, filler: 'b'.repeat(32) }),
  ];

  const restoreClock = freezeClock();
  try {
    for (const payload of payloads) {
      const res = await worker.fetch(driverReq('/backup', 'POST', driver.token, device, payload), env);
      eq(res.status, 200, `backup POST must succeed, got ${res.status}`);
    }
  } finally {
    restoreClock();
  }

  const ptr = JSON.parse(await kv.get(`user:${driver.userId}:device:${device}:bptr`));
  eq(ptr.keys.length, 2, 'full-backup pointer must contain exactly two keys');
  eq(new Set(ptr.keys).size, 2, 'full-backup pointer must not contain duplicate keys');
  eq(ptr.count, 2, 'full-backup pointer count must reflect unique keys');

  const got = await worker.fetch(driverReq('/backup', 'GET', driver.token, device), env);
  eq(got.status, 200, 'latest full backup must remain readable');
  eq(await got.text(), payloads[1], 'latest full backup must be the second payload byte-for-byte');
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
