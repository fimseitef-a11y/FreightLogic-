// Worker v30 — server reminders + PushWard Live Activity delivery.
//
// These drive the REAL exported fetch and scheduled handlers from
// cloud-backup-worker.js against an in-memory KV, with global fetch stubbed
// only at the outbound boundary (PushWard). Drivers are minted through the real
// invite/claim path.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-reminders.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';
const PUSH_KEY = 'hlk_test_key_123456789012345678901234';

function makeKV() {
  const m = new Map();
  const exp = new Map();
  const api = {
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
      if (opts && opts.expirationTtl) exp.set(k, api.now() + opts.expirationTtl * 1000); else exp.delete(k);
    },
    async delete(k) { m.delete(k); exp.delete(k); },
    listCalls: 0,
    async list({ prefix = '' } = {}) {
      api.listCalls++;
      return { keys: [...m.keys()].filter(k => api._live(k) && k.startsWith(prefix)).map(name => ({ name })) };
    },
  };
  return api;
}

async function loadWorker() {
  return (await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href)).default;
}

const REQ = (url, opts = {}) => new Request('https://worker.test' + url, opts);
const newEnv = (extra = {}) => ({ BACKUPS: makeKV(), ADMIN_TOKEN: ADMIN, ...extra });
const hdrs = (token) => ({ 'Content-Type': 'application/json', 'X-Backup-Token': token, 'X-Device-Id': 'dev_rem1' });

let ipSeq = 10;
async function seedDriver(worker, env, name = 'Reminder Driver') {
  const inv = await (await worker.fetch(REQ('/admin/invites', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN },
    body: JSON.stringify({ name }),
  }), env)).json();
  const claimed = await (await worker.fetch(REQ('/claim', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.' + (ipSeq++) },
    body: JSON.stringify({ code: inv.code }),
  }), env)).json();
  return { token: claimed.token, userId: claimed.userId };
}

function stubFetch(status = 200) {
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), headers: new Headers(init.headers || {}), body: init.body ? JSON.parse(init.body) : null });
    return new Response(null, { status });
  };
  return { calls, restore() { globalThis.fetch = real; } };
}

const post = (worker, env, token, items) => worker.fetch(REQ('/reminders', {
  method: 'POST', headers: hdrs(token), body: JSON.stringify({ items }),
}), env);

const iso = (ms) => new Date(ms).toISOString();

test('[RM-01] reminder and PushWard routes refuse a request with no driver token', async () => {
  const env = newEnv(); const worker = await loadWorker();
  for (const [m, p] of [['GET', '/reminders'], ['POST', '/reminders'], ['GET', '/pushward'], ['POST', '/pushward/test']]) {
    const res = await worker.fetch(REQ(p, { method: m, headers: { 'Content-Type': 'application/json' }, body: m === 'GET' ? undefined : '{}' }), env);
    ok(res.status === 401 || res.status === 403, `${m} ${p} without a token must be refused, got ${res.status}`);
  }
});

test('[RM-02] an upload keeps only valid reminders and names the rejected ones', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  const res = await post(worker, env, d.token, [
    { id: 'good1', kind: 'delivery', at: iso(now + 3600e3), title: 'Delivery due 3:00 PM', body: 'Columbus, OH', url: './#trips' },
    { id: 'badkind', kind: 'launch', at: iso(now + 3600e3), title: 'x' },
    { id: 'badurl', kind: 'custom', at: iso(now + 3600e3), title: 'x', url: 'https://evil.example/' },
    { id: 'far', kind: 'custom', at: iso(now + 90 * 86400e3), title: 'x' },
    { id: 'notitle', kind: 'custom', at: iso(now + 3600e3), title: '   ' },
    { id: 'bad id!', kind: 'custom', at: iso(now + 3600e3), title: 'x' },
  ]);
  const body = await res.json();
  eq(res.status, 200, 'upload accepted');
  eq(body.stored, 1, 'only the valid reminder is stored');
  eq(JSON.stringify(body.rejected.slice(0, 4)), JSON.stringify(['badkind', 'badurl', 'far', 'notitle']), 'rejected ids are named');
  const got = await (await worker.fetch(REQ('/reminders', { headers: hdrs(d.token) }), env)).json();
  eq(got.items.length, 1, 'GET returns the stored reminder');
  eq(got.items[0].title, 'Delivery due 3:00 PM', 'title kept');
  const tooMany = await post(worker, env, d.token, Array.from({ length: 51 }, (_, i) => ({ id: 'r' + i, kind: 'custom', at: iso(now + 3600e3), title: 't' })));
  eq(tooMany.status, 400, 'more than 50 items is refused');
});

test('[RM-03] a due reminder is sent once through PushWard, never twice', async () => {
  const env = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const worker = await loadWorker();
  const d = await seedDriver(worker, env); const now = Date.now();
  await post(worker, env, d.token, [
    { id: 'due', kind: 'pickup', at: iso(now - 60e3), title: 'Leave now for pickup', body: 'Toledo, OH' },
    { id: 'later', kind: 'delivery', at: iso(now + 3600e3), title: 'Delivery due' },
  ]);
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    eq(f.calls.length, 1, 'exactly one PushWard call');
    ok(f.calls[0].url.startsWith('https://api.pushward.app/activities/freightlogic-'), 'fixed PushWard API origin');
    eq(f.calls[0].headers.get('Authorization'), 'Bearer ' + PUSH_KEY, 'Worker secret used as bearer auth');
    eq(f.calls[0].body.content.state, 'Leave now for pickup', 'title carried');
    eq(f.calls[0].body.content.subtitle, 'Toledo, OH', 'minimal body carried');
    ok(!JSON.stringify(f.calls[0].body).includes(d.userId), 'driver user id is not sent');
    await worker.scheduled({ scheduledTime: now + 5 * 60e3 }, env);
    eq(f.calls.length, 1, 'second run does not resend');
  } finally { f.restore(); }
  const got = await (await worker.fetch(REQ('/reminders', { headers: hdrs(d.token) }), env)).json();
  ok(got.items.find(i => i.id === 'due').sentAt, 'sent reminder marked');
  ok(!got.items.find(i => i.id === 'later').sentAt, 'future reminder untouched');
});

test('[RM-04] a reminder more than 6h late is missed, not sent; old ones are pruned', async () => {
  const env = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const worker = await loadWorker();
  const d = await seedDriver(worker, env); const now = Date.now();
  await post(worker, env, d.token, [{ id: 'late', kind: 'pickup', at: iso(now - 7 * 3600e3), title: 'Leave now' }]);
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    eq(f.calls.length, 0, 'stale reminder not sent');
    const got = await (await worker.fetch(REQ('/reminders', { headers: hdrs(d.token) }), env)).json();
    eq(got.items[0].missed, true, 'recorded as missed');
    await worker.scheduled({ scheduledTime: now + 25 * 3600e3 }, env);
    eq(await env.BACKUPS.get('rem:' + d.userId), null, 'pruned');
    eq(await env.BACKUPS.get('rem:index'), '[]', 'driver leaves index');
  } finally { f.restore(); }
});

test('[RM-05] re-uploading unchanged sent reminder does not resend; a new time does', async () => {
  const env = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const worker = await loadWorker();
  const d = await seedDriver(worker, env); const now = Date.now();
  const item = { id: 'r1', kind: 'delivery', at: iso(now - 60e3), title: 'Delivery due' };
  await post(worker, env, d.token, [item]); const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    await post(worker, env, d.token, [item]);
    await worker.scheduled({ scheduledTime: now + 60e3 }, env);
    eq(f.calls.length, 1, 'same id + time not resent');
    await post(worker, env, d.token, [{ ...item, at: iso(now + 30e3) }]);
    await worker.scheduled({ scheduledTime: now + 120e3 }, env);
    eq(f.calls.length, 2, 'changed time is new reminder');
  } finally { f.restore(); }
});

test('[RM-06] PushWard secret stays server-side and missing configuration fails closed', async () => {
  const worker = await loadWorker(); const env = newEnv(); const d = await seedDriver(worker, env);
  const info = await (await worker.fetch(REQ('/pushward', { headers: hdrs(d.token) }), env)).json();
  eq(info.configured, false, 'missing secret reported without a value');
  const f = stubFetch(200);
  try {
    const t = await worker.fetch(REQ('/pushward/test', { method: 'POST', headers: hdrs(d.token) }), env);
    eq(t.status, 409, 'test fails closed');
    eq((await t.json()).status, 'not-configured', 'reason named');
    eq(f.calls.length, 0, 'no outbound request');
  } finally { f.restore(); }
  const envOk = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const d2 = await seedDriver(worker, envOk);
  const g = stubFetch(200);
  try {
    const t = await worker.fetch(REQ('/pushward/test', { method: 'POST', headers: hdrs(d2.token) }), envOk);
    const body = await t.json();
    eq(t.status, 200, 'test sends with secret');
    eq(g.calls.length, 1, 'one outbound call');
    eq(g.calls[0].headers.get('Authorization'), 'Bearer ' + PUSH_KEY, 'secret only on outbound auth');
    ok(!JSON.stringify(body).includes(PUSH_KEY), 'secret absent from response');
  } finally { g.restore(); }
});

test('[RM-07] a revoked driver gets nothing, and is dropped from the index', async () => {
  const env = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const worker = await loadWorker();
  const d = await seedDriver(worker, env); const now = Date.now();
  await post(worker, env, d.token, [{ id: 'r1', kind: 'custom', at: iso(now - 60e3), title: 'x' }]);
  eq((await worker.fetch(REQ('/admin/users/' + d.userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env)).status, 200, 'driver revoked');
  const f = stubFetch(200);
  try { await worker.scheduled({ scheduledTime: now }, env); eq(f.calls.length, 0, 'nothing sent'); } finally { f.restore(); }
  eq(await env.BACKUPS.get('rem:' + d.userId), null, 'reminders deleted');
  eq(await env.BACKUPS.get('rem:index'), '[]', 'driver removed from index');
});

test('[RM-08] the scheduled run and routes never call KV list()', async () => {
  const env = newEnv({ PUSHWARD_INTEGRATION_KEY: PUSH_KEY }); const worker = await loadWorker();
  const d = await seedDriver(worker, env); const now = Date.now(); const before = env.BACKUPS.listCalls;
  await post(worker, env, d.token, [{ id: 'r1', kind: 'custom', at: iso(now - 60e3), title: 'x' }]);
  const f = stubFetch(200);
  try { await worker.scheduled({ scheduledTime: now }, env); } finally { f.restore(); }
  await worker.fetch(REQ('/reminders', { method: 'DELETE', headers: hdrs(d.token) }), env);
  eq(env.BACKUPS.listCalls - before, 0, 'no KV list()');
});

test('[RM-09] deploy config contains no PushWard or HookTap credential', async () => {
  const cfg = readFileSync(path.join(ROOT, 'scripts/wrangler.backup-worker.jsonc'), 'utf8');
  ok(!cfg.includes('hlk_'), 'no PushWard key committed');
  ok(!cfg.includes('HOOKTAP_URL_TEMPLATE'), 'HookTap config removed');
  ok(!cfg.includes('hooks.hooktap.me'), 'HookTap host removed');
});

export async function runSpec() {
  return await run();
}
