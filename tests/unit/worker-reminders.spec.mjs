// Worker v29 — server reminders + HookTap delivery.
//
// These drive the REAL exported fetch and scheduled handlers from
// cloud-backup-worker.js against an in-memory KV, with global fetch stubbed
// only at the outbound boundary (HookTap). Drivers are minted through the real
// invite/claim path.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-reminders.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';
const HOOK_TPL = 'https://hooks.example.test/w/{id}';
const HOOK_ID = 'dcd6f546009d4bb5a96e915c';

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
    calls.push({ url: String(url), body: init.body ? JSON.parse(init.body) : null });
    return new Response(null, { status });
  };
  return { calls, restore() { globalThis.fetch = real; } };
}

const post = (worker, env, token, items) => worker.fetch(REQ('/reminders', {
  method: 'POST', headers: hdrs(token), body: JSON.stringify({ items }),
}), env);

const iso = (ms) => new Date(ms).toISOString();

test('[RM-01] reminder and HookTap routes refuse a request with no driver token', async () => {
  const env = newEnv(); const worker = await loadWorker();
  for (const [m, p] of [['GET', '/reminders'], ['POST', '/reminders'], ['POST', '/hooktap'], ['POST', '/hooktap/test']]) {
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

test('[RM-03] a due reminder is sent once through HookTap, never twice', async () => {
  const env = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL }); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  eq((await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), env)).status, 200, 'webhook ID saved');
  await post(worker, env, d.token, [
    { id: 'due', kind: 'pickup', at: iso(now - 60e3), title: 'Leave now for pickup', body: 'Toledo, OH' },
    { id: 'later', kind: 'delivery', at: iso(now + 3600e3), title: 'Delivery due' },
  ]);
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    eq(f.calls.length, 1, 'exactly one HookTap call for the one due reminder');
    eq(f.calls[0].url, 'https://hooks.example.test/w/' + HOOK_ID, 'sent to the operator template with the driver ID');
    eq(f.calls[0].body.title, 'Leave now for pickup', 'title carried');
    await worker.scheduled({ scheduledTime: now + 5 * 60e3 }, env);
    eq(f.calls.length, 1, 'a second run does not resend it');
  } finally { f.restore(); }
  const got = await (await worker.fetch(REQ('/reminders', { headers: hdrs(d.token) }), env)).json();
  ok(got.items.find(i => i.id === 'due').sentAt, 'sent reminder is marked');
  ok(!got.items.find(i => i.id === 'later').sentAt, 'future reminder is untouched');
});

test('[RM-04] a reminder more than 6h late is missed, not sent; old ones are pruned', async () => {
  const env = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL }); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), env);
  await post(worker, env, d.token, [{ id: 'late', kind: 'pickup', at: iso(now - 7 * 3600e3), title: 'Leave now' }]);
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    eq(f.calls.length, 0, 'a stale reminder is not sent');
    const got = await (await worker.fetch(REQ('/reminders', { headers: hdrs(d.token) }), env)).json();
    eq(got.items[0].missed, true, 'recorded as missed');
    await worker.scheduled({ scheduledTime: now + 25 * 3600e3 }, env);
    eq(await env.BACKUPS.get('rem:' + d.userId), null, 'pruned a day after its time');
    eq(await env.BACKUPS.get('rem:index'), '[]', 'driver leaves the index once nothing is left');
    eq(f.calls.length, 0, 'still nothing sent');
  } finally { f.restore(); }
});

test('[RM-05] re-uploading an unchanged sent reminder does not resend it; a new time does', async () => {
  const env = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL }); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), env);
  const item = { id: 'r1', kind: 'delivery', at: iso(now - 60e3), title: 'Delivery due' };
  await post(worker, env, d.token, [item]);
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    await post(worker, env, d.token, [item]);
    await worker.scheduled({ scheduledTime: now + 60e3 }, env);
    eq(f.calls.length, 1, 'same id + same time is not sent again');
    await post(worker, env, d.token, [{ ...item, at: iso(now + 30e3) }]);
    await worker.scheduled({ scheduledTime: now + 120e3 }, env);
    eq(f.calls.length, 2, 'a changed time is a new reminder');
  } finally { f.restore(); }
});

test('[RM-06] HookTap: the ID is validated, never returned, and nothing is sent without the operator template', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  eq((await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: 'https://evil.example/x' }) }), env)).status, 400, 'a URL is not a webhook ID');
  eq((await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), env)).status, 200, 'a real ID is accepted');
  const info = await (await worker.fetch(REQ('/hooktap', { headers: hdrs(d.token) }), env)).json();
  eq(info.configured, true, 'configured');
  eq(info.deliveryReady, false, 'no template, not ready');
  ok(!JSON.stringify(info).includes(HOOK_ID), 'the ID is never returned');
  const f = stubFetch(200);
  try {
    const t = await worker.fetch(REQ('/hooktap/test', { method: 'POST', headers: hdrs(d.token) }), env);
    eq(t.status, 409, 'test reports delivery not configured');
    eq((await t.json()).status, 'delivery-not-configured', 'reason named');
    const bad = newEnv({ HOOKTAP_URL_TEMPLATE: 'http://hooks.example.test/{id}' });
    const d2 = await seedDriver(worker, bad);
    await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d2.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), bad);
    eq((await (await worker.fetch(REQ('/hooktap/test', { method: 'POST', headers: hdrs(d2.token) }), bad)).json()).status, 'delivery-not-configured', 'a non-https template is refused');
    eq(f.calls.length, 0, 'no outbound call without a valid template');
  } finally { f.restore(); }
  const envOk = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL });
  const d3 = await seedDriver(worker, envOk);
  await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d3.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), envOk);
  const g = stubFetch(200);
  try {
    const t = await worker.fetch(REQ('/hooktap/test', { method: 'POST', headers: hdrs(d3.token) }), envOk);
    eq(t.status, 200, 'test sends with a template');
    eq(g.calls.length, 1, 'one outbound call');
  } finally { g.restore(); }
});

test('[RM-07] a revoked driver gets nothing, and is dropped from the index', async () => {
  const env = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL }); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  await worker.fetch(REQ('/hooktap', { method: 'POST', headers: hdrs(d.token), body: JSON.stringify({ webhookId: HOOK_ID }) }), env);
  await post(worker, env, d.token, [{ id: 'r1', kind: 'custom', at: iso(now - 60e3), title: 'x' }]);
  const del = await worker.fetch(REQ('/admin/users/' + d.userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env);
  eq(del.status, 200, 'driver revoked');
  const f = stubFetch(200);
  try {
    await worker.scheduled({ scheduledTime: now }, env);
    eq(f.calls.length, 0, 'nothing sent to a revoked driver');
  } finally { f.restore(); }
  eq(await env.BACKUPS.get('rem:' + d.userId), null, 'their reminders are deleted');
  eq(await env.BACKUPS.get('rem:index'), '[]', 'and they leave the index');
});

test('[RM-08] the scheduled run and the routes never call KV list()', async () => {
  const env = newEnv({ HOOKTAP_URL_TEMPLATE: HOOK_TPL }); const worker = await loadWorker();
  const d = await seedDriver(worker, env);
  const now = Date.now();
  const before = env.BACKUPS.listCalls;
  await post(worker, env, d.token, [{ id: 'r1', kind: 'custom', at: iso(now - 60e3), title: 'x' }]);
  const f = stubFetch(200);
  try { await worker.scheduled({ scheduledTime: now }, env); } finally { f.restore(); }
  await worker.fetch(REQ('/reminders', { method: 'DELETE', headers: hdrs(d.token) }), env);
  eq(env.BACKUPS.listCalls - before, 0, 'list() is budgeted at 1,000/day on the free tier');
});

export async function runSpec() {
  return await run();
}
