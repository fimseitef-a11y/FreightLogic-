import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const tests = [];
const failures = [];
let pass = 0;
let fail = 0;

function test(name, fn) { tests.push({ name, fn }); }
function ok(value, message) { if (!value) throw new Error(message); }
function eq(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}\nexpected: ${JSON.stringify(expected)}\nactual: ${JSON.stringify(actual)}`);
}
async function text(rel) { return await readFile(path.join(ROOT, rel), 'utf8'); }

async function loadConsoleModule() {
  return await import(pathToFileURL(path.join(ROOT, 'admin-console/app.js')).href + `?t=${Date.now()}`);
}

function response(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function makeFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const call = { url: u.toString(), path: u.pathname, method: init.method || 'GET', headers: new Headers(init.headers || {}), body: init.body || null };
    calls.push(call);
    const key = `${call.method} ${call.path}`;
    const handler = routes[key];
    if (!handler) return response(404, { ok: false, error: `unexpected ${key}` });
    return await handler(call);
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

function memoryStorage() {
  const m = new Map();
  return {
    getItem: k => m.has(k) ? m.get(k) : null,
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: k => m.delete(k),
    dump: () => [...m.entries()],
  };
}

test('[ADMIN-01] console is a separate static surface with no service worker', async () => {
  const html = await text('admin-console/index.html');
  ok(html.includes('Content-Security-Policy'), 'Admin Console must declare its own CSP');
  ok(html.includes('type="module"'), 'Admin Console must load its own module');
  ok(!/serviceWorker|service-worker/i.test(html), 'Admin Console MVP must not register or reference a service worker');
});

test('[ADMIN-02] console assets contain no permanent driver token transport or persistent admin storage', async () => {
  const assets = [await text('admin-console/index.html'), await text('admin-console/app.js'), await text('admin-console/styles.css')].join('\n');
  ok(!assets.includes('flk_'), 'Admin Console assets must never contain the permanent driver-token prefix');
  ok(!assets.includes('#token='), 'raw fragment token onboarding must not return');
  ok(!assets.includes('?token='), 'raw query token onboarding must not return');
  ok(!assets.includes('localStorage'), 'admin credential must never be persisted in localStorage');
  ok(!/navigator\.serviceWorker/.test(assets), 'Admin Console must remain online-only with no service worker');
});

test('[ADMIN-03] missing admin auth fails closed before any request is sent', async () => {
  const mod = await loadConsoleModule();
  const fetchImpl = makeFetch({});
  const api = mod.createAdminApi({ apiOrigin: 'https://worker.test', tokenProvider: () => '', fetchImpl });
  let threw = false;
  try { await api.listUsers(); } catch (e) { threw = /admin access/i.test(String(e.message)); }
  eq(threw, true, 'missing admin credential must fail closed with an auth error');
  eq(fetchImpl.calls.length, 0, 'missing admin credential must not send a network request');
});

test('[ADMIN-04] rejected admin auth is never stored; accepted auth is session-scoped', async () => {
  const mod = await loadConsoleModule();
  const store = mod.createCredentialStore(memoryStorage());
  const badFetch = makeFetch({ 'GET /admin/users': async () => response(401, { ok: false, error: 'Unauthorized' }) });
  let rejected = false;
  try {
    await mod.verifyAndStoreAdminToken({ token: 'wrong-admin-value', store, apiOrigin: 'https://worker.test', fetchImpl: badFetch });
  } catch { rejected = true; }
  eq(rejected, true, 'wrong admin credential must be rejected');
  eq(store.get(), '', 'rejected admin credential must not be retained');

  const goodFetch = makeFetch({ 'GET /admin/users': async () => response(200, { ok: true, users: [] }) });
  const users = await mod.verifyAndStoreAdminToken({ token: 'accepted-admin-value', store, apiOrigin: 'https://worker.test', fetchImpl: goodFetch });
  eq(Array.isArray(users), true, 'accepted auth should return the driver list');
  eq(store.get(), 'accepted-admin-value', 'accepted credential may live only in the provided session-scoped store');
});

test('[ADMIN-05] driver list uses only GET /admin/users with X-Admin-Token', async () => {
  const mod = await loadConsoleModule();
  const fetchImpl = makeFetch({ 'GET /admin/users': async call => {
    eq(call.headers.get('X-Admin-Token'), 'admin-session-value', 'list must send the admin credential only in X-Admin-Token');
    return response(200, { ok: true, users: [{ userId: 'u_12345678', name: 'Driver', active: true, backupCount: 2 }] });
  }});
  const api = mod.createAdminApi({ apiOrigin: 'https://worker.test', tokenProvider: () => 'admin-session-value', fetchImpl });
  const users = await api.listUsers();
  eq(users.length, 1, 'list should return the Worker user collection');
  eq(fetchImpl.calls[0].method, 'GET', 'list must be GET');
});

test('[ADMIN-06] new invite uses POST /admin/invites and builds only a #i= claim link', async () => {
  const mod = await loadConsoleModule();
  const code = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.slice(0, 24).replace(/[018]/g, 'A');
  const fetchImpl = makeFetch({ 'POST /admin/invites': async call => {
    const body = JSON.parse(call.body);
    eq(body.name, 'New Driver', 'new invite must send the driver name');
    eq(Object.keys(body).sort().join(','), 'name', 'new invite must not call a token-minting shape');
    return response(201, { ok: true, name: 'New Driver', code, expiresAt: '2026-09-21T00:00:00Z', userId: null, reinvite: false });
  }});
  const api = mod.createAdminApi({ apiOrigin: 'https://worker.test', tokenProvider: () => 'admin-session-value', fetchImpl });
  const invite = await api.createInvite('New Driver');
  const link = mod.buildClaimLink(invite.code, 'https://driver.example');
  eq(new URL(link).origin, 'https://driver.example', 'claim link must point to the configured driver origin');
  eq(new URL(link).hash, `#i=${encodeURIComponent(code)}`, 'claim link must carry only the claim code in #i=');
  ok(!link.includes('token='), 'claim link must not carry a raw permanent token parameter');
});

test('[ADMIN-07] re-invite posts only userId to /admin/invites and preserves returned userId', async () => {
  const mod = await loadConsoleModule();
  const userId = 'u_12345678';
  const code = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.slice(0, 24).replace(/[018]/g, 'A');
  const fetchImpl = makeFetch({ 'POST /admin/invites': async call => {
    const body = JSON.parse(call.body);
    eq(body.userId, userId, 're-invite must bind the existing userId');
    eq(Object.keys(body).sort().join(','), 'userId', 're-invite must not silently create/rename a different identity');
    return response(201, { ok: true, name: 'Driver', code, userId, reinvite: true });
  }});
  const api = mod.createAdminApi({ apiOrigin: 'https://worker.test', tokenProvider: () => 'admin-session-value', fetchImpl });
  const invite = await api.reinvite(userId);
  eq(invite.userId, userId, "client must preserve the Worker's canonical userId");
  eq(invite.reinvite, true, 're-invite response must remain distinguishable from a new invite');
});

test('[ADMIN-08] revoke uses only DELETE /admin/users/:id and no freight-data endpoint', async () => {
  const mod = await loadConsoleModule();
  const userId = 'u_12345678';
  const fetchImpl = makeFetch({ [`DELETE /admin/users/${userId}`]: async () => response(200, { ok: true, revoked: userId }) });
  const api = mod.createAdminApi({ apiOrigin: 'https://worker.test', tokenProvider: () => 'admin-session-value', fetchImpl });
  const result = await api.revoke(userId);
  eq(result.revoked, userId, 'revoke must return the same canonical userId');
  eq(fetchImpl.calls[0].method, 'DELETE', 'revoke must use DELETE');
  const source = await text('admin-console/app.js');
  for (const forbidden of ['/backup', '/delta', '/trip', '/expense', '/receipt', '/tax']) {
    ok(!source.includes(forbidden), `Admin Console must not gain freight-data access through ${forbidden}`);
  }
});

test('[ADMIN-09] production Worker CORS remains exact-match, never wildcard', async () => {
  const worker = await text('cloud-backup-worker.js');
  ok(worker.includes('requestOrigin === configuredOrigin'), 'Worker must exact-match the configured admin origin');
  ok(worker.includes("ALLOWED_ORIGINS.has(requestOrigin)"), 'Worker must exact-match built-in approved origins');
  ok(!/Access-Control-Allow-Origin['\"]?\s*:\s*['\"]\*/.test(worker), 'Worker must never emit wildcard CORS');
});

test('[ADMIN-10] console refuses to initialize on the driver origin', async () => {
  const mod = await loadConsoleModule();
  let blocked = false;
  try {
    mod.assertSeparateAdminOrigin('https://driver.example', 'https://driver.example');
  } catch (error) {
    blocked = /separate origin/i.test(String(error?.message || error));
  }
  eq(blocked, true, 'same-origin admin + driver hosting must fail closed');
  eq(
    mod.assertSeparateAdminOrigin('https://admin.example', 'https://driver.example'),
    'https://admin.example',
    'a distinct HTTPS admin origin must remain eligible'
  );

  const source = await text('admin-console/app.js');
  ok(
    source.includes('assertSeparateAdminOrigin(window.location.origin, driverOrigin)'),
    'browser bootstrap must enforce the separate-origin guard before session storage/auth setup'
  );
  ok(
    source.includes('adminInput.disabled = true') && source.includes('connectButton.disabled = true'),
    'same-origin failure must disable credential entry rather than leave an apparently usable form'
  );
});

export async function runSpec() {
  for (const { name, fn } of tests) {
    try { await fn(); pass += 1; console.log(`  PASS ${name}`); }
    catch (error) { fail += 1; failures.push({ name, error: String(error?.stack || error) }); console.error(`  FAIL ${name}\n    ${error?.message || error}`); }
  }
  return { file: 'integration/admin-console.spec.mjs', pass, fail, failures };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runSpec();
  console.log(`\n${result.pass} passed, ${result.fail} failed`);
  process.exit(result.fail ? 1 : 0);
}
