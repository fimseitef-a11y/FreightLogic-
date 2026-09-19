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

test('[ADMIN-09] production Worker CORS remains exact-match and names the dedicated admin origin', async () => {
  const worker = await text('cloud-backup-worker.js');
  ok(worker.includes('requestOrigin === configuredOrigin'), 'Worker must exact-match the configured admin origin');
  ok(worker.includes("ALLOWED_ORIGINS.has(requestOrigin)"), 'Worker must exact-match built-in approved origins');
  ok(!/Access-Control-Allow-Origin['\"]?\s*:\s*['\"]\*/.test(worker), 'Worker must never emit wildcard CORS');

  const deployConfig = await text('scripts/wrangler.backup-worker.jsonc');
  ok(
    deployConfig.includes('"ALLOWED_ORIGIN": "https://freightlogic-admin-console.fimseitef.workers.dev"'),
    'backup/API Worker deploy config must allow exactly the dedicated Admin Console origin; the driver production origin remains built into ALLOWED_ORIGINS'
  );
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

test('[ADMIN-11] distinct-origin deployment declares fail-closed response headers', async () => {
  const headers = await text('admin-console/_headers');
  ok(/Content-Security-Policy:/i.test(headers), 'deployment must send a response-level CSP, not rely only on a meta tag');
  ok(/frame-ancestors\s+'none'/i.test(headers), 'response CSP must prevent framing');
  ok(/X-Content-Type-Options:\s*nosniff/i.test(headers), 'admin assets must opt out of MIME sniffing');
  ok(/Referrer-Policy:\s*no-referrer/i.test(headers), 'admin requests must not leak referrer data');
  ok(/Cache-Control:\s*no-store/i.test(headers), 'privileged console documents must not be cached by shared intermediaries');
  ok(/Permissions-Policy:/i.test(headers), 'admin deployment must explicitly deny unused device capabilities');
  ok(/camera=\(\)/i.test(headers) && /microphone=\(\)/i.test(headers) && /geolocation=\(\)/i.test(headers),
    'MVP admin surface must deny camera, microphone and geolocation');
  ok(!/Access-Control-Allow-Origin/i.test(headers), 'static admin origin must not invent CORS headers; Worker owns API CORS');
});


test('[ADMIN-12] Cloudflare separate-origin deploy wrapper applies security headers to every asset response', async () => {
  const cfg = JSON.parse(await text('admin-console/wrangler.jsonc'));
  eq(cfg.name, 'freightlogic-admin-console', 'admin site must deploy under its own Worker name');
  eq(cfg.main, 'worker.js', 'admin deploy must use the dedicated response-hardening Worker');
  eq(cfg.assets?.directory, '.', 'admin static assets must come only from the isolated admin-console subtree');
  eq(cfg.assets?.binding, 'ASSETS', 'Worker must receive the static-assets binding');
  eq(cfg.assets?.run_worker_first, true, 'Worker must run before every asset so security headers cannot be bypassed');

  const workerPath = pathToFileURL(path.join(ROOT, 'admin-console/worker.js')).href + `?t=${Date.now()}`;
  const worker = await import(workerPath);
  const assetHeaders = new Headers({ 'Content-Type': 'text/html', 'X-Upstream': 'kept' });
  const env = {
    ASSETS: {
      fetch: async () => new Response('<h1>Admin</h1>', { status: 200, headers: assetHeaders }),
    },
  };
  const result = await worker.default.fetch(new Request('https://admin.example/'), env);
  eq(result.status, 200, 'wrapper must preserve the asset response status');
  eq(result.headers.get('X-Upstream'), 'kept', 'wrapper must preserve safe asset response headers');
  eq(result.headers.get('Cache-Control'), 'no-store', 'privileged admin assets must never be browser/shared-cache durable');
  eq(result.headers.get('Referrer-Policy'), 'no-referrer', 'admin responses must suppress referrer leakage');
  eq(result.headers.get('X-Content-Type-Options'), 'nosniff', 'admin responses must disable MIME sniffing');
  eq(result.headers.get('X-Frame-Options'), 'DENY', 'admin responses must deny legacy framing');
  ok(/frame-ancestors 'none'/.test(result.headers.get('Content-Security-Policy') || ''), 'response CSP must deny framing');
  ok(/camera=\(\)/.test(result.headers.get('Permissions-Policy') || ''), 'admin response must deny unused camera permission');
  ok(!result.headers.has('Access-Control-Allow-Origin'), 'static admin Worker must not invent API CORS');
});

test('[ADMIN-13] Cloudflare asset upload excludes deployment/control-plane files', async () => {
  const ignore = await text('admin-console/.assetsignore');
  for (const file of ['worker.js', 'wrangler.jsonc', 'README.md', '_headers', '.assetsignore', 'verify-live.mjs', 'deploy.sh']) {
    ok(ignore.split(/\r?\n/).map(x => x.trim()).includes(file), `${file} must not be published as a client static asset`);
  }
});


test('[ADMIN-14] repository exposes a confirmed manual deploy path for the separate Admin Console Worker', async () => {
  const workflow = await text('.github/workflows/deploy-admin-console.yml');
  ok(/workflow_dispatch:/.test(workflow), 'Admin Console deployment must be manual-dispatch only');
  ok(/confirm:/.test(workflow) && /DEPLOY/.test(workflow), 'manual deploy must require an explicit DEPLOY confirmation');
  ok(/CLOUDFLARE_API_TOKEN/.test(workflow), 'deploy workflow must use the existing Cloudflare secret rather than a committed credential');
  ok(/bash\s+admin-console\/deploy\.sh/.test(workflow),
    'workflow must delegate to the fail-closed Admin Console deployment wrapper');
  ok(!/wrangler@4\s+deploy/.test(workflow),
    'workflow must not duplicate Wrangler deployment logic already owned by admin-console/deploy.sh');
});


test('[ADMIN-15] live verifier proves dedicated-origin headers, exact API CORS and unauthenticated admin denial', async () => {
  const mod = await import(pathToFileURL(path.join(ROOT, 'admin-console/verify-live.mjs')).href + `?t=${Date.now()}`);
  const adminOrigin = 'https://freightlogic-admin-console.fimseitef.workers.dev';
  const apiOrigin = 'https://freightlogic-backup.fimseitef.workers.dev';
  const security = {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    if (u.origin === adminOrigin && u.pathname === '/') {
      return new Response('<title>FreightLogic Admin Console</title>', { status: 200, headers: security });
    }
    if (u.origin === adminOrigin) return new Response('missing', { status: 404, headers: security });
    if (u.origin === apiOrigin && u.pathname === '/health') {
      return new Response('{"ok":true}', { status: 200, headers: { 'Access-Control-Allow-Origin': adminOrigin } });
    }
    if (u.origin === apiOrigin && u.pathname === '/admin/users') {
      return new Response('{"ok":false}', { status: 401, headers: { 'Access-Control-Allow-Origin': adminOrigin } });
    }
    throw new Error(`unexpected URL ${url}`);
  };
  const result = await mod.verifyLiveAdmin({ adminOrigin, apiOrigin, fetchImpl });
  eq(result.ok, true, 'all safe live-contract checks should pass');
  eq(result.checks.filter(x => x.ok).length, result.checks.length, 'every live check must be individually true');

  const wildcardFetch = async (url, init = {}) => {
    const u = new URL(url);
    if (u.origin === adminOrigin && u.pathname === '/') {
      return new Response('<title>FreightLogic Admin Console</title>', { status: 200, headers: security });
    }
    if (u.origin === adminOrigin) return new Response('missing', { status: 404, headers: security });
    if (u.origin === apiOrigin && u.pathname === '/health') {
      return new Response('{}', { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } });
    }
    return new Response('{}', { status: 401, headers: { 'Access-Control-Allow-Origin': '*' } });
  };
  const bad = await mod.verifyLiveAdmin({ adminOrigin, apiOrigin, fetchImpl: wildcardFetch });
  eq(bad.ok, false, 'wildcard API CORS must fail the live verifier');
});


test('[ADMIN-16] deploy wrapper refuses config drift, dry-runs first, and verifies the live origin', async () => {
  const deploy = await text('admin-console/deploy.sh');
  ok(/set -euo pipefail/.test(deploy), 'deployment wrapper must fail closed on command errors and unset variables');
  ok(/freightlogic-admin-console/.test(deploy), 'wrapper must pin the dedicated admin Worker identity');
  ok(/wrangler@4\s+deploy\s+-c\s+["']?\$CONFIG["']?\s+--dry-run/.test(deploy),
    'wrapper must dry-run the exact isolated config before deployment');
  ok(/wrangler@4\s+deploy\s+-c\s+["']?\$CONFIG["']?(?:\s|$)/.test(deploy),
    'wrapper must deploy the exact isolated config');
  ok(/verify-live\.mjs/.test(deploy), 'wrapper must run the no-secret live verifier after deploy');
  ok(!/deploy\s+-c\s+(?:\.\/)?wrangler\.jsonc/.test(deploy),
    'wrapper must never deploy the repository root/driver Wrangler config');
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
