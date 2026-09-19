import { fileURLToPath } from 'node:url';

export const DEFAULT_ADMIN_ORIGIN = 'https://freightlogic-admin-console.fimseitef.workers.dev';
export const DEFAULT_API_ORIGIN = 'https://freightlogic-backup.fimseitef.workers.dev';

function origin(value, label) {
  const url = new URL(String(value || ''));
  if (url.protocol !== 'https:') throw new Error(`${label} must be HTTPS`);
  return url.origin;
}

function check(checks, name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok), detail: String(detail || '') });
}

export async function verifyLiveAdmin({
  adminOrigin = DEFAULT_ADMIN_ORIGIN,
  apiOrigin = DEFAULT_API_ORIGIN,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required.');

  const admin = origin(adminOrigin, 'Admin origin');
  const api = origin(apiOrigin, 'API origin');
  if (admin === api) throw new Error('Admin and API origins must remain distinct.');

  const checks = [];
  let root;
  try {
    root = await fetchImpl(admin + '/', {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
  } catch (error) {
    check(checks, 'admin root reachable', false, error?.message || error);
    return { ok: false, adminOrigin: admin, apiOrigin: api, checks };
  }

  const body = await root.text().catch(() => '');
  check(checks, 'admin root returns 200', root.status === 200, `HTTP ${root.status}`);
  check(checks, 'admin shell identity', /FreightLogic Admin Console/i.test(body), 'expected Admin Console title');
  check(checks, 'CSP denies framing', /frame-ancestors\s+'none'/i.test(root.headers.get('Content-Security-Policy') || ''));
  check(checks, 'cache disabled', /no-store/i.test(root.headers.get('Cache-Control') || ''));
  check(checks, 'MIME sniffing disabled', /^nosniff$/i.test(root.headers.get('X-Content-Type-Options') || ''));
  check(checks, 'legacy framing denied', /^DENY$/i.test(root.headers.get('X-Frame-Options') || ''));
  check(checks, 'unused device permissions denied', /camera=\(\)/i.test(root.headers.get('Permissions-Policy') || ''));
  check(checks, 'static origin does not set API CORS', !root.headers.has('Access-Control-Allow-Origin'));

  for (const path of ['/worker.js', '/wrangler.jsonc', '/README.md', '/_headers', '/.assetsignore', '/verify-live.mjs']) {
    try {
      const res = await fetchImpl(admin + path, {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      check(checks, `control asset hidden: ${path}`, res.status !== 200, `HTTP ${res.status}`);
    } catch (error) {
      check(checks, `control asset hidden: ${path}`, false, error?.message || error);
    }
  }

  try {
    const health = await fetchImpl(api + '/health', {
      method: 'GET',
      headers: { Origin: admin },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
    check(checks, 'API health reachable from admin origin', health.status === 200, `HTTP ${health.status}`);
    check(
      checks,
      'API CORS echoes exact admin origin',
      health.headers.get('Access-Control-Allow-Origin') === admin,
      health.headers.get('Access-Control-Allow-Origin') || 'missing'
    );
  } catch (error) {
    check(checks, 'API health reachable from admin origin', false, error?.message || error);
    check(checks, 'API CORS echoes exact admin origin', false, 'health request failed');
  }

  try {
    const denied = await fetchImpl(api + '/admin/users', {
      method: 'GET',
      headers: { Origin: admin },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
    check(checks, 'unauthenticated admin is denied', denied.status === 401, `HTTP ${denied.status}`);
    check(
      checks,
      'admin denial preserves exact CORS',
      denied.headers.get('Access-Control-Allow-Origin') === admin,
      denied.headers.get('Access-Control-Allow-Origin') || 'missing'
    );
  } catch (error) {
    check(checks, 'unauthenticated admin is denied', false, error?.message || error);
    check(checks, 'admin denial preserves exact CORS', false, 'admin request failed');
  }

  return {
    ok: checks.length > 0 && checks.every(item => item.ok),
    adminOrigin: admin,
    apiOrigin: api,
    checks,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = await verifyLiveAdmin().catch(error => ({
    ok: false,
    adminOrigin: DEFAULT_ADMIN_ORIGIN,
    apiOrigin: DEFAULT_API_ORIGIN,
    checks: [{ name: 'verifier execution', ok: false, detail: String(error?.message || error) }],
  }));

  for (const item of result.checks) {
    console.log(`${item.ok ? 'PASS' : 'FAIL'}  ${item.name}${item.detail ? ` — ${item.detail}` : ''}`);
  }
  console.log(`ADMIN LIVE VERDICT: ${result.ok ? 'PASS' : 'FAIL'}`);
  process.exit(result.ok ? 0 : 1);
}
