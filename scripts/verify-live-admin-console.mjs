#!/usr/bin/env node
// Live Admin Console proof (Issue #231, Worker v23).
//
// WHAT IT PROVES. The Admin Console deploy gate (admin-console/verify-live.mjs)
// observes only the unauthenticated half: the shell loads, its headers are
// strict, and it refuses non-read methods. The half that matters — an admin
// signing in and listing, inviting, re-inviting and revoking drivers against
// the PRODUCTION Worker, cross-origin, through the real console code — had no
// observation at all, because no CI job may hold ADMIN_TOKEN.
//
// HOW, WITHOUT ADMIN_TOKEN. Worker v23 accepts a certification credential:
// `flac_<64 hex>`, stored only as `admcert:<sha256>` with a 15-minute TTL and
// its own `expiresAt`, and it is NARROWER than ADMIN_TOKEN — it can never reach
// the two routes that return a permanent `flk_` token. This script seeds one,
// seeds one synthetic driver under a certification name, drives the real
// deployed console in headless Chromium, and deletes every key it touched.
//
// VERDICTS, the same three the other live gates use:
//   0 PASS        every step observed and correct
//   1 FAILURE     real evidence the console or the Worker got it wrong
//   2 UNOBSERVED  credentials missing, origin unreachable, KV never propagated,
//                 or the admin rate limit spent — NO claim either way
//
// RATE BUDGET. /admin/* is 20 requests/hr per IP. This run spends at most 14
// (up to 8 propagation polls + 6 console actions). Do not dispatch it twice in
// one clock hour.
import { chromium } from 'playwright';
import crypto from 'node:crypto';

const ADMIN_ORIGIN = process.argv[2] || 'https://freightlogic-admin-console.fimseitef.workers.dev';
const API_ORIGIN = process.argv[3] || 'https://freightlogic-backup.fimseitef.workers.dev';
const API_ORIGIN_EXACT = new URL(API_ORIGIN).origin;
const CF_TOKEN = process.env.FL_CF_API_TOKEN || '';
const CF_ACCOUNT = process.env.FL_CF_ACCOUNT_ID || '';
const KV_NS = process.env.FL_KV_NAMESPACE_ID || '';

const RUN_ID = crypto.randomBytes(4).toString('hex');
const CERT_NAME = `FreightLogic Admin Cert ${RUN_ID}`;
const INVITE_NAME = `FreightLogic Admin Cert invite ${RUN_ID}`;
const created = new Set();
const results = [];

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const pass = (name, detail = '') => { results.push({ ok: true }); console.log(`  PASS  ${name}${detail ? ' — ' + detail : ''}`); };
const fail = (name, detail = '') => { results.push({ ok: false }); console.log(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`); };
const check = (name, cond, detail) => (cond ? pass : fail)(name, detail);

class Unobserved extends Error {}

const kvBase = () => `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/storage/kv/namespaces/${KV_NS}`;
async function kvPut(key, value, ttlSeconds) {
  const res = await fetch(`${kvBase()}/values/${encodeURIComponent(key)}?expiration_ttl=${ttlSeconds}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${CF_TOKEN}`, 'Content-Type': 'text/plain' },
    body: value,
  }).catch(() => null);
  const body = res ? await res.json().catch(() => null) : null;
  if (!res || !res.ok || !body || body.success !== true) throw new Unobserved(`KV write rejected for ${key.split(':')[0]}:… (HTTP ${res ? res.status : 'none'})`);
  created.add(key);
}
async function kvDelete(key) {
  try {
    const res = await fetch(`${kvBase()}/values/${encodeURIComponent(key)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${CF_TOKEN}` } });
    return res.ok;
  } catch { return false; }
}

/** Mandatory: a revoke rewrites `user:<id>` with no TTL, so without this the
 *  synthetic driver would live in production KV forever. Not silent on failure. */
async function cleanup() {
  const stuck = [];
  for (const key of created) if (!(await kvDelete(key))) stuck.push(key.split(':')[0] + ':…');
  if (stuck.length) console.log(`\n  CLEANUP INCOMPLETE — ${stuck.length} synthetic key(s) remain (${stuck.join(', ')}); they carry the name "${CERT_NAME}".`);
}

async function run() {
  if (!CF_TOKEN || !CF_ACCOUNT || !KV_NS) throw new Unobserved('Cloudflare KV credentials are not configured');

  console.log(`Admin Console live proof — console ${ADMIN_ORIGIN}, API ${API_ORIGIN}, run ${RUN_ID}`);

  const certToken = 'flac_' + crypto.randomBytes(32).toString('hex');
  const userId = 'u_' + crypto.randomBytes(10).toString('hex');
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
  await kvPut('admcert:' + sha256(certToken), JSON.stringify({ purpose: 'certification', expiresAt, runId: RUN_ID }), 900);
  await kvPut('user:' + userId, JSON.stringify({
    userId, name: CERT_NAME, tokenHash: sha256('flk_' + crypto.randomBytes(16).toString('hex')),
    createdAt: new Date().toISOString(), active: true, backupCount: 0,
  }), 900);

  // KV is eventually consistent; wait until the Worker sees the credential.
  let visible = false;
  for (let i = 0; i < 8 && !visible; i++) {
    const res = await fetch(API_ORIGIN + '/admin/users', { headers: { 'X-Admin-Token': certToken } }).catch(() => null);
    if (res && res.status === 429) throw new Unobserved('admin rate limit is spent for this IP; retry next clock hour');
    if (res && res.status === 200) {
      const body = await res.json().catch(() => null);
      visible = Array.isArray(body?.users) && body.users.some(u => u.userId === userId);
    }
    if (!visible) await new Promise(r => setTimeout(r, 8000));
  }
  if (!visible) throw new Unobserved('the certification credential or synthetic driver never became visible to the live Worker');

  const browser = await chromium.launch(process.env.FL_CHROME_PATH ? { executablePath: process.env.FL_CHROME_PATH } : {});
  try {
    const page = await browser.newPage();
    page.on('dialog', d => d.accept());
    const bodies = [];
    const codes = [];
    page.on('response', async r => {
      let origin = '';
      try { origin = new URL(r.url()).origin; } catch { return; }
      if (origin !== API_ORIGIN_EXACT) return;
      const text = await r.text().catch(() => '');
      bodies.push(text);
      try { const j = JSON.parse(text); if (j && typeof j.code === 'string') codes.push(j.code); } catch {}
    });

    const nav = await page.goto(ADMIN_ORIGIN + '/', { waitUntil: 'domcontentloaded' }).catch(() => null);
    if (!nav) throw new Unobserved('Admin Console origin unreachable');
    check('console loads', nav.status() === 200, `HTTP ${nav.status()}`);

    const status = () => page.locator('#status').textContent();
    await page.fill('#adminAccess', certToken);
    await page.locator('#connectForm button[type="submit"]').click();
    await page.waitForFunction(() => /connected|rejected|required|fail|error/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 30000 }).catch(() => {});
    check('sign in through the console', /Admin connected/i.test(await status()), await status());
    check('access is session-only (sessionStorage, never localStorage)',
      await page.evaluate(() => localStorage.length === 0 && Boolean(sessionStorage.getItem('freightlogic_admin_session_v1'))));

    const card = page.locator('.driver-card', { hasText: CERT_NAME });
    check('list shows the synthetic driver exactly once', await card.count() === 1, `${await card.count()} card(s)`);

    await page.fill('#driverName', INVITE_NAME);
    await page.locator('#inviteForm button[type="submit"]').click();
    await page.waitForFunction(() => /Invite created|fail|error|Unauthor/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 30000 }).catch(() => {});
    const link = await page.locator('#inviteResult a').getAttribute('href').catch(() => '');
    check('create invite yields a driver-origin claim link', /Invite created/.test(await status()) && /^https:\/\/freightlogic-v2\.fimseitef\.workers\.dev\/#i=[A-Z2-7]{24}$/.test(link || ''), `${await status()} ${link ? '(link ok)' : '(no link)'}`);

    await card.getByRole('button', { name: 'Re-invite' }).click();
    await page.waitForFunction(() => /Re-invite created|fail|error|unexpected/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 30000 }).catch(() => {});
    check('re-invite binds the existing driver', /Re-invite created/.test(await status()), await status());

    await card.getByRole('button', { name: 'Revoke access' }).click();
    await page.waitForFunction(() => /refreshed|fail|error/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 30000 }).catch(() => {});
    const after = page.locator('.driver-card', { hasText: CERT_NAME });
    check('revoke leaves ONE record for the driver, marked Revoked',
      (await after.count()) === 1 && /Revoked/.test(await after.first().textContent()),
      `${await after.count()} card(s); ${(await after.first().textContent().catch(() => '')).replace(/\s+/g, ' ').slice(0, 80)}`);

    check('no response carried a permanent flk_ bearer token', !bodies.some(b => /flk_[a-f0-9]{8,}/.test(b)));
    for (const c of codes) created.add('inv:' + sha256(c));
  } finally {
    await browser.close();
  }
}

let code;
try {
  await run();
  code = results.every(r => r.ok) && results.length ? 0 : 1;
} catch (err) {
  if (err instanceof Unobserved) { console.log(`  UNOBSERVED  ${err.message}`); code = 2; }
  else { console.log(`  FAIL  unexpected error — ${err && err.message}`); code = 1; }
} finally {
  await cleanup();
}
console.log(`\nADMIN CONSOLE VERDICT: ${code === 0 ? 'PASS' : code === 2 ? 'UNOBSERVED' : 'FAILURE'}`);
process.exit(code);
