// v24.0.4 item 4 — service-worker subresource semantics.
//
// These drive the REAL shipped service-worker.js against a real Chromium with a
// real Cache Storage, and then kill the origin server outright so the failure
// path is a genuine network failure rather than an emulated one. (Playwright's
// context.setOffline() does not reliably apply to fetches the service worker
// itself makes, which is why the origin is shut down instead.)
//
// The defect being regressed: the old handler classified every same-origin `.js`
// as app logic and fell back to `cache.match(req) || cache.match(APP_SHELL)`.
// `cache.match(req)` does not pass { ignoreSearch: true }, so any `?v=` drift was
// a hard miss and the handler answered a <script src> with index.html — HTTP 200,
// Content-Type: text/html. The browser refuses to execute that, silently, with no
// 404 and no console error. Proven against the shipped worker during the
// RECON_24_0_2.md audit.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const MIME = {
  '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.md': 'text/markdown',
};

const { test, run } = createSuite('integration/sw-subresource-semantics.spec.mjs');

let server = null, sockets = new Set(), browser = null, ctx = null, page = null, BASE = '';

async function startOrigin() {
  server = http.createServer((req, res) => {
    const p = decodeURIComponent(req.url.split('?')[0]);
    const rel = p === '/' ? '/index.html' : p;
    const full = path.join(REPO_ROOT, rel);
    if (!full.startsWith(REPO_ROOT) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(full)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(fs.readFileSync(full));
  });
  server.on('connection', c => { sockets.add(c); c.on('close', () => sockets.delete(c)); });
  await new Promise(r => server.listen(0, r));
  BASE = 'http://127.0.0.1:' + server.address().port;
}

/** A real network failure: close the listener AND destroy live sockets. */
async function killOrigin() {
  await new Promise(r => { server.close(r); for (const c of sockets) c.destroy(); });
  await new Promise(r => setTimeout(r, 400));
}

async function probe(url) {
  return await page.evaluate(async (u) => {
    try {
      const r = await fetch(u);
      const t = await r.text();
      return {
        status: r.status,
        contentType: r.headers.get('content-type'),
        isHTML: /^\s*<!doctype html/i.test(t),
        length: t.length,
        head: t.slice(0, 60),
      };
    } catch (e) { return { error: String(e.message || e) }; }
  }, url);
}

test('setup: install the real service worker and let it precache the shell', async () => {
  await startOrigin();
  browser = await chromium.launch({ args: ['--no-sandbox'] });
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await page.goto(BASE + '/index.html', { waitUntil: 'load' });
  await page.waitForFunction(
    async () => { const r = await navigator.serviceWorker.getRegistration(); return !!(r && r.active); },
    { timeout: 30000 });
  await page.waitForFunction(() => !!navigator.serviceWorker.controller, { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(1500);
  const controlled = await page.evaluate(() => !!navigator.serviceWorker.controller);
  ok(controlled, 'the service worker must be controlling the page before these probes mean anything');
});

test('[SW-01] cold offline: the app shell still boots from cache with the origin dead', async () => {
  await killOrigin();
  const nav = await probe('index.html');
  eq(nav.status, 200, 'a navigation must still be served offline');
  ok(nav.isHTML, 'a navigation is the one request that SHOULD receive HTML');
  ok(nav.length > 1000, `expected the real shell, got ${nav.length} bytes`);
});

test('[SW-02] cold offline: a precached script is served as JavaScript, not HTML', async () => {
  const r = await probe('app.js?v=' + await page.evaluate(() => {
    const s = [...document.querySelectorAll('script[src]')].map(x => x.getAttribute('src')).find(x => x.startsWith('app.js'));
    return s.split('?v=')[1];
  }));
  eq(r.status, 200, 'the precached app.js must be served offline');
  ok(!r.isHTML, 'app.js must not be answered with HTML');
  ok(/javascript/.test(r.contentType || ''), `expected a JavaScript content-type, got ${r.contentType}`);
});

test('[SW-03] version-query drift self-heals to the real file for a KNOWN app asset', async () => {
  // This is the exact hazard: index.html asking for a ?v= the precache does not
  // hold. It must resolve to the real script, never to the shell.
  const r = await probe('app.js?v=99.9.9');
  eq(r.status, 200, 'a drifted query on a known app asset must still resolve');
  ok(!r.isHTML, 'DRIFT MUST NOT RETURN HTML — this was the silent script-vanishing defect');
  ok(/javascript/.test(r.contentType || ''), `expected JavaScript, got ${r.contentType}`);
  ok(r.head.includes('use strict') || r.length > 100000, `expected the real app.js body, got: ${r.head}`);
});

test('[SW-04] a no-query request for a known app asset also resolves to the script', async () => {
  const r = await probe('app.js');
  eq(r.status, 200, 'the bare path must resolve for a known app asset');
  ok(!r.isHTML, 'must not be answered with HTML');
  ok(/javascript/.test(r.contentType || ''), `expected JavaScript, got ${r.contentType}`);
});

test('[SW-05] an UNKNOWN same-origin script is never answered with the app shell', async () => {
  // dat-rateview.js is same-origin, ends in .js, and is deliberately NOT in CORE.
  // The old wildcard policy would have cached it on success and served the shell
  // for it on failure.
  const r = await probe('dat-rateview.js');
  ok(!r.isHTML, 'an unknown script must never receive index.html');
  ok(r.status === 504 || r.status === 404 || r.error,
    `expected an honest failure for an uncached unknown script, got status ${r.status} / ${r.contentType}`);
  if (r.status === 504) ok(/text\/plain/.test(r.contentType || ''), 'the offline failure must be plain text, not HTML');
});

test('[SW-06] a wholly unknown path fails honestly rather than returning the shell', async () => {
  const r = await probe('definitely-not-a-real-asset-' + Date.now() + '.js');
  ok(!r.isHTML, 'an unknown path must never receive index.html');
  ok(r.status !== 200 || r.error, `expected a failure status, got ${r.status}`);
});

test('[SW-07] the known-asset set is derived from CORE, not written twice', async () => {
  const src = fs.readFileSync(path.join(REPO_ROOT, 'service-worker.js'), 'utf8');
  ok(/const KNOWN_ASSET_PATHS = new Set\(\s*CORE\.map/.test(src),
    'KNOWN_ASSET_PATHS must be derived from CORE so the fetch policy cannot drift from the precache list');
  ok(!/url\.pathname\.endsWith\('\.js'\)\s*\|\|/.test(src.split('const isNavigation')[0] || ''),
    'the old wildcard "every same-origin .js is app logic" classification must be gone');
});

export async function runSpec() {
  try {
    return await run();
  } finally {
    if (browser) await browser.close().catch(() => {});
    try { if (server && server.listening) await killOrigin(); } catch {}
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
