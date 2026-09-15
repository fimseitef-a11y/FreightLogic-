// Test harness for FreightLogic — launches the real app in a headless Chromium
// browser (Playwright) served from the repo root, with real IndexedDB and
// Cache Storage (no mocks). Each call to launchApp() gets a fresh, isolated
// browser context (fresh IndexedDB/localStorage/sessionStorage), equivalent
// to a brand-new device.
//
// Usage:
//   NODE_PATH=/opt/node22/lib/node_modules node tests/integration/foo.spec.mjs
//
// The repo has no local package.json/node_modules; Playwright is installed
// globally in this environment. The static test server below uses only Node
// built-ins, so CI never depends on `npx` package resolution or a warm npm cache.

import { chromium } from 'playwright';
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const ROOT_PREFIX = REPO_ROOT.endsWith(path.sep) ? REPO_ROOT : REPO_ROOT + path.sep;

const MIME = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ico', 'image/x-icon'],
  ['.jpeg', 'image/jpeg'],
  ['.jpg', 'image/jpeg'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json; charset=utf-8'],
  ['.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
]);

function contentTypeFor(filePath) {
  return MIME.get(path.extname(filePath).toLowerCase()) || 'application/octet-stream';
}

function requestPath(req) {
  const rawPath = new URL(req.url || '/', 'http://127.0.0.1').pathname;
  let pathname;
  try { pathname = decodeURIComponent(rawPath); }
  catch { return null; }
  if (pathname === '/') pathname = '/index.html';
  const filePath = path.resolve(REPO_ROOT, '.' + pathname);
  if (filePath !== REPO_ROOT && !filePath.startsWith(ROOT_PREFIX)) return null;
  return filePath;
}

async function serveStatic(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD', 'Cache-Control': 'no-store' });
    res.end();
    return;
  }

  let filePath = requestPath(req);
  if (!filePath) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end('Bad request');
    return;
  }

  try {
    const info = await stat(filePath);
    if (info.isDirectory()) filePath = path.join(filePath, 'index.html');
    const body = await readFile(filePath);
    res.writeHead(200, {
      'Content-Type': contentTypeFor(filePath),
      'Content-Length': String(body.length),
      'Cache-Control': 'no-store',
      'Service-Worker-Allowed': '/',
    });
    if (req.method === 'HEAD') res.end();
    else res.end(body);
  } catch (error) {
    const notFound = error && (error.code === 'ENOENT' || error.code === 'ENOTDIR');
    res.writeHead(notFound ? 404 : 500, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(notFound ? 'Not found' : 'Test server error');
  }
}

let sharedServer = null; // { server, port } — reused across launchApp() calls in one process

async function ensureServer() {
  if (sharedServer) return sharedServer;

  const server = http.createServer((req, res) => {
    serveStatic(req, res).catch((error) => {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      }
      if (!res.writableEnded) res.end('Test server error');
      console.error('test static server request failed:', error);
    });
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(0, '127.0.0.1');
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise(resolve => server.close(resolve));
    throw new Error('test static server did not expose a TCP port');
  }

  sharedServer = { server, port: address.port };
  return sharedServer;
}

export async function stopServer() {
  if (sharedServer) {
    const { server } = sharedServer;
    sharedServer = null;
    await new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
}

async function waitForAppBoot(page, enableTestExports) {
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  if (!enableTestExports) return;

  // `app.js` exposes window.__FL_TESTS at PARSE time but assigns the shared
  // IndexedDB handle `db` only inside the boot IIFE, so there is a real window in
  // every fresh document where T.dumpStore exists and `db` is still null. That is
  // why the probe below exists at all (PRs #148/#149).
  //
  // The probe alone is not sufficient, and CI proved it: run 34951456824 failed
  // SMS-04 with `TypeError: Cannot read properties of null (reading 'transaction')`
  // at tx() <- addExpense(), on the FIRST statement of the test body — i.e. the
  // probe had already succeeded. A single successful probe only proves the
  // document that answered it had booted; it says nothing about the document the
  // test body will actually run in.
  //
  // Something does swap the document: `sw-bridge.js` calls window.location.reload()
  // from reloadOnce(), driven by a controllerchange AND by an unconditional
  // `setTimeout(reloadOnce, 3000)` fallback. So a launch that boots in ~200ms can
  // be reloaded seconds later, mid-test, handing the test a brand-new document
  // with __FL_TESTS present and `db` back to null.
  //
  // Two conditions close that window, neither of which weakens any assertion.

  // 1. Let the service worker reach a settled state, so the bridge has no waiting
  //    or installing worker left to request SKIP_WAITING for. Best-effort and
  //    bounded: a spec that deliberately drives the update handshake must not be
  //    turned into a hard timeout, so an unsettled worker proceeds rather than
  //    failing the launch.
  await page.waitForFunction(async () => {
    if (!('serviceWorker' in navigator)) return true;
    const regs = await navigator.serviceWorker.getRegistrations().catch(() => []);
    return regs.every(r => !r.installing && !r.waiting);
  }, { timeout: 5000 }).catch(() => {});

  // 2. Require the SAME document to complete the probe twice with a gap between.
  //    A reload between the two attempts resets the token, so the loop simply
  //    keeps going until one document answers twice — which is the property the
  //    caller actually needs, rather than "some document answered once".
  const probe = () => page.evaluate(async () => {
    const T = window.__FL_TESTS;
    if (!T || typeof T.dumpStore !== 'function') return null;
    try { await T.dumpStore('settings'); } catch { return null; }
    if (!window.__flBootToken) {
      window.__flBootToken = `${performance.timeOrigin}:${Math.random().toString(36).slice(2)}`;
    }
    return window.__flBootToken;
  }).catch(() => null); // an in-flight navigation destroys the execution context

  const deadline = Date.now() + 15000;
  let previous = null;
  while (Date.now() < deadline) {
    const token = await probe();
    if (token && token === previous) return;
    previous = token;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('waitForAppBoot: the app never presented a stable booted document within 15s');
}

/**
 * Launches a fresh browser context + page loaded with index.html, and waits
 * for app boot. With test exports enabled, readiness includes a successful
 * IndexedDB-backed test operation so callers cannot race app DB initialization.
 * Returns { browser, context, page, baseUrl, close() }.
 */
export async function launchApp({ headless = true, geolocation = null, permissions = [], enableTestExports = true } = {}) {
  const { port } = await ensureServer();
  const browser = await chromium.launch({ headless, ...(process.env.FL_CHROME_PATH ? { executablePath: process.env.FL_CHROME_PATH } : {}) });
  const context = await browser.newContext({
    geolocation: geolocation || undefined,
    permissions: geolocation ? ['geolocation', ...permissions] : permissions,
  });
  // Opt-in to window.__FL_TESTS (gated on __FL_TESTS_ENABLED as of the F-5 fix).
  // Defaults to true because most of this suite drives pure functions through
  // __FL_TESTS; pass enableTestExports:false to test a genuine production load.
  if (enableTestExports) {
    await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  }
  const page = await context.newPage();
  const baseUrl = `http://127.0.0.1:${port}`;
  await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
  await waitForAppBoot(page, enableTestExports);
  return {
    browser, context, page, baseUrl,
    close: async () => { await browser.close(); },
  };
}

/**
 * Launches a fresh, isolated browser context on a BLANK same-origin page — no
 * app.js, no open IndexedDB connection. Use this when a test has to establish
 * database state before the app's own initDB() runs (a seeded-old-version
 * upgrade test, for example: a live page holding the DB open at the current
 * version makes seeding an older version impossible).
 *
 * Call `bootApp()` on the returned object to then navigate the same context to
 * index.html and wait for boot, exactly as launchApp() does.
 */
export async function launchBlank({ headless = true, enableTestExports = true } = {}) {
  const { port } = await ensureServer();
  const browser = await chromium.launch({ headless, ...(process.env.FL_CHROME_PATH ? { executablePath: process.env.FL_CHROME_PATH } : {}) });
  const context = await browser.newContext();
  if (enableTestExports) {
    await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  }
  const page = await context.newPage();
  const baseUrl = `http://127.0.0.1:${port}`;
  await page.goto(`${baseUrl}/tests/fixtures/blank.html`, { waitUntil: 'load' });
  return {
    browser, context, page, baseUrl,
    bootApp: async () => {
      await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
      await waitForAppBoot(page, enableTestExports);
    },
    close: async () => { await browser.close(); },
  };
}

/**
 * Suppress the F26 First-Time Setup Wizard, which auto-opens ~800ms after
 * boot on an empty DB and steals pointer events as a full-screen modal. Call
 * this immediately after launchApp() in specs that do not themselves seed a
 * trip as their first action.
 */
export async function skipFirstRunWizard(page) {
  await page.evaluate(async () => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readwrite');
        txn.objectStore('settings').put({ key: 'f26SetupComplete', value: true });
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  });
}

export function ok(cond, msg) {
  if (!cond) throw new Error('ASSERTION FAILED: ' + msg);
}

export function eq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`ASSERTION FAILED: ${msg}\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`);
  }
}

// ---- tiny per-file test suite ----
// Each spec file calls createSuite() to get its own isolated {test, run} pair
// so multiple spec files can be imported into one runner process without
// their test registries colliding.
export function createSuite(fileLabel) {
  const REGISTRY = [];
  return {
    test(name, fn) { REGISTRY.push({ name, fn }); },
    async run() {
      let pass = 0, fail = 0;
      const failures = [];
      console.log(`\n${fileLabel}`);
      for (const { name, fn } of REGISTRY) {
        try {
          await fn();
          console.log(`  \x1b[32m✓\x1b[0m ${name}`);
          pass++;
        } catch (e) {
          console.log(`  \x1b[31m✗ ${name}\x1b[0m`);
          console.log(`    ${String(e.message || e).split('\n').join('\n    ')}`);
          fail++;
          failures.push({ name, error: String(e.message || e) });
        }
      }
      console.log(`  -- ${fileLabel}: ${pass} passed, ${fail} failed --`);
      return { file: fileLabel, pass, fail, failures };
    },
  };
}