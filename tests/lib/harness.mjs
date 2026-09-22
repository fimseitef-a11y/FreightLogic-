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
import { AsyncLocalStorage } from 'node:async_hooks';

/* Parallel-suite spec context.
 *
 * `run-all.mjs` can execute several specs concurrently. Two things break if
 * nothing knows which spec a given async continuation belongs to:
 *   1. console output interleaves into an unreadable braid, and
 *   2. the #224 lifecycle dump — deliberately "every live page" — would report
 *      OTHER specs' pages as evidence for this spec's failure, which is worse
 *      than no diagnostic because it reads as a real finding.
 * An AsyncLocalStorage store carries the label through every await, so both
 * stay correct. Concurrency 1 behaves exactly as before: the store is simply
 * always the same value. */
export const SPEC_CTX = new AsyncLocalStorage();

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

// ── Issue #224: lifecycle diagnostics ────────────────────────────────────────
//
// `main` intermittently fails with the app's module-scoped IndexedDB handle
// `null` inside `tx()` — `Cannot read properties of null (reading
// 'objectStoreNames')` at `physicalFor` — in specs that had already completed
// `waitForAppBoot()`. The handle is assigned once (`db = await initDB()`) and
// nothing sets it back to null, so the only way it can be null AFTER readiness
// is a NEW DOCUMENT: a reload or navigation that re-ran the IIFE.
//
// That was a deduction, not an observation, and nothing recorded which it was.
// This substrate makes it observable rather than inferred:
//
//   - every tracked page is stamped with a per-document id at init-script time,
//     so a re-bootstrap is detectable by comparing the id at readiness with the
//     id now — a reload gets a new stamp;
//   - main-frame navigations, page errors and console errors are recorded;
//   - `createSuite()` dumps all of it for every live page when an assertion
//     fails, so a CI failure arrives WITH its evidence instead of prompting
//     another rerun.
//
// Deliberately harness-only: no production byte changes for diagnostics. It is
// also deliberately not a retry, a timeout bump, or a weakened assertion —
// #224 forbids all three, and they would hide the very transition being hunted.
const TRACKED = new Set();

const LIFECYCLE_INIT = () => {
  window.__FL_DOC_ID = Math.random().toString(36).slice(2) + ':' + Date.now();
  window.__FL_DOC_ERRORS = [];
  window.addEventListener('error', e => {
    try { window.__FL_DOC_ERRORS.push('error: ' + (e.message || '')); } catch (_) {}
  });
};

function trackPage(page, label) {
  const rec = { page, label, spec: SPEC_CTX.getStore()?.label ?? null, navigations: [], pageErrors: [], consoleErrors: [], bootDocId: null };
  page.on('framenavigated', f => {
    try { if (f === page.mainFrame()) rec.navigations.push(f.url()); } catch (_) {}
  });
  page.on('pageerror', e => rec.pageErrors.push(String(e && e.message || e)));
  page.on('console', m => { if (m.type() === 'error') rec.consoleErrors.push(m.text().slice(0, 300)); });
  page.on('close', () => TRACKED.delete(rec));
  TRACKED.add(rec);
  return rec;
}

/** Everything known about one tracked page's document lifecycle, right now. */
async function lifecycleOf(rec) {
  let live = { docId: null, dbNull: null, readyErr: null };
  try {
    live = await rec.page.evaluate(async () => {
      const out = { docId: window.__FL_DOC_ID || null, dbNull: null, readyErr: null,
                    errors: (window.__FL_DOC_ERRORS || []).slice(0, 5) };
      try { await window.__FL_TESTS.dumpStore('settings'); out.dbNull = false; }
      catch (e) { out.dbNull = true; out.readyErr = String(e && e.message || e); }
      return out;
    });
  } catch (e) { live.readyErr = 'evaluate failed: ' + String(e && e.message || e); }
  return {
    label: rec.label,
    bootDocId: rec.bootDocId,
    currentDocId: live.docId,
    reBootstrapped: !!(rec.bootDocId && live.docId && rec.bootDocId !== live.docId),
    dbUnusableNow: live.dbNull,
    dbError: live.readyErr,
    navigations: rec.navigations,
    pageErrors: rec.pageErrors.slice(0, 5),
    consoleErrors: rec.consoleErrors.slice(0, 5),
    inPageErrors: live.errors || [],
  };
}

/** Printed by createSuite() on any assertion failure. */
async function dumpLifecycleDiagnostics() {
  if (!TRACKED.size) return;
  // Under a parallel run, report only the pages this spec actually owns.
  // Outside one (or for pages created before any context existed) the set is
  // unfiltered, which is the original single-threaded behaviour.
  const spec = SPEC_CTX.getStore()?.label ?? null;
  const scoped = spec ? [...TRACKED].filter(r => r.spec === spec || r.spec === null) : [...TRACKED];
  if (!scoped.length) return;
  const lines = [];
  for (const rec of scoped) {
    let info;
    try { info = await lifecycleOf(rec); } catch (e) { info = { label: rec.label, error: String(e) }; }
    lines.push(`    [#224 lifecycle] ${JSON.stringify(info)}`);
    if (info.reBootstrapped) {
      lines.push('    [#224 lifecycle] *** DOCUMENT RE-BOOTSTRAPPED AFTER READINESS — this is the db===null mechanism ***');
    }
  }
  console.log(lines.join('\n'));
}

/** The readiness contract every page in this suite must satisfy before a test
 *  touches persistence — exported so a spec that opens its OWN extra page (two
 *  tabs, a concurrency test) cannot settle for a weaker wait. */
export async function waitForAppReady(page, { timeout = 15000 } = {}) {
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout });

  // appMeta can populate before initDB() has assigned the app's shared IndexedDB
  // handle. Tests that call persistence helpers immediately after launch therefore
  // race `db === null` nondeterministically. Probe the same exported data path the
  // suite is about to use and only return once it can complete.
  //
  // Issue #224 — why this polls from NODE and not with `page.waitForFunction()`.
  // `waitForFunction` evaluates its predicate and tests the RESULT for truthiness
  // without awaiting it. An `async` predicate always returns a Promise, and a
  // Promise is always truthy, so the FIRST probe satisfies the wait whatever that
  // probe actually found — the polling loop never runs a second time, and the
  // database check inside it never decides anything.
  //
  // Stated that precisely because the observed shape is narrower than "it returns
  // instantly". Playwright still awaits the accepted Promise while serialising the
  // result, so the wait lasts as long as ONE probe: it returns after a single
  // FAILED probe rather than polling until one succeeds. HR-08 measures exactly
  // that and reports the attempt count — with this form reinstated it reads
  // `1 attempts`. HR-09 covers the other end: a probe that never settles hangs the
  // serialisation instead of establishing anything.
  //
  // None of this is taken from documentation. `probeResolvesWithoutAwaiting()`
  // below drives the real Playwright build this suite runs on and measures it
  // (67ms against a predicate that cannot become true for 3000ms), and HR-06
  // fails if the behaviour ever changes or if this file goes back to that form.
  //
  // `page.evaluate()` DOES await a returned Promise, so the poll is a Node-side
  // loop over evaluate. This is not a retry of a failed assertion and not a
  // timeout bump: it is the wait that was written here doing the waiting it
  // always claimed to do.
  const deadline = Date.now() + timeout;
  let lastErr = 'never probed';
  for (;;) {
    let ok = false;
    try {
      const r = await page.evaluate(async () => {
        const T = window.__FL_TESTS;
        if (typeof T?.dumpStore !== 'function') return { ok: false, err: '__FL_TESTS.dumpStore missing' };
        try {
          await T.dumpStore('settings');
          return { ok: true, err: null };
        } catch (e) {
          return { ok: false, err: String(e && e.message || e) };
        }
      });
      ok = r.ok;
      if (!ok) lastErr = r.err;
    } catch (e) {
      // A navigation mid-evaluate destroys the execution context. That is the
      // #224 re-bootstrap itself, so it is a reason to keep waiting for the NEW
      // document to become ready, not a reason to fail here.
      lastErr = 'evaluate failed: ' + String(e && e.message || e);
    }
    if (ok) return;
    if (Date.now() >= deadline) {
      throw new Error(`waitForAppReady: IndexedDB not ready within ${timeout}ms — last probe: ${lastErr}`);
    }
    await new Promise(r => setTimeout(r, 25));
  }
}

/** Drives the real Playwright build this suite runs on and reports whether
 *  `waitForFunction` resolves an `async` predicate WITHOUT awaiting it — the
 *  Issue #224 mechanism, measured rather than asserted from documentation.
 *  Returns { resolvedMs, awaited } where `awaited: false` is the defect.
 *  Exported for HR-04; not used by the readiness path itself. */
export async function probeResolvesWithoutAwaiting(page, settleMs = 600) {
  await page.evaluate(ms => {
    window.__FL_PROBE_READY = false;
    setTimeout(() => { window.__FL_PROBE_READY = true; }, ms);
  }, settleMs);
  const t0 = Date.now();
  await page.waitForFunction(async () => {
    await new Promise(r => setTimeout(r, 20));
    return window.__FL_PROBE_READY;
  }, { timeout: settleMs * 10 });
  const resolvedMs = Date.now() - t0;
  return { resolvedMs, awaited: resolvedMs >= settleMs };
}

async function waitForAppBoot(page, enableTestExports, rec) {
  if (!enableTestExports) {
    await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    return;
  }
  await waitForAppReady(page);
  if (rec) {
    // The document that satisfied readiness. If a later failure sees a different
    // id, the app re-bootstrapped underneath the test.
    rec.bootDocId = await page.evaluate(() => window.__FL_DOC_ID || null).catch(() => null);
  }
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
  await context.addInitScript(LIFECYCLE_INIT);   // Issue #224 diagnostics
  const page = await context.newPage();
  const rec = trackPage(page, 'launchApp:page');
  // Pages belonging to THIS app handle. `TRACKED` is process-wide, and every
  // app's first page carries the same label, so a caller doing
  // `.find(l => l.label === 'launchApp:page')` over the global set silently
  // reads whichever app happens to be first — another spec's, once specs run
  // concurrently. An instance method must answer for its own instance.
  const owned = [rec];
  const baseUrl = `http://127.0.0.1:${port}`;
  await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
  await waitForAppBoot(page, enableTestExports, rec);
  return {
    browser, context, page, baseUrl,
    /** Issue #224: open an ADDITIONAL tab in this context, already tracked and
     *  already past the same readiness contract page 1 satisfied. Specs used to
     *  hand-roll this with an `#appMeta`-only wait, which the harness's own
     *  comment documents as insufficient. */
    newReadyPage: async (label = 'extra') => {
      const p = await context.newPage();
      const r = trackPage(p, label);
      owned.push(r);
      await p.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
      await waitForAppReady(p);
      r.bootDocId = await p.evaluate(() => window.__FL_DOC_ID || null).catch(() => null);
      return p;
    },
    lifecycle: async () => Promise.all(owned.filter(r => TRACKED.has(r)).map(lifecycleOf)),
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
  await context.addInitScript(LIFECYCLE_INIT);   // Issue #224 diagnostics
  const page = await context.newPage();
  const rec = trackPage(page, 'launchBlank:page');
  const baseUrl = `http://127.0.0.1:${port}`;
  await page.goto(`${baseUrl}/tests/fixtures/blank.html`, { waitUntil: 'load' });
  return {
    browser, context, page, baseUrl,
    // Same scoping rule as launchApp(): this handle answers for its own page.
    lifecycle: async () => Promise.all([rec].filter(r => TRACKED.has(r)).map(lifecycleOf)),
    bootApp: async () => {
      await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
      await waitForAppBoot(page, enableTestExports, rec);
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
          // Issue #224: a failure prints the document lifecycle of every live
          // page, so a post-readiness re-bootstrap shows up as evidence in the
          // CI log instead of being deduced from a stack trace afterwards.
          try { await dumpLifecycleDiagnostics(); } catch (_) {}
          fail++;
          failures.push({ name, error: String(e.message || e) });
        }
      }
      console.log(`  -- ${fileLabel}: ${pass} passed, ${fail} failed --`);
      return { file: fileLabel, pass, fail, failures };
    },
  };
}