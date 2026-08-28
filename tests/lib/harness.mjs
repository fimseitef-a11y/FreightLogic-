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
// globally in this environment. Run tests with NODE_PATH set as above, or
// via `bash tests/run-all.sh` which sets it for you.

import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

let sharedServer = null; // { proc, port } — reused across launchApp() calls in one process

async function ensureServer() {
  if (sharedServer) return sharedServer;
  const port = await getFreePort();
  const proc = spawn('npx', ['http-server', REPO_ROOT, '-p', String(port), '-c-1', '--silent'], {
    stdio: 'ignore',
    env: process.env,
  });
  await new Promise((resolve, reject) => {
    const start = Date.now();
    const tryConnect = () => {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.end(); resolve(); });
      sock.once('error', () => {
        if (Date.now() - start > 10000) reject(new Error('server did not start'));
        else setTimeout(tryConnect, 100);
      });
    };
    tryConnect();
  });
  sharedServer = { proc, port };
  return sharedServer;
}

export async function stopServer() {
  if (sharedServer) {
    sharedServer.proc.kill();
    sharedServer = null;
  }
}

/**
 * Launches a fresh browser context + page loaded with index.html, and waits
 * for app boot (window.__FL_TESTS present + #appMeta populated).
 * Returns { browser, context, page, baseUrl, close() }.
 */
export async function launchApp({ headless = true, geolocation = null, permissions = [], enableTestExports = true } = {}) {
  const { port } = await ensureServer();
  const browser = await chromium.launch({ headless });
  const context = await browser.newContext({
    geolocation: geolocation || undefined,
    permissions: geolocation ? ['geolocation', ...permissions] : permissions,
  });
  // Opt-in to window.__FL_TESTS (app.js:16021-16038, gated on __FL_TESTS_ENABLED as of
  // the F-5 fix). Defaults to true because most of this suite drives pure functions
  // through __FL_TESTS; pass enableTestExports:false to test a genuine production load
  // (this is how tests/integration/fl-tests-exposure.spec.mjs proves/regresses F-5).
  if (enableTestExports) {
    await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  }
  const page = await context.newPage();
  const baseUrl = `http://localhost:${port}`;
  await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
  // Boot-ready signal must NOT depend on __FL_TESTS — that would hang forever on a
  // genuine (enableTestExports:false) production load once F-5 gates the export.
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
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
  const browser = await chromium.launch({ headless });
  const context = await browser.newContext();
  if (enableTestExports) {
    await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  }
  const page = await context.newPage();
  const baseUrl = `http://localhost:${port}`;
  await page.goto(`${baseUrl}/tests/fixtures/blank.html`, { waitUntil: 'load' });
  return {
    browser, context, page, baseUrl,
    bootApp: async () => {
      await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
      await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    },
    close: async () => { await browser.close(); },
  };
}

/**
 * Suppress the F26 First-Time Setup Wizard, which auto-opens ~800ms after
 * boot on an empty DB (app.js:3390-3397, checkFirstRunSetup) and steals
 * pointer events as a full-screen modal. Call this immediately after
 * launchApp() — before any waitForTimeout()/multi-step UI interaction —
 * in any spec that doesn't itself seed a trip in its first action (seeding
 * a trip also suppresses it, via the same isEmpty check, but not every
 * spec wants to do that as its first step).
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
