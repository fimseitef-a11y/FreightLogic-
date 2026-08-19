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
export async function launchApp({ headless = true, geolocation = null, permissions = [] } = {}) {
  const { port } = await ensureServer();
  const browser = await chromium.launch({ headless });
  const context = await browser.newContext({
    geolocation: geolocation || undefined,
    permissions: geolocation ? ['geolocation', ...permissions] : permissions,
  });
  const page = await context.newPage();
  const baseUrl = `http://localhost:${port}`;
  await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load' });
  await page.waitForFunction(() => !!(window.__FL_TESTS && document.getElementById('appMeta')?.textContent), { timeout: 15000 });
  return {
    browser, context, page, baseUrl,
    close: async () => { await browser.close(); },
  };
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
