// Diagnostics — install identity readout.
//
// The A1 field investigation (installed iPhone launched on v23.7.0 against a
// v24.0.2 candidate, showing first-run onboarding) could not be settled from
// inside the app. Diagnostics reported App Version, Service Worker and Cache
// Status, none of which distinguish "this update failed" from "this icon is
// installed from a different origin" — and an installed PWA keeps the origin it
// was installed from, with its own IndexedDB and Cache Storage, so those two
// look identical to a driver.
//
// These rows make that answerable in one tap. The mismatch case matters most:
// the shell cache is named `freightlogic-<SW_VERSION>`, so a cached generation
// that disagrees with APP_VERSION is the visible signature of an update that
// never completed, and it must read as a problem rather than as detail.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/diagnostics-install-identity.spec.mjs');

async function openDiagnostics(page) {
  await page.evaluate(async () => { await window.__FL_TESTS.openDiagnosticsPanel(); });
  // Wait for EVERY row these tests read, not just the first one. The panel
  // fills rows as its async checks complete, and Cached Generation lands after
  // Origin — waiting only on Origin let a fast machine read '...' out of a row
  // that had not been populated yet, which is how [DXI-04] failed in CI while
  // passing locally.
  await page.waitForFunction(() => {
    const ids = ['dxOrigin', 'dxDisplay', 'dxSwUrl', 'dxScope', 'dxCacheGen'];
    return ids.every(id => {
      const el = document.getElementById(id);
      return el && el.textContent && el.textContent !== '...';
    });
  }, { timeout: 15000 });
}

/**
 * Removes the service worker before a test seeds a versioned cache.
 *
 * The SW's `activate` handler deletes every cache except CACHE_NAME,
 * RECEIPT_CACHE and SHARE_CACHE — so a seeded `freightlogic-<x.y.z>` is exactly
 * the shape the app is designed to garbage-collect. [DXI-04] seeded one and
 * then raced that cleanup: it survived on a machine where the SW activated
 * late, and was purged before the panel read it on a machine where activation
 * landed inside the test window. Detaching the SW first makes the seeded cache
 * stable; the panel only enumerates caches, so it needs no worker.
 */
async function detachServiceWorker(page) {
  await page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map(r => r.unregister()));
  });
}

const rowText = (page, id) => page.evaluate(i => document.getElementById(i)?.textContent || '', id);
const rowColor = (page, id) => page.evaluate(i => document.getElementById(i)?.style.color || '', id);

test('[DXI-01] the panel reports the origin the app is actually running from', async () => {
  const app = await launchApp();
  try {
    await openDiagnostics(app.page);
    const shown = await rowText(app.page, 'dxOrigin');
    const actual = await app.page.evaluate(() => location.origin);
    eq(shown, actual, 'the Origin row must be the real origin, not a configured or assumed one');
    ok(/^https?:\/\//.test(shown), `and a usable URL, got ${shown}`);
  } finally { await app.close(); }
});

test('[DXI-02] launch mode distinguishes an installed PWA from a browser tab', async () => {
  const app = await launchApp();
  try {
    await openDiagnostics(app.page);
    // Playwright drives a normal tab, so this is the browser case. The value
    // matters because an installed icon and a tab can be on different origins.
    eq(await rowText(app.page, 'dxDisplay'), 'Browser tab', 'a non-installed context must say so');
  } finally { await app.close(); }
});

test('[DXI-03] the service-worker script URL and scope are reported, not inferred', async () => {
  const app = await launchApp();
  try {
    await app.page.evaluate(() => navigator.serviceWorker.ready);
    await openDiagnostics(app.page);
    const url = await rowText(app.page, 'dxSwUrl');
    const scope = await rowText(app.page, 'dxScope');
    ok(/service-worker\.js/.test(url), `the SW script URL must be shown, got ${url}`);
    ok(/^https?:\/\//.test(scope), `the scope must be shown, got ${scope}`);
    // The whole point: these carry the origin, so a wrong-origin install is
    // visible even when the version number alone looks plausible.
    const origin = await app.page.evaluate(() => location.origin);
    ok(url.startsWith(origin), 'the SW script URL is origin-qualified');
  } finally { await app.close(); }
});

test('[DXI-04] a cached shell generation that disagrees with the app reads as a problem', async () => {
  const app = await launchApp();
  try {
    // Exactly the A1 signature: a shell cache from an older release sitting
    // under a newer app build. Detach the SW first — see detachServiceWorker().
    await detachServiceWorker(app.page);
    await app.page.evaluate(async () => { await caches.open('freightlogic-1.2.3'); });
    await openDiagnostics(app.page);
    const txt = await rowText(app.page, 'dxCacheGen');
    ok(/1\.2\.3/.test(txt), `the stale generation must be named, got ${txt}`);
    ok(/vs app/.test(txt), 'and compared against the running app version');
    eq(await rowColor(app.page, 'dxCacheGen'), 'var(--bad)', 'a mismatch must render as a fault, not as neutral detail');
  } finally { await app.close(); }
});

test('[DXI-05] the share-target cache is not misread as a shell generation', async () => {
  const app = await launchApp();
  try {
    // `freightlogic-share-v2` is a real cache the SW creates for share-target
    // POSTs. A looser match would report it as a bogus generation and cry wolf
    // on a healthy install. Detached for the same determinism reason as above.
    await detachServiceWorker(app.page);
    await app.page.evaluate(async () => { await caches.open('freightlogic-share-v2'); });
    await openDiagnostics(app.page);
    const txt = await rowText(app.page, 'dxCacheGen');
    ok(!/share/.test(txt), `the share cache must not appear as a generation, got ${txt}`);
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
