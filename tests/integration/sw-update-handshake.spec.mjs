// Service-worker update handshake — the A1 field failure.
//
// On 2026-09-02 the operator's installed iPhone PWA launched on v23.7.0 while
// the candidate was v24.0.2, so FIELD_TEST_CHECKLIST.md A1 is a FAIL. Exact
// source review found the v24.0.2 update handshake broken in a way no test
// covered: `app.js`'s "Reload" button posted SKIP_WAITING straight to the new
// worker, bypassing `window._flRequestSWUpdate`, so sw-bridge.js's private
// `skipWaitingRequested` flag stayed false and its `controllerchange` handler
// ignored the activation that followed. The new worker took over and the page
// never reloaded — the update installs and the driver keeps looking at the old
// version. `_flRequestSWUpdate` was independently wrong: it posted to
// `navigator.serviceWorker.controller`, the OLD active worker, whose
// skipWaiting() is a no-op.
//
// (That defect cannot by itself explain a device pinned to v23.7.0 — that
// device is running v23.7.0's bridge, which reloads unconditionally — so the
// deployed origin/generation remains the separate live-gate question. The
// handshake defect is real regardless, and this is its regression.)
//
// These tests drive a REAL service-worker update in Chromium against the real
// unmodified sw-bridge.js: register v1, take control, rewrite the worker bytes,
// update, then ask the bridge to finish the handover. A load counter in the
// fixture proves the outcome is exactly one reload — not zero, not a loop.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchBlank } from '../lib/harness.mjs';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const SW_PATH = path.join(ROOT, 'tests/fixtures/sw-update/sw.js');
const SW_V1 = readFileSync(SW_PATH, 'utf8');
const SW_V2 = SW_V1.replace("const FIXTURE_GENERATION = 'v1';", "const FIXTURE_GENERATION = 'v2';");

const { test, run } = createSuite('integration/sw-update-handshake.spec.mjs');

/** Boots the fixture page under a v1 worker that has taken control. */
async function bootControlled() {
  const app = await launchBlank();
  await app.page.goto(`${app.baseUrl}/tests/fixtures/sw-update/index.html`, { waitUntil: 'load' });
  await app.page.evaluate(async () => {
    const reg = await navigator.serviceWorker.register('./sw.js');
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise(res => navigator.serviceWorker.addEventListener('controllerchange', res, { once: true }));
    }
    return reg.scope;
  });
  return app;
}

/** Publishes v2 bytes and waits for it to reach `waiting`. */
async function stageUpdate(page) {
  writeFileSync(SW_PATH, SW_V2);
  await page.evaluate(async () => {
    const reg = await navigator.serviceWorker.getRegistration();
    await reg.update();
    if (!reg.waiting) {
      await new Promise((res, rej) => {
        const t = setTimeout(() => rej(new Error('no waiting worker appeared')), 10000);
        const check = () => { if (reg.waiting) { clearTimeout(t); res(); } };
        reg.addEventListener('updatefound', () => {
          const nw = reg.installing;
          if (!nw) return check();
          nw.addEventListener('statechange', check);
        });
        check();
      });
    }
  });
}

async function loadCount(page) {
  return await page.evaluate(() => Number(sessionStorage.getItem('loads') || '0'));
}

test('[SWU-01] the bridge completes the handover: waiting worker takes over and the page reloads exactly once', async () => {
  const app = await bootControlled();
  try {
    eq(await loadCount(app.page), 1, 'the fixture starts on its first load');
    await stageUpdate(app.page);

    // What the repaired app.js button does: hand the NEW worker to the bridge.
    await app.page.evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      window._flRequestSWUpdate(reg.waiting);
    });
    await app.page.waitForFunction(() => Number(sessionStorage.getItem('loads') || '0') >= 2, { timeout: 15000 });
    eq(await loadCount(app.page), 2, 'exactly one reload followed the handover');

    // The new generation is genuinely in control — the update actually landed.
    const active = await app.page.evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      return { hasWaiting: !!reg.waiting, controlled: !!navigator.serviceWorker.controller };
    });
    ok(active.controlled, 'the page is controlled after the reload');
    ok(!active.hasWaiting, 'no worker is left stranded in waiting');

    // And the 3s fallback timer must not fire a SECOND reload after the first.
    await app.page.waitForTimeout(4000);
    eq(await loadCount(app.page), 2, 'the fallback timer never produces a second reload');
  } finally {
    writeFileSync(SW_PATH, SW_V1);
    await app.close();
  }
});

test('[SWU-02] posting SKIP_WAITING behind the bridge activates the worker but never reloads — the shipped defect', async () => {
  // This is the exact code path app.js used to take. It proves the regression
  // above has teeth: the worker really does take over, so a test that only
  // checked "did the new worker activate" would have passed while the driver
  // sat on a stale page.
  const app = await bootControlled();
  try {
    eq(await loadCount(app.page), 1, 'first load');
    await stageUpdate(app.page);

    const took = await app.page.evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      const changed = new Promise(res => navigator.serviceWorker.addEventListener('controllerchange', () => res(true), { once: true }));
      reg.waiting.postMessage({ type: 'SKIP_WAITING' });   // bypasses the bridge
      const raced = await Promise.race([changed, new Promise(r => setTimeout(() => r(false), 8000))]);
      return raced;
    });
    ok(took, 'the new worker does take control — activation is not the failure');
    await app.page.waitForTimeout(1500);
    eq(await loadCount(app.page), 1,
       'and the page does NOT reload, which is exactly why the driver kept seeing the old version');
  } finally {
    writeFileSync(SW_PATH, SW_V1);
    await app.close();
  }
});

test('[SWU-03] the bridge targets the waiting worker, not the old controller', async () => {
  // `_flRequestSWUpdate()` called with no argument must still find the waiting
  // worker for itself. Posting to navigator.serviceWorker.controller — the old,
  // already-active worker — is a no-op skipWaiting() and the update never lands.
  const app = await bootControlled();
  try {
    await stageUpdate(app.page);
    const targeted = await app.page.evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      const controllerScriptURL = navigator.serviceWorker.controller?.scriptURL;
      const waitingExists = !!reg.waiting;
      // Record what the bridge posts to by instrumenting both candidates.
      let postedToWaiting = false, postedToController = false;
      const wp = reg.waiting.postMessage.bind(reg.waiting);
      reg.waiting.postMessage = (m) => { postedToWaiting = true; wp(m); };
      const ctrl = navigator.serviceWorker.controller;
      if (ctrl) { const cp = ctrl.postMessage.bind(ctrl); ctrl.postMessage = () => { postedToController = true; }; }
      await window._flRequestSWUpdate();          // no argument — must self-resolve
      return { waitingExists, postedToWaiting, postedToController, controllerScriptURL };
    });
    ok(targeted.waitingExists, 'a waiting worker was staged');
    ok(targeted.postedToWaiting, 'the bridge posted SKIP_WAITING to the WAITING worker');
    ok(!targeted.postedToController, 'and not to the old active controller, whose skipWaiting() is a no-op');
  } finally {
    writeFileSync(SW_PATH, SW_V1);
    await app.close();
  }
});

export async function runSpec() { return run(); }
