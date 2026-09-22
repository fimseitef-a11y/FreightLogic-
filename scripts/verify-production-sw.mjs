#!/usr/bin/env node
/**
 * FreightLogic — production service-worker / offline behaviour gate.
 *
 * Completion-plan blocking evidence item 2: "prove the exact candidate,
 * including the formerly missing admin runtime asset, survives normal
 * update/reload/offline behavior without destructive clearing."
 *
 * WHY THIS IS A SEPARATE GATE FROM PARITY. `verify-cloudflare-parity.mjs`
 * fetches each declared asset with `fetch()` and asserts status and content.
 * That proves DELIVERY. It cannot prove that a browser, having installed the
 * deployed service worker, then survives a reload and a genuine network loss —
 * which is the behaviour a driver actually depends on in a dead zone, and the
 * axis on which this app has failed before (v24.0.4: a `?v=` mismatch made the
 * worker answer a `<script src>` with index.html, HTTP 200, text/html; the
 * browser refused to execute it, with no 404 and no console error).
 *
 * WHAT IT NEVER DOES. It never clears site data, never unregisters a worker on
 * an operator device, never deploys, and never writes to the repository. It
 * drives a FRESH, THROWAWAY browser profile against the public origin — the
 * completion plan's warning about destroying IndexedDB evidence is about the
 * operator's own phone, and nothing here touches it.
 *
 * OFFLINE IS DONE THROUGH CDP, DELIBERATELY. Playwright's `context.setOffline()`
 * does not reliably apply to fetches made BY a service worker (CLAUDE.md records
 * this against `sw-subresource-semantics.spec.mjs`, which had to kill its origin
 * outright instead). A remote origin cannot be killed, so this uses
 * `Network.emulateNetworkConditions` over CDP, which applies at the browser's
 * network stack and therefore does cover service-worker traffic.
 *
 * Verdicts match verify-cloudflare-parity.mjs exactly, for the same reason:
 *   PASS       exit 0 — live evidence observed, everything agreed
 *   FAILURE    exit 1 — real evidence of a mismatch
 *   UNOBSERVED exit 2 — the origin was never reached; NO claim in either direction
 * An unobserved gate is not a passed gate, which is why exit 2 is still non-zero.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { declaredRuntimeAssets, REPO_ROOT } from './lib/deploy-assets.mjs';

const args = process.argv.slice(2);
const positional = args.filter((a) => !a.startsWith('--'));
const appOrigin = (positional[0] || 'https://freightlogic-v2.fimseitef.workers.dev').replace(/\/$/, '');

const APP_VERSION = readFileSync(path.join(REPO_ROOT, 'app.js'), 'utf8')
  .match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];

let failures = 0;
let offlineUnobserved = false;
const reach = { responses: 0, transportErrors: 0 };
const pass = (m) => console.log(`PASS  ${m}`);
const fail = (m) => { failures++; console.log(`FAIL  ${m}`); };
const info = (m) => console.log(`      ${m}`);

/** Wait for `fn()` to return truthy, or return null at the deadline. */
async function until(fn, ms = 30000, step = 250) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) return null;
    await new Promise((r) => setTimeout(r, step));
  }
}

async function main() {
  console.log('== FreightLogic production service-worker / offline gate ==');
  console.log(`app origin:  ${appOrigin}`);
  console.log(`app version: v${APP_VERSION ?? '?'}\n`);

  if (!APP_VERSION) fail('app.js does not declare a readable APP_VERSION');

  const inventory = declaredRuntimeAssets();
  if (inventory.problems?.length) {
    for (const p of inventory.problems) fail(`asset inventory: ${p}`);
  }
  const declared = [...inventory.assets.keys()];
  info(`${declared.length} declared runtime assets`);

  // Same convention as tests/lib/harness.mjs: honour FL_CHROME_PATH when the
  // environment supplies its own Chromium. Unset — as in CI, which runs
  // `playwright install chromium` — the launch options are the plain default.
  const browser = await chromium.launch(
    process.env.FL_CHROME_PATH ? { executablePath: process.env.FL_CHROME_PATH } : {},
  );
  const context = await browser.newContext({ serviceWorkers: 'allow' });
  const page = await context.newPage();

  let offlineNow = false;
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(String(e)));
  page.on('response', () => { reach.responses++; });
  page.on('requestfailed', (r) => {
    // Only a failure reaching the ORIGIN is evidence of unreachability. A
    // blocked third-party font or a deliberately offline request is not.
    if (r.url().startsWith(appOrigin) && !offlineNow) reach.transportErrors++;
  });

  let cdp = null;

  try {
    /* ---------------------------------------------- 1. first load + install */

    const res = await page.goto(appOrigin + '/', { waitUntil: 'load', timeout: 45000 }).catch((e) => {
      reach.transportErrors++;
      info(`navigation error: ${e.message}`);
      return null;
    });

    if (!res) {
      return finish(browser);
    }
    res.status() === 200
      ? pass(`origin serves the app shell — HTTP ${res.status()}`)
      : fail(`origin returned HTTP ${res.status()} for the app shell`);

    const swReady = await until(async () => page.evaluate(async () => {
      if (!('serviceWorker' in navigator)) return null;
      const reg = await navigator.serviceWorker.getRegistration();
      return reg && reg.active ? reg.active.scriptURL : null;
    }), 45000);

    swReady
      ? pass(`service worker reached ACTIVATED — ${swReady.replace(appOrigin, '')}`)
      : fail('no service worker reached the activated state within 45s');

    /* -------------------------------------------- 2. reload: worker controls */

    await page.reload({ waitUntil: 'load', timeout: 45000 });

    const controlled = await until(() => page.evaluate(() => !!navigator.serviceWorker.controller), 20000);
    controlled
      ? pass('the page is CONTROLLED by the service worker after one reload')
      : fail('the page is still uncontrolled after a reload — offline will not work');

    // Injection only happens on a navigation the SERVICE WORKER handled, so this
    // must be read after the worker controls the page — on the very first load
    // there is no worker yet and the origin's own HTML carries neither tag.
    // This is the 2026-09-13 defect's exact surface: service-worker.js injects
    // admin-driver-ui.js into every HTML response it serves, while .assetsignore
    // kept the file from ever being published, so the tag pointed at a 404 and
    // every parity check stayed green.
    const html = await page.content();
    // Issue #231 Phase C (v24.0.33): admin-driver-ui.js was deleted with the
    // driver-app admin surface. A worker that still injects it is serving a
    // superseded generation, so its presence is now the failure.
    /admin-driver-ui\.js/.test(html)
      ? fail('admin-driver-ui.js is still injected into the worker-served HTML — the driver app must carry no admin module')
      : pass('admin-driver-ui.js is NOT injected — the driver app carries no admin module');
    for (const [name, re] of [
      ['midwest-stack-authority.js', /midwest-stack-authority\.js/],
    ]) {
      if (!re.test(html)) { fail(`${name} tag is absent from the worker-served HTML`); continue; }
      const probe = await page.evaluate(async (n) => {
        try {
          const r = await fetch('/' + n, { cache: 'no-store' });
          return { status: r.status, type: r.headers.get('content-type') || '' };
        } catch (e) { return { status: 0, type: '', error: String(e) }; }
      }, name);
      // A present tag is not enough: the tag pointing at a 404 IS the defect.
      probe.status === 200 && !/text\/html/i.test(probe.type)
        ? pass(`${name} is injected AND fetchable as script — HTTP 200 (${probe.type || 'no content-type'})`)
        : fail(`${name} is injected but returns HTTP ${probe.status} (${probe.type || 'no content-type'})`);
    }

    const cacheState = await page.evaluate(async () => {
      const names = await caches.keys();
      const shell = names.find((n) => n.startsWith('freightlogic-'));
      if (!shell) return { names, shell: null, urls: [] };
      const c = await caches.open(shell);
      const reqs = await c.keys();
      return { names, shell, urls: reqs.map((r) => r.url) };
    });

    if (!cacheState.shell) {
      fail(`no freightlogic-* precache exists (found: ${cacheState.names.join(', ') || 'none'})`);
    } else {
      cacheState.shell === `freightlogic-${APP_VERSION}`
        ? pass(`precache is the current generation — ${cacheState.shell}`)
        : fail(`precache is ${cacheState.shell}, expected freightlogic-${APP_VERSION}`);

      // Every declared runtime asset must actually be IN the cache, not merely
      // fetchable. A worker that installed but precached nothing looks healthy
      // right up to the moment the network goes away.
      const cachedPaths = new Set(cacheState.urls.map((u) => {
        try { return new URL(u).pathname.replace(/^\//, ''); } catch { return u; }
      }));
      const missing = declared.filter((p) => !cachedPaths.has(p));
      missing.length === 0
        ? pass(`all ${declared.length} declared runtime assets are present in the precache`)
        : fail(`${missing.length} declared asset(s) missing from the precache: ${missing.join(', ')}`);
    }

    /* ------------------------------ 3. the app actually renders after reload */

    const shellOk = await until(() => page.evaluate(() => {
      const tabs = document.querySelectorAll('[data-nav]');
      const home = document.querySelector('#view-home');
      return tabs.length >= 5 && !!home && getComputedStyle(home).display !== 'none';
    }), 20000);
    shellOk
      ? pass('after reload the driver shell renders: five tabs and a visible Today surface')
      : fail('the driver shell did not render after reload');

    pageErrors.length === 0
      ? pass('no uncaught page errors during install and reload')
      : fail(`uncaught page error(s): ${pageErrors.slice(0, 3).join(' | ')}`);

    /* ----------------------------------------------------- 4. genuine offline */

    // Taking the network away is the whole gate, so every offline claim below is
    // re-proved at the moment it is made, not once at the top.
    //
    // Why it must be re-proved: `context.setOffline()` is documented as
    // unreliable for fetches made BY a service worker, and CDP
    // Network.emulateNetworkConditions is scoped to the target it is sent to. A
    // service worker is a separate target, and it RESTARTS across a reload — so
    // emulation demonstrably covers the worker instance that was running when it
    // was applied, and demonstrably stops covering the one that replaces it.
    // This was not assumed; it was observed while building this gate: the same
    // uncached path returned the worker's offline marker before a reload and a
    // live origin 404 immediately after one.
    //
    // So: prove offline, assert, re-prove, assert. Where it cannot be re-proved,
    // the affected checks are UNOBSERVED — not PASS (nothing was shown) and not
    // FAIL (nothing is known broken). Claiming an offline pass from a browser
    // that was not offline is the green-for-the-wrong-reason evidence this
    // repository keeps finding.
    cdp = await context.newCDPSession(page);
    await cdp.send('Network.enable');

    const goOffline = async () => {
      offlineNow = true;
      await context.setOffline(true);
      await cdp.send('Network.emulateNetworkConditions', {
        offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1,
      });
    };

    // An uncached, unknown same-origin path lands in the worker's branch 4:
    // `try { return await fetch(req) } catch { return offlineFailure() }`. So the
    // worker itself reports whether its NETWORK attempt threw, via `X-FL-Offline: 1`
    // on its 504. That marker — or the fetch throwing outright — is the proof.
    // Any real origin response without the marker means the network is still up.
    // NOTE ON THIS PROBE'S SECOND JOB. A worker carrying the pre-v24.0.4 defect
    // answers any miss with the app shell, so it never emits the marker — which
    // would make a broken worker read as "offline emulation did not take" and
    // quietly skip the very check that catches it. That was observed, not
    // theorised: reintroducing the defect in a mirrored origin turned this gate
    // UNOBSERVED instead of FAILURE. So the probe also inspects what came back:
    // a 200 HTML body for a path that has never existed IS the masquerade, in
    // any network state, and is reported as a failure here rather than deferred.
    const offlineIsReal = async () => {
      const r = await page.evaluate(async () => {
        try {
          const res = await fetch('/__offline_effectiveness_probe_' + Date.now(), { cache: 'no-store' });
          return {
            threw: false,
            status: res.status,
            marker: res.headers.get('X-FL-Offline'),
            type: res.headers.get('content-type') || '',
            body: (await res.text()).slice(0, 40),
          };
        } catch { return { threw: true, status: 0, marker: null, type: '', body: '' }; }
      });
      const isHtml = /text\/html/i.test(r.type) || /^\s*<!doctype html/i.test(r.body);
      if (!r.threw && r.status === 200 && isHtml) {
        fail(`a path that has never existed was answered with the app shell — HTTP 200, ${r.type}. `
          + 'This is the pre-v24.0.4 masquerade: the browser refuses to execute it, with no 404 and no console error.');
        return true; // the worker is answering from cache, so the network is not what is being tested
      }
      return r.threw || r.marker === '1';
    };

    await goOffline();
    const offlineBefore = await offlineIsReal();

    /* ------------- 5. offline, a subresource miss must never answer with HTML */

    // v24.0.4's rule: only a NAVIGATION may receive the app shell. Every other
    // request gets an honest 504 text/plain. HTML returned for a .js request is
    // the silent-vanish failure — the browser refuses to execute it and reports
    // nothing at all: no 404, no console error, the script simply disappears.
    //
    // This runs FIRST, against the worker instance just proved offline, because
    // a reload would replace that instance and silently restore its network.
    if (offlineBefore) {
      info('network: OFFLINE — verified against the running worker instance');

      const masquerade = await page.evaluate(async () => {
        const probe = async (url) => {
          try {
            const r = await fetch(url, { cache: 'no-store' });
            return { url, status: r.status, type: r.headers.get('content-type') || '', marker: r.headers.get('X-FL-Offline'), body: (await r.text()).slice(0, 40) };
          } catch (e) {
            return { url, status: 0, type: '', marker: null, body: '', error: String(e) };
          }
        };
        return Promise.all([
          probe('/does-not-exist-' + Date.now() + '.js'),
          probe('/app.js?v=definitely-not-the-current-generation'),
        ]);
      });

      for (const m of masquerade) {
        const isHtml = /text\/html/i.test(m.type) || /^\s*<!doctype html/i.test(m.body);
        const label = m.url.split('?')[0].replace(/-\d{13}\.js$/, '.js');
        isHtml
          ? fail(`offline subresource miss answered with HTML — ${label} (HTTP ${m.status}, ${m.type})`)
          : pass(`offline subresource miss is not HTML — ${label} (HTTP ${m.status || 'transport error'}, ${m.type || 'no content-type'})`);
      }

      // The known-asset branch must self-heal a `?v=` drift to the real file
      // rather than answering with the shell — the v24.0.3 CG-05 hazard.
      const drifted = masquerade.find((m) => m.url.includes('app.js'));
      drifted && drifted.status === 200 && /javascript/i.test(drifted.type)
        ? pass('a drifted ?v= on a known asset self-heals to the real file offline')
        : fail(`a drifted ?v= on app.js did not self-heal (HTTP ${drifted?.status}, ${drifted?.type})`);
    } else {
      info('network: offline emulation did not take on the running worker instance');
      offlineUnobserved = true;
    }

    /* ------------------- 6b. the shell that WOULD be served offline is intact */

    // The offline NAVIGATION itself cannot be observed from here, and saying so
    // is better than faking it. A navigation replaces the service-worker
    // instance, and the replacement is not covered by the network emulation that
    // covered its predecessor — re-applying it, and re-attaching a fresh CDP
    // session, were both tried and neither carries over. That is a limitation of
    // driving a REMOTE origin: the local spec that does prove offline navigation,
    // `tests/integration/sw-subresource-semantics.spec.mjs`, kills its origin
    // outright, which production does not permit.
    //
    // So this asserts the same underlying fact by the axis that IS observable:
    // the exact bytes the worker would answer a navigation with are in the cache
    // and are a complete, current shell. Together with the proven-offline policy
    // checks above and the full precache, that is the evidence chain. The live
    // navigation on a real device stays where it belongs — A1-A10 in
    // FIELD_TEST_CHECKLIST.md, on the operator's iPhone.
    const shell = await page.evaluate(async (version) => {
      const names = await caches.keys();
      const gen = names.find((n) => n === `freightlogic-${version}`);
      if (!gen) return { ok: false, why: 'no generation cache' };
      const c = await caches.open(gen);
      const res = (await c.match('/index.html')) || (await c.match('/')) || (await c.match(location.origin + '/'));
      if (!res) return { ok: false, why: 'no app shell cached' };
      const body = await res.text();
      return {
        ok: true,
        type: res.headers.get('content-type') || '',
        isHtml: /^\s*<!doctype html/i.test(body),
        hasTabs: /data-nav=/.test(body),
        hasCurrentMarkers: body.includes(`?v=${version}`),
        bytes: body.length,
      };
    }, APP_VERSION);

    if (!shell.ok) {
      fail(`the app shell is not in the precache — nothing would be served offline (${shell.why})`);
    } else {
      shell.isHtml && shell.bytes > 1000
        ? pass(`the cached app shell is a complete HTML document (${shell.bytes} bytes, ${shell.type})`)
        : fail(`the cached app shell is not a usable HTML document (${shell.bytes} bytes, ${shell.type})`);
      shell.hasTabs
        ? pass('the cached shell carries the driver tab bar markup')
        : fail('the cached shell has no data-nav tab markup — it would render without navigation');
      shell.hasCurrentMarkers
        ? pass(`the cached shell requests the current generation's assets (?v=${APP_VERSION})`)
        : fail(`the cached shell does not reference ?v=${APP_VERSION} — it would pull a stale generation`);
    }
    info('NOT observed here: the offline navigation itself. See the note above and');
    info('FIELD_TEST_CHECKLIST.md A1-A10 for the on-device confirmation.');

    /* ------------------------------------------- 6. back online, still sound */

    await cdp.send('Network.emulateNetworkConditions', {
      offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1,
    });
    offlineNow = false;
    await context.setOffline(false);
    info('network: ONLINE');

    const backOnline = await page.reload({ waitUntil: 'load', timeout: 45000 }).catch(() => null);
    backOnline && backOnline.status() === 200
      ? pass('recovers cleanly when the network returns')
      : fail('the app did not reload cleanly after the network returned');

    // Only version-shaped names are release GENERATIONS. `freightlogic-share-v2`
    // is SHARE_CACHE, where share-target POSTs are staged for 5 minutes — it is
    // supposed to be there and is not a stale generation.
    const allCaches = await page.evaluate(() => caches.keys());
    const generations = allCaches.filter((n) => /^freightlogic-\d+\.\d+\.\d+$/.test(n));
    generations.length === 1 && generations[0] === `freightlogic-${APP_VERSION}`
      ? pass(`exactly one generation cache survives — ${generations[0]} (no stale generation left behind)`)
      : fail(`expected only freightlogic-${APP_VERSION}, found generation cache(s): ${generations.join(', ') || 'none'}`);
    info(`other caches present (expected, not generations): ${allCaches.filter((n) => !generations.includes(n)).join(', ') || 'none'}`);
  } finally {
    if (cdp) await cdp.detach().catch(() => {});
    await browser.close().catch(() => {});
  }

  return finish();
}

function finish() {
  console.log('');
  // Same doctrine as the parity gate: an origin that answered is OBSERVED, even
  // if what it said was wrong. Unreachable means zero responses.
  if (reach.responses === 0 && reach.transportErrors > 0) {
    console.log('The production origin was never reached from this runner.');
    console.log('VERDICT: UNOBSERVED');
    return 2;
  }
  if (failures) {
    console.log(`${failures} production service-worker check(s) failed.`);
    console.log('VERDICT: FAILURE');
    return 1;
  }
  // A real mismatch outranks unobservability — a failed check is evidence
  // whether or not the offline half could be demonstrated. But a run whose
  // offline emulation never took has NOT proved offline behaviour, and must not
  // be cited as though it had.
  if (offlineUnobserved) {
    console.log('Install, reload, injection, precache and recovery verified.');
    console.log('The OFFLINE half was not demonstrated: the browser never actually went offline.');
    console.log('VERDICT: UNOBSERVED');
    return 2;
  }
  console.log('Production service-worker install, reload, offline and recovery all verified.');
  console.log('VERDICT: PASS');
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(await main());
}
