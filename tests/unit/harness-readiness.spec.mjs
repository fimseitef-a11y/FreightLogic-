// Issue #224 — the suite's own readiness contract, and the diagnostics that
// make a post-readiness re-bootstrap observable.
//
// WHAT #224 REPORTS. `main` intermittently fails with the app's module-scoped
// IndexedDB handle `null` inside `tx()`:
//
//     TypeError: Cannot read properties of null (reading 'objectStoreNames')
//         at physicalFor (app.js:2852)
//         at tx (app.js:2853)
//         at Object.upsertTrip (app.js:3013)
//
// in specs that had already completed `waitForAppBoot()`. The handle is assigned
// once (`db = await initDB()`) and nothing in `app.js` sets it back to null, so
// after readiness the only thing that can produce null is a NEW DOCUMENT — a
// reload or navigation that re-ran the IIFE and reset `let db = null`.
//
// WHAT IS AND IS NOT ESTABLISHED HERE, stated plainly because #224 forbids
// clearing this with a rerun:
//
//   - The failure did NOT reproduce locally. The full 59-file suite ran green
//     at 557/0 on the first attempt on this tree, and targeted probes found no
//     post-readiness re-bootstrap: an idle app page over 4s (0/8), a second tab
//     waiting only for `#appMeta` (0/12), and the same under 20x CPU throttling
//     (0/8). So the root cause is NOT proven and #224 stays open.
//   - What IS fixed is 15 real instances of the same class, and HR-02 found 13
//     of them that reading had missed. Two were tabs opened by
//     `toctou-concurrent-edit.spec.mjs` waiting only for `#appMeta` to have
//     text — the harness's own comment documents that as insufficient, since
//     appMeta populates BEFORE `initDB()` assigns the handle, and that spec is
//     the most contended point in the suite, opening five pages and killing each
//     mid-transaction.
//
//     The other 13, in `field-resilience` (10), `backup-restore-parity` (2) and
//     `batch-a-release-integrity` (1), are the more interesting shape: each is a
//     deliberate `page.reload()` followed by the `#appMeta`-only wait. A reload
//     IS the re-bootstrap #224 deduces — it re-runs the IIFE and resets
//     `let db = null` — so those call sites were a post-readiness re-bootstrap
//     followed by a wait too weak to cover it. That is the reported mechanism
//     exactly, written into the suite in 13 places. Whether it is also the CI
//     failure cannot be claimed: the CI failures were in specs that do not
//     reload. All 15 now use `waitForAppReady()`.
//   - What makes the next CI failure diagnosable instead of speculative is the
//     lifecycle record: every tracked page is stamped per document, and
//     `createSuite()` prints the stamp, the navigation list, page errors and
//     whether the handle is usable RIGHT NOW for every live page whenever an
//     assertion fails. A re-bootstrap is then a printed fact.
//
// HR-01/02 are the ones that keep the contract from being quietly weakened back
// to the state that made the race possible.
//
// NEGATIVE CONTROLS, all verified to fire: deleting the DB-backed probe from
// `waitForAppReady()` fails HR-01; restoring any one of the 15 `#appMeta`-only
// waits fails HR-02; removing the failure-path dump from `createSuite()` fails
// HR-03; removing the per-document stamp fails HR-04.
//
// HR-02 is also the assertion that did the finding rather than merely guarding
// the fix, which is the argument for writing it as a directory sweep instead of
// a list of the sites already known.

import { launchApp, waitForAppReady, probeResolvesWithoutAwaiting, createSuite, ok, eq } from '../lib/harness.mjs';
import { readFileSync } from 'node:fs';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { test, run } = createSuite('unit/harness-readiness.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = f => readFileSync(path.join(ROOT, f), 'utf8');

test('[HR-01] readiness is gated on a real IndexedDB operation, not on #appMeta', async () => {
  const h = read('tests/lib/harness.mjs');
  const fn = h.match(/export async function waitForAppReady\([\s\S]*?\n\}/);
  ok(fn, 'could not find waitForAppReady()');
  const body = fn[0];

  ok(body.includes('appMeta'), 'the cheap DOM check is still a useful first gate');
  ok(/dumpStore\(['"]settings['"]\)/.test(body),
    'readiness MUST complete a real IndexedDB-backed operation — `#appMeta` populates before `db = await initDB()` resolves, which is the whole race');
  ok(/page\.evaluate\(/.test(body),
    'the probe must run through page.evaluate(), which awaits a returned Promise — see HR-06');
  ok(/Date\.now\(\)\s*>=\s*deadline|Date\.now\(\)\s*<\s*deadline/.test(body),
    'a probe that never succeeds must time out loudly rather than resolving readiness');
  ok(/throw new Error/.test(body),
    'readiness must FAIL when the database never becomes usable — returning quietly is the bug it is meant to catch');
});

test('[HR-02] no spec settles for an #appMeta-only wait on a page it opens itself', async () => {
  // The provable instance of the reported failure class. A spec that opens its
  // own tab and waits only for `#appMeta` has exactly the window the harness
  // comment describes; `app.newReadyPage()` exists so it does not have to.
  const offenders = [];
  for (const dir of ['unit', 'integration']) {
    for (const f of readdirSync(path.join(ROOT, 'tests', dir))) {
      if (!f.endsWith('.spec.mjs')) continue;
      const src = readFileSync(path.join(ROOT, 'tests', dir, f), 'utf8');
      const lines = src.split('\n');
      lines.forEach((line, i) => {
        if (!/waitForFunction\(\(\)\s*=>\s*!!document\.getElementById\(['"]appMeta['"]\)/.test(line)) return;
        // Allowed only in the harness itself; a spec doing this is racing initDB.
        offenders.push(`${dir}/${f}:${i + 1}`);
      });
    }
  }
  eq(offenders.join(' | '), '',
    `these specs wait only for #appMeta on a page they opened, which resolves before the app's IndexedDB handle exists — use app.newReadyPage() or waitForAppReady(): ${offenders.join(' | ')}`);
});

test('[HR-03] an assertion failure prints the document lifecycle of every live page', async () => {
  const h = read('tests/lib/harness.mjs');
  ok(h.includes('dumpLifecycleDiagnostics'),
    'the lifecycle dump must exist — #224 step 1 is exactly "make a post-readiness reload observable"');
  const start = h.indexOf('export function createSuite(');
  ok(start !== -1, 'could not find createSuite()');
  const suite = [h.slice(start)];
  ok(/catch \(e\)[\s\S]*?dumpLifecycleDiagnostics\(\)/.test(suite[0]),
    'createSuite must dump lifecycle diagnostics on the FAILURE path — a diagnostic nobody prints is a diagnostic nobody has');

  // And it must not have become a retry, a timeout bump, or a skip: #224
  // forbids all three, and each would hide the transition being hunted.
  ok(!/\bretry|retries\b/i.test(suite[0]), 'the failure path must not retry a failing assertion');
  ok(!/\.skip\b/.test(suite[0]), 'the failure path must not skip');
});

test('[HR-04] each document carries a stamp, so a re-bootstrap is detectable', async () => {
  const app = await launchApp();
  try {
    const first = await app.page.evaluate(() => window.__FL_DOC_ID || null);
    ok(first, 'a tracked page must carry a per-document stamp');

    // A reload is the mechanism #224 deduces. Prove the stamp actually detects
    // it — otherwise the diagnostic would report "no re-bootstrap" through one.
    await app.page.reload({ waitUntil: 'load' });
    await waitForAppReady(app.page);
    const second = await app.page.evaluate(() => window.__FL_DOC_ID || null);
    ok(second, 'the reloaded document must be stamped too');
    ok(first !== second,
      'a reload must change the stamp — this is what makes a post-readiness re-bootstrap observable rather than deduced');

    const info = (await app.lifecycle()).find(l => l.label === 'launchApp:page');
    ok(info, 'the page must be tracked');
    eq(info.reBootstrapped, true, 'the lifecycle record must flag the re-bootstrap it just observed');
    eq(info.dbUnusableNow, false, 'and must report the handle usable again once the new document finished booting');
    ok(info.navigations.length >= 1, 'main-frame navigations must be recorded');
  } finally { await app.close(); }
});

test('[HR-05] a freshly opened extra tab is ready for persistence immediately', async () => {
  // The positive half of HR-02: the replacement must actually work, or specs
  // would be pushed back to hand-rolling a weaker wait.
  const app = await launchApp();
  try {
    const p2 = await app.newReadyPage('hr:tabB');
    const r = await p2.evaluate(async () => {
      try {
        await window.__FL_TESTS.upsertTrip({
          orderNo: 'HR-05-TAB-B', customer: 'X', origin: 'Gary, IN', destination: 'Toledo, OH',
          pay: 600, loadedMiles: 220, emptyMiles: 0,
        });
        return 'ok';
      } catch (e) { return String(e && e.message || e); }
    });
    eq(r, 'ok', 'a page from newReadyPage() must be able to write immediately — no db===null window');

    const seen = await app.page.evaluate(async () =>
      (await window.__FL_TESTS.dumpStore('trips')).some(t => t.orderNo === 'HR-05-TAB-B'));
    ok(seen, 'and the write must be visible from the first tab — one shared origin, one database');
  } finally { await app.close(); }
});

test('[HR-06] readiness does not rely on waitForFunction awaiting an async predicate', async () => {
  // THE #224 ROOT CAUSE, MEASURED. `waitForAppReady()` used to poll with
  //
  //     await page.waitForFunction(async () => { ...await dumpStore()...; }, ...)
  //
  // `waitForFunction` evaluates its predicate and tests the RESULT for
  // truthiness WITHOUT awaiting it. An `async` function always returns a
  // Promise, and a Promise is always truthy — so that wait satisfied itself on
  // its first poll and the database probe inside it never decided anything.
  // Readiness therefore returned before `db = await initDB()` had assigned the
  // handle, which is exactly the `db === null` window #224 reports.
  //
  // This does not take that on documentation's word: it drives the real
  // Playwright build this suite runs on and measures it, so the assertion stays
  // honest if the behaviour ever changes.
  const app = await launchApp();
  try {
    const { resolvedMs, awaited } = await probeResolvesWithoutAwaiting(app.page, 600);
    eq(awaited, false,
      `Playwright resolved an async waitForFunction predicate only after ${resolvedMs}ms — it now appears to await it. ` +
      'That is a behaviour change, not a pass: re-read whether the Node-side poll in waitForAppReady() is still required before relaxing anything.');

    // And the harness must not have gone back to that form.
    const h = read('tests/lib/harness.mjs');
    const fn = h.match(/export async function waitForAppReady\([\s\S]*?\n\}/);
    ok(fn, 'could not find waitForAppReady()');
    ok(!/waitForFunction\(\s*async/.test(fn[0]),
      'waitForAppReady() must not pass an async predicate to waitForFunction — that resolves on the first poll and waits for nothing');
  } finally { await app.close(); }
});

test('[HR-07] readiness holds until persistence genuinely works, across re-bootstraps', async () => {
  // The behavioural half of HR-06, run against the mechanism #224 names: a
  // reload re-runs the IIFE and resets `let db = null`.
  //
  // STATED PLAINLY: this assertion's negative control does NOT reliably fire.
  // With the async-predicate wait reinstated it still passed 6/6 here — the
  // window between readiness resolving and `db = await initDB()` settling is
  // short on a fast host, which is precisely why #224 presented as an
  // intermittent CI failure and not a reproducible one. HR-01 and HR-06 are the
  // assertions that actually hold the repair; this one is kept because it
  // exercises the real sequence end to end and would catch a repair that
  // satisfied the static checks while still returning early. A negative control
  // that does not fire is the finding, not a formality.
  const app = await launchApp();
  try {
    for (let i = 0; i < 6; i++) {
      await app.page.reload({ waitUntil: 'load' });
      await waitForAppReady(app.page);
      const r = await app.page.evaluate(async n => {
        try {
          await window.__FL_TESTS.upsertTrip({
            orderNo: 'HR-07-' + n, customer: 'X', origin: 'Gary, IN', destination: 'Toledo, OH',
            pay: 600, loadedMiles: 220, emptyMiles: 0,
          });
          return 'ok';
        } catch (e) { return String(e && e.message || e); }
      }, i);
      eq(r, 'ok', `iteration ${i}: a write immediately after readiness must not race db === null`);
    }
  } finally { await app.close(); }
});

test('[HR-08] a probe that fails and then succeeds keeps waiting, then resolves', async () => {
  // Required by the #240 handoff, and it is the control HR-07 could not be.
  // HR-07 depends on the real initDB() race, which is short on a fast host and
  // therefore probabilistic. This injects the condition instead: the probe fails
  // a known number of times and then succeeds, so "did readiness actually wait?"
  // has a deterministic answer.
  const app = await launchApp();
  try {
    await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      const real = T.dumpStore;
      window.__HR08 = { attempts: 0 };
      T.dumpStore = async (...a) => {
        window.__HR08.attempts++;
        if (window.__HR08.attempts <= 4) throw new Error('HR-08 induced failure');
        return real.apply(T, a);
      };
    });

    await waitForAppReady(app.page, { timeout: 10000 });

    const attempts = await app.page.evaluate(() => window.__HR08.attempts);
    ok(attempts >= 5,
      `readiness must keep polling through a failing probe and return only once it succeeds; ` +
      `it saw ${attempts} attempts, so it stopped before the probe could succeed`);
    // With the async-predicate form reinstated this reads exactly `1 attempts`,
    // which is the #224 mechanism stated as a number: the wait lasted one probe,
    // not until the probe was true.
  } finally {
    await app.page.evaluate(() => { delete window.__HR08; }).catch(() => {});
    await app.close();
  }
});

test('[HR-09] a held probe blocks readiness until it settles SUCCESSFULLY, not merely settles', async () => {
  // State 2 of the three the #224 acceptance contract names, and the wording of
  // that contract is load-bearing: readiness must not resolve until the probe
  // settles *successfully*.
  //
  // Holding the probe and then releasing it into a SUCCESS does not discriminate,
  // and that was established by running it rather than assumed: under the
  // async-predicate form Playwright accepts the pending Promise but then blocks
  // serialising it, so the observable ordering is identical and the control stays
  // silent. Releasing into a FAILURE is what separates the two — the pre-fix form
  // accepts that one settled probe and calls the app ready (HR-08 measures the
  // same thing as `1 attempts`), while the repaired wait keeps polling until a
  // probe actually succeeds.
  const app = await launchApp();
  try {
    await app.page.evaluate(() => {
      const T = window.__FL_TESTS;
      const real = T.dumpStore;
      window.__HR09 = { phase: 'held' };
      T.dumpStore = (...a) => new Promise((resolve, reject) => {
        const tick = () => {
          if (window.__HR09.phase === 'held') return setTimeout(tick, 20);
          if (window.__HR09.phase === 'fail') return reject(new Error('HR-09 released as failure'));
          real.apply(T, a).then(resolve, reject);
        };
        tick();
      });
    });

    let settled = false;
    const ready = waitForAppReady(app.page, { timeout: 15000 }).then(() => { settled = true; });

    await new Promise(r => setTimeout(r, 800));
    eq(settled, false,
      'readiness resolved while its database probe was still PENDING — it accepted a Promise as evidence ' +
      'rather than the value the Promise had not yet produced');

    // Settle it — as a failure. The probe has now settled; readiness must NOT
    // treat that as ready.
    await app.page.evaluate(() => { window.__HR09.phase = 'fail'; });
    await new Promise(r => setTimeout(r, 800));
    eq(settled, false,
      'the held probe settled as a FAILURE and readiness resolved anyway — it waited for the probe to settle ' +
      'rather than for the database to be usable, which is the #224 defect');

    await app.page.evaluate(() => { window.__HR09.phase = 'ok'; });
    await ready;
    eq(settled, true, 'and once a probe finally succeeds, readiness must complete');
  } finally {
    await app.page.evaluate(() => { delete window.__HR09; }).catch(() => {});
    await app.close();
  }
});

test('[HR-10] a permanently failing probe hits the bounded timeout and throws', async () => {
  // State 3. "I could not establish readiness" is not readiness, so the only
  // correct outcome is a bounded, loud failure naming what was being waited for —
  // never a resolve on a truthy Promise or JSHandle, and never a silent return
  // that hands the spec a database the app has not finished opening.
  const app = await launchApp();
  try {
    await app.page.evaluate(() => {
      window.__FL_TESTS.dumpStore = async () => { throw new Error('HR-10 permanent failure'); };
    });

    const t0 = Date.now();
    let threw = null;
    try { await waitForAppReady(app.page, { timeout: 2500 }); }
    catch (e) { threw = String(e && e.message || e); }
    const waited = Date.now() - t0;

    ok(threw, 'a permanently failing probe must FAIL readiness, not satisfy it');
    ok(/not ready|IndexedDB/i.test(threw),
      'the failure must name what it was waiting for, so a CI log says "the database never became usable" ' +
      `rather than a bare Playwright timeout; got: ${threw}`);
    ok(/HR-10 permanent failure/.test(threw),
      `and must carry the probe's own error, or the next #224-shaped failure arrives without its cause; got: ${threw}`);
    ok(waited >= 2000 && waited < 12000,
      `the timeout must be BOUNDED and actually waited out; it took ${waited}ms`);
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
