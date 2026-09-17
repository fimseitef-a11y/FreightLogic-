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

import { launchApp, waitForAppReady, createSuite, ok, eq } from '../lib/harness.mjs';
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
  ok(/catch\s*\{?\s*\n?\s*return false/.test(body) || body.includes('return false'),
    'a failed probe must keep waiting rather than resolving readiness');
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

export async function runSpec() { return run(); }
