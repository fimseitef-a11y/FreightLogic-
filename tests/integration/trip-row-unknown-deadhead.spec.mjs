// D-01 — tripRow() renders a loaded-only RPM as True RPM when deadhead is UNKNOWN.
//
// NOT YET WIRED INTO tests/run-all.mjs. This spec asserts the CORRECT behaviour
// and therefore FAILS against main today (see AUDIT_REPORT.md D-01 for the
// captured reproduction). app.js is SHARED and was under the gpt lane's
// lock/app-js when this was written, so the fix could not land alongside it.
// Whoever lands the fix: add this file to run-all.mjs in the same commit, per
// tests/README.md ("Exit code") — a logged-but-unfixed finding is kept out of
// the default run so it cannot sink an otherwise-green gate, and is wired in the
// moment it turns green.
//
// Invariant (v24.0.1 knownNum doctrine, v24.0.5 tripHasKnownDeadhead):
//   emptyMiles null/undefined/blank means UNKNOWN. It must never enter a
//   denominator as zero. An explicit 0 is a verified zero and scores normally.
//
// Both tripRow modes are driven through the real router and the real DOM —
// #tripList (Trips page, full mode) and #homeRecentTrips (Home, compact mode) —
// rather than through an internal, because the defect is what the driver SEES.
import { launchApp, createSuite, eq, ok, skipFirstRunWizard } from '../lib/harness.mjs';
const { test, run } = createSuite('integration/trip-row-unknown-deadhead.spec.mjs');
let app;

// Three trips, all $600 for 100 loaded miles:
//   TRU-UNK-LEGACY  emptyMiles null, needsReview FORCED false — the legacy-defence
//                   vector: a stored record whose review bit is stale or missing.
//   TRU-ZERO        emptyMiles 0 — explicit verified zero. Control: must read
//                   $6.00/mi and grade A in both modes.
//   TRU-UNK         emptyMiles null exactly as sanitizeTrip() persists it today
//                   (needsReview true, 'Deadhead miles are unknown').
async function seed(){
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS, db = await T.initDB();
    const tx = db.transaction('trips', 'readwrite'), store = tx.objectStore('trips');
    store.clear();
    const base = { pickupDate: T.isoDate(), deliveryDate: T.isoDate(), pay: 600, loadedMiles: 100 };
    store.put({ ...T.sanitizeTrip({ id: 'tru-0', orderNo: 'TRU-UNK-LEGACY', ...base, emptyMiles: null }), needsReview: false });
    store.put({ ...T.sanitizeTrip({ id: 'tru-1', orderNo: 'TRU-ZERO', ...base, emptyMiles: 0 }) });
    store.put({ ...T.sanitizeTrip({ id: 'tru-2', orderNo: 'TRU-UNK', ...base, emptyMiles: null }) });
    await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
    db.close(); T.invalidateKPICache();
  });
}

async function go(hash, readySel, count){
  await app.page.evaluate(h => { location.hash = h; }, hash);
  await app.page.waitForFunction(({ sel, n }) => document.querySelectorAll(sel).length >= n, { sel: readySel, n: count }, { timeout: 15000 });
}

test('[TRU-01] Trips page (full row): UNKNOWN deadhead shows no RPM and no grade; explicit zero scores normally', async () => {
  await seed();
  await go('#trips', '#tripList .fl-trip-full', 3);
  const rows = await app.page.evaluate(() => [...document.querySelectorAll('#tripList .fl-trip-full')].map(el => ({
    order: (el.querySelector('.fl-tf-origin')?.textContent || '').trim().split(/\s/)[0],
    rpm:   (el.querySelector('.fl-tf-rpm')?.textContent || '').trim(),
    grade: (el.querySelector('.fl-grade-chip')?.textContent || '').trim(),
  })));
  const by = Object.fromEntries(rows.map(r => [r.order, r]));
  ok(by['TRU-ZERO'] && by['TRU-UNK'] && by['TRU-UNK-LEGACY'], `all three rows rendered: ${JSON.stringify(rows)}`);
  eq(by['TRU-ZERO'].rpm, '$6.00/mi', 'explicit-zero control: True RPM is real');
  eq(by['TRU-ZERO'].grade, 'A', 'explicit-zero control: grade is real');
  for (const k of ['TRU-UNK', 'TRU-UNK-LEGACY']){
    eq(by[k].rpm, '—', `${k}: an unknown deadhead must not render a $/mi figure (loaded-only RPM dressed as True RPM)`);
    eq(by[k].grade, '?', `${k}: an unknown deadhead must not render a letter grade`);
  }
});

test('[TRU-02] Home recent trips (compact row): same invariant', async () => {
  await go('#home', '#homeRecentTrips .fl-tc', 3);
  const rows = await app.page.evaluate(() => [...document.querySelectorAll('#homeRecentTrips .fl-tc')].map(el => ({
    text:  (el.textContent || ''),
    rpm:   (el.querySelector('.fl-tc-rpm')?.textContent || '').trim(),
    meta:  (el.querySelector('.fl-tc-meta')?.textContent || '').trim(),
    grade: (el.querySelector('.fl-grade-chip')?.textContent || '').trim(),
  })));
  const find = k => rows.find(r => r.text.includes(k));
  const zero = find('TRU-ZERO'), unk = find('TRU-UNK'), legacy = find('TRU-UNK-LEGACY');
  ok(zero && unk && legacy, `all three compact rows rendered: ${JSON.stringify(rows.map(r => r.text.slice(0, 40)))}`);
  eq(zero.rpm, '$6.00', 'explicit-zero control: True RPM is real');
  eq(zero.grade, 'A', 'explicit-zero control: grade is real');
  for (const [k, r] of [['TRU-UNK', unk], ['TRU-UNK-LEGACY', legacy]]){
    eq(r.rpm, '—', `${k}: no $/mi figure for an unknown deadhead`);
    ok(!/\$\d/.test(r.meta), `${k}: meta line must not carry a $/mi figure either; got ${JSON.stringify(r.meta)}`);
    eq(r.grade, '?', `${k}: no letter grade for an unknown deadhead`);
  }
});

export async function runSpec(){
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForFunction(() => !!window.__FL_TESTS);
  try { return await run(); } finally { await app.close(); }
}
if (process.argv[1]?.endsWith('trip-row-unknown-deadhead.spec.mjs')){ const r = await runSpec(); process.exit(r.fail ? 1 : 0); }
