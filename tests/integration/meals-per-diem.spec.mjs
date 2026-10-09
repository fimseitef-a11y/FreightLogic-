// Meals vs per diem — owner decision 2026-10-09.
//
// The per diem standard meal allowance REPLACES actual meal costs. F30 used to
// deduct a logged Meals expense inside "Other expenses" AND subtract per diem,
// so the same meals were deducted twice. Now: with per diem claimed, logged
// meals deduct nothing (and the screen says why); with no per diem, actual
// meals deduct at the Sec 274(n) percentage (50% for a cargo van), never 100%.
// The same mealsTaxTreatment() rule feeds the accountant package, the CPA view,
// the Settings tax quick view and the Money card estimate.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/meals-per-diem.spec.mjs');

async function seed(page, { trips = [], expenses = [] }) {
  await page.evaluate(async ({ trips, expenses }) => {
    const T = window.__FL_TESTS;
    await T.saveActiveVehicleProfile({
      vehicleTaxMethod: T.VEHICLE_TAX_METHOD.STANDARD_MILEAGE,
      firstYearElection: T.FIRST_YEAR_ELECTION.STANDARD_MILEAGE,
    });
    const rows = trips.map(t => T.sanitizeTrip({ customer: 'Broker', isPaid: true, emptyMiles: 0, ...t, deliveryDate: t.pickupDate, invoiceDate: t.pickupDate }));
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const tripStore = db.objectStoreNames.contains('tripRecords') ? 'tripRecords' : 'trips';
        const txn = db.transaction([tripStore, 'expenses'], 'readwrite');
        for (const t of rows) txn.objectStore(tripStore).put(t);
        for (const e of expenses) txn.objectStore('expenses').add(e);
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  }, { trips, expenses });
}

async function openF30(page, year) {
  await page.evaluate(() => { location.hash = '#reports'; });
  await page.waitForSelector('#reportsTax', { state: 'visible', timeout: 10000 });
  await page.click('#reportsTax');
  await page.waitForSelector('.f30-yr', { timeout: 10000 });
  await page.evaluate(y => document.querySelector(`.f30-yr[data-year="${y}"]`)?.click(), year);
  await page.waitForFunction(() => /Ln\s*28/.test(document.querySelector('#f30Content')?.textContent || ''), null, { timeout: 10000 });
}

// Amount on the first rendered row whose label contains `label`.
const rowAmount = (page, label) => page.evaluate(lbl => {
  const row = [...document.querySelectorAll('#f30Content div')].find(d => d.children.length === 2 && d.children[0].textContent.includes(lbl));
  return row ? Number(row.children[1].textContent.replace(/[^0-9.-]/g, '')) : null;
}, label);

async function captureCsv(page) {
  await page.evaluate(() => {
    window.__csv = null;
    const orig = URL.createObjectURL.bind(URL);
    URL.createObjectURL = b => { b.text().then(t => { window.__csv = t; }); return orig(b); };
  });
  await page.click('#f30ExportCsv');
  await page.waitForFunction(() => window.__csv, null, { timeout: 5000 });
  return page.evaluate(() => window.__csv);
}

test('[MPD-01] with per diem claimed, a logged meal is not deducted a second time', async () => {
  const app = await launchApp();
  try {
    // One road day: per diem = 1 day x $80 x 50% = $40. Mileage 200 mi x $0.725 = $145.
    await seed(app.page, {
      trips: [{ orderNo: 'MPD-1', pickupDate: '2026-03-02', origin: 'Chicago, IL', destination: 'Detroit, MI', pay: 900, loadedMiles: 200 }],
      expenses: [
        { date: '2026-03-02', category: 'Meals', amount: 40, notes: 'truck stop dinner' },
        { date: '2026-03-02', category: 'Tolls', amount: 10, notes: '' },
      ],
    });
    await openF30(app.page, 2026);
    eq(await rowAmount(app.page, 'Per diem deduction'), 40, 'per diem stays 1 day x $80 x 50%');
    // Deductions = mileage 145 + tolls 10 + per diem 40. The $40 meal is NOT in it.
    eq(await rowAmount(app.page, 'Total deductions'), 195, 'total must not include the logged meal on top of per diem');
    eq(await rowAmount(app.page, 'Other expenses'), 10, 'Other expenses holds the toll only, not the meal');
    const note = await app.page.evaluate(() => document.querySelector('#f30MealsNote')?.textContent || '');
    ok(/\$40\.00/.test(note) && /per diem/i.test(note), `the screen must say the $40 meal is covered by per diem, got "${note}"`);
    const csv = await captureCsv(app.page);
    ok(/covered by per diem, not deducted","0\.00"/.test(csv), 'the CSV must carry the meals row at 0.00 with the reason');
    ok(/"Total deductions","195\.00"/.test(csv), 'the CSV total must match the screen');
  } finally { await app.close(); }
});

test('[MPD-02] with no per diem, actual meals deduct at 50% for a cargo van, not 100%', async () => {
  const app = await launchApp();
  try {
    // An expense-only year: no road days, so no per diem; the meal is the only meals claim.
    await seed(app.page, {
      expenses: [
        { date: '2025-05-10', category: 'Meals', amount: 30, notes: '' },
        { date: '2025-05-10', category: 'Parking', amount: 12, notes: '' },
      ],
    });
    await openF30(app.page, 2025);
    eq(await rowAmount(app.page, 'Meals (actual, 50%)'), 15, 'a $30 meal deducts $15 under Sec 274(n)');
    eq(await rowAmount(app.page, 'Total deductions'), 27, 'parking 12 + meals 15');
    ok(!(await app.page.locator('#f30MealsNote').count()), 'no "covered by per diem" note when no per diem is claimed');
  } finally { await app.close(); }
});

// Same release, found while proving it: under CPU load the first-run Setup
// Wizard (800 ms boot timer) replaced whatever screen the driver had already
// opened, because there is one shared #modal. That is what made the Diagnostics
// spec (DXI-01..04) time out intermittently in CI. It must defer instead, and
// still open on a later boot (it is not marked complete).
test('[FRS-01] the first-run wizard never replaces a screen that is already open', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.openDiagnosticsPanel();
      await T.checkFirstRunSetup(); // a fresh install: no trips, setup not complete
      const kept = !!document.getElementById('dxOrigin');
      const title = document.querySelector('#modalTitle')?.textContent || '';
      const done = await T.getSetting('f26SetupComplete', false);
      document.querySelector('#modalClose')?.click();
      await new Promise(r => setTimeout(r, 500)); // closeModal hides after 350 ms
      await T.checkFirstRunSetup(); // nothing open now: the wizard is offered
      return { kept, title, done, after: document.querySelector('#modalTitle')?.textContent || '' };
    });
    ok(r.kept, `Diagnostics must still be on screen, but the modal is "${r.title}"`);
    eq(r.done, false, 'deferring must not mark setup complete');
    ok(/Welcome/i.test(r.after), `with nothing open the wizard still appears, got "${r.after}"`);
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
