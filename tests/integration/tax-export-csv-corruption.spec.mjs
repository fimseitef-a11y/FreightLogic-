// FINDING F-3 (Critical) — Schedule C tax-export CSV field quoting.
//
// FIXED: app.js's F30 export (openTaxSeasonExport's #f30ExportCsv handler)
// now calls the shared, correctly-quoted downloadCSV(rows, filename) helper
// (app.js:1347-1356) — the same one the general trip/expense/fuel export
// already used correctly (previously app.js:1349, now the single source of
// truth) — instead of hand-joining unquoted cells. An unquoted comma in
// trip.origin/trip.destination ("Springfield, IL") used to shift every
// column after it in the mileage log; downloadCSV quotes every cell and
// escapes embedded quotes, so the app's own quote-aware CSV parser
// (parseCSVLines, app.js:1539-1559, exposed via __FL_TESTS) round-trips the
// value exactly.
//
// This spec proves three things:
//   1. The comma-in-destination case that broke column alignment now
//      round-trips exactly (F-3's original failure mode).
//   2. A three-way reconciliation (per-trip sum in the seeded fixture,
//      the rendered Schedule C summary card's numbers, and the exported
//      CSV's summary section) agree to the cent — the fix didn't silently
//      change any dollar figure, only how it's escaped.
//   3. Year-boundary date bucketing (a trip pickup at 2025-12-31 vs one at
//      2026-01-01) still lands in the correct tax year after the fix.
//
// Scope note (stale as of v23.9): this suite predates the X-02/X-03 fixes.
// F30 now has a real Standard Mileage / Actual Expense toggle per vehicle
// (see tests/unit/pure-functions.spec.mjs and
// tests/integration/insurance-migration.spec.mjs for X-02/X-03 coverage) and
// export is gated on a method being set — this suite's "setup" test below
// sets Standard Mileage so the original F-3 assertions (unrelated to X-02/
// X-03: CSV field quoting, three-way reconciliation, year-boundary bucketing)
// keep working unmodified. The mileage rate used below (0.725) is still
// correct for both fixture dates (2026-01-01 and 2026-03-01), which fall
// before the 2026-07-01 midyear increase (X-02) — getMileageRate() returns
// the same value a flat 2026 constant would have for these specific dates.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/tax-export-csv-corruption.spec.mjs');
let app;

async function seedTrip(page, overrides) {
  return page.evaluate(async (overrides) => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: overrides.orderNo, customer: 'Test Broker LLC',
      pickupDate: overrides.pickupDate, deliveryDate: overrides.pickupDate, invoiceDate: overrides.pickupDate,
      origin: overrides.origin, destination: overrides.destination,
      pay: overrides.pay, loadedMiles: overrides.loadedMiles, emptyMiles: overrides.emptyMiles || 0,
      isPaid: true,
    });
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('trips', 'readwrite');
        txn.objectStore('trips').put(t);
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
    return t;
  }, overrides);
}

async function openTaxExportUI(page, year) {
  await page.evaluate(() => { location.hash = '#more'; });
  await page.waitForSelector('.menu-tile .tt', { state: 'attached', timeout: 10000 });
  await page.waitForTimeout(300);
  const expanded = await page.evaluate(() => {
    const toggles = Array.from(document.querySelectorAll('div'));
    const t = toggles.find(el => el.textContent?.trim() === '▶ More Tools' || /More Tools/.test(el.textContent || '') && el.children.length <= 2);
    if (t) { t.click(); return true; }
    return false;
  });
  ok(expanded, 'could not find/click the "More Tools" advanced-section toggle');
  await page.waitForTimeout(300);
  const clicked = await page.evaluate(() => {
    const tiles = Array.from(document.querySelectorAll('.menu-tile'));
    const tile = tiles.find(el => /tax season export/i.test(el.querySelector('.tt')?.textContent || ''));
    if (tile) { tile.click(); return true; }
    return false;
  });
  ok(clicked, 'could not locate the "Tax Season Export" tile in the More menu');
  await page.waitForTimeout(500);
  if (year) {
    const switched = await page.evaluate((y) => {
      const btn = Array.from(document.querySelectorAll('.f30-yr')).find(b => b.dataset.year === String(y));
      if (btn) { btn.click(); return true; }
      return false;
    }, year);
    ok(switched, `could not find the ${year} year tab in Tax Season Export`);
    await page.waitForTimeout(400);
  }
}

async function exportCsvAndCapture(page) {
  await page.evaluate(() => {
    window.__capturedBlobText = null;
    if (!URL.__flOrigCreate) URL.__flOrigCreate = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      blob.text().then(t => { window.__capturedBlobText = t; });
      return URL.__flOrigCreate(blob);
    };
  });
  await page.waitForSelector('#f30ExportCsv', { timeout: 10000 });
  await page.click('#f30ExportCsv');
  await page.waitForTimeout(500);
  const csv = await page.evaluate(() => window.__capturedBlobText);
  ok(csv, 'CSV export did not produce a captured Blob — cannot verify');
  return csv;
}

test('setup: set vehicle tax method to Standard Mileage (v23.9 X-03 gates F30 export on this)', async () => {
  // X-03 blocks Schedule C export entirely while vehicleTaxMethod is UNSET — a
  // precondition this suite predates. Resolve firstYearElection too so these
  // captures aren't also carrying the X-03 DRAFT-unverified header.
  const v = await app.page.evaluate(async () => {
    await window.__FL_TESTS.saveActiveVehicleProfile({
      vehicleTaxMethod: window.__FL_TESTS.VEHICLE_TAX_METHOD.STANDARD_MILEAGE,
      firstYearElection: window.__FL_TESTS.FIRST_YEAR_ELECTION.STANDARD_MILEAGE,
    });
    return (await window.__FL_TESTS.getActiveVehicleProfile()).vehicleTaxMethod;
  });
  eq(v, 'STANDARD_MILEAGE', 'active vehicle profile must be set to Standard Mileage for this suite');
});

test('seed one trip with a comma in destination + one on each side of a year boundary', async () => {
  const t1 = await seedTrip(app.page, { orderNo: 'AUDIT-CSV-1', pickupDate: '2026-03-01', origin: 'Chicago, IL', destination: 'Springfield, IL', pay: 1000, loadedMiles: 200 });
  eq(t1.destination, 'Springfield, IL', 'seeded trip destination retains the comma');
  // Year-boundary fixtures: one trip 11pm-equivalent on Dec 31 2025, one on Jan 1 2026.
  // sanitizeTrip stores plain date strings (no time component), so "11pm local on
  // Dec 31" and "Dec 31" are the same bucketing input here — the app has no
  // timestamp-with-time field on trips, only a YYYY-MM-DD pickupDate.
  await seedTrip(app.page, { orderNo: 'AUDIT-YEARBOUNDARY-2025', pickupDate: '2025-12-31', origin: 'Milwaukee, WI', destination: 'Chicago, IL', pay: 500, loadedMiles: 100 });
  await seedTrip(app.page, { orderNo: 'AUDIT-YEARBOUNDARY-2026', pickupDate: '2026-01-01', origin: 'Milwaukee, WI', destination: 'Chicago, IL', pay: 700, loadedMiles: 150 });
});

test('[FINDING F-3 / FIXED] Tax Season Export CSV round-trips a comma in destination exactly (no column shift)', async () => {
  await openTaxExportUI(app.page, 2026);
  const csv = await exportCsvAndCapture(app.page);

  const lines = csv.replace(/^﻿/, '').split(/\r\n|\n/);
  const headerLine = lines.find(l => l.replace(/"/g, '').startsWith('Date,Trip #,From,To,'));
  ok(headerLine, 'could not find mileage-log header row in exported CSV');
  const dataLine = lines.find(l => l.includes('AUDIT-CSV-1'));
  ok(dataLine, 'seeded trip AUDIT-CSV-1 not found in exported mileage log');

  // Quote-aware parse using the app's OWN CSV parser (parseCSVLines,
  // app.js:1539-1559) — this is what a correct consumer (or the app's own
  // CSV importer) uses, so this is the real round-trip test, not a naive
  // split(',') that would still misreport a properly-quoted comma as 2 cells.
  const [headerRow, dataRow] = await app.page.evaluate(([h, d]) => window.__FL_TESTS.parseCSVLines([h, d]), [headerLine, dataLine]);

  console.log('    [evidence] header (parsed): ' + JSON.stringify(headerRow));
  console.log('    [evidence] data row (parsed): ' + JSON.stringify(dataRow));

  eq(dataRow.length, headerRow.length,
    `expected the parsed data row to have exactly as many columns (${headerRow.length}) as the header — ` +
    `got ${dataRow.length}: ${JSON.stringify(dataRow)}`);
  eq(dataRow[headerRow.indexOf('To')], 'Springfield, IL', 'the "To" column must round-trip the comma-containing city exactly, not be split by it');
  eq(dataRow[headerRow.indexOf('From')], 'Chicago, IL', 'the "From" column must round-trip exactly');
  eq(dataRow[headerRow.indexOf('Deduction ($)')], '145.00', 'deduction figure must land in the correct (last) column, not be shifted');
});

test('[FINDING F-3 / FIXED] three-way reconciliation: per-trip sum, rendered summary card, and exported CSV summary agree to the cent', async () => {
  // Per-trip sum, computed here from the same fixtures seeded above (2026 only).
  const expectedGross = 1000 + 700; // AUDIT-CSV-1 (1000) + AUDIT-YEARBOUNDARY-2026 (700); the 2025 trip is out of year.
  const mileageRate = 0.725; // IRS.MILEAGE_RATE_2026 per CLAUDE.md
  const expectedMileage = ((200 + 0) + (150 + 0)) * mileageRate; // sum of (loaded+dead) miles x rate

  // Rendered Schedule C summary card (already on screen from the previous test's year switch).
  const rendered = await app.page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#f30Content > div'));
    const grab = (lineNum) => {
      const row = rows.find(r => r.textContent?.includes(`Ln ${lineNum}`));
      if (!row) return null;
      const spans = row.querySelectorAll('span');
      return spans[spans.length - 1]?.textContent || null;
    };
    return { grossLine: grab('1'), mileageLine: grab('9') };
  });
  const parseMoney = (s) => s ? Number(String(s).replace(/[^0-9.-]/g, '')) : NaN;
  const renderedGross = parseMoney(rendered.grossLine);
  const renderedMileage = parseMoney(rendered.mileageLine);
  console.log(`    [evidence] rendered card: gross=${rendered.grossLine} mileage=${rendered.mileageLine}`);

  eq(Math.round(renderedGross * 100), Math.round(expectedGross * 100),
    `rendered Schedule C gross income (${renderedGross}) must equal the per-trip sum (${expectedGross})`);
  eq(Math.round(renderedMileage * 100), Math.round(expectedMileage * 100),
    `rendered mileage deduction (${renderedMileage}) must equal the computed sum (${expectedMileage})`);

  // Exported CSV summary section (re-export to get a fresh capture in this test).
  const csv = await exportCsvAndCapture(app.page);
  // Keep each line's own quoting intact (don't strip outer quotes here) —
  // parseCSVLines needs the real leading `"` to know a field is quoted.
  const csvLines = csv.replace(/^﻿/, '').split(/\r\n|\n/);
  const grossCsvLine = csvLines.find(l => /Gross receipts/.test(l)) || '';
  const parsedGrossRow = await app.page.evaluate((line) => window.__FL_TESTS.parseCSVLines([line])[0], grossCsvLine);
  ok(parsedGrossRow && parsedGrossRow.length >= 3, 'could not locate/parse the Schedule C "Gross receipts" line in the exported CSV');
  const csvGross = Number(parsedGrossRow[2]);
  eq(Math.round(csvGross * 100), Math.round(expectedGross * 100),
    `CSV-exported gross income (${csvGross}) must equal the per-trip sum (${expectedGross}) and the rendered card (${renderedGross})`);
});

test('[FINDING F-3 / FIXED] year-boundary bucketing: a Dec 31 trip and a Jan 1 trip land in the correct tax year', async () => {
  await openTaxExportUI(app.page, 2025);
  const csv2025 = await exportCsvAndCapture(app.page);
  ok(csv2025.includes('AUDIT-YEARBOUNDARY-2025'), '2025 export must include the Dec 31 2025 trip');
  ok(!csv2025.includes('AUDIT-YEARBOUNDARY-2026'), '2025 export must NOT include the Jan 1 2026 trip');

  await openTaxExportUI(app.page, 2026);
  const csv2026 = await exportCsvAndCapture(app.page);
  ok(csv2026.includes('AUDIT-YEARBOUNDARY-2026'), '2026 export must include the Jan 1 2026 trip');
  ok(!csv2026.includes('AUDIT-YEARBOUNDARY-2025'), '2026 export must NOT include the Dec 31 2025 trip');
});

export async function runSpec() {
  app = await launchApp();
  try {
    return await run();
  } finally {
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
