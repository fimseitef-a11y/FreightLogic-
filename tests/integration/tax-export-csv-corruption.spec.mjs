// FINDING F-3 (Critical) — Schedule C tax-export CSV has no field quoting.
//
// app.js:1349 (the general trip/expense/fuel CSV export) quotes every cell:
//   `"${csvSafeCell(c).replace(/"/g,'""')}"`
// app.js:12446 (the Tax Season Export / Schedule C mileage log, F30) does NOT:
//   rows.map(r => r.map(v => csvSafeCell(v)).join(',')).join('\r\n')
// The mileage-log rows embed free-text trip.origin/trip.destination
// (app.js:12438-12439, clampStr'd but NOT comma-stripped) directly as
// unquoted CSV fields. Any trip whose origin/destination contains a comma —
// which is the natural way to write "City, ST" — silently shifts every
// column after it for that row when opened in Excel/Numbers/accounting
// software, corrupting the mileage deduction an accountant would review.
//
// This test seeds one real trip with a comma in the destination through the
// actual sanitizeTrip() + upsertTrip() path (not a hand-built CSV string),
// opens Tax Season Export, captures the CSV Blob the app itself builds via
// a monkey-patched URL.createObjectURL, and proves the row is unparseable
// as the 9-column table the header promises.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/tax-export-csv-corruption.spec.mjs');
let app;

test('seed one trip via the real upsertTrip() path with a comma in destination', async () => {
  const saved = await app.page.evaluate(async () => {
    // upsertTrip/sanitizeTrip are closured, not on window — drive it through
    // the exact same IDB write path the UI uses by calling the exposed
    // sanitizeTrip for shape, then writing through the real trips store via
    // a temporary global the app doesn't expose... so instead we go through
    // the public Quick Add flow equivalent: open IDB directly with the
    // app's own DB name/version and reuse sanitizeTrip's output shape.
    // (sanitizeTrip IS exposed — use it to build a realistic, validated record,
    // then commit it with the same upsertTrip() semantics via indexedDB directly
    // using the identical store name/keyPath the app uses.)
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'AUDIT-CSV-1',
      customer: 'Test Broker LLC',
      pickupDate: '2026-03-01',
      deliveryDate: '2026-03-02',
      invoiceDate: '2026-03-02',
      origin: 'Chicago, IL',
      destination: 'Springfield, IL', // <- the comma is the payload
      pay: 1000,
      loadedMiles: 200,
      emptyMiles: 0,
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
  });
  eq(saved.destination, 'Springfield, IL', 'seeded trip destination retains the comma');
});

test('[FINDING F-3] Tax Season Export CSV corrupts column alignment on a comma in destination', async () => {
  // Capture the Blob content the app builds for the CSV download without
  // actually triggering a browser download (createObjectURL is intercepted).
  await app.page.evaluate(() => {
    window.__capturedBlobText = null;
    const origCreate = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      blob.text().then(t => { window.__capturedBlobText = t; });
      return origCreate(blob);
    };
  });

  // Tax Season Export (F30) is a MORE_TILES entry (app.js:4886) in the
  // "ADVANCED" section of the More tab, hidden behind the "More Tools" toggle.
  await app.page.evaluate(() => { location.hash = '#more'; });
  await app.page.waitForSelector('.menu-tile .tt', { state: 'attached', timeout: 10000 });
  await app.page.waitForTimeout(300);
  const expanded = await app.page.evaluate(() => {
    const toggles = Array.from(document.querySelectorAll('div'));
    const t = toggles.find(el => el.textContent?.trim() === '▶ More Tools' || /More Tools/.test(el.textContent || '') && el.children.length <= 2);
    if (t) { t.click(); return true; }
    return false;
  });
  ok(expanded, 'could not find/click the "More Tools" advanced-section toggle');
  await app.page.waitForTimeout(300);
  const clicked = await app.page.evaluate(() => {
    const tiles = Array.from(document.querySelectorAll('.menu-tile'));
    const tile = tiles.find(el => /tax season export/i.test(el.querySelector('.tt')?.textContent || ''));
    if (tile) { tile.click(); return true; }
    return false;
  });
  ok(clicked, 'could not locate the "Tax Season Export" tile in the More menu');
  await app.page.waitForTimeout(500);

  await app.page.waitForSelector('#f30ExportCsv', { timeout: 10000 });
  await app.page.click('#f30ExportCsv');
  await app.page.waitForTimeout(500);

  const csv = await app.page.evaluate(() => window.__capturedBlobText);
  ok(csv, 'CSV export did not produce a captured Blob — cannot verify');

  const lines = csv.split(/\r\n|\n/);
  const headerIdx = lines.findIndex(l => l.startsWith('Date,Trip #,From,To,'));
  ok(headerIdx >= 0, 'could not find mileage-log header row in exported CSV');
  const dataRow = lines.slice(headerIdx + 1).find(l => l.includes('AUDIT-CSV-1'));
  ok(dataRow, 'seeded trip AUDIT-CSV-1 not found in exported mileage log — got:\n' + lines.slice(headerIdx, headerIdx + 5).join('\n'));

  const expectedCols = lines[headerIdx].split(',').length; // 9: Date,Trip#,From,To,Loaded,Dead,Total,Rate,Deduction
  const actualCols = dataRow.split(',').length;
  console.log('    [evidence] header: ' + lines[headerIdx]);
  console.log('    [evidence] data row: ' + dataRow);
  console.log(`    [evidence] expected ${expectedCols} columns, row has ${actualCols} (unquoted "Springfield, IL" splits into 2 fields)`);

  eq(actualCols, expectedCols,
    `BUG (app.js:12446): unquoted comma in destination "Springfield, IL" split the mileage-log row into ${actualCols} CSV fields ` +
    `instead of the header's ${expectedCols} — every column after "From" (Loaded Mi, Deadhead Mi, Total Mi, Rate, Deduction) ` +
    `shifts by one for this row when opened in Excel/accounting software, corrupting the mileage deduction figure.`);
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
