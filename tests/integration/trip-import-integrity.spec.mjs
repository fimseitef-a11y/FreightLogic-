// v24.0.43 — trip CSV/XLSX import integrity (Airtable recG8I51SR28EQb34).
//
// A real 142-trip work-history import came out dirty: 30 pickup dates reset to
// the import day, 29 $0-pay records, 62 zero-loaded-mile records and duplicate
// order numbers. The importer turned an unreadable date into TODAY, a blank pay
// or loaded-miles cell into 0, any non-empty Status (e.g. "Completed") into a
// known "unpaid", and re-importing a file added every row again.
//
// Each test drives the real importFile() with a real CSV File and reads the
// trips store back.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/trip-import-integrity.spec.mjs');

async function importCsv(page, csv, name = 'trips.csv') {
  return await page.evaluate(async ({ csv, name }) => {
    const T = window.__FL_TESTS;
    // Record every toast: an unrelated info toast (e.g. "installed") can
    // replace ours before the test reads it.
    const el = document.getElementById('toast');
    window.__tiiToasts = [];
    const mo = new MutationObserver(() => window.__tiiToasts.push(el.textContent || ''));
    mo.observe(el, { childList: true, characterData: true, subtree: true });
    await T.importFile(new File([csv], name, { type: 'text/csv' }));
    mo.disconnect();
    return await T.dumpStore('trips');
  }, { csv, name });
}

const HEADER = 'Order#,Customer,Pickup,Delivery,Origin,Destination,Pay,LoadedMiles,EmptyMiles,Status';

test('[TII-01] US and Excel date formats import as the date written, never today', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const trips = await importCsv(app.page, [HEADER,
      'A1,Broker,9/14/2026,9/15/2026,Atlanta GA,Dayton OH,900,500,40,Paid',
      'A2,Broker,Sep 10 2026,,Atlanta GA,Toledo OH,800,520,20,Paid',
      'A3,Broker,46275,,Atlanta GA,Gary IN,700,600,10,Paid',
    ].join('\n'));
    const by = Object.fromEntries(trips.map(t => [t.orderNo, t]));
    eq(by.A1?.pickupDate, '2026-09-14', 'M/D/YYYY pickup');
    eq(by.A1?.deliveryDate, '2026-09-15', 'M/D/YYYY delivery');
    eq(by.A2?.pickupDate, '2026-09-10', 'month-name pickup');
    eq(by.A3?.pickupDate, '2026-09-10', 'Excel serial pickup');
  } finally { await app.close(); }
});

test('[TII-02] a row with an unreadable pickup date is skipped and named, not dated today', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const trips = await importCsv(app.page, [HEADER,
      'B1,Broker,sometime,,Atlanta GA,Dayton OH,900,500,40,Paid',
      'B2,Broker,,,Atlanta GA,Dayton OH,900,500,40,Paid',
      'B3,Broker,2026-09-12,,Atlanta GA,Dayton OH,900,500,40,Paid',
    ].join('\n'));
    const orders = trips.map(t => t.orderNo);
    ok(!orders.includes('B1') && !orders.includes('B2'), `rows with no readable date must not be saved: ${orders}`);
    ok(orders.includes('B3'), 'a readable row in the same file still imports');
    const msg = (await app.page.evaluate(() => window.__tiiToasts)).join(' | ');
    ok(/2 skipped: no readable pickup date \(row 2, 3\)/.test(msg || ''), `the toast names the skipped rows: ${msg}`);
  } finally { await app.close(); }
});

test('[TII-03] blank pay and blank loaded miles are flagged for review, not trusted as 0', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const trips = await importCsv(app.page, [HEADER,
      'C1,Broker,2026-09-12,,Atlanta GA,Dayton OH,,500,40,Paid',
      'C2,Broker,2026-09-12,,Atlanta GA,Toledo OH,900,,40,Paid',
      'C3,Broker,2026-09-12,,Atlanta GA,Gary IN,900,500,,Paid',
      'C4,Broker,2026-09-12,,Atlanta GA,Akron OH,900,500,40,Paid',
    ].join('\n'));
    const by = Object.fromEntries(trips.map(t => [t.orderNo, t]));
    ok(by.C1?.needsReview && by.C1.reviewReasons.includes('Pay must be greater than 0'), 'blank pay is flagged');
    ok(by.C2?.needsReview && by.C2.reviewReasons.includes('Loaded miles are unknown'), 'blank loaded miles are flagged');
    eq(by.C3?.emptyMiles, null, 'blank deadhead stays UNKNOWN');
    eq(by.C4?.needsReview, false, 'a complete row is not flagged');
  } finally { await app.close(); }
});

test('[TII-04] payment status is known only for a recognisable answer', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const trips = await importCsv(app.page, [HEADER,
      'D1,Broker,2026-09-12,,Atlanta GA,Dayton OH,900,500,40,Completed',
      'D2,Broker,2026-09-12,,Atlanta GA,Toledo OH,900,500,40,Unpaid',
      'D3,Broker,2026-09-12,,Atlanta GA,Gary IN,900,500,40,Paid',
    ].join('\n'));
    const by = Object.fromEntries(trips.map(t => [t.orderNo, t]));
    eq(by.D1?.paymentStatusKnown, false, '"Completed" says nothing about payment');
    eq(by.D2?.paymentStatusKnown, true, 'Unpaid is known'); eq(by.D2?.isPaid, false, 'Unpaid is unpaid');
    eq(by.D3?.paymentStatusKnown, true, 'Paid is known'); eq(by.D3?.isPaid, true, 'Paid is paid');
  } finally { await app.close(); }
});

test('[TII-05] re-importing the same file adds nothing; a reused order # on another load still imports', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const csv = [HEADER,
      'E1,Broker,2026-09-12,,Atlanta GA,Dayton OH,900,500,40,Paid',
      ',Broker,2026-09-13,,Macon GA,Akron OH,650,400,30,Paid',
    ].join('\n');
    await importCsv(app.page, csv);
    let trips = await importCsv(app.page, csv);
    eq(trips.length, 2, `a second import of the same file adds no rows: ${trips.map(t => t.orderNo)}`);
    const msg = (await app.page.evaluate(() => window.__tiiToasts)).join(' | ');
    ok(/2 already saved, skipped/.test(msg || ''), `the toast reports the skipped duplicates: ${msg}`);
    trips = await importCsv(app.page, [HEADER, 'E1,Other Broker,2026-09-20,,Nashville TN,Raleigh NC,700,548,120,Paid'].join('\n'));
    eq(trips.filter(t => t.orderNo === 'E1').length, 2, 'the same order # on a different load is a different trip');
  } finally { await app.close(); }
});

test('[TII-06] a missing pickup date takes the delivery date, in CSV and JSON import', async () => {
  const app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    const trips = await importCsv(app.page, [HEADER, 'F1,Broker,,2/21/2026,Racine WI,Elk Grove Village IL,450,70,10,Paid'].join('\n'));
    eq(trips.find(t => t.orderNo === 'F1')?.pickupDate, '2026-02-21', 'CSV: blank pickup uses the delivery date');
    const json = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const payload = { meta: { app: 'FreightLogic' }, trips: [{ id: 'hist-f2', orderNo: 'F2', deliveryDate: '2026-02-03',
        origin: 'South Bend IN', destination: 'Milwaukee WI', pay: 400, loadedMiles: 90, emptyMiles: 5 }] };
      await T.importJSON(new File([JSON.stringify(payload)], 'h.json', { type: 'application/json' }), { mode: 'merge' });
      return (await T.dumpStore('trips')).find(t => t.orderNo === 'F2');
    });
    eq(json?.pickupDate, '2026-02-03', 'JSON: a trip with only a delivery date is not dated today');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
