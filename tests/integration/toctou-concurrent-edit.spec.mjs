// FINDING F-6 (Medium/High) — Concurrent edits from two tabs silently lose data.
//
// upsertTrip() (app.js:943-955) reads the existing record and writes the new
// one inside a single IndexedDB readwrite transaction, and is commented
// "TOCTOU-safe: read + write in single readwrite transaction". That is true
// ONLY for the audit-log snapshot written inside that same call — it says
// nothing about the trip data itself, because the read that actually
// matters (populating the edit form) happened much earlier, in a separate
// transaction, when the wizard was opened (openTripWizard(existing), around
// app.js:8650-8653). save()/collectTrip() (app.js:8809-8852) then always
// writes the ENTIRE in-memory `trip` object with `stores.trips.put(t)` — a
// full overwrite, not a field-level patch, and with no version/updatedAt
// precondition check.
//
// Two tabs open on the same trip therefore race: whichever tab calls
// upsertTrip() last wins completely, silently reverting any field the other
// tab changed that it didn't itself touch — a classic lost-update bug, not
// prevented by the transaction atomicity the comment invokes.
//
// This test opens the SAME saved trip in two independent browser tabs
// (contexts), changes a different field in each, saves Tab A first then Tab
// B, and shows Tab B's save silently discards Tab A's change.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/toctou-concurrent-edit.spec.mjs');
let app, page2;

test('seed one trip and open it for editing in two independent tabs', async () => {
  await app.page.evaluate(async () => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo: 'AUDIT-TOCTOU-1', customer: 'Original Customer', pay: 1000,
      loadedMiles: 400, emptyMiles: 0, pickupDate: '2026-03-01', deliveryDate: '2026-03-02',
      origin: 'Chicago, IL', destination: 'Indianapolis, IN', isPaid: false,
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
  });

  // Tab B = a second page in the SAME browser context, sharing the same
  // origin's IndexedDB — exactly like two browser tabs on one device, or
  // (for the cloud-sync-less local case this app targets) the most direct
  // reproduction of "two tabs open".
  page2 = await app.context.newPage();
  await page2.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
  await page2.waitForFunction(() => !!(window.__FL_TESTS && document.getElementById('appMeta')?.textContent), { timeout: 15000 });

  for (const p of [app.page, page2]) {
    await p.evaluate(() => { location.hash = '#trips'; });
    await p.waitForSelector('.fl-trip-full', { timeout: 10000 });
    await p.evaluate(() => {
      const rows = Array.from(document.querySelectorAll('.fl-trip-full'));
      const row = rows.find(r => (r.textContent || '').includes('AUDIT-TOCTOU-1'));
      row?.querySelector('[data-act="edit"]')?.click();
    });
    await p.waitForSelector('#f_pay', { timeout: 10000 });
  }
});

test('[FINDING F-6] Tab B saving after Tab A silently reverts Tab A\'s change (lost update)', async () => {
  // Tab A: raises pay 1000 -> 1500, saves first.
  await app.page.fill('#f_pay', '1500');
  await app.page.click('#saveTrip');
  await app.page.waitForTimeout(500);

  // Tab B: never touched pay (still shows the original 1000 it loaded before
  // Tab A saved) but changes an unrelated field (loadedMiles) and saves.
  const tabBPayBeforeSave = await page2.$eval('#f_pay', el => el.value);
  await page2.fill('#f_loaded', '450');
  await page2.click('#saveTrip');
  await page2.waitForTimeout(500);

  const finalState = await app.page.evaluate(async () => {
    return await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('trips', 'readonly');
        const getReq = txn.objectStore('trips').get('AUDIT-TOCTOU-1');
        getReq.onsuccess = () => { db.close(); resolve(getReq.result); };
        getReq.onerror = () => reject(getReq.error);
      };
      req.onerror = () => reject(req.error);
    });
  });

  console.log(`    [evidence] Tab B's form still showed pay=${tabBPayBeforeSave} when it saved (stale — Tab A had already changed it to 1500 in storage)`);
  console.log(`    [evidence] final stored trip: pay=${finalState.pay}, loadedMiles=${finalState.loadedMiles}`);

  ok(finalState.loadedMiles === 450, 'sanity: Tab B\'s own edit (loadedMiles) should be present');
  eq(finalState.pay, 1500,
    `BUG (app.js:943-955, 8809-8852): Tab B's save silently overwrote Tab A's pay change (1000 -> 1500) back to ` +
    `Tab B's stale in-memory value (${tabBPayBeforeSave}) because upsertTrip() does a full-object put with no ` +
    `optimistic-concurrency check — two tabs/devices editing the same trip lose whichever change was saved first.`);
});

export async function runSpec() {
  app = await launchApp();
  try {
    return await run();
  } finally {
    await page2?.close().catch(() => {});
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
