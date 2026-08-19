// FINDING F-6 (High, FIXED) — Concurrent edits from two tabs used to silently lose data.
//
// upsertTrip()'s (app.js:943-...) "TOCTOU-safe: read + write in single
// readwrite transaction" comment was accurate only for the audit-log
// snapshot written inside that same call — it said nothing about the trip
// data itself, because the read that actually matters (populating the edit
// form) happened much earlier, in a separate transaction, when the wizard
// was opened (openTripWizard(existing)). save()/collectTrip() then always
// wrote the ENTIRE in-memory `trip` object with `stores.trips.put(t)` — a
// full overwrite, not a field-level patch, with no version/updatedAt
// precondition check. Two tabs open on the same trip raced: whichever
// tab's upsertTrip() call landed last won completely, silently reverting
// any field the other tab changed that it didn't itself touch.
//
// FIX (this commit): upsertTrip() now captures the caller's in-memory
// `updatedAt` (preserved untouched through the whole edit session by
// openTripWizard/collectTrip) as an optimistic-concurrency precondition.
// Inside the same transaction that reads the current record, it compares
// the current stored `updatedAt` against that expectation; a mismatch
// aborts the transaction and throws an `FL_CONFLICT` error instead of
// overwriting — no lock, nothing waits on anything, so a tab that dies
// mid-transaction can't strand other tabs (an uncommitted IndexedDB
// transaction just auto-aborts per spec). The trip wizard's save() handler
// catches FL_CONFLICT, tells the driver, and reopens the wizard on the
// current server copy so they can redo their edit against fresh data.
//
// This spec proves two things:
//   1. Two tabs, sequential saves (A then B): B's save is rejected as a
//      conflict, Tab A's change survives, and Tab B is shown the fresh
//      server record — no silent loss.
//   2. Best-effort "kill mid-write": a third tab fires a save and its page
//      is closed immediately without awaiting completion; the stored
//      record afterward is checked for structural well-formedness and for
//      matching one of the two known-good snapshots (pre- or fully-post-
//      write), never a partial hybrid. See the caveat on this test below —
//      IndexedDB transaction timing from outside the page can't be pinned
//      to an exact instruction, so this demonstrates the invariant holds
//      across repeated attempts rather than proving a single deterministic
//      interruption point.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/toctou-concurrent-edit.spec.mjs');
let app, page2;

async function seedTrip(page, orderNo, pay) {
  await page.evaluate(async ({ orderNo, pay }) => {
    const t = window.__FL_TESTS.sanitizeTrip({
      orderNo, customer: 'Original Customer', pay,
      loadedMiles: 400, emptyMiles: 0, pickupDate: '2026-03-01', deliveryDate: '2026-03-02',
      origin: 'Chicago, IL', destination: 'Indianapolis, IN', isPaid: false,
    });
    // Stamp updatedAt the way the real upsertTrip() always does on every
    // save — sanitizeTrip() itself never sets this field, only upsertTrip
    // does. Seeding without it would mean this "already exists" fixture
    // looks identical to a genuinely brand-new trip (which correctly skips
    // the F-6 conflict check), silently defeating the test.
    t.updatedAt = Date.now();
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
  }, { orderNo, pay });
}

async function getTrip(page, orderNo) {
  return page.evaluate(async (orderNo) => {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('trips', 'readonly');
        const getReq = txn.objectStore('trips').get(orderNo);
        getReq.onsuccess = () => { db.close(); resolve(getReq.result); };
        getReq.onerror = () => reject(getReq.error);
      };
      req.onerror = () => reject(req.error);
    });
  }, orderNo);
}

async function openTripForEdit(page, orderNo) {
  await page.evaluate(() => { location.hash = '#trips'; });
  await page.waitForSelector('.fl-trip-full', { timeout: 10000 });
  await page.evaluate((orderNo) => {
    const rows = Array.from(document.querySelectorAll('.fl-trip-full'));
    const row = rows.find(r => (r.textContent || '').includes(orderNo));
    row?.querySelector('[data-act="edit"]')?.click();
  }, orderNo);
  await page.waitForSelector('#f_pay', { timeout: 10000 });
}

test('seed one trip and open it for editing in two independent tabs', async () => {
  await seedTrip(app.page, 'AUDIT-TOCTOU-1', 1000);

  // Tab B = a second page in the SAME browser context, sharing the same
  // origin's IndexedDB — exactly like two browser tabs on one device.
  page2 = await app.context.newPage();
  await page2.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
  await page2.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  await openTripForEdit(app.page, 'AUDIT-TOCTOU-1');
  await openTripForEdit(page2, 'AUDIT-TOCTOU-1');
});

test('[FINDING F-6] Tab B is rejected as a conflict — Tab A\'s change survives, no silent loss', async () => {
  // Tab A: raises pay 1000 -> 1500, saves first (succeeds — nothing to conflict with yet).
  await app.page.fill('#f_pay', '1500');
  await app.page.click('#saveTrip');
  await app.page.waitForTimeout(500);

  const afterTabA = await getTrip(app.page, 'AUDIT-TOCTOU-1');
  eq(afterTabA.pay, 1500, 'sanity: Tab A\'s save must land first');

  // Tab B: still holds the pre-Tab-A copy (pay=1000) it loaded before Tab A
  // saved. It never touched pay, but changes an unrelated field
  // (loadedMiles) and saves — this is exactly the case that used to
  // silently revert Tab A's pay change back to 1000.
  const tabBPayBeforeSave = await page2.$eval('#f_pay', el => el.value);
  await page2.fill('#f_loaded', '450');
  await page2.click('#saveTrip');
  await page2.waitForTimeout(500);

  const finalState = await getTrip(app.page, 'AUDIT-TOCTOU-1');
  console.log(`    [evidence] Tab B's form still showed pay=${tabBPayBeforeSave} when it saved (stale — Tab A had already changed it to 1500 in storage)`);
  console.log(`    [evidence] final stored trip: pay=${finalState.pay}, loadedMiles=${finalState.loadedMiles}`);

  eq(finalState.pay, 1500,
    'Tab A\'s pay change must survive Tab B\'s conflicting save — got ' + finalState.pay);
  eq(finalState.loadedMiles, 400,
    'Tab B\'s loadedMiles=450 edit must NOT have been silently applied via a lost-update overwrite — ' +
    'it was rejected as a conflict, so the record must still show Tab A\'s last-known-good state (400)');

  // Tab B must be told, not silently left showing its own (now-discarded) edit.
  const tabBState = await page2.evaluate(() => ({
    payFieldValue: document.getElementById('f_pay')?.value ?? null,
    modalStillShowsOldForm: !!document.getElementById('f_pay'),
  }));
  console.log(`    [evidence] Tab B post-conflict form pay field: ${JSON.stringify(tabBState.payFieldValue)}`);
  // The wizard reopens on the fresh server record (app.js save()'s FL_CONFLICT
  // handler calls openTripWizard(e.serverRecord)), so Tab B's pay field should
  // now show the CURRENT server value (1500), not silently keep showing 1000
  // as if nothing happened.
  eq(tabBState.payFieldValue, '1500',
    'Tab B should be shown the fresh server record after a conflict, not left on its stale form');
});

test('[F-6 best-effort] a save fired then the tab closed immediately never leaves a corrupt/partial record', async () => {
  // Caveat: from outside the page, we cannot pin a page.close() to an exact
  // instruction inside the in-flight IndexedDB transaction — this proves
  // the record stays well-formed and matches one of the two known-good
  // states across repeated attempts, not a single deterministically-timed
  // interruption. IndexedDB transactions are atomic by spec (a transaction
  // that hasn't committed when its connection is torn down is aborted, not
  // partially applied) — this test is empirical confirmation of that
  // holding in this app's actual code path, not a claim this app's own
  // code adds extra protection beyond what IndexedDB already guarantees.
  await seedTrip(app.page, 'AUDIT-TOCTOU-KILL', 2000);

  for (let attempt = 0; attempt < 5; attempt++) {
    const page3 = await app.context.newPage();
    await page3.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
    await page3.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    await openTripForEdit(page3, 'AUDIT-TOCTOU-KILL');
    await page3.fill('#f_pay', '9999');
    // Fire-and-forget: click without awaiting the save's own promise chain,
    // then close the page immediately.
    page3.click('#saveTrip').catch(() => {});
    await page3.close();
    await app.page.waitForTimeout(150);

    const state = await getTrip(app.page, 'AUDIT-TOCTOU-KILL');
    ok(state && typeof state.orderNo === 'string' && state.orderNo === 'AUDIT-TOCTOU-KILL',
      `attempt ${attempt}: record missing/malformed after kill: ${JSON.stringify(state)}`);
    ok(Number.isFinite(state.pay) && Number.isFinite(state.updatedAt),
      `attempt ${attempt}: record has non-numeric pay/updatedAt (partial write?): ${JSON.stringify(state)}`);
    ok(state.pay === 2000 || state.pay === 9999,
      `attempt ${attempt}: record.pay is neither the pre-write (2000) nor fully-written (9999) value — ` +
      `possible partial/corrupt write: ${JSON.stringify(state)}`);
    // Reset for the next attempt.
    await seedTrip(app.page, 'AUDIT-TOCTOU-KILL', 2000);
  }
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
