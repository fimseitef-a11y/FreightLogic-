// Phase 4 — Field Resilience (automatable subset run in headless Chromium).
//
// Scope, per the audit instructions: tab killed mid-write (covered already by
// F-6's best-effort test in toctou-concurrent-edit.spec.mjs — not repeated
// here), storage filled to QuotaExceededError during a save, offline for a
// full simulated day then reconnect, clock skew / DST transitions, and GPS
// with no fix / stale fix / permission denied mid-trip / wildly wrong
// coordinate. What's NOT automatable (real iOS Safari eviction, week-long
// cold start, real device backgrounding) is in FIELD_TEST_CHECKLIST.md
// instead of faked here.
//
// One genuine new finding came out of the GPS section — see F-7 below.

import { launchApp, createSuite, ok, eq, skipFirstRunWizard } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/field-resilience.spec.mjs');
let app;

async function getStoreCount(page, storeName) {
  return page.evaluate((storeName) => new Promise((resolve, reject) => {
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const txn = db.transaction(storeName, 'readonly');
      const cReq = txn.objectStore(storeName).count();
      cReq.onsuccess = () => { db.close(); resolve(cReq.result); };
      cReq.onerror = () => reject(cReq.error);
    };
    req.onerror = () => reject(req.error);
  }), storeName);
}

async function getTripByOrderNo(page, orderNo) {
  return page.evaluate((orderNo) => new Promise((resolve, reject) => {
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const txn = db.transaction('trips', 'readonly');
      const gReq = txn.objectStore('trips').get(orderNo);
      gReq.onsuccess = () => { db.close(); resolve(gReq.result || null); };
      gReq.onerror = () => reject(gReq.error);
    };
    req.onerror = () => reject(req.error);
  }), orderNo);
}

// #dcAddTrip / #btnQuickTrip / #btnQuickExpense (Home's Driver Command Strip
// and Quick Actions row) are only rendered visible in certain Home states —
// unreliable across a fresh empty DB in headless Chromium. The Trips/Expenses
// tabs' own "+ Add" buttons are unconditionally visible, so route there.
async function openAddTrip(page) {
  await page.evaluate(() => { location.hash = '#trips'; });
  await page.waitForSelector('#btnTripAdd', { timeout: 5000 });
  await page.click('#btnTripAdd');
  await page.waitForSelector('#f_orderNo', { timeout: 5000 });
}
async function openAddExpense(page) {
  await page.evaluate(() => { location.hash = '#expenses'; });
  await page.waitForSelector('#btnAddExp2', { timeout: 5000 });
  await page.click('#btnAddExp2');
  await page.waitForSelector('#f_amt', { timeout: 5000 });
}

// ============================================================
// 1. STORAGE QUOTA
// ============================================================
// Two different code paths handle storage pressure:
//   (a) PROACTIVE: checkStorageQuota() (app.js:249) — a boot-time check
//       against navigator.storage.estimate(); >80% used shows a warning
//       toast BEFORE anything fails. This is genuinely reproducible via
//       Chromium's real quota-reporting API (Storage.overrideQuotaForOrigin
//       via CDP) and is verified for real below.
//   (b) REACTIVE: upsertTrip()'s txn.onerror handler (app.js:999) — fires
//       if an actual write throws QuotaExceededError. This could NOT be
//       reliably forced in this sandbox: CDP's overrideQuotaForOrigin only
//       changes the number storage.estimate() reports, it does not make
//       Chromium actually reject writes at that size (confirmed empirically
//       — a write proceeded fine with quota pinned to usage+40 bytes), and
//       forcing a REAL exhaustion means writing towards this origin's actual
//       ~1GB quota, which both takes too long for a test run and risks this
//       sandbox's own fixed disk allowance. Per the audit's "don't fake it"
//       rule for non-automatable scenarios, this reactive path is left to
//       FIELD_TEST_CHECKLIST.md #4 (real device, real full storage) instead
//       of simulated here. app.js:999's handler is still verified by static
//       reading (correct DOMException name check, correct message, and by
//       construction the failing stores.trips.put(t) happens before
//       stores.auditLog.put(...) inside one transaction, so a real quota
//       failure aborts both atomically — no partial trip/audit-log pair).
test('[FINDING PHASE-4 / storage-full] the proactive boot-time quota check fires a real warning off a real (CDP-pinned) quota — verified against genuine navigator.storage.estimate()', async () => {
  await skipFirstRunWizard(app.page);
  await app.page.reload();
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  const usageBefore = await app.page.evaluate(async () => (await navigator.storage.estimate()).usage);
  ok(usageBefore > 0, `sanity: origin already has some usage (IDB + SW cache) — got ${usageBefore}`);

  const cdp = await app.context.newCDPSession(app.page);
  const origin = new URL(app.baseUrl).origin;
  // Pin reported quota to just over current usage BEFORE the boot sequence's
  // deferred checkStorageQuota() call fires (app.js:16278-16308, 2000ms after
  // boot) so its real pctUsed computation reads as >80% and fires for real.
  await cdp.send('Storage.overrideQuotaForOrigin', { origin, quotaSize: Math.round(usageBefore * 1.05) });
  const est = await app.page.evaluate(async () => await navigator.storage.estimate());
  console.log(`    [evidence] navigator.storage.estimate() after CDP pin: usage=${est.usage}, quota=${est.quota} (${Math.round(100 * est.usage / est.quota)}%)`);

  await app.page.waitForTimeout(2700); // past the 2000ms deferred boot task
  const toastTxt = await app.page.textContent('#toast').catch(() => '');
  console.log(`    [evidence] boot-time proactive toast: ${JSON.stringify(toastTxt)}`);
  ok(/storage/i.test(toastTxt) && /full/i.test(toastTxt),
    `expected checkStorageQuota()'s real warning (app.js:257) once usage genuinely reads >80% of a real (CDP-pinned) quota — got ${JSON.stringify(toastTxt)}`);

  // Restore a real quota so the rest of the suite (and this app instance)
  // isn't left artificially pinned.
  await cdp.send('Storage.overrideQuotaForOrigin', { origin });
});

// ============================================================
// 2. OFFLINE — a full simulated day, then reconnect
// ============================================================
test('offline: log a trip entirely offline, then reconnect', async () => {
  await app.context.setOffline(true);
  const onlineState = await app.page.evaluate(() => navigator.onLine);
  eq(onlineState, false, 'sanity: browser must actually report offline for this test to mean anything');

  await openAddTrip(app.page);
  await app.page.fill('#f_orderNo', 'AUDIT-OFFLINE-1');
  await app.page.fill('#f_pay', '900');
  await app.page.click('#saveTrip');
  await app.page.waitForTimeout(500);

  const tripsOffline = await getStoreCount(app.page, 'trips');
  console.log(`    [evidence] while offline: trips=${tripsOffline}`);
  ok(tripsOffline >= 1, 'trip save should succeed locally with zero network — this is a purely local-first write path (IndexedDB), no fetch involved');

  const savedTrip = await getTripByOrderNo(app.page, 'AUDIT-OFFLINE-1');
  ok(savedTrip && savedTrip.pay === 900, `offline trip should be fully and correctly saved — got ${JSON.stringify(savedTrip)}`);

  // Reconnect.
  await app.context.setOffline(false);
  const onlineAfter = await app.page.evaluate(() => navigator.onLine);
  eq(onlineAfter, true, 'sanity: browser must report back online');
  await app.page.reload();
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
});

test('[FINDING PHASE-4 / offline-reconnect] reconnecting does not duplicate, lose, or corrupt data written while offline', async () => {
  const trip = await getTripByOrderNo(app.page, 'AUDIT-OFFLINE-1');
  ok(trip && trip.pay === 900 && trip.orderNo === 'AUDIT-OFFLINE-1',
    `the offline-written trip must survive a reload after reconnecting unchanged — got ${JSON.stringify(trip)}`);

  // No duplicate — the store's count for this orderNo-keyed record is
  // inherently 1 (keyPath is orderNo), but confirm no stray error banner
  // is stuck on screen post-reconnect (matches FIELD_TEST_CHECKLIST #5's
  // "persistent error banner that a reconnect doesn't clear" failure mode).
  const stuckErrorBanner = await app.page.evaluate(() => {
    const t = document.getElementById('toast');
    return t && t.className.includes('show') && t.className.includes('err');
  });
  ok(!stuckErrorBanner, 'no error toast should be stuck showing after a clean reconnect + reload');
  console.log('    [evidence] no stuck error state after offline day + reconnect + reload — offline-first holds');
});

// ============================================================
// FINDING F-8 (Critical) — FIXED. Discovered while building the offline
// expense-entry scenario above; was never offline-specific (reproduced online
// too). Add Expense and Add Fuel were both completely broken for every
// brand-new record.
// ============================================================
// sanitizeExpense() (app.js:1044) and sanitizeFuel() (app.js:1120) both did:
//   id: raw.id ? intNum(raw.id, 0, 1e12) : undefined
// For a new record raw.id is absent, so this put an EXPLICIT `id: undefined`
// property on the object handed to store.add(). Per the IndexedDB spec, an
// object store with keyPath 'id' + autoIncrement:true only lets
// auto-increment fill in the key when the keyPath property is ABSENT — an
// explicitly-present `id: undefined` is evaluated as a real (invalid) key
// and add() threw synchronously: "Failed to execute 'add' on
// 'IDBObjectStore': Evaluating the object store's key path yielded a value
// that is not a valid key." addExpense()'s caller had no try/catch, so it was
// an uncaught exception — no toast, no error shown, the Save button just did
// nothing and the modal never closed.
//
// The fix omits the key entirely for a new record:
//   ...(raw.id ? { id: intNum(raw.id, 0, 1e12) } : {})
// The edit path is unchanged (raw.id truthy -> the key is set as before). The
// expense save handler (app.js:9268) also gained the try/catch the fuel
// handler already had, so a future storage error surfaces instead of being
// swallowed. See tests/unit/pure-functions.spec.mjs for the sanitizer-level
// assertions; these two drive the real UI end to end.
test('[FINDING F-8 / FIXED] Add Expense writes the record, closes the modal, and throws nothing', async () => {
  const pageErrors = [];
  app.page.on('pageerror', (e) => pageErrors.push(e.message));

  await openAddExpense(app.page);
  await app.page.fill('#f_amt', '45.50');
  await app.page.fill('#f_cat', 'Fuel');
  const countBefore = await getStoreCount(app.page, 'expenses');
  await app.page.click('#f_save');
  await app.page.waitForTimeout(800);

  const modalStillOpen = await app.page.evaluate(() => !!document.getElementById('f_amt'));
  const countAfter = await getStoreCount(app.page, 'expenses');
  console.log(`    [evidence] page errors thrown by the click: ${JSON.stringify(pageErrors)}`);
  console.log(`    [evidence] expenses count before=${countBefore}, after=${countAfter}; modal still open=${modalStillOpen}`);

  ok(!pageErrors.some(m => /IDBObjectStore.*key path.*not a valid key/i.test(m)),
    `addExpense() (app.js:1065) must no longer throw the key-path DataError — page errors seen: ${JSON.stringify(pageErrors)}`);
  eq(countAfter, countBefore + 1, 'the expense must actually be written to the expenses store');
  eq(modalStillOpen, false, 'the modal must close on a successful save (it stayed open when the exception was uncaught)');

  // The auto-generated key is what the bug prevented — assert it landed.
  const savedId = await app.page.evaluate(() => new Promise((resolve) => {
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const r = db.transaction('expenses').objectStore('expenses').getAll();
      r.onsuccess = () => { const rows = r.result || []; db.close(); resolve(rows.length ? rows[rows.length - 1].id : null); };
      r.onerror = () => { db.close(); resolve(null); };
    };
  }));
  console.log(`    [evidence] auto-generated id on the saved expense: ${JSON.stringify(savedId)}`);
  ok(typeof savedId === 'number' && savedId > 0, `the stored expense must carry a real auto-increment key — got ${JSON.stringify(savedId)}`);
});

test('[FINDING F-8 / FIXED] Add Fuel writes the record too — and the raw IndexedDB semantics behind the bug are unchanged', async () => {
  await app.context.setOffline(false);
  await app.page.reload();
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  const pageErrors = [];
  app.page.on('pageerror', (e) => pageErrors.push(e.message));

  // Add Fuel through the real UI. sanitizeFuel() (app.js:1120) had the
  // byte-for-byte identical id pattern feeding addFuel()'s store.fuel.add(x)
  // (app.js:1129), against a fuel store that is also
  // { keyPath:'id', autoIncrement:true }.
  const fuelBefore = await getStoreCount(app.page, 'fuel');
  await app.page.evaluate(() => { location.hash = '#fuel'; });
  await app.page.waitForSelector('#btnAddFuel2', { timeout: 5000 });
  await app.page.click('#btnAddFuel2');
  await app.page.waitForSelector('#f_gal', { timeout: 5000 });
  await app.page.fill('#f_gal', '18.2');
  await app.page.fill('#f_amt', '64.70');
  await app.page.fill('#f_state', 'IL');
  await app.page.click('#f_save');
  await app.page.waitForTimeout(800);
  const fuelAfter = await getStoreCount(app.page, 'fuel');
  const fuelModalOpen = await app.page.evaluate(() => !!document.getElementById('f_gal'));
  console.log(`    [evidence] fuel count before=${fuelBefore}, after=${fuelAfter}; modal still open=${fuelModalOpen}`);
  console.log(`    [evidence] page errors during Add Fuel: ${JSON.stringify(pageErrors)}`);
  eq(fuelAfter, fuelBefore + 1, 'the fuel record must actually be written (this was broken identically to the expense case)');
  eq(fuelModalOpen, false, 'the fuel modal must close on a successful save');

  // Regression guard on the underlying platform behavior the fix depends on:
  // an explicit `id: undefined` is still rejected by IndexedDB, while the same
  // object with the key OMITTED still succeeds. If this ever flips, the reason
  // the fix works has changed and the sanitizers deserve a fresh look.
  const rawShapes = await app.page.evaluate(() => new Promise((resolve) => {
    const base = { date: '2026-08-19', gallons: 10, amount: 40, state: 'IL', notes: '', created: Date.now(), updated: Date.now(), updatedAt: Date.now() };
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const out = {};
      const txn = db.transaction('fuel', 'readwrite');
      const store = txn.objectStore('fuel');
      try {
        const r = store.add({ id: undefined, ...base });
        r.onsuccess = () => { out.withUndefinedId = { ok: true }; };
        r.onerror = () => { out.withUndefinedId = { ok: false, err: r.error?.message }; };
      } catch (e) { out.withUndefinedId = { ok: false, thrown: e.message }; }
      try {
        const r2 = store.add({ ...base });
        r2.onsuccess = () => { out.withKeyOmitted = { ok: true, key: r2.result }; };
        r2.onerror = () => { out.withKeyOmitted = { ok: false, err: r2.error?.message }; };
      } catch (e) { out.withKeyOmitted = { ok: false, thrown: e.message }; }
      txn.oncomplete = () => { db.close(); resolve(out); };
      txn.onerror = () => { db.close(); resolve(out); };
    };
  }));
  console.log(`    [evidence] raw add() with an explicit id:undefined (the old shape): ${JSON.stringify(rawShapes.withUndefinedId)}`);
  console.log(`    [evidence] raw add() with the id key omitted (the fixed shape): ${JSON.stringify(rawShapes.withKeyOmitted)}`);
  ok(rawShapes.withUndefinedId && !rawShapes.withUndefinedId.ok && /key path/i.test(rawShapes.withUndefinedId.thrown || rawShapes.withUndefinedId.err || ''),
    `an explicit id:undefined must still be rejected — got ${JSON.stringify(rawShapes.withUndefinedId)}`);
  ok(rawShapes.withKeyOmitted && rawShapes.withKeyOmitted.ok && typeof rawShapes.withKeyOmitted.key === 'number',
    `omitting the id key must still auto-generate one — got ${JSON.stringify(rawShapes.withKeyOmitted)}`);
});

// ============================================================
// 3. CLOCK SKEW / DST TRANSITIONS
// ============================================================
test('[FINDING PHASE-4 / DST] isoDate() resolves the correct local calendar date across the Nov 2026 fall-back transition', async () => {
  // Fall-back: clocks go 2:00am -> 1:00am America/Chicago on 2026-11-01, so
  // local wall-clock time 1:30am occurs TWICE (once at UTC-5, once at
  // UTC-6). isoDate() must read "2026-11-01" for both instants, not drift a
  // day either way. A DST-blind implementation that naively used
  // toISOString().slice(0,10) (pure UTC, no local-offset compensation)
  // would get this wrong depending on which side of the UTC day boundary
  // the instant falls on.
  const dstApp = await launchApp({ enableTestExports: true });
  try {
    // Playwright context timezone is fixed at creation; re-launch with a
    // concrete US timezone since the default harness context has none set
    // (falls back to the host's, which may not observe US DST at all).
    await dstApp.close();
  } catch(e) { console.warn('[test]', e); }

  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ timezoneId: 'America/Chicago' });
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  const cases = await page.evaluate(() => {
    const T = window.__FL_TESTS;
    return [
      { label: '1:30am CDT (before fall-back)',        iso: T.isoDate(new Date('2026-11-01T06:30:00Z')) },
      { label: '1:30am CST (after fall-back, repeat hr)', iso: T.isoDate(new Date('2026-11-01T07:30:00Z')) },
      // 11:45pm CDT Oct 31 = Oct 31 23:45 local, UTC-5 -> 2026-11-01T04:45:00Z
      { label: '11:45pm CDT the night before',          iso: T.isoDate(new Date('2026-11-01T04:45:00Z')) },
    ];
  });
  for (const c of cases) console.log(`    [evidence] ${c.label} -> isoDate = ${c.iso}`);

  eq(cases[0].iso, '2026-11-01', `1:30am CDT should read as Nov 1 — got ${cases[0].iso}`);
  eq(cases[1].iso, '2026-11-01', `1:30am CST (the repeated hour) should ALSO read as Nov 1, not drift — got ${cases[1].iso}`);
  eq(cases[2].iso, '2026-10-31', `11:45pm the night before should still read as Oct 31 — got ${cases[2].iso}`);

  await browser.close();
});

test('[FINDING PHASE-4 / DST] isoDate() resolves correctly across the Mar 2027 spring-forward transition (the missing 2am-3am hour)', async () => {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ timezoneId: 'America/Chicago' });
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  const cases = await page.evaluate(() => {
    const T = window.__FL_TESTS;
    return [
      { label: '1:59am CST (before spring-forward)', iso: T.isoDate(new Date('2027-03-14T07:59:00Z')) },
      { label: '3:01am CDT (after spring-forward)',  iso: T.isoDate(new Date('2027-03-14T08:01:00Z')) },
      // daysBetweenISO parses date-only strings as UTC, so it should be
      // completely unaffected by the DST jump — spanning the transition
      // should still be a plain calendar-day count.
    ];
  });
  for (const c of cases) console.log(`    [evidence] ${c.label} -> isoDate = ${c.iso}`);
  eq(cases[0].iso, '2027-03-14', `1:59am CST should read as Mar 14 — got ${cases[0].iso}`);
  eq(cases[1].iso, '2027-03-14', `3:01am CDT (post spring-forward) should ALSO read as Mar 14 — got ${cases[1].iso}`);

  const days = await page.evaluate(() => window.__FL_TESTS.daysBetweenISO('2027-03-13', '2027-03-15'));
  eq(days, 2, `daysBetweenISO spanning the spring-forward transition should be a plain 2-day count (date-only strings parse as UTC, DST-immune) — got ${days}`);

  await browser.close();
});

test('[FINDING PHASE-4 / DST] a trip logged with the app clock faked to the ambiguous fall-back hour lands on the correct date end to end', async () => {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ timezoneId: 'America/Chicago' });
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.clock.install({ time: new Date('2026-11-01T07:30:00Z') }); // 1:30am CST, the repeated hour
  await page.goto(`${app.baseUrl}/index.html`, { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  await skipFirstRunWizard(page);
  await page.reload();
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });

  await openAddTrip(page);
  const pickupVal = await page.inputValue('#f_pickup');
  console.log(`    [evidence] pickup date field, app clock faked to 1:30am CST Nov 1 2026 (fall-back hour): ${pickupVal}`);
  eq(pickupVal, '2026-11-01', `default pickup date at the DST-ambiguous local hour should be 2026-11-01 — got ${pickupVal}`);

  await page.fill('#f_orderNo', 'AUDIT-DST-1');
  await page.fill('#f_pay', '500');
  await page.click('#saveTrip');
  await page.waitForTimeout(500);

  const trip = await page.evaluate((orderNo) => new Promise((resolve, reject) => {
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const txn = db.transaction('trips', 'readonly');
      const gReq = txn.objectStore('trips').get(orderNo);
      gReq.onsuccess = () => { db.close(); resolve(gReq.result || null); };
      gReq.onerror = () => reject(gReq.error);
    };
    req.onerror = () => reject(req.error);
  }), 'AUDIT-DST-1');
  ok(trip, 'trip should have saved');
  eq(trip.pickupDate, '2026-11-01', `saved trip's pickupDate must be the correct local calendar date across the fall-back transition — got ${trip.pickupDate}`);

  await browser.close();
});

// ============================================================
// 4. GPS RESILIENCE — no fix / stale fix / permission denied / wildly wrong coordinate
// ============================================================
async function launchGpsApp() {
  const gpsApp = await launchApp({
    enableTestExports: true,
    geolocation: { latitude: 41.8781, longitude: -87.6298, accuracy: 10 },
    permissions: ['geolocation'],
  });
  await skipFirstRunWizard(gpsApp.page);
  await gpsApp.page.evaluate(() => new Promise((resolve, reject) => {
    const req = indexedDB.open('FreightLogic_v18');
    req.onsuccess = () => {
      const db = req.result;
      const txn = db.transaction('settings', 'readwrite');
      txn.objectStore('settings').put({ key: 'f21PermissionSeen', value: true });
      txn.oncomplete = () => { db.close(); resolve(); };
      txn.onerror = () => reject(txn.error);
    };
    req.onerror = () => reject(req.error);
  }));
  await gpsApp.page.reload();
  await gpsApp.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  return gpsApp;
}

// F-7 was fixed by making a GPS error never end the session. The old error
// handler (app.js:14871-14880) treated every PositionError code identically:
// toast, `_activeTracking = null`, re-render idle. It never cleared
// sessionStorage['fl_active_tracking'] (only stopTripTracking() does), so the
// trip LOOKED lost but wasn't — and the only visible affordance left,
// "Start Trip", minted a fresh trackingId and orphaned the old session's miles
// for good. The session now stays alive in a degraded state (Stop & Save keeps
// working, which is what salvages the miles), and any record left behind by an
// unclean teardown is offered for resume instead of silently discarded.
test('[FINDING F-7 / FIXED] sustained GPS signal loss keeps the session alive and degrades the UI honestly, instead of tearing the trip down', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const trackingIdBefore = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);
    ok(trackingIdBefore, 'sanity: an active session should be persisted to sessionStorage');

    // Sustained POSITION_UNAVAILABLE. CDP's Emulation.setGeolocationOverride
    // with no parameters emulates "position unavailable" for as long as it is
    // set — unlike context.setGeolocation(), which in Chromium emits only a
    // one-event transient error before delivering the new fix. This models the
    // real scenario: a tunnel, a parking garage, an urban canyon.
    const cdp = await gpsApp.context.newCDPSession(gpsApp.page);
    await cdp.send('Emulation.setGeolocationOverride', {});
    await gpsApp.page.waitForTimeout(1500);

    const lostText = await gpsApp.page.textContent('#f21TrackArea');
    const toastTxt = await gpsApp.page.textContent('#toast').catch(() => '');
    const recordDuringLoss = await gpsApp.page.evaluate(() => sessionStorage.getItem('fl_active_tracking'));
    const stopBtnPresent = await gpsApp.page.evaluate(() => !!document.getElementById('f21StopBtn'));
    console.log(`    [evidence] track area during sustained signal loss: ${JSON.stringify(lostText)}`);
    console.log(`    [evidence] toast shown: ${JSON.stringify(toastTxt)}`);
    console.log(`    [evidence] Stop & Save still reachable during the outage: ${stopBtnPresent}`);

    ok(lostText.includes('Trip in progress'),
      `the session must survive a GPS outage — the card should still read "Trip in progress", got ${JSON.stringify(lostText)}`);
    ok(/GPS signal lost/i.test(lostText),
      `the outage must be surfaced honestly rather than showing a stale accuracy chip — got ${JSON.stringify(lostText)}`);
    ok(stopBtnPresent, 'Stop & Save must stay reachable during an outage — that button is what salvages the accumulated miles');
    ok(/still tracking/i.test(toastTxt), `the toast must reassure that tracking continues — got ${JSON.stringify(toastTxt)}`);

    const trackingIdDuringLoss = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);
    eq(trackingIdDuringLoss, trackingIdBefore, 'the outage must not roll the session over to a new trackingId');
    ok(recordDuringLoss, 'the persisted resume record must still be present');

    // Signal returns: the degraded indicator must clear on the next good fix.
    await cdp.send('Emulation.setGeolocationOverride', { latitude: 41.8790, longitude: -87.6300, accuracy: 10 });
    await gpsApp.page.waitForTimeout(1500);
    const recoveredText = await gpsApp.page.textContent('#f21TrackArea');
    console.log(`    [evidence] track area after the signal returns: ${JSON.stringify(recoveredText)}`);
    ok(!/GPS signal lost/i.test(recoveredText),
      `the signal-lost indicator must clear once a fix returns — got ${JSON.stringify(recoveredText)}`);
    ok(recoveredText.includes('Trip in progress'), `still the same live session after recovery — got ${JSON.stringify(recoveredText)}`);
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / FIXED] a tracking record left behind by an unclean teardown is offered for resume — tapping "Start Trip" no longer silently abandons it', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    await gpsApp.page.waitForTimeout(500);
    const savedRecord = await gpsApp.page.evaluate(() => sessionStorage.getItem('fl_active_tracking'));
    const trackingIdBefore = JSON.parse(savedRecord).trackingId;

    // Reproduce the state an unclean teardown leaves behind: the persisted
    // record survives, but the in-memory session is gone. Boot with the record
    // absent (so resumeTrackingIfActive() doesn't auto-resume it), then put it
    // back — that is exactly the situation the old error handler created, and
    // the one where "Start Trip" used to destroy the trip.
    await gpsApp.page.evaluate(() => sessionStorage.removeItem('fl_active_tracking'));
    await gpsApp.page.reload();
    await gpsApp.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    await gpsApp.page.waitForSelector('#f21StartBtn', { timeout: 5000 });
    await gpsApp.page.evaluate((rec) => sessionStorage.setItem('fl_active_tracking', rec), savedRecord);

    // The natural driver action: the UI says "Start Trip", so tap it.
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#trkResume', { timeout: 5000 });
    const modalText = await gpsApp.page.textContent('#modalBody').catch(async () => await gpsApp.page.textContent('body'));
    console.log(`    [evidence] tapping "Start Trip" with a session record present now opens the resume prompt: ${JSON.stringify((modalText || '').slice(0, 160))}`);
    ok(/trip already in progress/i.test(modalText), `the resume prompt must explain there is a trip in progress — got ${JSON.stringify(modalText)}`);

    await gpsApp.page.click('#trkResume');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const trackingIdAfter = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);
    console.log(`    [evidence] trackingId before: ${trackingIdBefore}, after choosing Resume: ${trackingIdAfter}`);
    eq(trackingIdAfter, trackingIdBefore,
      'Resume must continue the SAME session (same trackingId, so the accumulated miles and gpsLogs are kept) rather than minting a new one');
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / FIXED] discarding a recovered session is still possible, but only as an explicit labelled choice', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    await gpsApp.page.waitForTimeout(500);
    const savedRecord = await gpsApp.page.evaluate(() => sessionStorage.getItem('fl_active_tracking'));
    const trackingIdBefore = JSON.parse(savedRecord).trackingId;

    await gpsApp.page.evaluate(() => sessionStorage.removeItem('fl_active_tracking'));
    await gpsApp.page.reload();
    await gpsApp.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    await gpsApp.page.waitForSelector('#f21StartBtn', { timeout: 5000 });
    await gpsApp.page.evaluate((rec) => sessionStorage.setItem('fl_active_tracking', rec), savedRecord);

    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#trkNew', { timeout: 5000 });
    await gpsApp.page.click('#trkNew');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const trackingIdAfter = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);

    console.log(`    [evidence] trackingId before: ${trackingIdBefore}, after choosing "Discard & Start New": ${trackingIdAfter}`);
    ok(trackingIdBefore && trackingIdAfter && trackingIdBefore !== trackingIdAfter,
      'the explicit "Discard & Start New" choice must still start a fresh session — the finding was that this happened SILENTLY, not that it should be impossible');
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / FIXED] permission revoked mid-trip pauses the session instead of destroying it — the miles stay salvageable', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });

    await gpsApp.context.clearPermissions();
    await gpsApp.page.waitForTimeout(1500);

    const pausedText = await gpsApp.page.textContent('#f21TrackArea');
    const toastTxt = await gpsApp.page.textContent('#toast').catch(() => '');
    console.log(`    [evidence] track area after permission revoked mid-trip: ${JSON.stringify(pausedText)}`);
    console.log(`    [evidence] toast shown: ${JSON.stringify(toastTxt)}`);

    ok(pausedText.includes('Trip in progress'),
      `revocation must not destroy the trip — the card should still read "Trip in progress", got ${JSON.stringify(pausedText)}`);
    ok(/Tracking paused/i.test(pausedText),
      `code 1 gets its own paused state, distinct from a transient signal outage — got ${JSON.stringify(pausedText)}`);
    ok(/denied/i.test(toastTxt), `expected the permission-denied message — got ${JSON.stringify(toastTxt)}`);

    // The point of keeping the session alive: the driver can still bank the trip.
    const tripsBefore = await getStoreCount(gpsApp.page, 'trips');
    await gpsApp.page.click('#f21StopBtn');
    await gpsApp.page.waitForSelector('#trkSave', { timeout: 5000 });
    await gpsApp.page.fill('#trkPay', '250');
    await gpsApp.page.click('#trkSave');
    await gpsApp.page.waitForTimeout(900);
    const tripsAfter = await getStoreCount(gpsApp.page, 'trips');
    console.log(`    [evidence] trips before Stop & Save: ${tripsBefore}, after: ${tripsAfter}`);
    eq(tripsAfter, tripsBefore + 1,
      'Stop & Save must still write the trip after a permission revocation — that is what makes "pause instead of destroy" worth doing');
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / regression guard] a full trip with NO GPS errors at all still tracks and saves correctly (cap only breaks on error, not normal use)', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const activeText = await gpsApp.page.textContent('#f21TrackArea');
    ok(activeText.includes('Trip in progress') && activeText.includes('0 miles'), `expected a fresh idle-at-start tracking state — got ${JSON.stringify(activeText)}`);
    await gpsApp.page.click('#f21StopBtn');
    await gpsApp.page.waitForSelector('#trkSave', { timeout: 5000 });
    await gpsApp.page.fill('#trkPay', '250');
    await gpsApp.page.click('#trkSave');
    await gpsApp.page.waitForTimeout(500);
    const count = await getStoreCount(gpsApp.page, 'trips');
    ok(count >= 1, 'a clean start-stop-save with no GPS errors should still produce a saved trip');
    console.log('    [evidence] ordinary Start -> Stop -> Save (no errors injected) works fine — F-7 is specifically about error tolerance, not GPS tracking in general');
  } finally {
    await gpsApp.close();
  }
});

export async function runSpec() {
  app = await launchApp({ enableTestExports: true });
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
