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
// F-8 (Critical) was discovered here — while building the offline
// expense-entry scenario above — and is now FIXED. Its regression coverage
// lives in tests/integration/expense-fuel-write.spec.mjs, which asserts the
// corrected behavior directly (new expense and fuel records save through the
// real UI, add() and put() both accept a sanitized new record, and recurring
// string ids survive). The two tests that used to sit here documented the
// broken behavior instead, so they were removed rather than left asserting a
// bug that no longer exists.
//
// What remains verified HERE is the offline half that F-8 was found inside:
// the offline trip write above, and the reconnect check that follows it.
// ============================================================

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

test('[FINDING F-7 / NEW, High] a single transient GPS error kills the live tab\'s tracking UI; recovery only exists via an undocumented reload, and the visible "Start Trip" affordance instead creates a fresh session that abandons the old miles', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const activeText = await gpsApp.page.textContent('#f21TrackArea');
    ok(activeText.includes('Trip in progress'), `tracking should be active after Start — got ${JSON.stringify(activeText)}`);

    const trackingIdBefore = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);
    ok(trackingIdBefore, 'sanity: an active session should be persisted to sessionStorage');

    // Any ordinary position update (the driver's GPS coordinate simply
    // changing, which happens continuously while driving) is what triggers
    // this in Chromium's geolocation provider — a ONE-EVENT transient
    // PositionError (code 2, POSITION_UNAVAILABLE) fires immediately before
    // the updated fix is delivered. This mirrors a real, ordinary driving
    // scenario: a tunnel, a parking garage, an urban canyon, or a brief
    // GPS/cell handoff can all produce exactly this kind of single transient
    // "position unavailable" blink without any real loss of GPS signal.
    await gpsApp.context.setGeolocation({ latitude: 41.8790, longitude: -87.6300, accuracy: 10 });
    await gpsApp.page.waitForTimeout(1500);

    const idleText = await gpsApp.page.textContent('#f21TrackArea');
    const toastTxt = await gpsApp.page.textContent('#toast').catch(() => '');
    // app.js:14871-14880's error handler nulls _activeTracking and re-renders
    // idle, but never calls sessionStorage.removeItem('fl_active_tracking')
    // (only stopTripTracking() does that) — so the stale resume record is
    // still sitting there, unbeknownst to the live tab's own UI.
    const staleRecord = await gpsApp.page.evaluate(() => sessionStorage.getItem('fl_active_tracking'));
    console.log(`    [evidence] track area after ONE transient GPS error: ${JSON.stringify(idleText)}`);
    console.log(`    [evidence] toast shown: ${JSON.stringify(toastTxt)}`);
    console.log(`    [evidence] sessionStorage record survives the crash (app.js's error handler never clears it): ${JSON.stringify(staleRecord)}`);

    ok(idleText.includes('Start Trip'),
      'CONFIRMED BUG: a single transient location error tears down the LIVE tab\'s tracking UI back to idle "Start Trip" — ' +
      `no in-tab retry or grace window before abandoning an in-progress trip. Got: ${JSON.stringify(idleText)}`);
    ok(/couldn.?t get your location|location.*denied|location timed out/i.test(toastTxt),
      `a toast IS shown — got ${JSON.stringify(toastTxt)}`);

    // Reload IS a working recovery path (resumeTrackingIfActive(), app.js:15007,
    // reads the still-present sessionStorage record on boot and re-arms
    // watchPosition with the old trackingId + accumulated totalMiles intact).
    await gpsApp.page.reload();
    await gpsApp.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
    await gpsApp.page.waitForTimeout(500);
    const afterReloadText = await gpsApp.page.textContent('#f21TrackArea');
    const resumeToast = await gpsApp.page.textContent('#toast').catch(() => '');
    console.log(`    [evidence] track area after reloading the tab: ${JSON.stringify(afterReloadText)}`);
    console.log(`    [evidence] toast on reload: ${JSON.stringify(resumeToast)}`);
    ok(afterReloadText.includes('Trip in progress'),
      `a page reload DOES recover the session via resumeTrackingIfActive() — got ${JSON.stringify(afterReloadText)}. ` +
      'This is the actual bug: recovery exists, but nothing in the crashed tab\'s own UI tells the driver reloading would help.');
    eq(resumeToast, 'Trip tracking resumed.', 'expected the resumeTrackingIfActive() toast confirming the SAME session (same trackingId/miles) came back');
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / NEW, High] the ONLY visible affordance after the crash ("Start Trip") does not use the reload recovery path — it silently starts a brand-new session, abandoning the old one\'s accumulated miles for good', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    const trackingIdBefore = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);

    await gpsApp.context.setGeolocation({ latitude: 41.8790, longitude: -87.6300, accuracy: 10 });
    await gpsApp.page.waitForTimeout(2500);
    await gpsApp.page.waitForSelector('#f21StartBtn', { timeout: 5000 }); // back to idle
    // Confirm the crash genuinely settled (not a transient mid-flicker read)
    // before treating the next tap as "the driver's post-crash action" —
    // this specific event's timing can otherwise land right on the
    // ERR-then-OK boundary and read a stale DOM snapshot.
    const idleTextConfirm = await gpsApp.page.textContent('#f21TrackArea');
    ok(idleTextConfirm.includes('Start Trip'), `expected idle state to have settled before proceeding — got ${JSON.stringify(idleTextConfirm)}`);

    // The natural driver action: the UI says "Start Trip", so tap it again.
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });
    // _persistTrackingState() (which overwrites sessionStorage with the NEW
    // trackingId) only runs from inside a watchPosition success callback or
    // the 30s interval tick — NOT synchronously when Start Trip is tapped —
    // so sessionStorage can still read the OLD (crashed) trackingId for a
    // moment even though _activeTracking in memory is already a fresh
    // object. Give a real position event time to land and persist before
    // reading it, or this assertion racy-false-passes on a stale value.
    await gpsApp.page.waitForTimeout(1500);
    const trackingIdAfter = await gpsApp.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_active_tracking') || '{}').trackingId);

    console.log(`    [evidence] trackingId before crash: ${trackingIdBefore}, trackingId after tapping "Start Trip" again: ${trackingIdAfter}`);
    ok(trackingIdBefore && trackingIdAfter && trackingIdBefore !== trackingIdAfter,
      'CONFIRMED: tapping the visible "Start Trip" button after a crash creates a BRAND NEW trackingId/session (startTripTracking() only checks `if (_activeTracking) return`, which is false since the crash nulled it) — ' +
      'the old session\'s gpsLogs/accumulated miles are orphaned, not resumed. The only way to actually get them back is the undiscoverable "reload the page" path proven in the previous test.');
  } finally {
    await gpsApp.close();
  }
});

test('[FINDING F-7 / NEW] permission revoked mid-trip hits the identical no-tolerance teardown path as a transient GPS blip', async () => {
  const gpsApp = await launchGpsApp();
  try {
    await gpsApp.page.click('#f21StartBtn');
    await gpsApp.page.waitForSelector('#f21StopBtn', { timeout: 5000 });

    await gpsApp.context.clearPermissions();
    await gpsApp.page.waitForTimeout(1500);

    const idleText = await gpsApp.page.textContent('#f21TrackArea');
    const toastTxt = await gpsApp.page.textContent('#toast').catch(() => '');
    console.log(`    [evidence] track area after permission revoked mid-trip: ${JSON.stringify(idleText)}`);
    console.log(`    [evidence] toast shown: ${JSON.stringify(toastTxt)}`);

    ok(idleText.includes('Start Trip'), `permission revocation should also tear the session down (same err handler, code 1) — got ${JSON.stringify(idleText)}`);
    ok(/denied/i.test(toastTxt), `expected the permission-denied message — got ${JSON.stringify(toastTxt)}`);
    console.log('    [evidence] same root cause as the transient-blip case above: app.js:14871-14880 treats every PositionError code (1/2/3) identically — one event, total session loss, no distinction between "user revoked forever" and "signal blipped for a second"');
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
