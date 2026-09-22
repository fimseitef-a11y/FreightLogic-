// Issue #304 — trip delete must become non-actionable immediately during the Undo window.
//
// Physical iPhone evidence (2026-09-19): Edit Trip -> Delete returned to Trips,
// but the target card remained visible for roughly 3-5 seconds. The storage delete
// is intentionally deferred five seconds by showUndoToast(), so the modal path
// looked like it failed and could be attempted again. Swipe-delete already removed
// its row immediately; the modal path did not.
//
// The historical missing order 960760 is NOT attributed to this mechanism here.
// The regression proves exact stable-id deletion and neighboring-record survival.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/trip-delete-safety.spec.mjs');
let app;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const TARGET = 'TDS-304-TARGET';
const NEIGHBOR = 'TDS-304-NEIGHBOR';

async function seedTrips(page) {
  await page.evaluate(async ({ target, neighbor }) => {
    const T = window.__FL_TESTS;
    const now = Date.now();
    await T.upsertTrip({
      id: 'tds304-target-id', orderNo: target, customer: 'Delete Safety Target',
      pay: 650, loadedMiles: 420, emptyMiles: 0,
      pickupDate: '2026-09-21', deliveryDate: '2026-09-22',
      origin: 'Wytheville, VA', destination: 'Columbus, OH',
      paymentStatusKnown: true, isPaid: false, created: now,
    });
    await T.upsertTrip({
      id: 'tds304-neighbor-id', orderNo: neighbor, customer: 'Neighbor Must Survive',
      pay: 700, loadedMiles: 430, emptyMiles: 0,
      pickupDate: '2026-09-21', deliveryDate: '2026-09-22',
      origin: 'Wytheville, VA', destination: 'Indianapolis, IN',
      paymentStatusKnown: true, isPaid: false, created: now - 1,
    });
    T.invalidateKPICache();
  }, { target: TARGET, neighbor: NEIGHBOR });
}

async function goTrips(page) {
  await page.evaluate(() => { location.hash = '#trips'; });
  await page.waitForSelector('.fl-trip-full', { timeout: 10000 });
  await sleep(250);
}
async function visibleOrders(page) {
  return page.$$eval('.fl-trip-full', rows =>
    rows.map(r => (r.textContent || '').replace(/\s+/g, ' ').trim()));
}
async function clickEditDelete(page, orderNo) {
  const clicked = await page.evaluate((orderNo) => {
    const row = [...document.querySelectorAll('.fl-trip-full')]
      .find(r => (r.textContent || '').includes(orderNo));
    if (!row) return false;
    row.querySelector('[data-act="edit"]')?.click();
    return true;
  }, orderNo);
  ok(clicked, `expected rendered row for ${orderNo}`);
  await page.waitForSelector('#delTrip', { state: 'visible', timeout: 10000 });
  await page.click('#delTrip');
  await sleep(150);
}
async function storedOrders(page) {
  return page.evaluate(async () =>
    (await window.__FL_TESTS.dumpStore('trips')).map(t => t.orderNo));
}

test('[TDS-01] Edit Trip delete suppresses the target immediately and across re-render, then Undo restores it', async () => {
  await goTrips(app.page);
  await clickEditDelete(app.page, TARGET);
  const immediate = await visibleOrders(app.page);
  const repeatAffordanceVisible = immediate.some(t => t.includes(TARGET));

  await app.page.evaluate(() => { location.hash = '#home'; });
  await sleep(180);
  await app.page.evaluate(() => { location.hash = '#trips'; });
  await sleep(350);
  const afterRerender = await visibleOrders(app.page);

  await app.page.click('#undoToast .undo-btn');
  await sleep(450);
  const afterUndo = await visibleOrders(app.page);
  const storedAfterUndo = await storedOrders(app.page);

  console.log('    [evidence] immediate=' + JSON.stringify(immediate));
  console.log('    [evidence] afterRerender=' + JSON.stringify(afterRerender));
  console.log('    [evidence] afterUndo=' + JSON.stringify(afterUndo));

  eq(repeatAffordanceVisible, false,
    'the target must be non-actionable immediately; a visible row invites a repeated delete');
  eq(afterRerender.some(t => t.includes(TARGET)), false,
    'a route/list re-render inside the Undo window must not resurrect the pending target');
  ok(immediate.some(t => t.includes(NEIGHBOR)) && afterRerender.some(t => t.includes(NEIGHBOR)),
    'the neighboring trip must remain visible while only the target is pending');
  ok(afterUndo.some(t => t.includes(TARGET)) && afterUndo.some(t => t.includes(NEIGHBOR)),
    'Undo must restore the target without disturbing its neighbor');
  ok(storedAfterUndo.includes(TARGET) && storedAfterUndo.includes(NEIGHBOR),
    'Undo must leave both stable records persisted');
});

test('[TDS-02] committed delete removes only the exact stable-id target and the neighbor survives', async () => {
  await clickEditDelete(app.page, TARGET);
  const immediate = await visibleOrders(app.page);
  await sleep(5300);
  const stored = await storedOrders(app.page);
  const rendered = await visibleOrders(app.page);

  console.log('    [evidence] commit immediate=' + JSON.stringify(immediate));
  console.log('    [evidence] stored after commit=' + JSON.stringify(stored));

  eq(immediate.some(t => t.includes(TARGET)), false,
    'the committed path must suppress the target immediately, before IndexedDB commit');
  eq(stored.includes(TARGET), false, 'the exact target stable record must be deleted after the Undo window');
  eq(stored.includes(NEIGHBOR), true, 'a neighboring trip must survive the target deletion');
  eq(rendered.some(t => t.includes(TARGET)), false, 'the committed target must stay absent from Trips');
  eq(rendered.some(t => t.includes(NEIGHBOR)), true, 'the neighboring trip must stay rendered');
});

export async function runSpec() {
  app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    await sleep(1600);
    await seedTrips(app.page);
    return await run();
  } finally {
    await app?.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
