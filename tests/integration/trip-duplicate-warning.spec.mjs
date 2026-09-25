// v24.0.42 — saving a trip whose order # is already saved.
//
// The operator asked (2026-09-25) that re-sending screenshots never leaves a
// pile of duplicate trips. A relay item never saves anything; the trip form
// does. It was meant to warn on a repeated order #, but the warning was written
// and then overwritten by "Looks good." on the next line, so a second save of
// the same load went through silently. The form now stops once, shows the saved
// trip, and offers Open existing / Save anyway. It warns and never merges,
// because different brokers can reuse an order number.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/trip-duplicate-warning.spec.mjs');
let app;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function tripsWith(orderNo) {
  return app.page.evaluate(async (o) =>
    (await window.__FL_TESTS.dumpStore('trips')).filter((t) => t.orderNo === o).length, orderNo);
}

async function openNewTrip(orderNo, pay) {
  await app.page.evaluate(() => { window.__FL_TESTS.closeModal?.(); window.__FL_TESTS.openTripWizard(); });
  await sleep(300);
  await app.page.fill('#f_orderNo', orderNo);
  await app.page.fill('#f_pay', String(pay));
}

test('[TDW-01] saving an order # that is already saved stops and shows the saved trip', async () => {
  await app.page.evaluate(async () => {
    const t = window.__FL_TESTS.sanitizeTrip({ orderNo: 'DUP-1214704', pay: 650, loadedMiles: 380, emptyMiles: 44,
      pickupDate: '2026-09-24', deliveryDate: '2026-09-25', origin: 'Mobile, AL', destination: 'Pascagoula, MS' });
    await window.__FL_TESTS.upsertTrip(t);
  });
  eq(await tripsWith('DUP-1214704'), 1, 'precondition: one saved trip');
  await openNewTrip('DUP-1214704', 650);
  await app.page.click('#saveTrip');
  await sleep(600);
  const warn = await app.page.evaluate(() => {
    const w = document.getElementById('tripDupWarn');
    return w && w.offsetParent ? w.textContent.replace(/\s+/g, ' ') : '';
  });
  console.log(`    [evidence] ${JSON.stringify(warn.slice(0, 160))}`);
  ok(/already saved/i.test(warn), 'a visible warning says the order # is already saved');
  ok(/Mobile, AL → Pascagoula, MS/.test(warn), 'and shows the saved trip\'s route');
  eq(await tripsWith('DUP-1214704'), 1, 'nothing was saved');
});

test('[TDW-02] Save anyway saves it as a separate load', async () => {
  await app.page.click('#tripDupSave');
  await app.page.click('#saveTrip');
  await sleep(900);
  eq(await tripsWith('DUP-1214704'), 2, 'the second trip is saved only after Save anyway');
});

test('[TDW-03] Open existing opens the saved trip instead of adding one', async () => {
  await openNewTrip('DUP-1214704', 650);
  await app.page.click('#saveTrip');
  await sleep(600);
  await app.page.click('[data-dup-open="0"]');
  await sleep(500);
  const r = await app.page.evaluate(() => ({
    order: document.getElementById('f_orderNo')?.value,
    locked: document.getElementById('f_orderNo')?.disabled,
  }));
  eq(r.order, 'DUP-1214704', 'the saved trip is open');
  eq(r.locked, true, 'in edit mode, not as a new trip');
  eq(await tripsWith('DUP-1214704'), 2, 'nothing new was saved');
});

test('[TDW-04] a new order # saves with no warning', async () => {
  await openNewTrip('FRESH-777001', 500);
  await app.page.click('#saveTrip');
  await sleep(900);
  eq(await tripsWith('FRESH-777001'), 1, 'saved straight away');
});

export async function runSpec() {
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
