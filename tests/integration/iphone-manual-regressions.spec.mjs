// 2026-09-27 real-iPhone manual-test regressions.
//
// These regressions pin failures observed on the physical iPhone rather than
// reinterpreting them from synthetic state: evaluator booking opened a blank
// disabled Order #, imported "Unknown Destination" bled into a new trip,
// newly-created trips immediately looked delivered and prompted a lane review,
// the trip card's economic score read like an outcome ("PREMIUM WIN"), and an
// Undo message remained visible after its five-second window.
import { readFileSync } from 'node:fs';
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/iphone-manual-regressions.spec.mjs');
let app;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function closeModal() {
  await app.page.evaluate(() => window.__FL_TESTS.closeModal?.());
  await sleep(420);
}

test('[IPR-01] Evaluate → Book as Trip opens add mode with editable Order #', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    location.hash = '#omega';
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    set('mwOrigin', 'Chicago, IL');
    set('mwDest', 'Indianapolis, IN');
    set('mwLoadedMi', '300');
    set('mwDeadMi', '0');
    set('mwRevenue', '500');
    await T.mwEvaluateLoad();
  });
  await app.page.waitForSelector('#mwBookTrip', { state: 'visible', timeout: 10000 });
  await app.page.click('#mwBookTrip');
  await sleep(250);
  const r = await app.page.evaluate(() => ({
    title: document.getElementById('modalTitle')?.textContent || '',
    orderDisabled: document.getElementById('f_orderNo')?.disabled,
    order: document.getElementById('f_orderNo')?.value || '',
    pay: document.getElementById('f_pay')?.value || '',
    loaded: document.getElementById('f_loaded')?.value || '',
  }));
  ok(/Book Load|Add Trip/.test(r.title), `booking must open add/prefill mode — got ${r.title}`);
  eq(r.orderDisabled, false, 'Order # must be editable');
  eq(r.order, '', 'Order # starts blank so the operator can enter the real order');
  eq(r.pay, '500', 'evaluated pay is preserved');
  eq(r.loaded, '300', 'evaluated loaded miles are preserved');
  await closeModal();
});

test('[IPR-02] a placeholder Unknown Destination never auto-fills a new trip Origin', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.upsertTrip({
      orderNo: 'IPR-UNKNOWN-SOURCE', customer: 'Imported fixture',
      pay: 1200, loadedMiles: 500, emptyMiles: null,
      pickupDate: '2025-12-11', deliveryDate: '2025-12-11',
      origin: 'Unknown Origin', destination: 'Unknown Destination',
      created: Date.now() + 10000,
    });
    T.openTripWizard();
  });
  await sleep(450);
  const origin = await app.page.inputValue('#f_origin');
  eq(origin, '', 'placeholder import text is not a real reposition origin');
  await closeModal();
});

test('[IPR-03] a newly-created trip is Booked/Not started and does not trigger Lane Review', async () => {
  await app.page.evaluate(() => window.__FL_TESTS.openTripWizard());
  await sleep(250);
  await app.page.fill('#f_orderNo', 'IPR-BOOKED-001');
  await app.page.fill('#f_pay', '500');
  await app.page.fill('#f_loaded', '300');
  await app.page.fill('#f_empty', '0');
  await app.page.click('#toStep2');
  await sleep(200);
  const stage = await app.page.evaluate(() => ({
    exists: !!document.getElementById('f_execution'),
    value: document.getElementById('f_execution')?.value || '',
    paymentLabel: document.querySelector('label[for="f_paid"]')?.textContent || '',
  }));
  ok(stage.exists, 'Step 2 exposes an explicit trip stage');
  eq(stage.value, 'NOT_STARTED', 'new trips default to Booked / Not started');
  await app.page.fill('#f_customer', 'Test Customer');
  await app.page.fill('#f_origin', 'Chicago, IL');
  await app.page.fill('#f_dest', 'Indianapolis, IN');
  await app.page.click('#saveTrip2');
  await sleep(650);
  await app.page.evaluate(() => window.__FL_TESTS.closeModal?.());
  await sleep(900);
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const trip = (await T.dumpStore('trips')).find(t => t.orderNo === 'IPR-BOOKED-001');
    const lc = (await T.listLifecycle()).find(x => x.orderNo === 'IPR-BOOKED-001');
    return {
      tripStage: trip?.executionStatus || null,
      lifecycleExecution: lc?.execution || null,
      title: document.getElementById('modalTitle')?.textContent || '',
      modalOpen: document.getElementById('modal')?.classList.contains('open') || false,
    };
  });
  eq(r.tripStage, 'NOT_STARTED', 'saved trip keeps explicit booked state');
  eq(r.lifecycleExecution, 'NOT_STARTED', 'lifecycle does not infer delivered from an appointment date');
  ok(!(r.modalOpen && /Lane Review/i.test(r.title)), 'Lane Review must not fire at booking time');
  await closeModal();
});

test('[IPR-04] Trips card labels the historical economics number as a score, not a win outcome', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.computeKPIs();
    const trip = (await T.dumpStore('trips')).find(t => t.orderNo === 'IPR-BOOKED-001');
    const row = T.tripRow(trip);
    return (row.textContent || '').replace(/\s+/g, ' ').trim();
  });
  ok(/LOAD SCORE\s+\d+/i.test(r), `card should say LOAD SCORE — got ${r}`);
  ok(!/PREMIUM WIN\s+\d+/i.test(r), 'a booked trip must not visually claim an outcome named PREMIUM WIN');
});

test('[IPR-05] Share Bid has no cloud-backup token dependency', async () => {
  const src = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
  const start = src.indexOf('async function shareBidToClipboard');
  const end = src.indexOf('\nfunction ', start + 1);
  const block = src.slice(start, end > start ? end : start + 3000);
  ok(start >= 0, 'shareBidToClipboard exists');
  ok(!block.includes('cloudBackupToken'), 'Share Bid must remain local/native-share and independent of cloud backup credentials');
});

test('[IPR-06] deleting the last expense renders empty state immediately and Undo fully disappears after timeout', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.addExpense({ date: T.isoDate(), amount: 10, category: 'Tolls', notes: 'IPR undo test' });
    location.hash = '#expenses';
  });
  await app.page.waitForSelector('#expenseList .item', { timeout: 10000 });
  await app.page.click('#expenseList [data-act="del"]');
  await sleep(200);
  const immediate = await app.page.evaluate(() => ({
    list: document.getElementById('expenseList')?.textContent || '',
    undo: document.getElementById('undoToast')?.textContent || '',
  }));
  ok(/No expenses yet/i.test(immediate.list), 'last-row delete should render the empty state during the Undo window');
  ok(/Tolls deleted/i.test(immediate.undo), 'Undo affordance is visible during its window');
  await sleep(5300);
  const after = await app.page.evaluate(() => ({
    text: document.getElementById('undoToast')?.textContent?.trim() || '',
    display: getComputedStyle(document.getElementById('undoToast')).display,
  }));
  eq(after.text, '', 'expired Undo content is removed, not left as stale page text');
  eq(after.display, 'none', 'expired Undo container is hidden');
});


test('[IPR-07] booked loads are not lane history and one completed run cannot claim Stable', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return T.computeLaneStats([
      {
        orderNo: 'IPR-LANE-1', origin: 'Chicago, IL', destination: 'Indianapolis, IN',
        pay: 500, loadedMiles: 300, emptyMiles: 0, pickupDate: '2026-09-20',
        deliveryDate: '2026-09-20', executionStatus: 'DELIVERED',
        needsReview: false, wouldRunAgain: null,
      },
      {
        orderNo: 'IPR-LANE-BOOKED', origin: 'Chicago, IL', destination: 'Indianapolis, IN',
        pay: 600, loadedMiles: 300, emptyMiles: 0, pickupDate: '2026-09-27',
        deliveryDate: '2026-09-28', executionStatus: 'NOT_STARTED',
        needsReview: false, wouldRunAgain: null,
      },
    ])[0];
  });
  eq(r.trips, 1, 'booked load is excluded from historical lane runs');
  eq(r.trendLabel, 'Need more history', 'one completed run cannot establish a stable trend');
});

test('[IPR-08] deleting the last fuel entry also renders its empty state immediately', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.addFuel({ date: T.isoDate(), gallons: 10, amount: 40, state: 'TN', notes: 'IPR fuel undo' });
    location.hash = '#fuel';
  });
  await app.page.waitForSelector('#fuelList .item', { timeout: 10000 });
  await app.page.click('#fuelList [data-act="del"]');
  await sleep(200);
  const immediate = await app.page.evaluate(() => ({
    list: document.getElementById('fuelList')?.textContent || '',
    undo: document.getElementById('undoToast')?.textContent || '',
  }));
  ok(/No fuel entries yet/i.test(immediate.list), 'last fuel delete shows the normal empty state during Undo');
  ok(/Fuel .* deleted/i.test(immediate.undo), 'fuel Undo affordance is visible during its window');
  await sleep(5300);
  const after = await app.page.evaluate(() => ({
    text: document.getElementById('undoToast')?.textContent?.trim() || '',
    display: getComputedStyle(document.getElementById('undoToast')).display,
  }));
  eq(after.text, '', 'fuel Undo content expires cleanly');
  eq(after.display, 'none', 'fuel Undo container is hidden after expiry');
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
