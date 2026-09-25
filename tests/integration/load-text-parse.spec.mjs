// v24.0.39 — Load Intake text parse, reported from a real iPhone 2026-09-25.
//
// The operator pasted a DispatchLand load (OCR'd elsewhere) into Load Intake
// and Parse Load produced: origin "Load, ID" (the "Load ID:" label read as a
// city in Idaho), deadhead 380 (the loaded miles, because "380⏎Empty Miles"
// matched "<number> empty" across the line break), and no order number
// ("Load ID:" was not a recognised label). These drive the real parser the
// sheet calls and assert the fields the review step shows.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/load-text-parse.spec.mjs');
let app;
const parse = (text) => app.page.evaluate((t) => window.__FL_TESTS.parseLoadTextForInbox(t), text);

// The block from the operator's screenshot, with the pickup lines above it.
const DISPATCHLAND = [
  'Load ID: 1214704',
  'Pickup: Mobile, AL, 36602, US',
  'Pickup Time: 09/24 at 03:00 PM CDT (today)',
  'Pickup #1',
  '',
  'Delivery: Pascagoula, MS, 39581, US',
  'Delivery Time: 09/25 APPT at 08:00 AM CDT (tomorrow)',
  'Delivery #1',
  '',
  'Loaded Miles: 380',
  'Empty Miles: 44',
  'Weight: 550 lbs',
].join('\n');

test('[LTP-01] a DispatchLand block parses origin, destination, miles, deadhead, weight and load id', async () => {
  const r = await parse(DISPATCHLAND);
  console.log(`    [evidence] ${JSON.stringify({ o: r.origin, d: r.destination, lm: r.loadedMiles, dh: r.emptyMiles, w: r.weight, id: r.orderNo })}`);
  eq(r.origin, 'Mobile, AL', 'origin comes from the Pickup line, never from "Load ID:"');
  eq(r.destination, 'Pascagoula, MS', 'destination comes from the Delivery line');
  eq(r.loadedMiles, 380, 'loaded miles');
  eq(r.emptyMiles, 44, 'deadhead is the Empty Miles figure, not the loaded miles on the line above');
  eq(r.weight, 550, 'weight');
  eq(r.orderNo, '1214704', '"Load ID:" is the order number');
});

test('[LTP-02] "Load ID" is never read as a city in Idaho, even with no Pickup line', async () => {
  const r = await parse(['Load ID: 1214704', 'Delivery: Pascagoula, MS, 39581, US', 'Loaded Miles: 380'].join('\n'));
  ok(!/Load/i.test(r.origin), `origin must not be built from the Load ID label — got ${JSON.stringify(r.origin)}`);
  eq(r.destination, 'Pascagoula, MS', 'destination still parses');
});

test('[LTP-03] no deadhead in the text stays UNKNOWN; an explicit 0 stays 0', async () => {
  const none = await parse(['Pickup: Mobile, AL', 'Delivery: Pascagoula, MS', 'Loaded Miles: 380'].join('\n'));
  eq(none.emptyMiles, null, 'an unstated deadhead is unknown, not 380 and not 0');
  const zero = await parse(['Pickup: Mobile, AL', 'Delivery: Pascagoula, MS', 'Loaded Miles: 380', 'Empty Miles: 0'].join('\n'));
  eq(zero.emptyMiles, 0, 'an explicit zero is a verified zero');
});

test('[LTP-04] a labelled rate is revenue; a per-mile rate is not', async () => {
  const flat = await parse(DISPATCHLAND + '\nRate: $650');
  eq(flat.pay, 650, 'Rate: $650 is the revenue');
  const perMile = await parse(DISPATCHLAND + '\nRate: $1.71/mi');
  ok(perMile.pay !== 1.71, 'a per-mile figure must never become the load revenue');
});

test('[LTP-05] the review sheet shows the parsed fields after Parse Load', async () => {
  const r = await app.page.evaluate(async (text) => {
    window.__FL_TESTS.openLoadIntake();
    await new Promise(res => setTimeout(res, 250));
    document.getElementById('liRawText').value = text;
    document.getElementById('liParse').click();
    await new Promise(res => setTimeout(res, 250));
    const v = (id) => document.getElementById(id)?.value;
    const out = { origin: v('liOrigin'), dest: v('liDest'), miles: v('liMiles'), dead: v('liDead'), order: v('liOrderNo'), weight: v('liWeight') };
    window.__FL_TESTS.closeModal?.();
    return out;
  }, DISPATCHLAND);
  eq(r.origin, 'Mobile, AL', 'review origin');
  eq(r.dest, 'Pascagoula, MS', 'review destination');
  eq(r.miles, '380', 'review loaded miles');
  eq(r.dead, '44', 'review deadhead');
  eq(r.order, '1214704', 'review order number');
  eq(r.weight, '550', 'review weight');
});

export async function runSpec() {
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
