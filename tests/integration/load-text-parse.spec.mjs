// v24.0.39 — Load Intake text parse, reported from a real iPhone 2026-09-25.
//
// The operator pasted a DispatchLand load (OCR'd elsewhere) into Load Intake
// and Parse Load produced: origin "Load, ID" (the "Load ID:" label read as a
// city in Idaho), deadhead 380 (the loaded miles, because "380⏎Empty Miles"
// matched "<number> empty" across the line break), and no order number
// ("Load ID:" was not a recognised label). These drive the real parser the
// sheet calls and assert the fields the review step shows.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

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

// v24.0.41 — "I want route and details pulled also if available." Times,
// timezone, pieces, dimensions and commodity were never read from text, and the
// review sheet had nowhere to show them even when a screenshot read them.
const DETAILED = DISPATCHLAND + '\n' + [
  'Pieces: 2',
  'Dimensions: 48x40x36 in',
  'Commodity: Auto parts',
  'Notes: Liftgate not required',
].join('\n');

test('[LTP-06] pickup/delivery date, time and timezone come from their labelled lines', async () => {
  const r = await parse(DETAILED);
  const yr = new Date().getFullYear();
  console.log(`    [evidence] ${JSON.stringify({ pd: r.pickupDate, pt: r.pickupTime, dd: r.deliveryDate, dt: r.deliveryTime, tz: r.timezone })}`);
  ok([`${yr}-09-24`, `${yr + 1}-09-24`].includes(r.pickupDate), `pickup date from "Pickup Time: 09/24" — got ${r.pickupDate}`);
  eq(r.pickupTime, '15:00', '03:00 PM is 15:00');
  ok([`${yr}-09-25`, `${yr + 1}-09-25`].includes(r.deliveryDate), `delivery date from "Delivery Time: 09/25" — got ${r.deliveryDate}`);
  eq(r.deliveryTime, '08:00', 'delivery appointment time');
  eq(r.timezone, 'CDT', 'timezone');
});

test('[LTP-07] pieces, dimensions, commodity and notes are read', async () => {
  const r = await parse(DETAILED);
  eq(r.pieces, 2, 'pieces');
  eq(r.dimensions, '48x40x36 in', 'dimensions');
  eq(r.commodity, 'Auto parts', 'commodity');
  eq(r.notes, 'Liftgate not required', 'notes');
});

test('[LTP-08] the review sheet shows the route and every detail after Parse Load', async () => {
  const r = await app.page.evaluate(async (text) => {
    window.__FL_TESTS.openLoadIntake();
    await new Promise(res => setTimeout(res, 250));
    document.getElementById('liRawText').value = text;
    document.getElementById('liParse').click();
    await new Promise(res => setTimeout(res, 250));
    const v = (id) => document.getElementById(id)?.value;
    const out = {
      route: (document.getElementById('liRoute')?.textContent || '').replace(/\s+/g, ' '),
      puTime: v('liPuTime'), delTime: v('liDelTime'), puDate: v('liPuDate'), delDate: v('liDelDate'),
      pieces: v('liPieces'), dims: v('liDims'), commodity: v('liCommodity'), notes: v('liNotes'),
    };
    window.__FL_TESTS.closeModal?.();
    return out;
  }, DETAILED);
  console.log(`    [evidence] route=${JSON.stringify(r.route)}`);
  ok(/Mobile, AL/.test(r.route) && /Pascagoula, MS/.test(r.route), 'the route line names both ends');
  ok(/380/.test(r.route) && /44/.test(r.route) && /424/.test(r.route), 'and the loaded, deadhead and total miles');
  eq(r.puTime, '15:00', 'pickup time field');
  eq(r.delTime, '08:00', 'delivery time field');
  ok(/-09-24$/.test(r.puDate || ''), 'pickup date field');
  ok(/-09-25$/.test(r.delDate || ''), 'delivery date field');
  eq(r.pieces, '2', 'pieces field');
  eq(r.dims, '48x40x36 in', 'dimensions field');
  eq(r.commodity, 'Auto parts', 'commodity field');
  eq(r.notes, 'Liftgate not required', 'notes field');
});

test('[LTP-09] Score This Load carries dimensions and the pickup time into the evaluator', async () => {
  const r = await app.page.evaluate(async (text) => {
    window.__FL_TESTS.openLoadIntake();
    await new Promise(res => setTimeout(res, 250));
    document.getElementById('liRawText').value = text;
    document.getElementById('liParse').click();
    await new Promise(res => setTimeout(res, 250));
    document.getElementById('liScore').click();
    await new Promise(res => setTimeout(res, 1500));
    const v = (id) => document.getElementById(id)?.value;
    return { len: v('mwLoadLengthIn'), wid: v('mwLoadWidthIn'), hgt: v('mwLoadHeightIn'), wt: v('mwLoadWeightLbs'), cutoff: v('mwPickupCutoff') };
  }, DETAILED);
  eq(r.len, '48', 'length'); eq(r.wid, '40', 'width'); eq(r.hgt, '36', 'height');
  eq(r.wt, '550', 'weight');
  ok(/-09-24T15:00$/.test(r.cutoff || ''), `pickup time reaches the pickup check — got ${r.cutoff}`);
});

// docs/DISPATCHLAND_SAMPLES.md is the sanitized corpus of real operator
// DispatchLand posts. It is read from disk rather than copied here, so a row
// added to the corpus is tested without an edit to this file. UNKNOWN cells
// produce no labelled line, and the parser must then leave that field unset.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const CORPUS_MD = readFileSync(fileURLToPath(new URL('../../docs/DISPATCHLAND_SAMPLES.md', import.meta.url)), 'utf8');
const corpusRows = () => CORPUS_MD.split('\n')
  .filter(l => /^\|\s*\d{5,}\s*\|/.test(l))
  .map(l => l.split('|').slice(1, -1).map(c => c.trim()))
  .map(([id, pickup, puTime, delivery, delTime, loaded, empty, weight, pieces, , expO, expD]) =>
    ({ id, pickup, puTime, delivery, delTime, loaded, empty, weight, pieces, expO, expD }));
const known = (v) => v && !/^UNKNOWN$/i.test(v);
const labelled = (r) => [
  `Load ID: ${r.id}`,
  `Pickup: ${r.pickup}`,
  known(r.puTime) && `Pickup Time: ${r.puTime}`,
  `Delivery: ${r.delivery}`,
  known(r.delTime) && `Delivery Time: ${r.delTime}`,
  known(r.loaded) && `Loaded Miles: ${r.loaded}`,
  known(r.empty) && `Empty Miles: ${r.empty}`,
  known(r.weight) && `Weight: ${r.weight}`,
  known(r.pieces) && `Pieces: ${r.pieces}`,
].filter(Boolean).join('\n');

test('[LTP-10] every DispatchLand corpus row parses to its expected route, miles, weight and load id', async () => {
  const rows = corpusRows();
  ok(rows.length >= 10, `corpus rows found — got ${rows.length}`);
  const bad = [];
  for (const r of rows){
    const p = await parse(labelled(r));
    const want = {
      orderNo: r.id, origin: r.expO, destination: r.expD,
      loadedMiles: Number(r.loaded), emptyMiles: Number(r.empty), weight: parseInt(r.weight, 10),
    };
    for (const [k, v] of Object.entries(want)) if (p[k] !== v) bad.push(`${r.id} ${k}: want ${JSON.stringify(v)} got ${JSON.stringify(p[k])}`);
  }
  eq(bad.length, 0, `corpus mismatches:\n      ${bad.join('\n      ')}`);
});

test('[LTP-11] corpus: pieces are read when shown and stay unset when UNKNOWN; loaded miles never become deadhead', async () => {
  const bad = [];
  for (const r of corpusRows()){
    const f = await parse(labelled(r));
    if (known(r.pieces) ? f.pieces !== Number(r.pieces) : !!f.pieces) bad.push(`${r.id} pieces: want ${known(r.pieces) ? r.pieces : 'unset'} got ${f.pieces}`);
    if (f.emptyMiles === f.loadedMiles) bad.push(`${r.id} deadhead equals loaded miles (${f.loadedMiles})`);
  }
  const noEmpty = await parse(labelled({ ...corpusRows()[2], empty: 'UNKNOWN' }));
  if (noEmpty.emptyMiles !== null) bad.push(`missing Empty Miles must stay UNKNOWN — got ${noEmpty.emptyMiles}`);
  eq(bad.length, 0, `corpus mismatches:\n      ${bad.join('\n      ')}`);
});

test('[LTP-12] corpus: identical routes keep their distinct load ids', async () => {
  const [a, b] = await Promise.all(['1201521', '1201423'].map(id => parse(labelled(corpusRows().find(r => r.id === id)))));
  eq(a.orderNo, '1201521', 'first posting id'); eq(b.orderNo, '1201423', 'second posting id');
  eq(a.origin, b.origin, 'same route origin'); eq(a.destination, b.destination, 'same route destination');
});

export async function runSpec() {
  app = await launchApp();
  // The first-run setup wizard opens ~800ms after boot and would replace the
  // Load Intake sheet LTP-05 drives.
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
