// Next Move S2 (v24.0.37) — deriveNextMove(), the one owner of the Today
// card's directive. docs/NEXT_MOVE_LAYER_SPEC.md §1–5 and §7.
//
// Before this slice the brief itself issued HOLD / REPOSITION / HUNT. "HUNT —
// Unknown market. No history yet — watch boards." was a directive built from
// missing data, a two-record reload average could direct the driver, an
// ambiguous position rendered nothing, and nothing said what evidence would
// unlock a real answer.
//
// NM2-01..07 drive the real deriveNextMove() with hand-built briefs, because
// the rules are about sample sizes and verdicts, and a brief is the input
// contract. NM2-08 renders the real Today card end to end.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/next-move-s2.spec.mjs');
let app;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const derive = (brief, position, decision) =>
  app.page.evaluate(([b, p, d]) => window.__FL_TESTS.deriveNextMove(b, p, d), [brief, position, decision]);

const brief = (o = {}) => ({
  city: 'Testville, ZZ', market: null, reloadScore: null, outboundLanes: [], nearbyMarkets: [],
  weatherAlerts: [], patterns: { totalTrips: 0 }, confidence: 'LOW', ...o,
});
const here = { known: true, ambiguous: false, city: 'Testville, ZZ' };
const anchor = { city: 'columbus', displayName: 'Columbus', role: 'anchor', zone: 'MIDWEST', distanceMi: 90 };
const reload = (grade, count, avg) => ({ grade, count, avg, label: { A: 'Hot market', B: 'Good reload', C: 'Slow reload', D: 'Dead zone' }[grade] });
const decision = (verdict, factsComplete = true) => ({ factsComplete, authority: { verdict, grade: 'B' }, confidence: { overall: 'MEDIUM' } });

test('[NM2-01] no evidence is UNKNOWN and names what is missing, never HUNT', async () => {
  const nm = await derive(brief(), here, null);
  eq(nm.move, 'UNKNOWN', 'an unrecognised market with no history cannot be directed');
  ok(nm.missing.length >= 2, 'UNKNOWN must name what would unlock a move');
  ok(nm.missing.some(m => /reload outcomes/.test(m)) && nm.missing.some(m => /outbound trips/.test(m)),
    'it names reload outcomes and outbound trips');
  ok(!/HUNT|watch boards/i.test(nm.reason), 'the retired HUNT wording must not come back');
});

test('[NM2-02] an ambiguous position is UNKNOWN even with strong evidence', async () => {
  const nm = await derive(brief({ reloadScore: reload('A', 12, 4) }), { ...here, ambiguous: true }, null);
  eq(nm.move, 'UNKNOWN', 'a tie on position cannot ground a directive');
  ok(nm.missing.some(m => /position/.test(m)), 'it names the missing confirmed position');
});

test('[NM2-03] only a complete canonical ACCEPT/STRATEGIC becomes TAKE', async () => {
  const b = brief({ reloadScore: reload('A', 12, 4) });
  eq((await derive(b, here, decision('ACCEPT'))).move, 'TAKE', 'ACCEPT with complete facts is TAKE');
  eq((await derive(b, here, decision('STRATEGIC'))).move, 'TAKE', 'STRATEGIC with complete facts is TAKE');
  for (const v of ['REJECT', 'UNAVAILABLE', 'DZ-EXIT', 'BOGUS']) {
    const nm = await derive(b, here, decision(v));
    ok(nm.move !== 'TAKE', `${v} must never render TAKE (got ${nm.move})`);
  }
  const partial = await derive(b, here, decision('ACCEPT', false));
  ok(partial.move !== 'TAKE', 'an ACCEPT over incomplete facts must not be TAKE');
});

test('[NM2-04] a LOW sample cannot direct a move on its own history', async () => {
  const nm = await derive(brief({ reloadScore: reload('A', 2, 3) }), here, null);
  eq(nm.move, 'UNKNOWN', 'two reload records (LOW) are not enough to say WAIT');
  const lanes = await derive(brief({ outboundLanes: [{ destDisplay: 'Dayton, OH', avgRPM: 1.8, count: 2 }] }), here, null);
  eq(lanes.move, 'UNKNOWN', 'two evidenced runs (LOW) are not enough to say WAIT');
});

test('[NM2-05] enough good reload history is WAIT, with the v24.1 sample tiers', async () => {
  const med = await derive(brief({ reloadScore: reload('B', 3, 12) }), here, null);
  eq(med.move, 'WAIT', 'three good reload records is WAIT');
  eq(med.confidence, 'MEDIUM', '3-9 records is MEDIUM');
  const high = await derive(brief({ reloadScore: reload('A', 10, 5) }), here, null);
  eq(high.confidence, 'HIGH', '10+ records is HIGH');
  ok(high.evidence.some(e => e.kind === 'reloadOutcomes' && e.count === 10 && e.provenance === 'OPERATOR_HISTORY'),
    'the move names the evidence it rests on');
});

test('[NM2-06] an evidenced slow market repositions to an ESTIMATED target', async () => {
  const nm = await derive(brief({ reloadScore: reload('C', 4, 36), nearbyMarkets: [anchor] }), here, null);
  eq(nm.move, 'REPOSITION', 'slow reload over 4 records with an anchor nearby is REPOSITION');
  ok(nm.target && nm.target.city === 'Columbus', 'it names the target market');
  eq(nm.target.distanceProvenance, 'ESTIMATED', 'a straight-line distance is never verified deadhead');
  const withLanes = await derive(brief({ reloadScore: reload('C', 4, 36), nearbyMarkets: [anchor],
    outboundLanes: [{ destDisplay: 'Dayton, OH', avgRPM: 1.8, count: 3 }] }), here, null);
  eq(withLanes.move, 'WAIT', 'a slow market with evidenced outbound lanes is WAIT, listing them');
  ok(/Dayton/.test(withLanes.reason), 'and names the best lane');
});

test('[NM2-07] a static market role informs only as LOW, labelled static', async () => {
  const nm = await derive(brief({ market: { role: 'anchor' } }), here, null);
  eq(nm.move, 'WAIT', 'an anchor with no history may still suggest WAIT');
  eq(nm.confidence, 'LOW', 'but only at LOW confidence');
  ok(/static/i.test(nm.reason), 'and the reason says it is a static classification');
  ok(nm.evidence.some(e => e.provenance === 'STATIC'), 'its evidence is labelled STATIC');
  const trapNoAnchor = await derive(brief({ market: { role: 'trap' } }), here, null);
  eq(trapNoAnchor.move, 'UNKNOWN', 'a trap with nowhere known to go is UNKNOWN, not a directive');
});

test('[NM2-08] the Today card renders UNKNOWN with what is missing for an unevidenced market', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.upsertTrip(T.sanitizeTrip({ orderNo: 'NM2-E2E', customer: 'NM-S2', origin: 'Dayton, OH',
      destination: 'Quuxburg, ZZ', pay: 500, loadedMiles: 300, emptyMiles: 0, isPaid: true, paymentStatusKnown: true,
      pickupDate: '2026-09-24', deliveryDate: '2026-09-24', created: Date.now() + 60000 }));
    T._clearPositioningCache();
    T.invalidateKPICache();
  });
  await app.page.evaluate(() => { location.hash = '#trips'; });
  await sleep(350);
  await app.page.evaluate(() => { location.hash = '#home'; });
  await sleep(2400);
  const card = await app.page.evaluate(() => {
    const el = document.querySelector('#homePositioningCard');
    const b = el && el.querySelector('.nm-block');
    return { text: (el && el.innerText) || '', move: b && b.dataset.move };
  });
  console.log(`    [evidence] card=${JSON.stringify(card.text.slice(0, 200))}`);
  eq(card.move, 'UNKNOWN', 'the rendered move for Quuxburg is UNKNOWN');
  ok(/Needs:/.test(card.text), 'the card names what is missing');
  ok(!/\bHUNT\b/.test(card.text), 'the card never renders HUNT');
});

export async function runSpec() {
  app = await launchApp();
  try {
    await skipFirstRunWizard(app.page);
    return await run();
  } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
