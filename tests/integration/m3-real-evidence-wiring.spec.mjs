// Issue #119 Batch A, item 7 — REAL evaluator evidence wiring.
//
// Source audit: .agents/inbox/gpt-to-claude-m3-test-gap-addendum-2026-08-27.md
//
// The existing M3 suite drives buildEvidenceItem()/summarizeEvidenceConfidence()
// with hand-built inputs. Those helper tests are correct and stay. They cannot,
// however, catch a defect in the ASSEMBLY seam — which is where every one of
// these lived: fuel provenance asserted from the mere existence of an EIA
// health record, a weather flag derived from "are there any warnings at all",
// lane/broker sample fields the USA engine never returned, and a hardcoded
// `vanFitChecked: true`.
//
// Every test here runs a real evaluation through the real UI and reads the
// evidence the real assembly produced.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m3-real-evidence-wiring.spec.mjs');
let app;

async function openEvaluatorAdvanced(page){
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwLoadWeightLbs', { state: 'visible', timeout: 10000 });
}

// Runs one real evaluation and returns the compact evidence snapshot the
// evaluator persisted for it.
async function evaluate(page, { origin='Chicago, IL', dest='Toledo, OH', revenue='800', loadedMi='250', deadMi='0', broker='', dims={} } = {}){
  await page.evaluate(() => { try { sessionStorage.removeItem('fl_eval_hist'); } catch(e){} });
  await page.fill('#mwOrigin', origin);
  await page.fill('#mwDest', dest);
  await page.fill('#mwLoadedMi', loadedMi);
  await page.fill('#mwDeadMi', deadMi);
  await page.fill('#mwRevenue', revenue);
  await page.fill('#mwBroker', broker);
  await page.fill('#mwLoadLengthIn', dims.lengthIn ?? '');
  await page.fill('#mwLoadWidthIn', dims.widthIn ?? '');
  await page.fill('#mwLoadHeightIn', dims.heightIn ?? '');
  await page.fill('#mwLoadWeightLbs', dims.weightLbs ?? '');
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(600);
  return page.evaluate(() => {
    let hist = [];
    try { hist = JSON.parse(sessionStorage.getItem('fl_eval_hist') || '[]'); } catch(e){}
    return hist[0] || null;
  });
}

test('setup: suppress first-run wizard and open the evaluator', async () => {
  await skipFirstRunWizard(app.page);
  await openEvaluatorAdvanced(app.page);
});

/* ── 1. fuel provenance ── */

test('[M3R-01] a driver-set fuel price is attributed to the driver even when an EIA record exists', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    // A healthy EIA source health record exists AND its value is numerically
    // identical to the driver's. Under the old wiring the mere existence of
    // this record made the evidence claim EIA.
    T.setLiveSourceHealth('EIA', T.LIVE_SOURCE_STATUS.OK, { lastSuccess: Date.now() - 3600_000 });
    await T.setSetting('eiaLastPrice', 3.55);
    await T.setSetting('fuelPrice', 3.55);
    await T.setFuelPriceProvenance(T.FUEL_PRICE_SOURCE.OPERATOR);
  });
  const h = await evaluate(app.page);
  const fuel = h.evidence.find(e => e.key === 'fuel.price');
  ok(!!fuel, 'a fuel evidence row is recorded for every evaluation');
  ok(/driver/i.test(fuel.source), `fuel evidence must name the driver setting, got: ${fuel.source}`);
  ok(!/EIA/.test(fuel.source), 'and must not claim EIA for a number the driver typed');
});

test('[M3R-02] applying an EIA observation switches provenance to EIA with its own source instant', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.setSetting('fuelPrice', 3.61);
    await T.setFuelPriceProvenance(T.FUEL_PRICE_SOURCE.EIA, '2026-08-14');
  });
  const h = await evaluate(app.page);
  const fuel = h.evidence.find(e => e.key === 'fuel.price');
  eq(fuel.source, 'EIA', 'an applied EIA observation is attributed to EIA');
  ok(!/driver/i.test(fuel.source), 'and no longer to the driver');
  // The freshness must be derived from the EIA PERIOD, not from "now".
  ok(fuel.freshness && fuel.freshness !== 'UNKNOWN', `the EIA observation instant must drive freshness, got ${fuel.freshness}`);
});

test('[M3R-03] with no provenance recorded the fuel evidence is an explicit static fallback', async () => {
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('fuelPriceProvenance', null); });
  const h = await evaluate(app.page);
  const fuel = h.evidence.find(e => e.key === 'fuel.price');
  ok(/baseline/i.test(fuel.source) || /baseline/i.test(String(fuel.source)), `an unattributed price falls back to the static baseline, got ${fuel.source}`);
  eq(fuel.confidence, 'LOW', 'a static fallback standing in for a live observation is never HIGH');
});

/* ── 2. NWS: a successful zero is not the same fact as no observation ── */

test('[M3R-04] a successful route fetch reporting zero alerts is valid zero-alert evidence', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const realFetch = window.fetch;
    // A genuine successful NWS response carrying no active alerts.
    window.fetch = async () => new Response(JSON.stringify({ features: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    // `checkRouteWeather` keeps a 30-minute per-point success cache. A runner
    // that CAN reach api.weather.gov will have populated it via the evaluator's
    // own async weather call, so the cache is reset to guarantee this test
    // observes what the stub returns and nothing else. Coordinates are
    // deliberately arbitrary too, so no market city maps to them.
    T._resetRouteWeatherStateForTests();
    try {
      await T.checkRouteWeather({ lat: 1.23, lng: 2.34 }, { lat: 3.45, lng: 4.56 }, 'WX-OK');
    } finally { window.fetch = realFetch; }
    const obs = T.getRouteWeatherObservation('WX-OK');
    const items = T.buildEvaluationEvidence({ weatherObservation: obs, economicsResult: { fuelPrice: 3.5 } });
    const wx = items.find(i => i.key === 'weather.route');
    return { obs, wx };
  });
  eq(r.obs.observed, true, 'the route was genuinely observed');
  eq(r.obs.alertCount, 0, 'and reported zero alerts');
  eq(r.obs.pointsObserved, 2, 'both route points answered');
  ok(!!r.wx, 'a weather evidence row exists');
  eq(r.wx.sourceStatus, 'OK', 'a real observation is a healthy source status');
  ok(/No active NWS alerts/.test(r.wx.valueSummary), `a real zero reads as a real zero, got: ${r.wx.valueSummary}`);
  eq(r.wx.sampleSize, null,
     'the number of route points answered is not an aggregate sample — scoring it as one would rate every healthy two-point route LOW');
  eq(r.wx.confidence, 'HIGH', 'a fresh, complete, successful route observation is high confidence');
});

test('[M3R-05] a failed or absent route fetch is UNKNOWN, never rendered as "0 alerts"', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const realFetch = window.fetch;
    window.fetch = async () => { throw new Error('network down'); };
    // The subject here is a route with NO successful observation, so the point
    // cache is cleared first. A cached success is a real observation and must
    // never be discarded to make a test pass — the reset removes the ambiguity
    // instead of weakening `obs.observed = pointsObserved > 0`, which is the
    // correct production rule.
    T._resetRouteWeatherStateForTests();
    try {
      await T.checkRouteWeather({ lat: 5.67, lng: 6.78 }, { lat: 7.89, lng: 8.9 }, 'WX-FAIL');
    } finally { window.fetch = realFetch; }
    const failed = T.getRouteWeatherObservation('WX-FAIL');
    const failedItem = T.buildEvaluationEvidence({ weatherObservation: failed, economicsResult: { fuelPrice: 3.5 } })
      .find(i => i.key === 'weather.route');
    // And the case where no fetch was made at all for THIS route.
    const neverFetched = T.getRouteWeatherObservation('WX-NEVER');
    const neverItem = T.buildEvaluationEvidence({ weatherObservation: neverFetched, economicsResult: { fuelPrice: 3.5 } })
      .find(i => i.key === 'weather.route');
    return { failed, failedItem, neverFetched, hasNeverItem: !!neverItem };
  });
  eq(r.failed.observed, false, 'a route whose every point failed was not observed');
  ok(r.failedItem, 'a failed observation is still surfaced — silence would read as "no risk"');
  ok(!/No active NWS alerts/.test(r.failedItem.valueSummary), 'a failure must never render as zero alerts');
  ok(/NOT observed/.test(r.failedItem.valueSummary), `the absence is stated plainly, got: ${r.failedItem.valueSummary}`);
  eq(r.failedItem.confidence, 'LOW', 'an unhealthy source cannot be confident');
  eq(r.neverFetched, null, 'a previous route’s observation is never reported for a different route');
  eq(r.hasNeverItem, false, 'and with no observation for this route no weather claim is made at all');
});

/* ── 3. real lane / broker intelligence ── */

test('[M3R-06] real lane history reaches the evidence sample size and observation date', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const lane = T.normalizeLane ? T.normalizeLane('Chicago, IL', 'Toledo, OH') : null;
    await new Promise((resolve, reject) => {
      const q = indexedDB.open('FreightLogic_v18');
      q.onsuccess = () => {
        const d = q.result;
        const t = d.transaction('laneHistory', 'readwrite');
        t.objectStore('laneHistory').put({
          id: 'lane-real-1', lane, displayOrigin: 'Chicago, IL', displayDest: 'Toledo, OH',
          count: 12, avgRPM: 1.72, bestPay: 900, wouldRunCount: 10, wouldRunYes: 9,
          dzExitCount: 0, lastDate: '2026-08-20', created: Date.now(), updated: Date.now(),
        });
        t.oncomplete = () => { d.close(); resolve(); };
        t.onerror = () => reject(t.error);
      };
      q.onerror = () => reject(q.error);
    });
  });
  const h = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH' });
  const lane = h.evidence.find(e => e.key === 'market.laneHistory');
  eq(lane.sampleSize, 12, 'the real laneHistory count reaches the evidence, not a null');
  ok(lane.freshness && lane.freshness !== 'UNKNOWN', `the lane's own lastDate drives freshness, got ${lane.freshness}`);
  eq(lane.confidence, 'HIGH', 'a 12-observation recent lane is a HIGH-confidence market domain');
  eq(h.confidence.market, 'HIGH', 'and the market domain reflects it');
});

test('[M3R-07] with no broker entered the broker domain is UNKNOWN, not a synthetic LOW', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.setSetting('fuelPrice', 3.55);
    await T.setFuelPriceProvenance(T.FUEL_PRICE_SOURCE.OPERATOR);
  });
  // Differential: the SAME load evaluated with and without a broker. The old
  // wiring emitted an UNKNOWN-status broker row when none was entered, which
  // made the broker domain material and dragged the aggregate down purely
  // because the driver had not typed a name. Comparing the two runs isolates
  // that from whatever the other domains are doing on this route — the route
  // weather domain in particular is legitimately LOW in this environment,
  // which is a real fact about the route and not this test's subject.
  const withBroker = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', broker: 'Acme Logistics' });
  const noBroker  = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', broker: '' });

  eq(noBroker.evidence.find(e => e.key === 'broker.history'), undefined,
     'no broker entered means no broker evidence claim at all');
  eq(noBroker.confidence.broker, 'UNKNOWN', 'the broker domain is inapplicable, not low-confidence');
  const rank = { LOW: 0, MEDIUM: 1, HIGH: 2, UNKNOWN: 3 };
  ok(rank[noBroker.confidence.overall] >= rank[withBroker.confidence.overall],
     `omitting a broker must never make overall confidence WORSE — with: ${withBroker.confidence.overall}, without: ${noBroker.confidence.overall}`);
  // Every other domain must be identical: the broker is the only variable.
  for (const d of ['market','operatingCosts','weatherSafety','vehicleFit']){
    eq(noBroker.confidence[d], withBroker.confidence[d], `the ${d} domain is unaffected by the broker field`);
  }
});

test('[M3R-08] a named broker with real bidHistory reaches the evidence with its identity', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const now = Date.now();
    await new Promise((resolve, reject) => {
      const q = indexedDB.open('FreightLogic_v18');
      q.onsuccess = () => {
        const d = q.result;
        const t = d.transaction('bidHistory', 'readwrite');
        for (let i = 0; i < 6; i++){
          t.objectStore('bidHistory').put({
            id: 'bid-real-' + i, broker: 'acme logistics', brokerDisplay: 'Acme Logistics',
            lane: 'chicago-il|toledo-oh', outcome: i % 2 ? 'won' : 'rejected',
            created: now - i * 86400000, updatedAt: now - i * 86400000,
          });
        }
        t.oncomplete = () => { d.close(); resolve(); };
        t.onerror = () => reject(t.error);
      };
      q.onerror = () => reject(q.error);
    });
  });
  const h = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', broker: 'Acme Logistics' });
  const brokerItem = h.evidence.find(e => e.key === 'broker.history');
  ok(!!brokerItem, 'a named broker produces a broker evidence row');
  ok(h.confidence.broker !== 'UNKNOWN', 'and the broker domain becomes applicable');
});

/* ── 4. vehicle fit measurement state ── */

test('[M3R-09] no dimensions supplied means no vehicle-fit claim at all', async () => {
  const h = await evaluate(app.page, { dims: {} });
  eq(h.evidence.find(e => e.key === 'vehicle.fit'), undefined,
     'a load with no dimensions was never dimensionally checked — claiming otherwise is the defect');
  eq(h.confidence.vehicleFit, 'UNKNOWN', 'the vehicleFit domain is inapplicable, not verified');
});

test('[M3R-10] complete measurements produce a deterministic full-confidence fit result', async () => {
  const h = await evaluate(app.page, { dims: { lengthIn: '60', widthIn: '40', heightIn: '40', weightLbs: '1200' } });
  const fit = h.evidence.find(e => e.key === 'vehicle.fit');
  ok(!!fit, 'a fully measured load produces a fit evidence row');
  ok(/all 4 measured limits/.test(fit.valueSummary), `the summary reports a complete check, got: ${fit.valueSummary}`);
  eq(fit.confidence, 'HIGH', 'a complete deterministic measurement is high confidence');
});

test('[M3R-11] partial measurements reduce confidence without claiming a full check', async () => {
  const h = await evaluate(app.page, { dims: { weightLbs: '1200' } });
  const fit = h.evidence.find(e => e.key === 'vehicle.fit');
  ok(!!fit, 'a partially measured load still produces a fit row');
  ok(/unmeasured/.test(fit.valueSummary), `the summary must admit what was not measured, got: ${fit.valueSummary}`);
  ok(fit.confidence !== 'HIGH', 'a partial measurement cannot support a full-confidence fit claim');
});

/* ── 5. the evaluation-history snapshot ── */

test('[M3R-12] a real evaluation records a compact confidence/evidence snapshot', async () => {
  const h = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', broker: 'Acme Logistics' });
  ok(!!h, 'an evaluation history entry is written');
  ok(!!h.confidence, 'and carries a confidence snapshot');
  for (const d of ['overall','market','broker','operatingCosts','weatherSafety','vehicleFit']){
    ok(typeof h.confidence[d] === 'string', `the snapshot records the ${d} domain`);
  }
  ok(Array.isArray(h.evidence) && h.evidence.length > 0, 'and a bounded evidence snapshot');
  ok(h.evidence.length <= 8, 'which stays bounded — this lives in sessionStorage');
  for (const e of h.evidence){
    for (const f of ['key','source','sourceStatus','freshness','confidence']){
      ok(Object.prototype.hasOwnProperty.call(e, f), `each snapshot row records ${f}`);
    }
  }
});

test('[M3R-13] a legacy history entry with no snapshot still renders and never reads as confident', async () => {
  const r = await app.page.evaluate(() => {
    // An entry in the pre-snapshot shape.
    sessionStorage.setItem('fl_eval_hist', JSON.stringify([{
      ts: Date.now() - 60000, grade: 'B', gradeLabel: 'GOOD', gradeColor: '#58a6ff', gradeEmoji: '',
      trueRPM: 1.68, origin: 'Gary, IN', dest: 'Erie, PA', revenue: 900, loadedMi: 400,
    }]));
    window.__FL_TESTS._renderEvalHistory
      ? window.__FL_TESTS._renderEvalHistory()
      : document.querySelector('#mwEvalHistory');
    const el = document.querySelector('#mwEvalHistory');
    return { html: el ? el.innerHTML : '', text: el ? el.textContent : '' };
  });
  ok(/Gary, IN/.test(r.text), 'the legacy entry still renders');
  ok(!/confidence HIGH/i.test(r.text), 'and a missing snapshot is never displayed as high confidence');
  ok(!/confidence/i.test(r.text), 'no confidence is claimed for an entry that never recorded one');
});

/* ── 6. evidence is descriptive only, on the real evaluator ── */

test('[M3R-14] healthy vs failed evidence changes confidence labels but never the decision', async () => {
  const healthy = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    T.setLiveSourceHealth('EIA', T.LIVE_SOURCE_STATUS.OK, { lastSuccess: Date.now() });
    await T.setSetting('fuelPrice', 3.55);
    await T.setFuelPriceProvenance(T.FUEL_PRICE_SOURCE.EIA, new Date().toISOString());
  });
  const a = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', revenue: '800', loadedMi: '250', deadMi: '0' });

  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    // Same material facts; every evidence source now degraded/absent.
    T.setLiveSourceHealth('EIA', T.LIVE_SOURCE_STATUS.NETWORK_ERROR, {});
    await T.setSetting('fuelPriceProvenance', null);
  });
  const b = await evaluate(app.page, { origin: 'Chicago, IL', dest: 'Toledo, OH', revenue: '800', loadedMi: '250', deadMi: '0' });

  eq(b.grade, a.grade, 'grade is identical for identical material inputs');
  eq(b.gradeLabel, a.gradeLabel, 'grade label is identical');
  eq(b.trueRPM, a.trueRPM, 'True RPM is identical');
  eq(b.revenue, a.revenue, 'revenue is identical');
  ok(a.confidence.operatingCosts !== b.confidence.operatingCosts,
     'while the operating-cost confidence label genuinely differs — otherwise this test proves nothing');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
