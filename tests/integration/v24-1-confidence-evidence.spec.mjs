// v24.1 Confidence + Evidence contract tests.
//
// These drive the real, unmodified helpers inside app.js in a live browser —
// no reimplementation of the confidence rules here. Every assertion maps to a
// numbered item in the acceptance contract of
// docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v24-1-confidence-evidence.spec.mjs');
let app;

const DAY = 86400;

// Fixed clock so every fixture is deterministic.
const NOW = Date.UTC(2026, 7, 23, 12, 0, 0);

function evidence(overrides = {}) {
  return app.page.evaluate(({ overrides, NOW }) => {
    const T = window.__FL_TESTS;
    const base = {
      nowMs: NOW,
      sourceHealth: {},
      hasRoute: true,
      laneIntel: { count: 18, avgRPM: 1.72, lastDate: '2026-08-20', dzExitCount: 0 },
      destReloadScore: { count: 12, avg: 6, grade: 'A', label: 'Hot market', lastObservedMs: NOW - 4 * 86400 * 1000 },
      rateBandFreshness: null,
      brokerEntered: false,
      brokerKey: '',
      brokerIntel: null,
      brokerIdentityResolved: true,
      brokerLegacyUnkeyedExcluded: 0,
      fuelPrice: 3.79,
      fuelPriceSource: 'DRIVER_SETTING',
      opCPM: 0.66,
      mpg: 18,
      mpgSource: 'DRIVER_SETTING',
      fuelObservedAtMs: null,
      weatherChecked: false,
      weatherMaterial: false,
      weatherAlertCount: 0,
      dimensionsProvided: false,
      dimensionsSuppliedCount: 0,
      vanProfileVerified: true,
    };
    return T.buildDecisionConfidence({ ...base, ...overrides });
  }, { overrides, NOW });
}

function itemFor(conf, key) {
  return conf.items.find(i => i.key === key) || null;
}

test('[V241-01] identical inputs produce an identical confidence projection', async () => {
  const a = await evidence();
  const b = await evidence();
  eq(JSON.stringify(a), JSON.stringify(b), 'confidence projection must be deterministic');
});

test('[V241-02] a stale market item is LOW and cannot relax the protective bid floor', async () => {
  // Lane history last observed well beyond the 30-day historical window.
  const conf = await evidence({ laneIntel: { count: 40, avgRPM: 1.72, lastDate: '2026-01-05', dzExitCount: 0 } });
  const lane = itemFor(conf, 'market.laneHistory');
  eq(lane.freshness, 'STALE', 'a 200-day-old observation must be STALE');
  eq(lane.confidence, 'LOW', 'stale evidence must be LOW even with a 40-trip sample');
  eq(conf.domains.market.confidence, 'LOW', 'one stale market item must drag the market domain to LOW');

  // The canonical bid is computed by a function the confidence layer cannot
  // reach. Prove the protective floor is identical under LOW confidence.
  const floors = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return T.deriveUnifiedBid(500, { urgencyBoost: 0, crossBorder: false }).range.minimum.rpm;
  });
  eq(floors, 1.40, 'LOW confidence must not lower the canonical $1.40 bid minimum');
});

test('[V241-03] a healthy, recent item with a sufficient sample can be HIGH', async () => {
  const conf = await evidence();
  const lane = itemFor(conf, 'market.laneHistory');
  eq(lane.freshness, 'CURRENT', '3-day-old lane observation is CURRENT');
  eq(lane.confidence, 'HIGH', 'healthy + current + n=18 must be HIGH');
  eq(conf.overall, 'HIGH', 'all material domains HIGH must roll up to HIGH');
});

test('[V241-04] a sample size of 1-2 can never be HIGH, and 3/9/10 boundaries are exact', async () => {
  const band = n => app.page.evaluate(n => window.__FL_TESTS.classifyEvidenceSampleSize(n), n);
  eq(await band(2), 'LOW', 'n=2 is LOW');
  eq(await band(3), 'MEDIUM', 'n=3 is the MEDIUM boundary');
  eq(await band(9), 'MEDIUM', 'n=9 is still MEDIUM');
  eq(await band(10), 'HIGH', 'n=10 is the HIGH boundary');

  const conf = await evidence({ laneIntel: { count: 2, avgRPM: 1.72, lastDate: '2026-08-22', dzExitCount: 0 } });
  eq(itemFor(conf, 'market.laneHistory').confidence, 'LOW', 'a 2-trip lane sample must be LOW however fresh');
});

test('[V241-05] unresolved broker identity cannot produce HIGH broker confidence', async () => {
  const resolved = await evidence({
    brokerEntered: true, brokerKey: 'acme logistics',
    brokerIntel: { sampleSize: 25, paySpeedSamples: 12, outcomeSamples: 13, lastObservedMs: NOW - 5 * 86400 * 1000 },
    brokerIdentityResolved: true,
  });
  eq(itemFor(resolved, 'broker.history').confidence, 'HIGH', 'explicitly keyed broker evidence with n=25 may be HIGH');

  const unresolved = await evidence({
    brokerEntered: true, brokerKey: 'acme logistics',
    brokerIntel: { sampleSize: 25, paySpeedSamples: 12, outcomeSamples: 13, lastObservedMs: NOW - 5 * 86400 * 1000 },
    brokerIdentityResolved: false,
  });
  eq(itemFor(unresolved, 'broker.history').confidence, 'LOW', 'legacyUnkeyed identity is LOW regardless of sample size');
  eq(unresolved.domains.broker.confidence, 'LOW', 'broker domain must follow the unresolved item');
  eq(unresolved.overall, 'LOW', 'a material LOW broker domain caps overall at LOW');
});

test('[V241-06] a failed source is visibly LOW/unavailable, never neutralized', async () => {
  const conf = await evidence({
    fuelPriceSource: 'EIA_LIVE',
    fuelObservedAtMs: NOW - 2 * DAY * 1000,
    sourceHealth: { EIA: { status: 'AUTH_ERROR', lastSuccess: NOW - 9 * DAY * 1000 } },
  });
  const fuel = itemFor(conf, 'cost.fuelPrice');
  eq(fuel.sourceStatus, 'AUTH_ERROR', 'the real failure status must survive normalization');
  eq(fuel.availability, 'SOURCE_UNAVAILABLE', 'a failed feed must be marked unavailable, not AVAILABLE');
  eq(fuel.confidence, 'LOW', 'a non-OK source is LOW');
  ok(/AUTH_ERROR/.test(fuel.valueSummary), 'the driver-facing summary must name the failure');
  ok(fuel.reasons.some(r => /source status AUTH_ERROR/.test(r)), 'the reason must state the source status');
  eq(conf.domains.operatingCosts.confidence, 'LOW', 'a failed fuel feed drags operating costs to LOW');
});

test('[V241-07] missing evidence is explicit and never conflated with favorable evidence', async () => {
  const conf = await evidence({ laneIntel: null, destReloadScore: null });
  const lane = itemFor(conf, 'market.laneHistory');
  ok(lane, 'a lane with no history must still produce an explicit evidence item');
  eq(lane.availability, 'NO_DATA', 'no history must read as NO_DATA');
  eq(lane.confidence, 'LOW', 'absent evidence is never favorable');
  ok(/No prior trips/i.test(lane.valueSummary), 'the summary must say the data is missing');

  // NO_DATA and SOURCE_UNAVAILABLE must remain distinguishable from each other.
  const failed = await evidence({
    weatherChecked: true, weatherMaterial: true,
    sourceHealth: { NWS: { status: 'TIMEOUT' } },
  });
  const wx = itemFor(failed, 'safety.routeWeather');
  eq(wx.availability, 'SOURCE_UNAVAILABLE', 'a timed-out feed is unavailable, not no-data');
  ok(/does NOT mean conditions are clear/.test(wx.valueSummary), 'unavailable weather must not imply safety');
  ok(lane.availability !== wx.availability, 'no-data and source-unavailable must stay distinct states');
});

test('[V241-08] overall confidence cannot average away a material LOW domain', async () => {
  const conf = await evidence({
    // market is pristine, but operating costs are unconfigured.
    opCPM: 0,
  });
  eq(conf.domains.market.confidence, 'HIGH', 'market evidence is healthy here');
  eq(conf.domains.operatingCosts.confidence, 'LOW', 'unconfigured op cost is LOW');
  eq(conf.overall, 'LOW', 'one material LOW domain must cap overall at LOW, not average to MEDIUM');

  const agg = await app.page.evaluate(() => window.__FL_TESTS.aggregateOverallConfidence(
    { a: { confidence: 'HIGH' }, b: { confidence: 'HIGH' }, c: { confidence: 'LOW' } },
    ['a', 'b', 'c'],
  ));
  eq(agg.overall, 'LOW', 'aggregation is a floor, not a mean');
});

test('[V241-09] domains irrelevant to the decision are excluded, not counted as HIGH', async () => {
  const conf = await evidence();
  eq(conf.domains.broker.confidence, 'UNKNOWN', 'no broker named -> broker domain is UNKNOWN');
  ok(!conf.materialDomains.includes('broker'), 'an UNKNOWN broker domain must not be material');
  ok(conf.materialDomains.includes('operatingCosts'), 'operating costs are always material');
  eq(conf.overall, 'HIGH', 'an excluded domain must not drag or inflate the roll-up');

  // Weather is reported but explicitly non-material on the evaluator path.
  const wx = await evidence({ weatherChecked: true, weatherMaterial: false, sourceHealth: { NWS: { status: 'OFFLINE' } } });
  eq(wx.domains.weatherSafety.confidence, 'LOW', 'an offline weather feed is still reported as LOW');
  ok(!wx.materialDomains.includes('weatherSafety'), 'display-only weather must not be material');
  eq(wx.overall, 'HIGH', 'a non-material LOW domain must not cap the overall label');
});

test('[V241-10] source-specific freshness windows are respected before the generic 14/30-day rule', async () => {
  const classify = (src, ageSec) => app.page.evaluate(({ src, ageSec }) => {
    const T = window.__FL_TESTS;
    return T.classifyEvidenceFreshness(ageSec, T.evidenceFreshnessWindow(src));
  }, { src, ageSec });

  // NWS caches per route point for 30 minutes.
  eq(await classify('NWS', 30 * 60), 'CURRENT', '30m NWS observation is inside its own window');
  eq(await classify('NWS', 30 * 60 + 1), 'AGING', 'just past the NWS window is AGING');
  eq(await classify('NWS', 2 * 30 * 60 + 1), 'STALE', 'beyond 2x the NWS window is STALE');

  // FMCSA caches per DOT for 24 hours; EIA throttles fetches to 3 days.
  eq(await classify('FMCSA', 24 * 3600), 'CURRENT', '24h FMCSA observation is CURRENT');
  eq(await classify('EIA', 3 * DAY), 'CURRENT', '3-day EIA observation is CURRENT');
  eq(await classify('EIA', 7 * DAY), 'STALE', 'a week-old EIA observation is STALE');

  // Anything not a live feed falls back to the generic historical window.
  eq(await classify(null, 14 * DAY), 'CURRENT', 'generic 14-day boundary is CURRENT');
  eq(await classify(null, 14 * DAY + 1), 'AGING', 'past 14 days is AGING');
  eq(await classify(null, 30 * DAY), 'AGING', 'generic 30-day boundary is still AGING');
  eq(await classify(null, 30 * DAY + 1), 'STALE', 'past 30 days is STALE');

  // An unknown age is never silently treated as current.
  eq(await classify(null, null), 'UNKNOWN', 'a missing age must be UNKNOWN');
});

test('[V241-11] static rate-band freshness is carried as evidence from the Midwest adapter', async () => {
  const stale = await evidence({ rateBandFreshness: { status: 'STALE', ageDays: 45, effectiveDate: '2026-07-09' } });
  const item = itemFor(stale, 'market.staticRateBands');
  eq(item.freshness, 'STALE', 'the adapter-owned freshness must be carried verbatim');
  eq(item.confidence, 'LOW', 'stale static bands are LOW evidence');
  eq(item.source, 'STATIC_RATE_OVERRIDE', 'the fallback nature of the source must be visible');

  const current = await evidence({ rateBandFreshness: { status: 'CURRENT', ageDays: 3, effectiveDate: '2026-08-20' } });
  // Static fallback data is never better than MEDIUM even when current.
  eq(itemFor(current, 'market.staticRateBands').confidence, 'MEDIUM', 'static fallback data caps at MEDIUM');
});

test('[V241-12] no percentage or probability is ever emitted', async () => {
  const conf = await evidence({
    brokerEntered: true, brokerKey: 'acme', brokerIntel: { sampleSize: 4, paySpeedSamples: 4, outcomeSamples: 0, lastObservedMs: NOW - 3 * 86400 * 1000 },
    rateBandFreshness: { status: 'AGING', ageDays: 20, effectiveDate: '2026-07-09' },
    weatherChecked: true, sourceHealth: { NWS: { status: 'OK', lastSuccess: NOW - 60000 } },
    dimensionsProvided: true, dimensionsSuppliedCount: 2,
  });
  const labels = new Set(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
  ok(labels.has(conf.overall), 'overall must be a categorical label');
  for (const item of conf.items) {
    ok(labels.has(item.confidence), `${item.key} must carry a categorical label`);
    ok(!/\d\s*%/.test(item.valueSummary), `${item.key} summary must not imply calibrated odds`);
    ok(!/probability|likelihood|odds/i.test(item.valueSummary), `${item.key} must not claim a probability`);
  }
  ok(!/\d\s*%/.test(conf.headline), 'headline must not contain a percentage');
});

test('[V241-13] provenance is present and carries no secrets', async () => {
  const conf = await evidence({
    brokerEntered: true, brokerKey: 'acme logistics',
    brokerIntel: { sampleSize: 12, paySpeedSamples: 6, outcomeSamples: 6, lastObservedMs: NOW - 2 * 86400 * 1000 },
    fuelPriceSource: 'EIA_LIVE',
    fuelObservedAtMs: NOW - DAY * 1000,
    sourceHealth: { EIA: { status: 'OK', lastSuccess: NOW - DAY * 1000 } },
  });
  const serialized = JSON.stringify(conf);
  for (const secret of ['apiKey', 'eiaApiKey', 'fmcsaApiKey', 'token', 'flk_', 'passphrase', 'Authorization']) {
    ok(!serialized.includes(secret), `provenance must not carry ${secret}`);
  }
  // Every question the spec requires provenance to answer must be answerable.
  const lane = itemFor(conf, 'market.laneHistory');
  ok(lane.source, 'evidence must name its source');
  ok(lane.sourceStatus, 'evidence must carry source health');
  ok(lane.ageSeconds !== null, 'a historical aggregate must expose its age');
  ok(lane.sampleSize !== null, 'a historical aggregate must expose its sample size');
  ok(itemFor(conf, 'broker.history').provenance.brokerKey === 'acme logistics', 'broker identity must be traceable');
});

test('[V241-14] vehicle-fit evidence weakens on partial dimensions without overriding the hard gate', async () => {
  const full = await evidence({ dimensionsProvided: true, dimensionsSuppliedCount: 4, vanProfileVerified: true });
  eq(itemFor(full, 'vehicle.fit').confidence, 'HIGH', 'a complete measured fit check is HIGH');

  const partial = await evidence({ dimensionsProvided: true, dimensionsSuppliedCount: 1, vanProfileVerified: true });
  eq(itemFor(partial, 'vehicle.fit').confidence, 'MEDIUM', 'a partial dimension set lowers fit confidence');

  const unverified = await evidence({ dimensionsProvided: true, dimensionsSuppliedCount: 4, vanProfileVerified: false });
  eq(itemFor(unverified, 'vehicle.fit').confidence, 'MEDIUM', 'an unverified van profile lowers fit confidence');

  // The hard fit gate itself is untouched by any of this.
  const blocked = await app.page.evaluate(() => window.__FL_TESTS.checkVanFit(
    { weightLbs: 99999 },
    window.__FL_TESTS.VAN_PROFILE_DEFAULT,
  ));
  eq(blocked.fits, false, 'an over-payload load must still fail the hard fit gate');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
