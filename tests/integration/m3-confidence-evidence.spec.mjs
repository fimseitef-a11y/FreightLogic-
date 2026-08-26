// Milestone 3 — v24.1 Confidence + Evidence.
//
// Maps 1:1 onto the 12-point acceptance contract in
// docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md. The load-bearing rule is that
// confidence is DESCRIPTIVE ONLY: it may explain uncertainty but may never
// change verdict, grade, True RPM, or the canonical bid range, and may never
// relax a protective floor because evidence is stale or a source failed.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m3-confidence-evidence.spec.mjs');
let app;

const ev = (spec) => app.page.evaluate((spec) => window.__FL_TESTS.buildEvidenceItem(spec), spec);
const summarize = (items, material) => app.page.evaluate(
  ({ items, material }) => window.__FL_TESTS.summarizeEvidenceConfidence(items, material),
  { items, material });

const DAY = 86400000;

/* ---- 1. determinism ---- */

test('[M3-01] identical inputs produce an identical confidence/evidence output', async () => {
  const spec = { key:'market.lane', category:'MARKET', source:'laneHistory',
    sourceStatus:'OK', sampleSize:12, observedAt: 1_700_000_000_000, evaluatedAt: 1_700_000_000_000 + DAY };
  const a = await ev(spec); const b = await ev(spec);
  eq(JSON.stringify(a), JSON.stringify(b), 'evidence normalization must be deterministic');
});

/* ---- 2. stale is LOW and cannot relax a floor ---- */

test('[M3-02] a stale market item is LOW', async () => {
  const item = await ev({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK',
    observedAt: 0, evaluatedAt: 45 * DAY });   // 45 days old, > 30d STALE threshold
  eq(item.freshness, 'STALE', 'past 30 days is STALE');
  eq(item.confidence, 'LOW', 'a stale item is LOW');
});

test('[M3-02b] LOW confidence cannot lower the protective bid floor', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const economicsResult = T.deriveUnifiedEconomics({ revenue:500, effectiveRevenue:500, loadedMi:80, deadMi:20, mpg:20, fuelPrice:4, opCPM:0.4 });
    const authorityResult = T.deriveUnifiedAuthority({ trueRPM:5, totalMi:100, deadheadPct:20, effectiveRevenue:500, initialVerdict:'ACCEPT', geo:{intoDensity:true} });
    const bidResult = T.deriveUnifiedBid(100, {});
    const stale = T.buildEvidenceItem({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK', observedAt:0, evaluatedAt: 45*86400000 });
    const withLow = T.buildUnifiedDecisionContract({ authorityResult, economicsResult, bidResult, evidenceItems:[stale] });
    const without = T.buildUnifiedDecisionContract({ authorityResult, economicsResult, bidResult });
    return {
      lowOverall: withLow.confidence.overall,
      sameVerdict: withLow.authority.verdict === without.authority.verdict,
      sameGrade: withLow.authority.grade === without.authority.grade,
      sameRPM: withLow.economics.trueRPM === without.economics.trueRPM,
      sameBid: JSON.stringify(withLow.bid.range) === JSON.stringify(without.bid.range),
    };
  });
  eq(r.lowOverall, 'LOW', 'the stale evidence really did produce LOW');
  ok(r.sameVerdict, 'verdict must be identical with and without LOW evidence');
  ok(r.sameGrade, 'grade must be identical');
  ok(r.sameRPM, 'True RPM must be identical');
  ok(r.sameBid, 'the canonical bid range must be byte-identical — LOW cannot soften a floor');
});

/* ---- 3/4. sample-size boundaries ---- */

test('[M3-03] a healthy recent item with a sufficient sample can be HIGH', async () => {
  const item = await ev({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK',
    sampleSize: 10, observedAt: 0, evaluatedAt: DAY });
  eq(item.confidence, 'HIGH', '10 observations at 1 day old is HIGH');
});

test('[M3-04] sample-size boundaries are exact at 2/3 and 9/10', async () => {
  const base = { key:'m', category:'MARKET', source:'s', sourceStatus:'OK', observedAt:0, evaluatedAt: DAY };
  eq((await ev({ ...base, sampleSize: 2 })).confidence, 'LOW', '2 is LOW');
  eq((await ev({ ...base, sampleSize: 3 })).confidence, 'MEDIUM', '3 is MEDIUM');
  eq((await ev({ ...base, sampleSize: 9 })).confidence, 'MEDIUM', '9 is MEDIUM');
  eq((await ev({ ...base, sampleSize: 10 })).confidence, 'HIGH', '10 is HIGH');
});

test('[M3-04b] a sample of 1-2 can never be HIGH even on a perfect source', async () => {
  for (const n of [0, 1, 2]){
    const item = await ev({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK', sampleSize:n, observedAt:0, evaluatedAt: 60_000 });
    ok(item.confidence !== 'HIGH', `sample ${n} must not be HIGH`);
  }
});

/* ---- 5. broker identity ---- */

test('[M3-05] unresolved broker identity cannot produce HIGH, whatever the sample', async () => {
  const item = await ev({ key:'b', category:'BROKER', source:'bidHistory', sourceStatus:'OK',
    sampleSize: 500, identityResolved: false, observedAt: 0, evaluatedAt: 60_000 });
  eq(item.confidence, 'LOW', 'legacyUnkeyed history stays LOW');
  ok(item.reasons.some(r => /unresolved/i.test(r)), 'the reason must name the unresolved identity');
});

/* ---- 6. source failure stays visible ---- */

test('[M3-06] a failed source is LOW and visibly failed, not neutralized', async () => {
  for (const status of ['AUTH_ERROR','HTTP_ERROR','TIMEOUT','NETWORK_ERROR','PARSE_ERROR']){
    const item = await ev({ key:'f', category:'FUEL', source:'EIA', sourceStatus:status, observedAt:0, evaluatedAt: 60_000 });
    eq(item.confidence, 'LOW', `${status} must be LOW`);
    eq(item.sourceStatus, status, 'the failure status must survive verbatim, not be flattened to OK/UNKNOWN');
  }
});

test('[M3-06b] an unrecognized status normalizes to UNKNOWN, never to OK', async () => {
  const item = await ev({ key:'f', category:'FUEL', source:'X', sourceStatus:'SOMETHING_ELSE', evaluatedAt: 60_000 });
  eq(item.sourceStatus, 'UNKNOWN', 'unknown vocabulary normalizes to UNKNOWN');
  eq(item.confidence, 'LOW', 'and is LOW, because it is unverified');
});

/* ---- 7. Worker boundary ---- */

test('[M3-07] the Worker payload carries client-owned labels it cannot replace', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const economicsResult = T.deriveUnifiedEconomics({ revenue:500, effectiveRevenue:500, loadedMi:80, deadMi:20, mpg:20, fuelPrice:4, opCPM:0.4 });
    const authorityResult = T.deriveUnifiedAuthority({ trueRPM:5, totalMi:100, deadheadPct:20, effectiveRevenue:500, initialVerdict:'ACCEPT', geo:{intoDensity:true} });
    const bidResult = T.deriveUnifiedBid(100, {});
    const item = T.buildEvidenceItem({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK', sampleSize:12, observedAt:0, evaluatedAt:86400000 });
    const d = T.buildUnifiedDecisionContract({ authorityResult, economicsResult, bidResult, evidenceItems:[item] });
    const ai = T.unifiedDecisionForAI(d);
    return { authority: ai.confidence.authority, overall: ai.confidence.overall, canonical: d.confidence.overall, frozen: Object.isFrozen(d.confidence) };
  });
  eq(r.authority, 'CLIENT_OWNED', 'the payload must declare the label as client-owned');
  eq(r.overall, r.canonical, 'the projection must echo the canonical label, not recompute one');
  ok(r.frozen, 'the canonical confidence object is frozen against mutation');
});

/* ---- 8. missing evidence stays missing ---- */

test('[M3-08] missing evidence is explicit and never reads as favorable', async () => {
  const empty = await summarize([], []);
  eq(empty.overall, 'LOW', 'no evidence must not be optimistic');
  ok(empty.reasons.some(r => /absence of evidence/i.test(r)), 'and must say so');
  const noneApplicable = await summarize([], ['market']);
  eq(noneApplicable.market, 'UNKNOWN', 'a domain with no evidence is UNKNOWN, not HIGH');
});

/* ---- aggregation: a material LOW is never averaged away ---- */

test('[M3-09] one material LOW domain caps overall at LOW', async () => {
  const items = [
    { key:'a', category:'MARKET', confidence:'HIGH' },
    { key:'b', category:'BROKER', confidence:'HIGH' },
    { key:'c', category:'FUEL', confidence:'LOW' },
  ];
  const s = await summarize(items, ['market','broker','operatingCosts']);
  eq(s.overall, 'LOW', 'three-quarters healthy must still be LOW overall');
  ok(s.reasons.some(r => /operatingCosts/.test(r)), 'the capping domain must be named');
});

test('[M3-10] overall is HIGH only when every material domain is HIGH', async () => {
  const allHigh = await summarize([
    { key:'a', category:'MARKET', confidence:'HIGH' },
    { key:'b', category:'BROKER', confidence:'HIGH' },
  ], ['market','broker']);
  eq(allHigh.overall, 'HIGH', 'all material domains HIGH');
  const oneMedium = await summarize([
    { key:'a', category:'MARKET', confidence:'HIGH' },
    { key:'b', category:'BROKER', confidence:'MEDIUM' },
  ], ['market','broker']);
  eq(oneMedium.overall, 'MEDIUM', 'a MEDIUM domain caps at MEDIUM');
});

test('[M3-11] an irrelevant domain is excluded, not counted as HIGH', async () => {
  const s = await summarize([
    { key:'a', category:'MARKET', confidence:'MEDIUM' },
    { key:'w', category:'WEATHER', confidence:'LOW' },
  ], ['market']);   // weather is not material to this decision
  eq(s.overall, 'MEDIUM', 'the non-material LOW weather domain must not drag it to LOW');
  eq(s.weatherSafety, 'LOW', 'but it is still reported honestly');
});

/* ---- source-specific freshness ---- */

test('[M3-12] source-specific freshness windows are applied before the generic 14/30-day rule', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      nwsFresh: T.classifyEvidenceFreshness(20 * 60, 'NWS'),
      nwsAging: T.classifyEvidenceFreshness(45 * 60, 'NWS'),
      nwsStale: T.classifyEvidenceFreshness(4 * 3600, 'NWS'),
      eiaFresh: T.classifyEvidenceFreshness(2 * 86400, 'EIA'),
      genericCurrent: T.classifyEvidenceFreshness(10 * 86400, null),
      genericAging: T.classifyEvidenceFreshness(20 * 86400, null),
      genericStale: T.classifyEvidenceFreshness(40 * 86400, null),
      unknown: T.classifyEvidenceFreshness(null, null),
    };
  });
  eq(r.nwsFresh, 'CURRENT', '20 min is inside the 30-min NWS window');
  eq(r.nwsAging, 'AGING', '45 min is aging for NWS');
  eq(r.nwsStale, 'STALE', '4 hours is stale for a 30-min cache — the generic 14-day rule must not apply');
  eq(r.eiaFresh, 'CURRENT', '2 days is inside the 3-day EIA throttle');
  eq(r.genericCurrent, 'CURRENT', '10 days generic');
  eq(r.genericAging, 'AGING', '20 days generic');
  eq(r.genericStale, 'STALE', '40 days generic');
  eq(r.unknown, 'UNKNOWN', 'unknown age is UNKNOWN, not CURRENT');
});

/* ---- backward compatibility ---- */

test('[M3-13] a decision built with no v24.1 input stays valid and backward-compatible', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const economicsResult = T.deriveUnifiedEconomics({ revenue:500, effectiveRevenue:500, loadedMi:80, deadMi:20, mpg:20, fuelPrice:4, opCPM:0.4 });
    const authorityResult = T.deriveUnifiedAuthority({ trueRPM:5, totalMi:100, deadheadPct:20, effectiveRevenue:500, netAfterFuel:450, profitMarginPct:40, opCPM:0.4, initialVerdict:'ACCEPT', geo:{intoDensity:true} });
    const d = T.buildUnifiedDecisionContract({ authorityResult, economicsResult, bidResult: T.deriveUnifiedBid(100, {}) });
    const legacy = T.unifiedDecisionToLegacy ? T.unifiedDecisionToLegacy(d) : null;
    return { evidence: d.evidence.length, overall: d.confidence.overall, verdict: d.authority.verdict, legacyOk: legacy ? legacy.trueRPM === d.economics.trueRPM : true };
  });
  eq(r.evidence, 0, 'no evidence supplied means an empty list, not a crash');
  eq(r.overall, 'LOW', 'and honestly reports LOW rather than defaulting to HIGH');
  eq(r.verdict, 'ACCEPT', 'the v24.0 verdict is untouched');
  ok(r.legacyOk, 'the legacy adapter still round-trips');
});

test('[M3-14] no calibrated percentage is ever emitted', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const item = T.buildEvidenceItem({ key:'m', category:'MARKET', source:'s', sourceStatus:'OK', sampleSize:12, observedAt:0, evaluatedAt:86400000 });
    const s = T.summarizeEvidenceConfidence([item], ['market']);
    return JSON.stringify({ item, s });
  });
  ok(!/\d+\s*%/.test(r), 'v24.1 must not emit any percentage — no calibrated odds until lifecycle data exists');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
