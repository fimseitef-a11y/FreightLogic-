// Milestone 6 — historical import + calibration MACHINERY.
//
// The pathway, not the operator's data. These fixtures are synthetic stand-ins
// for operator-verified files; when real files arrive it is a data-load, not a
// build. Covers the M6 rules from docs/COMPLETION_RELEASE_PLAN_2026-08-25.md:
// order vs quote-observation dedup, quote-is-not-completed, provenance and
// price-semantic preservation, DZ-EXIT cohort separation, no broker inference,
// and deterministic recency/sample-weighted calibration.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m6-historical-import.spec.mjs');
let app;

const importRows = (records, opts) => app.page.evaluate(
  ({ records, opts }) => window.__FL_TESTS.importHistoricalOpportunities(records, opts),
  { records, opts });
const calibrate = (obs, opts) => app.page.evaluate(
  ({ obs, opts }) => window.__FL_TESTS.calibrateWinningRange(obs, opts),
  { obs, opts });

test('[M6-01] orders and quote observations both import through the lifecycle', async () => {
  const r = await importRows([
    { kind:'ORDER', orderNo:'H-1', broker:'Acme', origin:'Chicago, IL', destination:'Toledo, OH', opportunity:'WON', execution:'DELIVERED', settlement:'PAID', amount:900, priceSemantic:'CARRIER_PAYOUT', operatorConfirmed:true, sourceName:'orders.csv', sourceTimestamp:1000 },
    { kind:'QUOTE_OBSERVATION', broker:'Acme', origin:'Chicago, IL', destination:'Detroit, MI', amount:500, priceSemantic:'SHIPPER_BOOKABLE_PRICE', sourceName:'quotes.csv', sourceTimestamp:2000 },
  ], { sourceFile:'batch-1' });
  eq(r.orders, 1, 'one order imported');
  eq(r.quoteObservations, 1, 'one quote observation imported');
  eq(r.errors, 0, 'no errors');
});

test('[M6-02] re-importing the same file is idempotent — no duplicates', async () => {
  const rows = [
    { kind:'ORDER', orderNo:'IDEM-1', broker:'Beta', opportunity:'WON', amount:800, priceSemantic:'CARRIER_PAYOUT', operatorConfirmed:true, sourceName:'idem.csv', sourceTimestamp:5000 },
    { kind:'QUOTE_OBSERVATION', broker:'Beta', origin:'A', destination:'B', amount:400, sourceName:'idem.csv', sourceTimestamp:5001 },
  ];
  const first = await importRows(rows, { sourceFile:'idem' });
  const second = await importRows(rows, { sourceFile:'idem' });
  eq(first.imported + first.quoteObservations >= 2 ? 2 : first.imported, 2, 'first pass imports both');
  eq(second.duplicatesSkipped, 2, 'second pass skips both as already imported');
  eq(second.imported, 0, 'nothing new created on re-import');
});

test('[M6-03] a quote observation is never dedup-collapsed by quote-ID alone', async () => {
  // Two DIFFERENT observations that happen to share a reused quote/order number
  // must remain two distinct records — quote-ID is not identity.
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const before = (await T.listLifecycle()).length;
    await T.importHistoricalOpportunities([
      { kind:'QUOTE_OBSERVATION', orderNo:'REUSED-9', broker:'Gamma', origin:'A', destination:'B', amount:300, sourceName:'q.csv', sourceTimestamp:7000 },
      { kind:'QUOTE_OBSERVATION', orderNo:'REUSED-9', broker:'Gamma', origin:'C', destination:'D', amount:600, sourceName:'q.csv', sourceTimestamp:8000 },
    ], { sourceFile:'reuse' });
    return { added: (await T.listLifecycle()).length - before };
  });
  eq(r.added, 2, 'two distinct observations with a reused quote-ID stay two records');
});

test('[M6-04] a quote observation cannot claim WON without operator award evidence', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([
      // Claims WON but is a quote observation with no operator award evidence.
      { kind:'QUOTE_OBSERVATION', orderNo:'QW-1', broker:'Delta', origin:'A', destination:'B', opportunity:'WON', amount:500, sourceName:'q.csv', sourceTimestamp:9000 },
    ], { sourceFile:'qw' });
    const row = (await T.listLifecycle()).find(x => x.orderNo === 'QW-1');
    return { opportunity: row?.opportunity };
  });
  eq(r.opportunity, 'SEEN', 'an unproven quote observation stays SEEN, never a fabricated WON');
});

test('[M6-05] an operator-confirmed correction on a quote IS honored (the expired-batch case)', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    // The 2026-08-24 expired batch: operator explicitly confirmed these as LOST.
    await T.importHistoricalOpportunities([
      { kind:'QUOTE_OBSERVATION', orderNo:'EXP-1', broker:'Epsilon', origin:'A', destination:'B', opportunity:'LOST', operatorConfirmed:true, awarded:true, amount:500, priceSemantic:'OPERATOR_BID', sourceName:'expired.csv', sourceTimestamp:10000 },
    ], { sourceFile:'expired' });
    const row = (await T.listLifecycle()).find(x => x.orderNo === 'EXP-1');
    return { opportunity: row?.opportunity };
  });
  eq(r.opportunity, 'LOST', 'an operator correction overrides the SEEN default — LOST comes from the operator, not from EXPIRED alone');
});

test('[M6-06] order history links to an existing lifecycle by stable identity', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    // Same broker+order across two files: a BID observed first, then WON.
    await T.importHistoricalOpportunities([
      { kind:'ORDER', orderNo:'LINK-1', broker:'Zeta', opportunity:'BID', amount:0, sourceName:'f1.csv', sourceTimestamp:11000 },
    ], { sourceFile:'f1' });
    await T.importHistoricalOpportunities([
      { kind:'ORDER', orderNo:'LINK-1', broker:'Zeta', opportunity:'WON', execution:'DELIVERED', amount:900, priceSemantic:'CARRIER_PAYOUT', operatorConfirmed:true, sourceName:'f2.csv', sourceTimestamp:12000 },
    ], { sourceFile:'f2' });
    const rows = (await T.listLifecycle()).filter(x => x.orderNo === 'LINK-1');
    return { count: rows.length, opportunity: rows[0]?.opportunity, execution: rows[0]?.execution };
  });
  eq(r.count, 1, 'the same broker+order is ONE lifecycle across files');
  eq(r.opportunity, 'WON', 'the later state wins');
  eq(r.execution, 'DELIVERED', 'the operator-confirmed correction is preserved');
});

test('[M6-07] an order with no broker cannot form a stable identity', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      full: T._orderStableKey({ broker:'Acme', orderNo:'X-1' }),
      noBroker: T._orderStableKey({ orderNo:'X-1' }),
      noOrder: T._orderStableKey({ broker:'Acme' }),
      customerOnly: T._orderStableKey({ customer:'some shipper text' }),
    };
  });
  ok(r.full.startsWith('ord:'), 'broker + order is a stable key');
  eq(r.noBroker, '', 'an order number alone is not identity');
  eq(r.noOrder, '', 'a broker alone is not identity');
  eq(r.customerOnly, '', 'ambiguous customer text is never identity');
});

test('[M6-08] price semantic and source provenance survive import', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([
      { kind:'ORDER', orderNo:'PROV-1', broker:'Theta', opportunity:'WON', amount:875, priceSemantic:'SETTLED_AMOUNT', operatorConfirmed:true, sourceName:'settlements.csv', sourceTimestamp:13000, rawEvidenceRef:'settle-abc' },
    ], { sourceFile:'prov' });
    const row = (await T.listLifecycle()).find(x => x.orderNo === 'PROV-1');
    return { source: row?.lastMutation?.source, imported: row?.migration?.importedLegacy, tokens: row?.migration?.migratedFrom?.length };
  });
  eq(r.source, 'IMPORT', 'recorded as an IMPORT mutation');
  eq(r.imported, true, 'flagged as imported legacy history');
  ok(r.tokens >= 1, 'provenance fingerprint retained for idempotency');
});

/* ---- calibration: deterministic, DZ-excluded, sample-aware ---- */

test('[M6-09] win rate obeys the lifecycle denominator and excludes DZ-EXIT', async () => {
  const r = await calibrate([
    { won:true,  rpm:1.8, observedAt:1000, deadZoneExit:false },
    { won:true,  rpm:1.6, observedAt:1000, deadZoneExit:false },
    { won:false, rpm:null, observedAt:1000, deadZoneExit:false },
    { won:true,  rpm:0.95, observedAt:1000, deadZoneExit:true },  // DZ — excluded
  ], { now: 1000, minSamples: 1 });
  eq(r.winDenominator, 3, 'DZ win excluded from the normal-market denominator');
  eq(r.wonCount, 2, 'two normal-market wins');
  eq(r.excludedDeadZone, 1, 'the DZ observation is excluded and reported');
  eq(Math.round(r.winRate * 100), 67, '2 of 3');
});

test('[M6-10] winning range needs enough samples and is null below the floor', async () => {
  const few = await calibrate([
    { won:true, rpm:1.8, observedAt:1000, deadZoneExit:false },
    { won:true, rpm:1.6, observedAt:1000, deadZoneExit:false },
  ], { now:1000, minSamples:3 });
  eq(few.sufficientSamples, false, '2 priced wins is below a 3-sample floor');
  eq(few.weightedMeanRpm, null, 'no range is asserted from too few samples');
});

test('[M6-11] recency weighting is deterministic and inspectable', async () => {
  const DAY = 86400000;
  const now = 100 * DAY;
  const obs = [
    { won:true, rpm:2.0, observedAt: now,            deadZoneExit:false }, // fresh, full weight
    { won:true, rpm:1.0, observedAt: now - 60*DAY,   deadZoneExit:false }, // one half-life old
    { won:true, rpm:1.5, observedAt: now,            deadZoneExit:false },
  ];
  const a = await calibrate(obs, { now, halfLifeDays:60, minSamples:3 });
  const b = await calibrate(obs, { now, halfLifeDays:60, minSamples:3 });
  eq(JSON.stringify(a), JSON.stringify(b), 'identical inputs give identical output');
  // The 60-day-old 1.0 observation carries weight 0.5; the fresh ones weight 1.
  const oldWeight = a.weights.find(w => w.rpm === 1.0).weight;
  eq(oldWeight, 0.5, 'a one-half-life-old observation is weighted exactly 0.5');
  ok(a.weightedMeanRpm > 1.5, 'fresh high-RPM wins pull the weighted mean above the naive mean');
});

test('[M6-12] an unknown RPM never counts as 0 in the winning range', async () => {
  const r = await calibrate([
    { won:true, rpm:1.8, observedAt:1000, deadZoneExit:false },
    { won:true, rpm:null, observedAt:1000, deadZoneExit:false }, // unknown — excluded, not 0
    { won:true, rpm:1.6, observedAt:1000, deadZoneExit:false },
    { won:true, rpm:1.7, observedAt:1000, deadZoneExit:false },
  ], { now:1000, minSamples:3 });
  eq(r.winningRangeSampleSize, 3, 'the unknown-RPM win is excluded from the priced sample, not counted as 0');
  ok(r.weightedMeanRpm >= 1.6 && r.weightedMeanRpm <= 1.8, 'the mean reflects only known RPMs');
});

test('[M6-13] an all-DZ or empty dataset yields a null win rate, not 0%', async () => {
  const empty = await calibrate([], { now:1000 });
  eq(empty.winRate, null, 'no data => null win rate');
  const allDz = await calibrate([{ won:true, rpm:0.95, observedAt:1000, deadZoneExit:true }], { now:1000 });
  eq(allDz.winDenominator, 0, 'all DZ => no normal-market denominator');
  eq(allDz.winRate, null, 'and a null rate, never 0%');
});

test('[M6-14] calibrateFromLifecycle bridges lifecycle rows via an rpm lookup', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const rows = [
      { lifecycleId:'lc1', opportunity:'WON',  updatedAt:1000, cohort:{ deadZoneExit:false } },
      { lifecycleId:'lc2', opportunity:'LOST', updatedAt:1000, cohort:{ deadZoneExit:false } },
      { lifecycleId:'lc3', opportunity:'SEEN', updatedAt:1000, cohort:{ deadZoneExit:false } },
    ];
    const rpm = { lc1: { rpm:1.75, observedAt:1000 } };
    return T.calibrateFromLifecycle(rows, id => rpm[id], { now:1000, minSamples:1 });
  });
  eq(r.winDenominator, 2, 'only WON+LOST rows enter the denominator; SEEN is excluded');
  eq(r.wonCount, 1, 'one win');
  eq(r.winningRangeSampleSize, 1, 'one priced win from the lookup');
});

test('[M6-15] a quote observation with LONG provenance stays idempotent on re-import', async () => {
  // Regression for the real 2026-08-27 bundle: fingerprints ran ~200 chars,
  // but migration.migratedFrom is persisted through clampStr(120). An unhashed
  // fingerprint was truncated on write and never matched on re-import, so
  // fingerprint-only quote observations duplicated. The fingerprint is now a
  // bounded hash. A long source name + evidence ref reproduces the overflow.
  const longSource = 'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv';
  const longEvidence = 'incr::Lake Zurich, IL-Toledo, OH-2026-08-21 operator-confirmed chat-recovered pending source match';
  const rec = { kind:'QUOTE_OBSERVATION', origin:'Lake Zurich, IL', destination:'Toledo, OH',
    amount:450, priceSemantic:'OPERATOR_BID', sourceName:longSource, sourceTimestamp:1787702400000, rawEvidenceRef:longEvidence };
  const r = await app.page.evaluate(async (rec) => {
    const T = window.__FL_TESTS;
    // B1 (Issue #119 Batch B): the fingerprint is now a SHA-256 digest, so it
    // is async. The bound it has to fit under is unchanged.
    const fp = await T._historicalRowFingerprint(rec);
    const before = (await T.listLifecycle()).length;
    await T.importHistoricalOpportunities([rec], { sourceFile:'longprov' });
    const mid = (await T.listLifecycle()).length;
    await T.importHistoricalOpportunities([rec], { sourceFile:'longprov' }); // re-import
    const after = (await T.listLifecycle()).length;
    return { fpLen: fp.length, addedFirst: mid - before, addedSecond: after - mid };
  }, rec);
  ok(r.fpLen <= 120, `the stored fingerprint token must fit under the 120-char persistence limit (was ${r.fpLen})`);
  eq(r.addedFirst, 1, 'first import creates the observation');
  eq(r.addedSecond, 0, 're-importing the same long-provenance observation must NOT duplicate');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
