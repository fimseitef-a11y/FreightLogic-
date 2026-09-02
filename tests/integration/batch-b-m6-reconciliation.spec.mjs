// Issue #119 Batch B — M6 historical reconciliation correctness.
//
// Source audit: .agents/inbox/gpt-to-claude-batch-b-source-audit-2026-08-28.md
// Contract:     docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md
//
// The M6 machinery imported and calibrated. What it did NOT do was keep two
// shipments that reuse one external order number apart, keep a later operator
// correction ahead of an earlier AI guess, keep per-field provenance, keep DRY
// RUN out of ordinary economics without discarding it, or refuse to treat an
// undated observation as a fresh one. Each of those is a way to produce a
// confident number from evidence that does not support it.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/batch-b-m6-reconciliation.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

/* ═══════════════ B1 — bounded, collision-resistant identity ═══════════════ */

test('[B-01] the fingerprint is a real digest: bounded, deterministic, and collision-resistant', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const rec = {
      kind:'QUOTE_OBSERVATION', sourceName:'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv',
      rawEvidenceRef:'incr::Lake Zurich, IL-Toledo, OH-2026-08-21 operator-confirmed chat-recovered pending source match',
      origin:'Lake Zurich, IL', destination:'Toledo, OH', amount:450, sourceTimestamp:'2026-08-21T14:05:33Z',
    };
    const a = await T._historicalRowFingerprint(rec);
    const b = await T._historicalRowFingerprint({ ...rec });
    // Differ by ONE material fact.
    const c = await T._historicalRowFingerprint({ ...rec, amount: 451 });
    // Differ only by the clock inside the same day — the old numeric-only
    // coercion dropped ISO source timestamps entirely, so this pair collided.
    const d = await T._historicalRowFingerprint({ ...rec, sourceTimestamp:'2026-08-21T21:47:02Z' });
    return { a, b, c, d, len: a.length };
  });
  eq(r.a, r.b, 'identical input produces an identical token — re-import stays idempotent');
  ok(r.a !== r.c, 'a different amount is a different observation');
  ok(r.a !== r.d, 'a different source clock on the same day is a different observation');
  ok(r.len <= 120, `the token must fit the persisted 120-char provenance bound (was ${r.len})`);
  ok(/^fp:sha256:/.test(r.a), `a cryptographic digest, not a 32-bit hash — got ${r.a}`);
});

/* ═══════════════ B2/B3 — reused external IDs stay separate ═══════════════ */

test('[B-02] an external order number supplied as stableId is not accepted as internal identity', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    return {
      laundered: T._orderStableKey({ stableId: 'Q-4471', orderNo: 'Q-4471' }),
      derived: T._orderStableKey({ orderNo: 'Q-4471', broker: 'Acme Logistics' }),
      internal: T._orderStableKey({ internalStableId: 'fl-internal-9' }),
      neither: T._orderStableKey({ orderNo: 'Q-4471' }),
    };
  });
  eq(r.laundered, '', 'a bare provider order number must never become internal identity');
  eq(r.derived, 'ord:acme logistics|Q-4471', 'broker + order remains a derivable candidate key');
  eq(r.internal, 'ord:FL-INTERNAL-9', 'an explicitly INTERNAL identity is still honoured');
  eq(r.neither, '', 'an order number with no broker forms no identity at all');
});

test('[B-03] two shipments reusing one order number on different lanes stay two records', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const base = {
      kind:'ORDER', orderNo:'DUP-4471', broker:'Acme Logistics', operatorConfirmed:true,
      amount: 900, priceSemantic:'CARRIER_PAYOUT', opportunity:'WON',
    };
    const before = (await T.listLifecycle()).length;
    await T.importHistoricalOpportunities([
      { ...base, origin:'Chicago, IL', destination:'Toledo, OH',   pickupAt:'2026-05-04T08:15:00Z', sourceName:'a.csv', rawEvidenceRef:'a:1' },
      { ...base, origin:'Chicago, IL', destination:'Nashville, TN', pickupAt:'2026-07-19T06:00:00Z', sourceName:'b.csv', rawEvidenceRef:'b:1' },
    ], {});
    const rows = (await T.listLifecycle()).filter(x => x.orderNo === 'DUP-4471');
    return { added: (await T.listLifecycle()).length - before, count: rows.length, dests: rows.map(x => x.destination).sort() };
  });
  eq(r.count, 2, 'a reused external order number on incompatible lanes must not collapse two shipments into one');
  eq(r.dests.join('|'), 'Nashville, TN|Toledo, OH', 'and each keeps its own route');
});

test('[B-04] the same shipment seen twice on compatible facts still reconciles to one record', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const base = {
      kind:'ORDER', orderNo:'SAME-77', broker:'Acme Logistics', operatorConfirmed:true,
      origin:'Gary, IN', destination:'Erie, PA', pickupAt:'2026-06-02T09:00:00Z',
      amount: 700, priceSemantic:'CARRIER_PAYOUT', opportunity:'WON',
    };
    await T.importHistoricalOpportunities([{ ...base, sourceName:'a.csv', rawEvidenceRef:'a:77' }], {});
    await T.importHistoricalOpportunities([{ ...base, sourceName:'b.csv', rawEvidenceRef:'b:77', execution:'DELIVERED' }], {});
    const rows = (await T.listLifecycle()).filter(x => x.orderNo === 'SAME-77');
    return { count: rows.length, execution: rows[0]?.execution };
  });
  eq(r.count, 1, 'compatible route/time evidence still reconciles — the fix is not "never link"');
  eq(r.execution, 'DELIVERED', 'and the second source contributes its state');
});

/* ═══════════════ B4/B5 — authority precedence and field provenance ═══════════════ */

test('[B-05] a later operator correction supersedes a populated lower-authority value', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const ai = {
      amount: 700, loadedMi: 300, origin: 'Chicago, IL',
      provenance: { authority:'AI_SECONDARY', sourceName:'RECOVERED.csv', sourceTimestampMs: 1000 },
    };
    const correction = {
      amount: 985,
      provenance: { authority:'OPERATOR_CORRECTION', sourceName:'operator', sourceTimestampMs: 2000 },
    };
    return T.reconcileEvidenceFields([ai, correction], ['amount','loadedMi','origin']);
  });
  eq(r.values.amount, 985, 'the correction wins over an already-populated AI value — fill-blanks could never do this');
  eq(r.fieldProvenance.amount.authority, 'OPERATOR_CORRECTION', 'and the winning authority is auditable');
  eq(r.values.loadedMi, 300, 'a field the correction did not touch keeps its value');
  eq(r.fieldProvenance.loadedMi.sourceName, 'RECOVERED.csv',
     'B5: that field still names the file it actually came from, not the winning row');
});

test('[B-06] per-field provenance survives into persisted evidence', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'PROV-1', broker:'Acme Logistics', operatorConfirmed:true,
      origin:'Fort Wayne, IN', destination:'Columbus, OH', pickupAt:'2026-04-01T07:00:00Z',
      amount: 640, priceSemantic:'CARRIER_PAYOUT', loadedMi: 220, mileageSemantic:'LOADED_MILES',
      sourceName:'All_Trips_App_Import_v1.csv', rawEvidenceRef:'alltrips:PROV-1',
      // Merged by the adapter from two different files.
      fieldProvenance: {
        amount:   { sourceName:'All_Trips_App_Import_v1.csv', authority:'OPERATOR_CONFIRMED_HISTORY' },
        loadedMi: { sourceName:'COMPLETE-UNIFIED-DATA.csv',   authority:'OPERATOR_CONFIRMED_HISTORY' },
      },
    }], {});
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'PROV-1');
    return {
      found: !!ev,
      amountSource: ev?.fieldProvenance?.amount?.sourceName,
      milesSource: ev?.fieldProvenance?.loadedMi?.sourceName,
      rowSource: ev?.provenance?.sourceName,
    };
  });
  ok(r.found, 'historical import persists durable evidence, not just lifecycle state');
  eq(r.amountSource, 'All_Trips_App_Import_v1.csv', 'the amount names its own source');
  eq(r.milesSource, 'COMPLETE-UNIFIED-DATA.csv',
     'and the mileage names the different file it actually came from — one row-level label would misattribute it');
});

/* ═══════════════ B6 — a Carrier column is not a broker ═══════════════ */

test('[B-07] a source carrier label is preserved as a carrier label, never promoted to broker', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'CARR-1', broker:'', carrierLabel:'Expedite Partners LLC',
      origin:'Toledo, OH', destination:'Erie, PA', pickupAt:'2026-05-11T10:00:00Z',
      amount: 500, priceSemantic:'CARRIER_PAYOUT', operatorConfirmed:true,
      sourceName:'text 2.csv', rawEvidenceRef:'text2:CARR-1',
    }], {});
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'CARR-1');
    const lc = (await T.listLifecycle()).find(e => e.orderNo === 'CARR-1');
    return { carrierLabel: ev?.carrierLabel, evBroker: ev?.broker, lcBroker: lc?.broker };
  });
  eq(r.carrierLabel, 'Expedite Partners LLC', 'the value is preserved under its actual source semantic');
  eq(r.evBroker, '', 'and canonical broker stays UNKNOWN rather than guessed');
  eq(r.lcBroker, '', 'in the lifecycle record too');
});

/* ═══════════════ B7 — DRY RUN is preserved and excluded ═══════════════ */

test('[B-08] a dry run is imported as its own class and excluded from normal-market calibration', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'DRY-1', broker:'Acme Logistics', operationalClass:'DRY_RUN',
      origin:'Gary, IN', destination:'Gary, IN', pickupAt:'2026-06-15T05:00:00Z',
      amount: 0, priceSemantic:'CARRIER_PAYOUT', opportunity:'SEEN', awarded:false,
      sourceName:'RECOVERED.csv', rawEvidenceRef:'recovered:DRY-1', statusRaw:'dry_run',
    }], {});
    const lc = (await T.listLifecycle()).find(e => e.orderNo === 'DRY-1');
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'DRY-1');
    const rate = T.lifecycleWinRate([lc, { opportunity:'WON', cohort:{ normalMarketEligible:true } }, { opportunity:'LOST', cohort:{ normalMarketEligible:true } }]);
    const cal = T.calibrateWinningRange([
      { won:true, rpm: 9.99, observedAt: Date.now(), dryRun: true },
      { won:true, rpm: 1.70, observedAt: Date.now() },
      { won:true, rpm: 1.80, observedAt: Date.now() },
      { won:true, rpm: 1.75, observedAt: Date.now() },
    ]);
    return {
      persisted: !!lc, evidencePersisted: !!ev, opClass: ev?.operationalClass,
      dryRunFlag: lc?.cohort?.dryRun, eligible: lc?.cohort?.normalMarketEligible,
      excludedDryRun: rate.excludedDryRun, calExcluded: cal.excludedDryRun, mean: cal.weightedMeanRpm,
    };
  });
  ok(r.persisted, 'a dry run is preserved operational history — discarding it loses the record entirely');
  ok(r.evidencePersisted, 'with its durable evidence row');
  eq(r.opClass, 'DRY_RUN', 'under its own operational class');
  eq(r.dryRunFlag, true, 'flagged distinctly from a DZ-EXIT — they are different operational facts');
  eq(r.eligible, false, 'and excluded from normal-market eligibility');
  eq(r.excludedDryRun, 1, 'the win-rate denominator reports the exclusion');
  eq(r.calExcluded, 1, 'and so does calibration');
  ok(r.mean !== null && r.mean < 2, `a $9.99 dry run must not enter the winning range — got ${r.mean}`);
});

/* ═══════════════ B8 — an unknown status never manufactures an award ═══════════════ */

test('[B-09] an unrecognized secondary status produces no award and no WON', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'UNK-1', broker:'Acme Logistics',
      origin:'Erie, PA', destination:'Gary, IN', pickupAt:'2026-07-02T12:00:00Z',
      amount: 550, priceSemantic:'CARRIER_PAYOUT',
      opportunity:'SEEN', awarded:null, statusRaw:'some_status_we_do_not_recognise',
      operatorConfirmed:false, sourceName:'RECOVERED.csv', rawEvidenceRef:'recovered:UNK-1',
    }], {});
    const lc = (await T.listLifecycle()).find(e => e.orderNo === 'UNK-1');
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'UNK-1');
    return { opportunity: lc?.opportunity, awarded: ev?.awarded, statusRaw: ev?.statusRaw, claim: ev?.opportunityClaim };
  });
  eq(r.opportunity, 'SEEN', 'an unrecognized status cannot promote a record to WON');
  eq(r.awarded, null, 'and cannot set an award flag — null is not false and emphatically not true');
  eq(r.statusRaw, 'some_status_we_do_not_recognise', 'the raw source status is still preserved as a claim');
  eq(r.claim, 'SEEN', 'the evidence records what the source actually established');
});

/* ═══════════════ B9 — timestamps keep their precision ═══════════════ */

test('[B-10] a full source timestamp survives import into persisted evidence unchanged', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'TS-1', broker:'Acme Logistics',
      origin:'Chicago, IL', destination:'Toledo, OH',
      pickupAt:'2026-08-21T14:05:33Z', deliveryAt:'2026-08-21T22:41:09Z',
      sourceTimestamp:'2026-08-21T14:05:33Z', observedAt:'2026-08-21T14:05:33Z',
      amount: 600, priceSemantic:'CARRIER_PAYOUT', operatorConfirmed:true,
      sourceName:'INCREMENTAL.csv', rawEvidenceRef:'incr:TS-1',
    }], {});
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'TS-1');
    return {
      pickupAt: ev?.pickupAt, deliveryAt: ev?.deliveryAt,
      sourceTs: ev?.provenance?.sourceTimestamp, observedISO: ev?.observedAtISO,
    };
  });
  eq(r.pickupAt, '2026-08-21T14:05:33Z', 'the pickup clock is not sliced down to a date');
  eq(r.deliveryAt, '2026-08-21T22:41:09Z', 'nor the delivery clock');
  eq(r.sourceTs, '2026-08-21T14:05:33Z', 'the source timestamp survives as an instant, not a null');
  eq(r.observedISO, '2026-08-21T14:05:33Z', 'and the observation instant keeps full precision');
});

/* ═══════════════ B10/B11 — recency weighting ═══════════════ */

test('[B-11] an undated win never receives full current weight', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const now = Date.now();
    const undatedOnly = T.calibrateWinningRange([
      { won:true, rpm: 3.00, observedAt: null },
      { won:true, rpm: 3.10, observedAt: null },
      { won:true, rpm: 3.20, observedAt: null },
    ], { now, minSamples: 3 });
    const mixed = T.calibrateWinningRange([
      { won:true, rpm: 3.00, observedAt: null },
      { won:true, rpm: 1.70, observedAt: now },
      { won:true, rpm: 1.75, observedAt: now },
      { won:true, rpm: 1.80, observedAt: now },
    ], { now, minSamples: 3 });
    return { undatedOnly, mixed };
  });
  eq(r.undatedOnly.sufficientSamples, false,
     'three undated rows cannot by themselves satisfy a recency-weighted sample floor');
  eq(r.undatedOnly.weightedMeanRpm, null, 'so no winning range is produced from them');
  eq(r.undatedOnly.winningRangeSampleSize, 3, 'while the rows stay visible and counted');
  eq(r.undatedOnly.unknownAgeCount, 3, 'and their unknown age is reported so the exclusion is inspectable');
  eq(r.mixed.weightedSampleSize, 3, 'only the dated rows carry recency weight');
  ok(r.mixed.weightedMeanRpm < 1.9,
     `the undated $3.00 row must not pull the range up — got ${r.mixed.weightedMeanRpm}`);
  ok(r.mixed.weights.every(w => w.rpm !== 3.00), 'and it appears in no weight row at all');
});

test('[B-12] importing or correcting an old row today does not reset its calibration age', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const now = Date.now();
    // A lifecycle row mutated RIGHT NOW (imported/corrected today) whose
    // evidence carries no durable observation time.
    const rows = [
      { lifecycleId:'lc_old_1', opportunity:'WON', updatedAt: now, cohort:{} },
      { lifecycleId:'lc_old_2', opportunity:'WON', updatedAt: now, cohort:{} },
      { lifecycleId:'lc_old_3', opportunity:'WON', updatedAt: now, cohort:{} },
    ];
    const noObservationTime = T.calibrateFromLifecycle(rows, () => ({ rpm: 2.50 }), { now, minSamples: 3 });
    // The same rows WITH a real, old source observation time.
    const twoYearsAgo = now - 730 * 86400000;
    const dated = T.calibrateFromLifecycle(rows, () => ({ rpm: 2.50, observedAt: twoYearsAgo }), { now, minSamples: 3 });
    return { noObservationTime, dated };
  });
  eq(r.noObservationTime.unknownAgeCount, 3,
     'a lifecycle mutation clock must never stand in for a market-observation clock');
  eq(r.noObservationTime.sufficientSamples, false, 'so these rows support no recency-weighted range');
  eq(r.noObservationTime.weightedMeanRpm, null, 'and produce none');
  eq(r.dated.weightedSampleSize, 3, 'a real observation time makes them weightable...');
  ok(r.dated.weights.every(w => w.weight < 0.1),
     `...at a properly decayed weight for two-year-old evidence — got ${JSON.stringify(r.dated.weights)}`);
});

/* ═══════════════ B12 — one evidence layer, not a parallel structure ═══════════════ */

test('[B-13] historical evidence survives export and re-import with its semantics', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    await T.importHistoricalOpportunities([{
      kind:'ORDER', orderNo:'RT-HIST-1', broker:'Acme Logistics', operatorConfirmed:true,
      origin:'Chicago, IL', destination:'Toledo, OH', pickupAt:'2026-03-05T11:22:33Z',
      amount: 812, priceSemantic:'SETTLED_AMOUNT',
      displayedTotalMi: 305, mileageSemantic:'DISPLAYED_TOTAL_MILES', sourceDisplayedRpm: 2.66,
      observedAt:'2026-03-05T11:22:33Z', sourceName:'unified.csv', rawEvidenceRef:'unified:RT-HIST-1',
    }], {});

    const captured = {};
    const origCreate = URL.createObjectURL;
    URL.createObjectURL = (blob) => { captured.blob = blob; return origCreate.call(URL, blob); };
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function(){};
    try { await T.exportJSON(); } finally { URL.createObjectURL = origCreate; HTMLAnchorElement.prototype.click = origClick; }
    const text = await captured.blob.text();

    await new Promise((resolve, reject) => {
      const q = indexedDB.open('FreightLogic_v18');
      q.onsuccess = () => { const d = q.result; const t = d.transaction('normalizedEvidence','readwrite');
        t.objectStore('normalizedEvidence').clear(); t.oncomplete = () => { d.close(); resolve(); }; t.onerror = () => reject(t.error); };
      q.onerror = () => reject(q.error);
    });
    await T.importJSON(new File([text], 'e.json', { type:'application/json' }), { mode:'merge' });
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'RT-HIST-1');
    return {
      restored: !!ev, amount: ev?.amount, semantic: ev?.priceSemantic, revenue: ev?.canonicalRevenue,
      displayedTotalMi: ev?.displayedTotalMi, loadedMi: ev?.loadedMi,
      sourceRpm: ev?.sourceDisplayedRpm, observedISO: ev?.observedAtISO,
    };
  });
  ok(r.restored, 'historical evidence uses the same durable layer, so it round-trips like any other evidence');
  eq(r.amount, 812, 'the amount survives');
  eq(r.semantic, 'SETTLED_AMOUNT', 'the price semantic survives');
  eq(r.revenue, 812, 'a settled amount is legitimately canonical revenue');
  eq(r.displayedTotalMi, 305, 'a displayed total stays a displayed total');
  eq(r.loadedMi, null, 'and never becomes loaded miles');
  eq(r.sourceRpm, 2.66, 'a source-displayed RPM is retained as source evidence');
  eq(r.observedISO, '2026-03-05T11:22:33Z', 'with its observation instant intact');
});

test('[B-14] a source-displayed RPM is never promoted into canonical True RPM', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const ev = (await T.listEvidence()).find(e => e.orderNo === 'RT-HIST-1');
    // Canonical economics refuses to compute at all without the facts.
    const econ = T.deriveUnifiedEconomics({
      loadedMi: ev.loadedMi, deadMi: ev.deadMi, revenue: ev.canonicalRevenue,
      mpg: 17.5, fuelPrice: 3.55,
    });
    return { sourceRpm: ev.sourceDisplayedRpm, available: econ.available, trueRPM: econ.trueRPM, unknown: econ.unknownFacts };
  });
  eq(r.sourceRpm, 2.66, 'the source figure is kept as evidence');
  eq(r.available, false, 'but with loaded and deadhead miles unknown, canonical economics is unavailable');
  eq(r.trueRPM, null, 'True RPM is null — never the source-displayed number, and never zero');
  ok(Array.isArray(r.unknown) && r.unknown.length > 0, 'and the missing facts are named');
});

export async function runSpec(){
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
