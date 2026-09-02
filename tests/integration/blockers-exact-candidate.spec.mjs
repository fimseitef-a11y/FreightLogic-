// v24.0.2 exact-candidate blockers 1-8.
//
// Source: .agents/inbox/gpt-to-claude-v2402-exact-candidate-blockers-2026-08-28.md
//
// Each of these is a way for the app to hold a confident record it cannot
// justify: lifecycle state for evidence that was never stored, a broker
// borrowed from a customer field, an external order number wearing internal
// identity, a whole typed row promoted by one checkbox, a historical HOLD that
// can never be cleared without rewriting history, a retained value relabelled
// with someone else's provenance, an older export quietly overwriting a newer
// correction, and a "no-op" re-import that rewrites protected history.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/blockers-exact-candidate.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

/* ═════════ 1. evidence-first durability ═════════ */

test('[BL-01] manual intake persists evidence BEFORE it creates lifecycle state', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    // Record the exact order of store writes on the real path.
    const order = [];
    const origPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function(...args){
      if (this.name === 'normalizedEvidence' || this.name === 'loadLifecycle') order.push(this.name);
      return origPut.apply(this, args);
    };
    try {
      await T.intakeOpportunity({ orderNo:'ORDER-1', broker:'Acme Logistics', origin:'Chicago, IL',
        destination:'Toledo, OH', amount: 800, priceSemantic:'CARRIER_PAYOUT' }, { sourceType:'MANUAL' });
    } finally { IDBObjectStore.prototype.put = origPut; }
    return { order };
  });
  eq(r.order[0], 'normalizedEvidence',
     `the semantic observation must be durable first — got write order ${JSON.stringify(r.order)}`);
  ok(r.order.includes('loadLifecycle'), 'lifecycle state is still created');
  ok(r.order.indexOf('normalizedEvidence') < r.order.indexOf('loadLifecycle'),
     'lifecycle state is never committed for an observation that is not yet stored');
});

test('[BL-02] a failed first evidence write creates no lifecycle row at all', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const before = (await T.listLifecycle()).length;
    const origPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function(...args){
      if (this.name === 'normalizedEvidence') throw new Error('simulated evidence store failure');
      return origPut.apply(this, args);
    };
    let threw = null;
    try {
      await T.intakeOpportunity({ orderNo:'FAIL-EV-1', broker:'Acme Logistics', origin:'Gary, IN',
        destination:'Erie, PA', amount: 500, priceSemantic:'CARRIER_PAYOUT' }, { sourceType:'MANUAL' });
    } catch(e){ threw = String(e?.message || e); }
    finally { IDBObjectStore.prototype.put = origPut; }
    const after = await T.listLifecycle();
    return { threw, added: after.length - before, orphan: after.some(x => x.orderNo === 'FAIL-EV-1') };
  });
  ok(r.threw, 'the failure surfaces rather than being swallowed');
  eq(r.added, 0, 'no lifecycle row is created when the evidence write failed');
  eq(r.orphan, false, 'and specifically no row for this observation — lifecycle never leads evidence');
});

test('[BL-03] a failed link attachment still leaves the observation durable', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    let evidenceWrites = 0;
    const origPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function(...args){
      // Let phase 1 through; fail the phase-3 attachment.
      if (this.name === 'normalizedEvidence' && ++evidenceWrites > 1) throw new Error('simulated attachment failure');
      return origPut.apply(this, args);
    };
    let res;
    try {
      res = await T.intakeOpportunity({ orderNo:'ATTACH-1', broker:'Acme Logistics', origin:'Fort Wayne, IN',
        destination:'Columbus, OH', amount: 640, priceSemantic:'CARRIER_PAYOUT' }, { sourceType:'EMAIL' });
    } finally { IDBObjectStore.prototype.put = origPut; }
    const stored = (await T.listEvidence()).find(e => e.orderNo === 'ATTACH-1');
    return { attachmentFailed: res?.attachmentFailed, stored: !!stored, amount: stored?.amount, linkState: stored?.linkState };
  });
  eq(r.attachmentFailed, true, 'the failed attachment is reported, not papered over as success');
  ok(r.stored, 'the observation itself stays durable — evidence is never deleted to tidy up');
  eq(r.amount, 640, 'with its material facts intact');
  eq(r.linkState, 'UNLINKED', 'and its link state honestly reflects that it is not attached');
});

test('[BL-04] historical import is evidence-first too', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const order = [];
    const origPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function(...args){
      if (this.name === 'normalizedEvidence' || this.name === 'loadLifecycle') order.push(this.name);
      return origPut.apply(this, args);
    };
    try {
      await T.importHistoricalOpportunities([{
        kind:'ORDER', orderNo:'HIST-ORD-1', broker:'Acme Logistics', operatorConfirmed:true,
        origin:'Chicago, IL', destination:'Toledo, OH', pickupAt:'2026-04-02T08:00:00Z',
        amount: 900, priceSemantic:'CARRIER_PAYOUT', opportunity:'WON',
        sourceName:'hist.csv', rawEvidenceRef:'hist:1',
      }], {});
    } finally { IDBObjectStore.prototype.put = origPut; }
    return { order };
  });
  eq(r.order[0], 'normalizedEvidence',
     `M6 had the same asymmetry in a different form — got ${JSON.stringify(r.order)}`);
  ok(r.order.indexOf('normalizedEvidence') < r.order.indexOf('loadLifecycle'),
     'the historical provenance row is durable before the lifecycle row it describes');
});

/* ═════════ 2/3. identity laundering ═════════ */

test('[BL-05] a customer name is never promoted into broker identity', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const rows = [{ lifecycleId:'lc_cust', orderNo:'CUST-9', broker: T.normBroker ? 'some company llc' : 'some company llc' }];
    // A trip whose ONLY company-ish field is `customer`.
    const m = T.resolveLifecycleForTrip(
      { orderNo:'CUST-9', customer:'Some Company LLC', origin:'Gary, IN', destination:'Erie, PA' }, rows);
    return { linked: !!m.lifecycle, unresolved: m.unresolved };
  });
  eq(r.linked, false,
     'without a real broker there is no broker+order pair — the customer name must not supply one');
});

test('[BL-06] an external order number cannot become an exact internal reference', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    // Two unrelated shipments that reuse one external order number. One of them
    // has a lifecycle row whose internal tripIds happens to contain that same
    // external string — the exact laundering under test.
    const rows = [
      { lifecycleId:'lc_a', orderNo:'REUSED-1', broker:'acme', origin:'Chicago, IL', destination:'Toledo, OH',
        sourceRefs: { tripIds: ['REUSED-1'] } },
    ];
    const viaOrderNo = T.resolveLifecycleForTrip(
      { orderNo:'REUSED-1', broker:'Acme', origin:'Chicago, IL', destination:'Nashville, TN' }, rows);
    const viaInternalId = T.resolveLifecycleForTrip(
      { id:'REUSED-1', orderNo:'REUSED-1', broker:'Acme', origin:'Chicago, IL', destination:'Nashville, TN' }, rows);
    return {
      orderNoMatched: !!viaOrderNo.lifecycle,
      orderNoUnresolved: viaOrderNo.unresolved,
      internalMatched: !!viaInternalId.lifecycle,
    };
  });
  eq(r.orderNoMatched, false,
     'an order number alone must never fire the exact internal-reference branch on a conflicting route');
  eq(r.orderNoUnresolved, true, 'the reused ID is surfaced as ambiguous instead');
  // The strong branch is still real — it fires when a genuinely internal id matches.
  eq(r.internalMatched, true, 'a real internal source reference still resolves exactly');
});

/* ═════════ 4. field-scoped confirmation authority ═════════ */

test('[BL-07] confirming revenue promotes the amount only, not the whole typed row', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({
      orderNo:'CONF-1', broker:'Acme Logistics', origin:'Chicago, IL', destination:'Toledo, OH',
      amount: 950, priceSemantic:'CARRIER_PAYOUT', operatorConfirmedRevenue: true,
      confirmationState:'OPERATOR_CONFIRMED',
    }, {
      sourceType:'MANUAL', stampConfirmationNow: true,
      authority: 'OPERATOR_ENTERED_UNVERIFIED', confirmedFields: ['amount','canonicalRevenue'],
    });
    const ev = res.evidence;
    return {
      rowAuthority: ev.provenance.authority,
      sourceType: ev.provenance.sourceType,
      amountAuthority: ev.fieldProvenance?.amount?.authority,
      revenueAuthority: ev.fieldProvenance?.canonicalRevenue?.authority,
      brokerAuthority: ev.fieldProvenance?.broker?.authority ?? null,
      originAuthority: ev.fieldProvenance?.origin?.authority ?? null,
      mileageAuthority: ev.fieldProvenance?.loadedMi?.authority ?? null,
    };
  });
  eq(r.rowAuthority, 'OPERATOR_ENTERED_UNVERIFIED',
     'a typed row is not a primary document, whatever the operator confirmed about the amount');
  eq(r.sourceType, 'MANUAL', 'and its SOURCE TYPE is still MANUAL — source and authority are separate facts');
  eq(r.amountAuthority, 'OPERATOR_CORRECTION', 'the confirmed amount is promoted');
  eq(r.revenueAuthority, 'OPERATOR_CORRECTION', 'and the revenue derived from it');
  eq(r.brokerAuthority, null, 'the broker was not confirmed and is not promoted');
  eq(r.originAuthority, null, 'nor the route');
  eq(r.mileageAuthority, null, 'nor the mileage');
});

test('[BL-08] an unconfirmed typed row is operator-authored but unverified, not AI', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({
      orderNo:'UNCONF-1', broker:'Acme Logistics', amount: 400, priceSemantic:'UNKNOWN_PRICE_SEMANTIC',
    }, { sourceType:'MANUAL', authority: 'OPERATOR_ENTERED_UNVERIFIED', confirmedFields: [] });
    return {
      authority: res.evidence.provenance.authority,
      sourceType: res.evidence.provenance.sourceType,
      vocabulary: T.EVIDENCE_AUTHORITY_ORDER,
      rankVsAi: T.evidenceAuthorityRank('OPERATOR_ENTERED_UNVERIFIED') < T.evidenceAuthorityRank('AI_SECONDARY'),
      rankVsDoc: T.evidenceAuthorityRank('OPERATOR_ENTERED_UNVERIFIED') > T.evidenceAuthorityRank('PRIMARY_DOCUMENT'),
    };
  });
  eq(r.authority, 'OPERATOR_ENTERED_UNVERIFIED', 'the row records what actually produced it');
  eq(r.sourceType, 'MANUAL', 'without relabelling a human keystroke as a machine summary');
  ok(r.vocabulary.includes('OPERATOR_ENTERED_UNVERIFIED'), 'the vocabulary was extended, not abused');
  eq(r.rankVsAi, true, 'it outranks an AI summary no human asserted');
  eq(r.rankVsDoc, true, 'and ranks below a real primary document');
});

/* ═════════ 6. provenance stays paired with the value ═════════ */

test('[BL-09] a stale incoming record cannot relabel a retained newer value', async () => {
  const r = await evalIn(() => {
    const T = window.__FL_TESTS;
    const local = {
      evidenceId:'ev_pair', revision: 3, recordedAt: 3000, amount: 900, loadedMi: 250,
      fieldProvenance: { amount: { sourceName:'operator', authority:'OPERATOR_CORRECTION' } },
    };
    const staleIncoming = {
      evidenceId:'ev_pair', revision: 2, recordedAt: 2000, amount: 700, loadedMi: 250,
      fieldProvenance: {
        amount: { sourceName:'recovered.csv', authority:'AI_SECONDARY' },
        loadedMi: { sourceName:'recovered.csv', authority:'AI_SECONDARY' },
      },
    };
    const merged = T.reconcileEvidenceRecord(local, staleIncoming);
    // And the reverse: a genuinely newer incoming record must win outright.
    const newerIncoming = {
      evidenceId:'ev_pair', revision: 5, recordedAt: 5000, amount: 1100,
      fieldProvenance: { amount: { sourceName:'rateconf.pdf', authority:'PRIMARY_DOCUMENT' } },
    };
    const merged2 = T.reconcileEvidenceRecord(local, newerIncoming);
    return {
      amount: merged.amount, amountSource: merged.fieldProvenance?.amount?.sourceName,
      amountAuthority: merged.fieldProvenance?.amount?.authority,
      // loadedMi is the SAME retained value in both records, so the loser's
      // provenance for it is safe to keep — it describes the retained fact.
      milesSource: merged.fieldProvenance?.loadedMi?.sourceName,
      newerAmount: merged2.amount, newerSource: merged2.fieldProvenance?.amount?.sourceName,
    };
  });
  eq(r.amount, 900, 'the newer local value wins the scalar conflict');
  eq(r.amountSource, 'operator', 'and keeps ITS OWN provenance — a stale row cannot relabel a value it lost');
  eq(r.amountAuthority, 'OPERATOR_CORRECTION', 'the operator correction is still attributed to the operator');
  eq(r.milesSource, 'recovered.csv', 'provenance for an identically retained fact is safely unioned');
  eq(r.newerAmount, 1100, 'a genuinely newer incoming record does win');
  eq(r.newerSource, 'rateconf.pdf', 'and its value stays paired with its own provenance');
});

/* ═════════ 7. local JSON merge reconciles protected history ═════════ */

test('[BL-10] an older export cannot downgrade newer local lifecycle or evidence on JSON merge', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    // A newer local correction.
    const lc = await T.upsertLifecycle({ lifecycleId:'lc_merge_1', orderNo:'MERGE-1', broker:'Acme Logistics',
      origin:'Chicago, IL', destination:'Toledo, OH', opportunity:'WON' });
    const corrected = await T.upsertLifecycle({ ...lc, opportunity:'LOST' },
      { expectedRevision: lc.revision, source:'USER', reason:'operator correction' });
    const ev = await T.putEvidence({ evidenceId:'ev_merge_1', orderNo:'MERGE-1', amount: 900,
      priceSemantic:'CARRIER_PAYOUT',
      fieldProvenance: { amount: { sourceName:'operator', authority:'OPERATOR_CORRECTION' } } });
    const ev2 = await T.putEvidence({ ...ev, amount: 950 }, { expectedRevision: ev.revision });

    // An OLDER protected export carrying the same internal ids.
    const older = {
      meta: { app:'Freight Logic', version:'24.0.1' },
      trips: [], expenses: [], fuel: [], settings: [],
      loadLifecycle: [{ ...corrected, revision: 1, updatedAt: 1, opportunity:'WON' }],
      normalizedEvidence: [{ ...ev2, revision: 1, recordedAt: 1, amount: 100,
        fieldProvenance: { amount: { sourceName:'old-export.json', authority:'AI_SECONDARY' } } }],
    };
    await T.importJSON(new File([JSON.stringify(older)], 'older.json', { type:'application/json' }), { mode:'merge' });

    const lcAfter = (await T.listLifecycle()).find(x => x.lifecycleId === 'lc_merge_1');
    const evAfter = (await T.listEvidence()).find(x => x.evidenceId === 'ev_merge_1');
    return { opportunity: lcAfter?.opportunity, revision: lcAfter?.revision,
             amount: evAfter?.amount, amountSource: evAfter?.fieldProvenance?.amount?.sourceName };
  });
  eq(r.opportunity, 'LOST', 'a merge import must not downgrade a newer local lifecycle correction');
  eq(r.amount, 950, 'nor a newer local evidence value');
  eq(r.amountSource, 'operator', 'and the retained value keeps its own provenance');
});

/* ═════════ 8. a true no-op re-import ═════════ */

test('[BL-11] re-importing an identical observation changes nothing at all', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    const raw = { orderNo:'NOOP-1', broker:'Acme Logistics', origin:'Gary, IN', destination:'Erie, PA',
      amount: 800, priceSemantic:'CARRIER_PAYOUT', observedAt:'2026-06-01T10:00:00Z' };
    const first = await T.intakeOpportunity(raw, { sourceType:'EMAIL' });
    await new Promise(r2 => setTimeout(r2, 20)); // guarantee the clock would move
    const second = await T.intakeOpportunity(raw, { sourceType:'EMAIL' });
    const rows = (await T.listEvidence()).filter(e => e.orderNo === 'NOOP-1');
    return {
      sameId: first.evidence.evidenceId === second.evidence.evidenceId,
      noop: second.noop === true,
      firstRevision: first.evidence.revision, secondRevision: second.evidence.revision,
      firstRecordedAt: first.evidence.recordedAt, secondRecordedAt: second.evidence.recordedAt,
      amount: second.evidence.amount, rowCount: rows.length,
      storedRevision: rows[0]?.revision,
    };
  });
  eq(r.sameId, true, 'the same observation resolves to the same record');
  eq(r.noop, true, 'and is recognised as a genuine no-op');
  eq(r.rowCount, 1, 'no second row');
  eq(r.secondRevision, r.firstRevision,
     'and NO revision bump — an unchanged observation must not mutate protected history');
  eq(r.secondRecordedAt, r.firstRecordedAt,
     'nor a new recordedAt, which would manufacture a cloud-delta candidate for nothing');
  eq(r.storedRevision, r.firstRevision, 'the persisted row is byte-for-byte the one already there');
  eq(r.amount, 800, 'with its facts unchanged');
});

test('[BL-12] a re-import that can now resolve a previously unresolved link IS a real mutation', async () => {
  const r = await evalIn(async () => {
    const T = window.__FL_TESTS;
    // Two competing lifecycle rows make the first intake unresolvable.
    await T.upsertLifecycle({ orderNo:'AMB-NOOP', broker:'Acme Logistics', origin:'Chicago, IL', destination:'Toledo, OH' });
    await T.upsertLifecycle({ orderNo:'AMB-NOOP', broker:'Acme Logistics', origin:'Chicago, IL', destination:'Nashville, TN' });
    const raw = { orderNo:'AMB-NOOP', broker:'Acme Logistics', origin:'Chicago, IL', destination:'Memphis, TN',
      amount: 700, priceSemantic:'CARRIER_PAYOUT' };
    const first = await T.intakeOpportunity(raw, { sourceType:'EMAIL' });
    const second = await T.intakeOpportunity(raw, { sourceType:'EMAIL' });
    return { firstLinkState: first.evidence.linkState, secondNoop: second.noop === true,
             secondRevision: second.evidence.revision, firstRevision: first.evidence.revision };
  });
  eq(r.firstLinkState, 'UNRESOLVED', 'the ambiguous link is recorded as unresolved');
  eq(r.secondNoop, false,
     'an unresolved observation is deliberately NOT treated as a no-op — it may now be linkable');
  ok(r.secondRevision > r.firstRevision, 'so a re-attempt is a real, recorded mutation');
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
