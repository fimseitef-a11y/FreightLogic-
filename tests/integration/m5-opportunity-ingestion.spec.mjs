// Milestone 5A/5B — normalized opportunity ingestion + manual/email intake.
//
// The provider-INDEPENDENT ingestion foundation the completion release
// requires (docs/COMPLETION_RELEASE_PLAN_2026-08-25.md M5;
// docs/EVIDENCE_PROVENANCE.md). Vision (5C) and provider adapters (5D) are
// explicitly non-blocking and not implemented here.
//
// The load-bearing rule: an amount becomes canonical carrier revenue ONLY when
// its price semantic proves carrier payout (or the operator confirmed it, or it
// is a settled amount). A SHIPPER_BOOKABLE_PRICE or an unlabelled number must
// never silently become revenue.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m5-opportunity-ingestion.spec.mjs');
let app;

const norm = (raw, opts) => app.page.evaluate(({ raw, opts }) => window.__FL_TESTS.normalizeOpportunity(raw, opts), { raw, opts });

test('[M5-01] a SHIPPER_BOOKABLE_PRICE never becomes canonical revenue', async () => {
  const r = await norm({ amount: 500, priceSemantic: 'SHIPPER_BOOKABLE_PRICE', broker: 'Warp' }, { sourceType: 'PROVIDER_API' });
  eq(r.amount, 500, 'the raw amount is retained as evidence');
  eq(r.priceSemantic, 'SHIPPER_BOOKABLE_PRICE', 'the semantic is retained');
  eq(r.canonicalRevenue, null, 'a shipper-bookable price is NOT carrier revenue');
});

test('[M5-02] an unlabelled amount is UNKNOWN_PRICE_SEMANTIC and not revenue', async () => {
  const r = await norm({ amount: 500, broker: 'X' }, { sourceType: 'MANUAL' });
  eq(r.priceSemantic, 'UNKNOWN_PRICE_SEMANTIC', 'no proven label => unknown semantic');
  eq(r.canonicalRevenue, null, 'an unlabelled number must stay isolated from revenue');
});

test('[M5-03] an OPERATOR_BID is not a win price and not revenue', async () => {
  const r = await norm({ amount: 450, priceSemantic: 'OPERATOR_BID' }, { sourceType: 'MANUAL' });
  eq(r.canonicalRevenue, null, 'a bid the operator submitted is not payment');
});

test('[M5-04] only CARRIER_PAYOUT or SETTLED_AMOUNT populate canonical revenue', async () => {
  const payout = await norm({ amount: 900, priceSemantic: 'CARRIER_PAYOUT' }, { sourceType: 'EMAIL' });
  const settled = await norm({ amount: 875, priceSemantic: 'SETTLED_AMOUNT' }, { sourceType: 'EMAIL' });
  eq(payout.canonicalRevenue, 900, 'a carrier payout is revenue');
  eq(settled.canonicalRevenue, 875, 'a settled amount is revenue');
});

test('[M5-05] an operator-confirmed expected revenue is allowed regardless of semantic', async () => {
  const r = await norm(
    { amount: 800, priceSemantic: 'UNKNOWN_PRICE_SEMANTIC', operatorConfirmedRevenue: true },
    { sourceType: 'MANUAL', confirmationState: 'OPERATOR_CONFIRMED' });
  eq(r.canonicalRevenue, 800, 'the operator sits atop evidence precedence');
  eq(r.provenance.confirmationState, 'OPERATOR_CONFIRMED', 'confirmation recorded');
  // A5.3 (Issue #119 Batch A): an UNKNOWN confirmation clock stays unknown.
  // This previously asserted a non-null timestamp, which the normalizer only
  // satisfied by defaulting to `Date.now()` — stamping every imported historical
  // confirmation with the import clock and manufacturing a fact that no source
  // established. The live-action path stamps `now` explicitly instead; see M5-05b.
  eq(r.provenance.operatorConfirmedAt, null, 'an unknown confirmation time is not invented');
});

test('[M5-05b] a live operator action may stamp the confirmation clock; a source time wins over it', async () => {
  const now = await norm(
    { amount: 800, priceSemantic: 'CARRIER_PAYOUT' },
    { sourceType: 'MANUAL', confirmationState: 'OPERATOR_CONFIRMED', stampConfirmationNow: true });
  ok(typeof now.provenance.operatorConfirmedAt === 'number' && now.provenance.operatorConfirmedAt > 0,
     'an explicit live confirmation boundary may stamp the current clock');
  const known = await norm(
    { amount: 800, priceSemantic: 'CARRIER_PAYOUT', operatorConfirmedAt: '2026-03-04T11:22:33Z' },
    { sourceType: 'HISTORY', confirmationState: 'OPERATOR_CONFIRMED', stampConfirmationNow: true });
  eq(known.provenance.operatorConfirmedAt, Date.parse('2026-03-04T11:22:33Z'),
     'a real known confirmation instant is preserved, never replaced by now');
});

test('[M5-06] a confirmed flag without the explicit revenue opt-in still gates revenue', async () => {
  const r = await norm(
    { amount: 800, priceSemantic: 'SHIPPER_BOOKABLE_PRICE' },
    { sourceType: 'MANUAL', confirmationState: 'OPERATOR_CONFIRMED' });
  eq(r.canonicalRevenue, null, 'confirming the opportunity is not confirming a bookable price AS revenue');
});

test('[M5-07] unknown material facts stay null, never 0 or inferred', async () => {
  const r = await norm({ broker: 'X', origin: 'Chicago, IL' }, { sourceType: 'MANUAL' });
  eq(r.amount, null, 'no amount => null');
  eq(r.loadedMi, null, 'no loaded miles => null');
  eq(r.deadMi, null, 'no deadhead => null');
  eq(r.destination, '', 'a missing city is empty, not invented');
});

test('[M5-08] mileage semantics stay distinct — a displayed total is not loaded miles', async () => {
  const r = await norm({ loadedMi: 480, mileageSemantic: 'DISPLAYED_TOTAL_MILES' }, { sourceType: 'VISION' });
  // A5.4 (Issue #119 Batch A): "labelled as a displayed total" was not enough —
  // the number still sat in the canonical `loadedMi` slot, which the durability
  // contract forbids outright ("displayed total is not loaded mileage"). The
  // semantic now decides the slot.
  eq(r.displayedTotalMi, 480, 'the number is kept, in the DISPLAYED TOTAL slot');
  eq(r.loadedMi, null, 'a displayed total must never occupy canonical loaded miles');
  eq(r.mileageSemantic, 'DISPLAYED_TOTAL_MILES', 'and the semantic is retained');
  const loaded = await norm({ loadedMi: 480, mileageSemantic: 'LOADED_MILES' }, { sourceType: 'VISION' });
  eq(loaded.loadedMi, 480, 'a proven loaded-mile figure does occupy loaded miles');
  eq(loaded.displayedTotalMi, null, 'and does not leak into the displayed-total slot');
});

test('[M5-09] identity is a minted lifecycleId, never the order number alone', async () => {
  const a = await norm({ orderNo: 'REUSED-123' }, { sourceType: 'MANUAL' });
  const b = await norm({ orderNo: 'REUSED-123' }, { sourceType: 'MANUAL' });
  ok(a.lifecycleId.startsWith('lc_'), 'a stable lifecycle id is minted');
  ok(a.lifecycleId !== b.lifecycleId, 'a reused order number does not collapse two opportunities into one identity');
  eq(a.orderNo, 'REUSED-123', 'the order number is retained as evidence');
});

test('[M5-10] a normalized opportunity defaults to SEEN, never a fabricated WON', async () => {
  const r = await norm({ broker: 'X', amount: 900, priceSemantic: 'CARRIER_PAYOUT' }, { sourceType: 'MANUAL' });
  eq(r.opportunity, 'SEEN', 'seeing an opportunity is not winning it');
});

test('[M5-11] provenance records source type, name and confirmation state', async () => {
  const r = await norm({ broker: 'Acme', sourceName: 'DispatchLand', fieldConfidence: 'HIGH' }, { sourceType: 'EMAIL' });
  eq(r.provenance.sourceType, 'EMAIL', 'source type recorded');
  eq(r.provenance.sourceName, 'DispatchLand', 'source name recorded');
  eq(r.provenance.confirmationState, 'UNCONFIRMED', 'unconfirmed by default');
  eq(r.provenance.fieldConfidence, 'HIGH', 'machine-extracted confidence retained');
});

test('[M5-12] manual intake creates a lifecycle opportunity at SEEN, offline-safe', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({ orderNo: 'INTAKE-1', broker: 'Acme', origin: 'Chicago, IL', destination: 'Toledo, OH' }, { sourceType: 'MANUAL' });
    const rows = await T.listLifecycle();
    const created = rows.find(x => x.orderNo === 'INTAKE-1');
    return { linkOk: res.link.ok, opportunity: created?.opportunity, source: created?.lastMutation?.source };
  });
  ok(r.linkOk, 'intake linked a lifecycle record');
  eq(r.opportunity, 'SEEN', 'a manually entered opportunity starts at SEEN');
  eq(r.source, 'USER', 'manual intake is a USER mutation');
});

test('[M5-13] email intake uses the same contract and records as IMPORT', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity(
      { orderNo: 'EMAIL-1', broker: 'Acme', amount: 900, priceSemantic: 'CARRIER_PAYOUT' },
      { sourceType: 'EMAIL', sourceName: 'broker confirmation' });
    const rows = await T.listLifecycle();
    const created = rows.find(x => x.orderNo === 'EMAIL-1');
    return { ok: res.link.ok, revenue: res.normalized.canonicalRevenue, source: created?.lastMutation?.source };
  });
  ok(r.ok, 'email intake works through the same normalized contract');
  eq(r.revenue, 900, 'a carrier-payout email amount is canonical revenue');
  eq(r.source, 'IMPORT', 'email-derived intake records as IMPORT, not USER');
});

test('[M5-14] intake does not fabricate provider access — it is pure local persistence', async () => {
  // If intake tried to reach a network the offline harness would surface it;
  // this asserts the return shape is fully local and synchronous-to-IDB.
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const res = await T.intakeOpportunity({ orderNo: 'OFFLINE-1', broker: 'Acme' }, { sourceType: 'MANUAL' });
    return { hasNormalized: !!res.normalized, hasLink: !!res.link, lifecycleId: res.normalized.lifecycleId };
  });
  ok(r.hasNormalized && r.hasLink, 'intake returns a fully local result');
  ok(r.lifecycleId.startsWith('lc_'), 'with a locally-minted identity');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
