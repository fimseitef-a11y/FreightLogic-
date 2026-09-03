// Optimistic concurrency must not depend on the clock ticking.
//
// F-6 (trips) and M2 (expenses/fuel) guard against a lost update by comparing
// the caller's `updatedAt` against the stored one and aborting when they differ.
// The stamp written on each save was `Date.now()`, which has MILLISECOND
// resolution — so a create and an edit, or two edits, landing inside the same
// millisecond leave `updatedAt` unchanged. The compare-and-abort then sees
// equal values for a record that HAS moved on, accepts the stale write, and
// silently discards the earlier edit: exactly the failure those guards exist to
// prevent, reachable on any device fast enough.
//
// This was not hypothetical and not caught by the existing M2 spec, which races
// two edits and relies on real time passing between them. On a fast CI runner
// [M2-01], [M2-02] and [M2-03] all failed for this reason while passing on
// slower hardware — the suite's verdict depended on how quick the machine was.
//
// Freezing the clock removes that dependency: the race below is decided by the
// concurrency contract alone, identically on every machine.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/same-millisecond-concurrency.spec.mjs');

/** Runs `fn` in the page with Date.now() pinned to a single millisecond. */
const FROZEN = (bodySource) => `(async () => {
  const realNow = Date.now.bind(Date);
  const frozen = realNow();
  Date.now = () => frozen;
  try { return await (${bodySource})(window.__FL_TESTS); }
  finally { Date.now = realNow; }
})`;

test('[SMS-01] a stale expense save is still rejected when every write shares one millisecond', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(new Function('return ' + FROZEN(`async (T) => {
      const byId = async (id) => (await T.dumpStore('expenses')).find(r => r.id === id);
      const created = await T.addExpense({ date:'2026-08-01', amount:100, category:'Tolls', notes:'original' });
      const tabA = { ...(await byId(created.id)) };
      const tabB = { ...(await byId(created.id)) };
      tabA.amount = 250; await T.updateExpense(tabA);
      let conflict = null;
      tabB.notes = 'tab B note';
      try { await T.updateExpense(tabB); } catch (e) { conflict = e.code; }
      const final = await byId(created.id);
      return { conflict, finalAmount: final.amount };
    }`))());
    eq(r.conflict, 'FL_CONFLICT', 'the stale save must be rejected even with no clock movement');
    eq(r.finalAmount, 250, "and tab A's edit must survive — this is the lost update the guard exists to stop");
  } finally { await app.close(); }
});

test('[SMS-02] a stale fuel save is still rejected when every write shares one millisecond', async () => {
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(new Function('return ' + FROZEN(`async (T) => {
      const byId = async (id) => (await T.dumpStore('fuel')).find(r => r.id === id);
      const created = await T.addFuel({ date:'2026-08-01', gallons:20, amount:70, state:'WI', notes:'original' });
      const tabA = { ...(await byId(created.id)) };
      const tabB = { ...(await byId(created.id)) };
      tabA.amount = 95; await T.updateFuel(tabA);
      let conflict = null;
      tabB.notes = 'tab B note';
      try { await T.updateFuel(tabB); } catch (e) { conflict = e.code; }
      const final = await byId(created.id);
      return { conflict, finalAmount: final.amount };
    }`))());
    eq(r.conflict, 'FL_CONFLICT', 'the stale save must be rejected even with no clock movement');
    eq(r.finalAmount, 95, "and tab A's edit must survive");
  } finally { await app.close(); }
});

test('[SMS-03] a stale trip save is still rejected when every write shares one millisecond', async () => {
  // upsertTrip carried the identical exposure. Money lives in these records, so
  // the trip path is covered here rather than assumed to be fine.
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(new Function('return ' + FROZEN(`async (T) => {
      const saved = await T.upsertTrip({ orderNo:'SMS-1', customer:'A', origin:'Gary, IN',
        destination:'Erie, PA', pay:100, loadedMiles:200, emptyMiles:0 });
      const tabA = { ...saved }, tabB = { ...saved };
      tabA.pay = 555; await T.upsertTrip(tabA);
      let conflict = null;
      tabB.customer = 'B';
      try { await T.upsertTrip(tabB); } catch (e) { conflict = e.code; }
      const final = (await T.dumpStore('trips')).find(t => t.orderNo === 'SMS-1');
      return { conflict, finalPay: final.pay, finalCustomer: final.customer };
    }`))());
    eq(r.conflict, 'FL_CONFLICT', 'the stale save must be rejected even with no clock movement');
    eq(r.finalPay, 555, "and tab A's pay correction must survive");
    eq(r.finalCustomer, 'A', 'the stale write must not have landed at all');
  } finally { await app.close(); }
});

test('[SMS-04] the revision stamp strictly increases, so an unchanged clock still advances it', async () => {
  // The property behind the three tests above, asserted directly: consecutive
  // saves inside one millisecond must still produce distinct revisions.
  const app = await launchApp();
  try {
    const stamps = await app.page.evaluate(new Function('return ' + FROZEN(`async (T) => {
      const byId = async (id) => (await T.dumpStore('expenses')).find(r => r.id === id);
      const created = await T.addExpense({ date:'2026-08-02', amount:10, category:'Tolls' });
      const seen = [(await byId(created.id)).updatedAt];
      let current = await byId(created.id);
      for (let i = 0; i < 3; i++){
        current = { ...current, amount: 10 + i + 1 };
        await T.updateExpense(current);
        current = await byId(created.id);
        seen.push(current.updatedAt);
      }
      return seen;
    }`))());
    for (let i = 1; i < stamps.length; i++){
      ok(stamps[i] > stamps[i - 1],
         `revision ${i} (${stamps[i]}) must exceed revision ${i - 1} (${stamps[i - 1]}) even with a frozen clock`);
    }
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
