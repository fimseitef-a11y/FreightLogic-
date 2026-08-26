// Milestone 2 — R-TOCTOU-EXPENSE-FUEL.
//
// F-6 gave `trips` compare-and-abort optimistic concurrency. `expenses` and
// `fuel` kept the original pattern: read the stored record for the audit
// snapshot, then unconditionally put() the whole in-memory object. Two tabs
// editing one record silently lost the first write — including in fields the
// second tab never touched.
//
// These drive real IndexedDB through the app's own update functions, the same
// way tests/integration/toctou-concurrent-edit.spec.mjs does for trips.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m2-expense-fuel-concurrency.spec.mjs');
let app;

// Simulates two tabs: both load the same record, both edit a DIFFERENT field,
// tab A saves first, then tab B saves from its now-stale copy.
const raceExpense = () => app.page.evaluate(async () => {
  const T = window.__FL_TESTS;
  const byId = async (store, id) => (await T.dumpStore(store)).find(r => r.id === id);
  const created = await T.addExpense({ date: '2026-08-01', amount: 100, category: 'Tolls', notes: 'original' });

  const tabA = { ...(await byId('expenses', created.id)) };
  const tabB = { ...(await byId('expenses', created.id)) };

  tabA.amount = 250;                 // tab A changes the amount
  await T.updateExpense(tabA);

  tabB.notes = 'tab B note';         // tab B changes only the notes
  let conflict = null;
  try { await T.updateExpense(tabB); }
  catch (e) { conflict = { code: e.code, hasServerRecord: !!e.serverRecord, serverAmount: e.serverRecord?.amount }; }

  const final = await byId('expenses', created.id);
  return { conflict, finalAmount: final.amount, finalNotes: final.notes };
});

const raceFuel = () => app.page.evaluate(async () => {
  const T = window.__FL_TESTS;
  const byId = async (store, id) => (await T.dumpStore(store)).find(r => r.id === id);
  const created = await T.addFuel({ date: '2026-08-01', gallons: 20, amount: 70, state: 'WI', notes: 'original' });

  const tabA = { ...(await byId('fuel', created.id)) };
  const tabB = { ...(await byId('fuel', created.id)) };

  tabA.amount = 95;
  await T.updateFuel(tabA);

  tabB.notes = 'tab B note';
  let conflict = null;
  try { await T.updateFuel(tabB); }
  catch (e) { conflict = { code: e.code, hasServerRecord: !!e.serverRecord, serverAmount: e.serverRecord?.amount }; }

  const final = await byId('fuel', created.id);
  return { conflict, finalAmount: final.amount, finalNotes: final.notes };
});

test('[M2-01] a stale expense save is rejected with FL_CONFLICT', async () => {
  const r = await raceExpense();
  ok(r.conflict, 'the second (stale) save must not succeed silently');
  eq(r.conflict.code, 'FL_CONFLICT', 'conflict code matches the trip contract');
  ok(r.conflict.hasServerRecord, 'the current server record is attached so the form can reopen on it');
  eq(r.conflict.serverAmount, 250, 'the attached record is the winning first write');
});

test('[M2-02] the earlier concurrent expense edit survives — no lost update', async () => {
  const r = await raceExpense();
  eq(r.finalAmount, 250, "tab A's amount must survive; a silent overwrite would restore 100");
  eq(r.finalNotes, 'original', "tab B's stale write must not have landed");
});

test('[M2-03] a stale fuel save is rejected with FL_CONFLICT', async () => {
  const r = await raceFuel();
  ok(r.conflict, 'the second (stale) save must not succeed silently');
  eq(r.conflict.code, 'FL_CONFLICT', 'conflict code matches the trip contract');
  ok(r.conflict.hasServerRecord, 'server record attached');
  eq(r.conflict.serverAmount, 95, 'the attached record is the winning first write');
});

test('[M2-04] the earlier concurrent fuel edit survives — no lost update', async () => {
  const r = await raceFuel();
  eq(r.finalAmount, 95, "tab A's amount must survive");
  eq(r.finalNotes, 'original', "tab B's stale write must not have landed");
});

test('[M2-05] a normal sequential edit is unaffected', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const byId = async (store, id) => (await T.dumpStore(store)).find(r => r.id === id);
    const created = await T.addExpense({ date: '2026-08-02', amount: 40, category: 'Parking', notes: 'a' });
    const loaded = { ...(await byId('expenses', created.id)) };
    loaded.amount = 55;
    await T.updateExpense(loaded);            // first edit, fresh copy
    const reloaded = { ...(await byId('expenses', created.id)) };
    reloaded.notes = 'b';
    await T.updateExpense(reloaded);          // second edit, reloaded copy
    const final = await byId('expenses', created.id);
    return { amount: final.amount, notes: final.notes };
  });
  eq(r.amount, 55, 'sequential edits still apply');
  eq(r.notes, 'b', 'the second sequential edit applies too');
});

test('[M2-06] the revision stamp advances on every write and is preserved by the sanitizer', async () => {
  const r = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const byId = async (store, id) => (await T.dumpStore(store)).find(r => r.id === id);
    const created = await T.addExpense({ date: '2026-08-03', amount: 10, category: 'Scale', notes: '' });
    const afterAdd = await byId('expenses', created.id);
    const loaded = { ...afterAdd };
    loaded.amount = 12;
    await T.updateExpense(loaded);
    const afterUpdate = await byId('expenses', created.id);
    // The sanitizer must carry a supplied stamp through untouched, or the
    // compare has nothing to compare against.
    const sanitized = T.sanitizeExpense({ id: 5, date: '2026-08-03', amount: 1, updatedAt: 12345 });
    const sanitizedNew = T.sanitizeExpense({ date: '2026-08-03', amount: 1 });
    return {
      addStamp: typeof afterAdd.updatedAt,
      advanced: afterUpdate.updatedAt >= afterAdd.updatedAt,
      preserved: sanitized.updatedAt,
      newRecordStamp: sanitizedNew.updatedAt,
      newRecordHasNoId: !('id' in sanitizedNew),
    };
  });
  eq(r.addStamp, 'number', 'a new record is stamped so its first edit is protected');
  ok(r.advanced, 'the stamp advances on update');
  eq(r.preserved, 12345, 'sanitizeExpense must preserve a supplied updatedAt, not overwrite it');
  eq(r.newRecordStamp, undefined, 'a new record has no prior revision to preserve');
  ok(r.newRecordHasNoId, 'F-8 must stay fixed: no explicit id key on a new record');
});

test('[M2-07] fuel sanitizer preserves the stamp and keeps F-8 intact', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const existing = T.sanitizeFuel({ id: 7, date: '2026-08-03', gallons: 1, amount: 4, updatedAt: 999 });
    const fresh = T.sanitizeFuel({ date: '2026-08-03', gallons: 1, amount: 4 });
    return { preserved: existing.updatedAt, freshStamp: fresh.updatedAt, freshHasNoId: !('id' in fresh) };
  });
  eq(r.preserved, 999, 'sanitizeFuel must preserve a supplied updatedAt');
  eq(r.freshStamp, undefined, 'no invented stamp on a new record');
  ok(r.freshHasNoId, 'F-8 must stay fixed for fuel too');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
