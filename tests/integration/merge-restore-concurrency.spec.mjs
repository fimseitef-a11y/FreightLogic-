// Merge-restore transaction integrity — the TOCTOU `docs/DEFERRED.md` left open.
//
// F-6 (pre-v23.9) made `upsertTrip()` TOCTOU-safe by reading and writing inside
// ONE readwrite transaction. `mergeRestoreData()` never got that treatment:
// trips, expenses, fuel, the five simple stores, receipts, settings and gpsLogs
// each ran their `get`/`getAll` in one transaction and their `put` in a second.
// The "is the incoming record newer?" decision was therefore made against a
// snapshot another context could invalidate before the write landed, and the
// restore then wrote its OLDER copy over the NEWER local record.
//
// WHY THESE TESTS ASSERT STRUCTURE RATHER THAN A RACE. Two earlier versions of
// this spec tried to reproduce the interleaving directly and BOTH passed against
// the unfixed code, which makes them worthless as regressions. Inside one tab
// the race is unreachable at all: `await idbReq(get)` resolves and the next line
// opens the write transaction in the same microtask, so nothing can land
// between them. Across two tabs it is reachable but not schedulable on demand —
// the other context's readwrite transaction has to be created inside the narrow
// interval while this one's read is in flight, and a harness cannot force that.
//
// So the invariant is asserted where it is deterministic: the merge must not
// open a readonly transaction on a store it is about to write. That is the
// property that makes the race impossible, it fails loudly against the pre-fix
// code, and it cannot pass by luck.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/merge-restore-concurrency.spec.mjs');

/**
 * Records the IDB transactions `mergeRestoreData` opens, as "store:mode".
 *
 * The hook is time-scoped, so it also sees any background app work that happens
 * to run during the merge's awaits — boot-time settings reads in particular.
 * An earlier version counted those against the merge and failed on a fix that
 * was actually correct, so each transaction is attributed by CALL STACK and
 * anything that is not the merge's own is ignored.
 */
const TRACE = `(async (payload) => {
  const seen = [];
  const proto = IDBDatabase.prototype;
  const original = proto.transaction;
  proto.transaction = function(names, mode, ...rest){
    const stack = new Error().stack || '';
    if (/mergeRestoreData/.test(stack)) {
      const list = Array.isArray(names) ? names : [names];
      for (const n of list) seen.push(n + ':' + (mode || 'readonly'));
    }
    return original.call(this, names, mode, ...rest);
  };
  try { await window.__FL_TESTS.mergeRestoreData(payload); }
  finally { proto.transaction = original; }
  return seen;
})`;

test('[MRC-01] the record merges never open a readonly transaction on a store they then write', async () => {
  const app = await launchApp();
  try {
    // Seed so every loop takes its "existing record" branch — the branch that
    // reads before deciding.
    await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.upsertTrip({ orderNo:'MRC-1', customer:'A', origin:'Chicago, IL', destination:'Toledo, OH',
        pay: 500, loadedMiles: 250, emptyMiles: 0, updatedAt: 1000 });
      await T.addExpense({ date:'2026-01-05', amount: 20, category:'Tolls' });
      await T.addFuel({ date:'2026-01-05', gallons: 10, cost: 35 });
      await T.setSetting('mrcExisting', 'local');
    });

    const seen = await app.page.evaluate(new Function('return ' + TRACE)(), {
      trips: [{ orderNo:'MRC-1', customer:'A', origin:'Chicago, IL', destination:'Toledo, OH',
        pay: 600, loadedMiles: 250, emptyMiles: 0, updatedAt: 3000 }],
      expenses: [{ id: 1, date:'2026-01-05', amount: 25, category:'Tolls', updatedAt: 3000 }],
      fuel: [{ id: 1, date:'2026-01-05', gallons: 11, cost: 40, updatedAt: 3000 }],
      settings: [{ key:'mrcExisting', value:'from-backup' }, { key:'mrcNew', value:'added' }],
      receipts: [{ tripOrderNo:'MRC-1', files: [{ id:'f1', name:'r.jpg' }] }],
      laneHistory: [{ id:'lh1', lane:'CHI-TOL', updated: 3000 }],
      gpsLogs: [{ id: 99, tripTrackingId:'tt1', timestamp: 1234 }],
    });

    const readonly = seen.filter(s => s.endsWith(':readonly'));
    eq(readonly.length, 0,
       `mergeRestoreData opened ${readonly.length} readonly transaction(s) — each one is a read whose ` +
       `decision can be invalidated before the matching write commits: ${JSON.stringify([...new Set(readonly)])}`);
    ok(seen.length > 0, 'the trace actually observed the merge opening transactions');
  } finally { await app.close(); }
});

test('[MRC-02] every store the merge touches is opened readwrite, including the bulk-checked ones', async () => {
  // settings and gpsLogs decide by scanning the whole store rather than by
  // per-record key, so they were easy to overlook: `getAll()` in a readonly
  // transaction, then a separate write. The add-only settings promise in
  // docs/BACKUP_CONTRACT.md — "a key already present locally is never
  // overwritten" — is only true if that scan and the write share a transaction.
  const app = await launchApp();
  try {
    const seen = await app.page.evaluate(new Function('return ' + TRACE)(), {
      settings: [{ key:'mrcBulk', value:'v' }],
      gpsLogs: [{ id: 7, tripTrackingId:'tt2', timestamp: 999 }],
    });
    ok(seen.includes('settings:readwrite'), `settings must be merged in a readwrite transaction, saw ${JSON.stringify(seen)}`);
    ok(seen.includes('gpsLogs:readwrite'), `gpsLogs must be merged in a readwrite transaction, saw ${JSON.stringify(seen)}`);
    eq(seen.filter(s => s === 'settings:readonly').length, 0, 'no readonly settings scan may precede the write');
    eq(seen.filter(s => s === 'gpsLogs:readonly').length, 0, 'no readonly gpsLogs scan may precede the write');
  } finally { await app.close(); }
});

test('[MRC-03] a restore still applies genuinely newer incoming records', async () => {
  // The fix must not turn into "the restore never writes". Without concurrency,
  // newer-wins/older-skips behaviour is unchanged.
  const app = await launchApp();
  try {
    const r = await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.upsertTrip({ orderNo:'MRC-NEW', customer:'A', origin:'Gary, IN', destination:'Erie, PA',
        pay: 100, loadedMiles: 200, emptyMiles: 0, updatedAt: 1000 });
      const stored = (await T.dumpStore('trips')).find(t => t.orderNo === 'MRC-NEW');
      await T.mergeRestoreData({ trips: [{ ...stored, pay: 777, updatedAt: (stored.updatedAt || 0) + 5000 }] });
      const newer = (await T.dumpStore('trips')).find(t => t.orderNo === 'MRC-NEW');
      await T.mergeRestoreData({ trips: [{ ...stored, pay: 111, updatedAt: 1 }] });
      const older = (await T.dumpStore('trips')).find(t => t.orderNo === 'MRC-NEW');
      return { afterNewer: newer.pay, afterOlder: older.pay };
    });
    eq(r.afterNewer, 777, 'a newer incoming record is applied');
    eq(r.afterOlder, 777, 'an older incoming record is skipped, not applied');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }
