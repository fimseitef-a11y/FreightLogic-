// Merge-restore transaction integrity — the TOCTOU `docs/DEFERRED.md` left open.
//
// F-6 (pre-v23.9) made `upsertTrip()` TOCTOU-safe by reading and writing inside
// ONE readwrite transaction. `mergeRestoreData()` never got that treatment:
// trips, expenses, fuel, the five simple stores, receipts, settings and gpsLogs
// each ran their `get`/`getAll` in one transaction and their `put` in a second.
// The "is the incoming record newer?" decision was therefore made against a
// snapshot another context could invalidate before the write landed, and the
// restore then wrote its OLDER copy over the NEWER local record. For `settings`
// the same gap breaks the add-only promise in docs/BACKUP_CONTRACT.md; for
// `gpsLogs` it duplicates instead of deduplicating.
//
// WHY THE INVARIANT IS ASSERTED AGAINST SOURCE. Three behavioural approaches
// were built and discarded, each for a reason worth recording so the time is
// not spent again:
//
//   1. Racing a restore against a save IN THE SAME TAB passed against the
//      unfixed code, and always will: `await idbReq(get)` resolves and the next
//      line opens the write transaction in the same microtask, so nothing can
//      land between them. The bug is unreachable from one tab.
//   2. Racing ACROSS TWO TABS also passed. The window is real there, but the
//      other context's readwrite transaction has to be created inside the
//      narrow interval while this one's read is in flight, and a harness cannot
//      schedule that on demand.
//   3. Instrumenting `IDBDatabase.prototype.transaction` and attributing by
//      time or by `Error().stack` both failed honestly: this app is never
//      quiescent — it reads settings/trips/expenses/fuel in the background
//      continuously — so a time window attributes nothing, and stack
//      attribution depends on V8 keeping the caller frame across an await,
//      which varies by Chromium build. A release gate must not rest on that.
//
// The property that makes the race impossible is structural: the merge must
// never open a readonly transaction on a store it then writes. So that is what
// is asserted, against real source, deterministically and identically on every
// engine. `[MRC-03]` covers the behaviour that must not regress.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('integration/merge-restore-concurrency.spec.mjs');

/** The body of `mergeRestoreData`, brace-matched from its declaration. */
function mergeRestoreSource() {
  const src = readFileSync(path.join(ROOT, 'app.js'), 'utf8');
  const start = src.indexOf('async function mergeRestoreData(');
  if (start < 0) throw new Error('mergeRestoreData not found in app.js');
  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return src.slice(start, i + 1); }
  }
  throw new Error('unbalanced braces while extracting mergeRestoreData');
}

/** Every `tx(...)` call in a source span, as written. */
function txCalls(body) {
  return (body.match(/\btx\((?:[^()]|\([^()]*\))*\)/g) || []);
}

test('[MRC-01] the merge never opens a readonly transaction on a store it writes', async () => {
  const body = mergeRestoreSource();
  const calls = txCalls(body);
  ok(calls.length >= 8, `expected the merge to open transactions for each store, found ${calls.length}`);

  // `tx(name)` defaults to readonly; only `tx(name,'readwrite')` is safe here,
  // because the read that decides and the write that acts must be the same
  // transaction for IndexedDB's serialisation to protect them.
  const readonly = calls.filter(c => !/['"]readwrite['"]/.test(c));
  eq(readonly.length, 0,
     `mergeRestoreData opens ${readonly.length} readonly transaction(s); each is a read whose ` +
     `decision can be invalidated before the matching write commits: ${JSON.stringify(readonly)}`);
});

test('[MRC-02] every store the merge touches is named in a readwrite transaction', async () => {
  // Guards against the fix being "achieved" by deleting a read rather than by
  // moving it: each of these stores must still be merged, and merged safely.
  // settings and gpsLogs matter most — they decide by scanning the whole store
  // rather than by key, which is why they were easy to overlook.
  const body = mergeRestoreSource();
  const calls = txCalls(body).filter(c => /['"]readwrite['"]/.test(c));
  const joined = calls.join(' | ');
  for (const store of ['trips','expenses','fuel','receipts','settings','gpsLogs','loadLifecycle']) {
    ok(new RegExp(`['"]${store}['"]`).test(joined),
       `${store} must be merged inside a readwrite transaction; saw: ${joined}`);
  }
  // The simple stores are opened through a loop variable rather than a literal.
  ok(/tx\(storeName,\s*['"]readwrite['"]\)/.test(body),
     'the laneHistory/weeklyReports/reloadOutcomes/bidHistory/documents loop must open readwrite');
  ok(/tx\(EVIDENCE_STORE,\s*['"]readwrite['"]\)/.test(body),
     'normalizedEvidence must be merged inside a readwrite transaction');
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
