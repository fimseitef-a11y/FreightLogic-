import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSuite, launchApp, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const { test, run } = createSuite('integration/st12-restore-transaction.gate.mjs');
let app;

function mergeRestoreSource() {
  const src = readFileSync(path.join(ROOT, 'app.js'), 'utf8');
  const start = src.indexOf('async function mergeRestoreData(');
  if (start < 0) throw new Error('mergeRestoreData not found');
  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error('unbalanced mergeRestoreData');
}

test('[ST12-01] restore transactions never resolve an error/abort as success', async () => {
  const body = mergeRestoreSource();
  ok(!/\.onerror\s*=\s*r\b/.test(body),
    'mergeRestoreData must not resolve transaction errors as success');
  ok(/\.onabort\s*=/.test(body),
    'mergeRestoreData must explicitly handle transaction aborts');
  ok(/reject/.test(body),
    'mergeRestoreData transaction failures must reject the restore');
});

test('[ST12-02] a real IndexedDB abort rejects, commits no row, and a retry can succeed', async () => {
  app = app || await launchApp();
  await skipFirstRunWizard(app.page);

  const result = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const incoming = T.sanitizeTrip({
      id: 'st12-abort-trip',
      orderNo: 'ST12-ABORT',
      customer: 'ST12 fixture',
      origin: 'Milwaukee, WI',
      destination: 'Chicago, IL',
      pay: 250,
      loadedMiles: 92,
      emptyMiles: 0,
      pickupDate: '2026-10-03',
      deliveryDate: '2026-10-03',
      updatedAt: Date.now() + 10000,
    });

    const originalPut = IDBObjectStore.prototype.put;
    let armed = true;
    IDBObjectStore.prototype.put = function(value, key) {
      const req = arguments.length > 1
        ? originalPut.call(this, value, key)
        : originalPut.call(this, value);
      if (armed && this.name === 'tripRecords' && value?.id === incoming.id) {
        armed = false;
        const transaction = this.transaction;
        queueMicrotask(() => {
          try { transaction.abort(); } catch {}
        });
      }
      return req;
    };

    let outcome;
    try {
      const merge = T.mergeRestoreData({ trips: [incoming] })
        .then(value => ({ kind: 'resolved', value }))
        .catch(error => ({ kind: 'rejected', error: String(error?.message || error) }));
      outcome = await Promise.race([
        merge,
        new Promise(resolve => setTimeout(() => resolve({ kind: 'timeout' }), 500)),
      ]);
    } finally {
      IDBObjectStore.prototype.put = originalPut;
    }

    const afterAbort = (await T.dumpStore('trips')).filter(t => t.id === incoming.id).length;
    let retryAdded = null;
    let afterRetry = null;
    if (outcome.kind === 'rejected') {
      const retry = await T.mergeRestoreData({ trips: [incoming] });
      retryAdded = retry.stats.trips.added;
      afterRetry = (await T.dumpStore('trips')).filter(t => t.id === incoming.id).length;
    }
    return { outcome, afterAbort, retryAdded, afterRetry };
  });

  eq(result.outcome.kind, 'rejected',
    'aborted restore transaction must reject promptly rather than resolve or hang');
  eq(result.afterAbort, 0, 'an aborted transaction must not leave a restored row');
  if (result.outcome.kind === 'rejected') {
    eq(result.retryAdded, 1, 'retry must count the row only after its transaction commits');
    eq(result.afterRetry, 1, 'retry must persist exactly one restored row');
  }
});

export async function runSpec() {
  try { return await run(); }
  finally {
    if (app) { await app.close(); app = null; }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
