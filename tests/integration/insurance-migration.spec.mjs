// v23.9 Phase 1 (X-03) + Amendment 3: the insurance-category-split migration
// must be idempotent (running it twice produces identical end state) and must
// write a retained pre-mutation backup before touching any record, so it can
// be reverted. Drives the real migrateInsuranceCategorySplit()/
// revertInsuranceCategorySplit() functions (exposed via window.__FL_TESTS)
// against real IndexedDB — no mocks.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/insurance-migration.spec.mjs');
let app;

async function seedExpenses(page, rows) {
  await page.evaluate(async (rows) => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('expenses', 'readwrite');
        const store = txn.objectStore('expenses');
        for (const r of rows) store.put(r);
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  }, rows);
}

async function dumpExpenses(page) {
  return page.evaluate(async () => {
    return await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('expenses', 'readonly');
        const getAll = txn.objectStore('expenses').getAll();
        getAll.onsuccess = () => { db.close(); resolve(getAll.result); };
        getAll.onerror = () => reject(getAll.error);
      };
      req.onerror = () => reject(req.error);
    });
  });
}

test('[X-03 / Amendment 3] migrateInsuranceCategorySplit is idempotent — running it twice yields identical end state', async () => {
  await seedExpenses(app.page, [
    { id: 1, date: '2026-03-01', amount: 120, category: 'Insurance', notes: '', type: 'expense', created: Date.now(), updatedAt: Date.now() },
    { id: 2, date: '2026-03-02', amount: 80,  category: 'Auto Insurance', notes: '', type: 'expense', created: Date.now(), updatedAt: Date.now(), insuranceBucket: 'A' },
    { id: 3, date: '2026-03-03', amount: 50,  category: 'Fuel', notes: '', type: 'expense', created: Date.now(), updatedAt: Date.now() },
  ]);

  const first = await app.page.evaluate(() => window.__FL_TESTS.migrateInsuranceCategorySplit());
  ok(first.migrated === 1, `first pass must migrate exactly the one bare "Insurance" record (id 1) — got ${first.migrated}`);
  ok(first.backedUp === true, 'first pass must write a retained backup before mutating');

  const afterFirst = await dumpExpenses(app.page);
  const rec1AfterFirst = afterFirst.find(e => e.id === 1);
  eq(rec1AfterFirst.insuranceBucket, 'C', 'bare "Insurance" record must resolve to bucket C (ambiguous)');
  eq(rec1AfterFirst.category, 'Insurance', 'migration must not rename the category — only add the field');

  const second = await app.page.evaluate(() => window.__FL_TESTS.migrateInsuranceCategorySplit());
  eq(second.migrated, 0, 'second pass must find nothing left to migrate (every insurance record already has insuranceBucket)');

  const afterSecond = await dumpExpenses(app.page);
  eq(JSON.stringify(afterSecond.sort((a,b)=>a.id-b.id)), JSON.stringify(afterFirst.sort((a,b)=>a.id-b.id)),
    'running the migration twice must produce byte-identical end state — this is the idempotency guarantee Amendment 3 requires');
});

test('[X-03 / Amendment 3] migrateInsuranceCategorySplit writes a reversible backup; revert restores the pre-migration state', async () => {
  await seedExpenses(app.page, [
    { id: 10, date: '2026-04-01', amount: 200, category: 'Insurance', notes: 'legacy row', type: 'expense', created: Date.now(), updatedAt: Date.now() },
  ]);

  const res = await app.page.evaluate(() => window.__FL_TESTS.migrateInsuranceCategorySplit());
  ok(res.backupKey, 'migration must return the backup key it wrote');

  const migrated = await dumpExpenses(app.page);
  eq(migrated.find(e => e.id === 10).insuranceBucket, 'C', 'sanity: record was actually migrated');

  const revertRes = await app.page.evaluate((key) => window.__FL_TESTS.revertInsuranceCategorySplit(key), res.backupKey);
  eq(revertRes.reverted, 1, 'revert must report exactly one record restored');

  const reverted = await dumpExpenses(app.page);
  ok(!Object.prototype.hasOwnProperty.call(reverted.find(e => e.id === 10), 'insuranceBucket'),
    'reverted record must have insuranceBucket removed entirely — it had no such field before migration');
});

export async function runSpec() {
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  try {
    return await run();
  } finally {
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
