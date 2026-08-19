// FINDING F-8 (Critical, FIXED) — Add Expense and Add Fuel were completely
// broken for every new record.
//
// sanitizeExpense (app.js:~1060) and sanitizeFuel (app.js:~1136) built the
// key-path property as `id: raw.id ? intNum(...) : undefined`. For a new
// record raw.id is absent, so the object handed to the store carried an
// EXPLICIT `id: undefined`. IndexedDB only lets a key generator assign a key
// when the key-path property is ABSENT; a present-but-undefined one is
// evaluated as a real (invalid) key and the write is rejected with a
// DataError — on put() as well as add(), which the original audit report got
// wrong and this spec pins down.
//
// Neither addExpense() nor addFuel() wrapped the call, so the exception was
// uncaught: no toast, no hint, the modal just sat there and nothing saved.
// Import paths caught it per-row and silently dropped the record.
//
// Second defect on the same line: upsertExpense() documents string ids for
// recurring monthly expenses ('rec_2026-08_ins'), but intNum() collapsed
// every one of them to 0, so all recurring expenses overwrote each other on
// key 0.
//
// FIX: sanitizeAutoId() omits the key entirely when there is no id, and
// preserves non-numeric string ids verbatim.

import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/expense-fuel-write.spec.mjs');
let app;

const count = (page, store) => page.evaluate((s) => new Promise((res) => {
  const r = indexedDB.open('FreightLogic_v18');
  r.onsuccess = () => { const q = r.result.transaction(s, 'readonly').objectStore(s).count();
    q.onsuccess = () => res(q.result); };
}), store);

const getAll = (page, store) => page.evaluate((s) => new Promise((res) => {
  const r = indexedDB.open('FreightLogic_v18');
  r.onsuccess = () => { const q = r.result.transaction(s, 'readonly').objectStore(s).getAll();
    q.onsuccess = () => res(q.result || []); };
}), store);

test('setup: suppress first-run wizard', async () => {
  await skipFirstRunWizard(app.page);
  await app.page.reload();
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
});

test('[FINDING F-8 / FIXED] Add Expense through the real UI actually saves the record', async () => {
  const errs = [];
  app.page.on('pageerror', (e) => errs.push(e.message));
  const before = await count(app.page, 'expenses');

  await app.page.evaluate(() => { location.hash = '#expenses'; });
  await app.page.waitForSelector('#btnAddExp2', { timeout: 10000 });
  await app.page.click('#btnAddExp2');
  await app.page.waitForSelector('#f_amt', { state: 'visible', timeout: 5000 });
  await app.page.fill('#f_amt', '45.50');
  await app.page.fill('#f_cat', 'Fuel');
  await app.page.click('#f_save');
  await app.page.waitForTimeout(800);

  const after = await count(app.page, 'expenses');
  const keyErr = errs.filter(m => /IDBObjectStore.*key path/i.test(m));
  console.log(`    [evidence] expenses ${before} -> ${after}; key-path page errors: ${keyErr.length}`);
  eq(keyErr.length, 0, `no IndexedDB key-path error should be thrown — got ${JSON.stringify(keyErr)}`);
  eq(after, before + 1, 'the expense must actually be written (this is the exact assertion that failed pre-fix)');

  const rows = await getAll(app.page, 'expenses');
  const saved = rows.find(r => r.amount === 45.5);
  ok(saved, `saved expense should be findable — got ${JSON.stringify(rows)}`);
  ok(Number.isInteger(saved.id) && saved.id > 0, `auto-increment must have assigned a real positive integer key — got ${JSON.stringify(saved.id)}`);
});

test('[FINDING F-8 / FIXED] Add Fill-up through the real UI actually saves the record', async () => {
  const errs = [];
  app.page.on('pageerror', (e) => errs.push(e.message));
  const before = await count(app.page, 'fuel');

  await app.page.evaluate(() => { location.hash = '#fuel'; });
  await app.page.waitForSelector('#btnAddFuel2', { timeout: 10000 });
  await app.page.click('#btnAddFuel2');
  await app.page.waitForSelector('#f_gal', { state: 'visible', timeout: 5000 });
  await app.page.fill('#f_gal', '25');
  await app.page.fill('#f_amt', '95');
  await app.page.click('#f_save');
  await app.page.waitForTimeout(800);

  const after = await count(app.page, 'fuel');
  const keyErr = errs.filter(m => /IDBObjectStore.*key path/i.test(m));
  console.log(`    [evidence] fuel ${before} -> ${after}; key-path page errors: ${keyErr.length}`);
  eq(keyErr.length, 0, `no IndexedDB key-path error should be thrown — got ${JSON.stringify(keyErr)}`);
  eq(after, before + 1, 'the fuel record must actually be written');
});

test('[FINDING F-8 / FIXED] both add() and put() accept a sanitized new record (put was ALSO broken, contrary to the original report)', async () => {
  const res = await app.page.evaluate(() => new Promise((resolve) => {
    const T = window.__FL_TESTS;
    const e = T.sanitizeExpense({ date: '2026-08-19', amount: 7, category: 'probe' });
    const f = T.sanitizeFuel({ date: '2026-08-19', gallons: 2, amount: 8, state: 'IL' });
    const r = indexedDB.open('FreightLogic_v18');
    r.onsuccess = () => {
      const db = r.result;
      const trial = (store, op, obj) => new Promise((res2) => {
        try {
          const q = db.transaction(store, 'readwrite').objectStore(store)[op](obj);
          q.onsuccess = () => res2('ok'); q.onerror = () => res2('ERR ' + q.error?.name);
        } catch (ex) { res2('THROW ' + ex.name); }
      });
      Promise.all([
        trial('expenses', 'add', { ...e }), trial('expenses', 'put', { ...e }),
        trial('fuel', 'add', { ...f }),     trial('fuel', 'put', { ...f }),
      ]).then(([ea, ep, fa, fp]) => resolve({
        expHasOwnId: Object.prototype.hasOwnProperty.call(e, 'id'),
        fuelHasOwnId: Object.prototype.hasOwnProperty.call(f, 'id'),
        ea, ep, fa, fp,
      }));
    };
  }));
  console.log(`    [evidence] sanitized new record carries an own 'id' key: expense=${res.expHasOwnId} fuel=${res.fuelHasOwnId}`);
  console.log(`    [evidence] expenses.add=${res.ea} expenses.put=${res.ep} fuel.add=${res.fa} fuel.put=${res.fp}`);
  eq(res.expHasOwnId, false, 'a new expense must NOT carry an own `id` key at all — present-and-undefined is what IndexedDB rejects');
  eq(res.fuelHasOwnId, false, 'a new fuel record must NOT carry an own `id` key at all');
  for (const [label, v] of [['expenses.add', res.ea], ['expenses.put', res.ep], ['fuel.add', res.fa], ['fuel.put', res.fp]]) {
    eq(v, 'ok', `${label} must succeed for a sanitized new record`);
  }
});

test('[FINDING F-8b / FIXED] recurring-expense string ids survive instead of all collapsing to 0', async () => {
  const ids = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return ['rec_2026-08_ins', 'rec_2026-08_van', 'rec_2026-09_ins']
      .map(id => T.sanitizeExpense({ id, category: 'Insurance', amount: 100, date: '2026-08-01' }).id);
  });
  console.log(`    [evidence] sanitized recurring ids: ${JSON.stringify(ids)}`);
  eq(new Set(ids).size, 3, `all three recurring ids must stay distinct — pre-fix every one became 0. Got ${JSON.stringify(ids)}`);
  eq(ids[0], 'rec_2026-08_ins', 'string ids must be preserved verbatim (upsertExpense documents them)');
});

test('[FINDING F-8 / FIXED] an existing numeric id is still preserved (edit path unaffected)', async () => {
  const out = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      numeric: T.sanitizeExpense({ id: 42, amount: 1, date: '2026-08-19' }).id,
      numericStr: T.sanitizeExpense({ id: '42', amount: 1, date: '2026-08-19' }).id,
      zero: T.sanitizeExpense({ id: 0, amount: 1, date: '2026-08-19' }).id,
    };
  });
  console.log(`    [evidence] id passthrough: ${JSON.stringify(out)}`);
  eq(out.numeric, 42, 'numeric id preserved');
  eq(out.numericStr, 42, 'numeric-looking string id coerced to int (matches pre-existing behavior for real keys)');
  eq(out.zero, 0, 'id 0 preserved — the stale key left behind by the pre-fix recurring collision must stay editable');
});

export async function runSpec() {
  app = await launchApp({ enableTestExports: true });
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
