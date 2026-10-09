// v24.5 redesign — Add Expense as the form-pattern benchmark (UI_BRIEF_V24.5.md §6.9, §9 step 6).
// Large amount, one-tap category grid, date, notes, prominent Save. Element IDs are unchanged;
// Fuel stays in the typed fuel store (Issue #417 Slice C).
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/add-expense-form.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot(){
  const app = await launchApp();
  await app.page.setViewportSize({ width: 390, height: 844 });
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout: 10000 });
  await sleep(450);
  return app;
}

async function openAddExpense(page){
  await page.evaluate(() => { location.hash = '#money'; });
  await page.waitForSelector('#btnAddCost');
  await page.click('#btnAddCost');
  await page.waitForSelector('[data-cost-kind="expense"]');
  await page.click('[data-cost-kind="expense"]');
  await page.waitForSelector('#f_amt');
}

const expenseCount = (page) => page.evaluate(async () => (await window.__FL_TESTS.dumpStore('expenses')).length);

test('[AE-01] amount leads the form, large and decimal; category grid, date, notes and a full-width Save follow', async () => {
  const app = await boot();
  try {
    await openAddExpense(app.page);
    const s = await app.page.evaluate(() => {
      const form = document.getElementById('f_amt').closest('.xf');
      const fields = [...form.querySelectorAll('input,textarea,button')].map(el => el.id || el.getAttribute('data-xf-cat'));
      const amt = document.getElementById('f_amt');
      const save = document.getElementById('f_save').getBoundingClientRect();
      const tiles = [...form.querySelectorAll('[data-xf-cat]')];
      return {
        hasForm: !!form,
        first: fields[0],
        amtFont: parseFloat(getComputedStyle(amt).fontSize),
        inputmode: amt.getAttribute('inputmode'),
        tiles: tiles.map(t => t.getAttribute('data-xf-cat')),
        minTile: Math.min(...tiles.map(t => t.getBoundingClientRect().height)),
        ids: ['f_date', 'f_cat', 'f_notes', 'f_hint'].filter(id => !!form.querySelector('#' + id)),
        saveWidthRatio: save.width / form.getBoundingClientRect().width,
        saveHeight: save.height,
        saveText: document.getElementById('f_save').textContent.trim(),
        overflow: document.documentElement.scrollWidth > window.innerWidth,
      };
    });
    ok(s.hasForm, 'the expense form must carry the .xf form-pattern root');
    eq(s.first, 'f_amt', 'amount must be the first control');
    ok(s.amtFont >= 28, `amount must be large (got ${s.amtFont}px)`);
    eq(s.inputmode, 'decimal', 'amount must open the decimal keypad');
    eq(JSON.stringify(s.tiles), JSON.stringify(['Fuel', 'Tolls', 'Repairs & Maintenance', 'Parking', 'Supplies', 'Tires', 'Oil Change', 'Other']));
    ok(s.minTile >= 44, `category tiles must be at least 44px tall (got ${s.minTile})`);
    eq(JSON.stringify(s.ids), JSON.stringify(['f_date', 'f_cat', 'f_notes', 'f_hint']), 'existing IDs are kept');
    ok(s.saveWidthRatio > 0.9, `Save must span the form (ratio ${s.saveWidthRatio.toFixed(2)})`);
    ok(s.saveHeight >= 48, `Save must be at least 48px tall (got ${s.saveHeight})`);
    eq(s.saveText, 'Save Expense');
    ok(!s.overflow, 'no horizontal page scroll at 390px');
  } finally { await app.close(); }
});

test('[AE-02] a category tile writes the canonical category text and shows one selected tile; typing clears it', async () => {
  const app = await boot();
  try {
    await openAddExpense(app.page);
    await app.page.click('[data-xf-cat="Repairs & Maintenance"]');
    const a = await app.page.evaluate(() => ({
      cat: document.getElementById('f_cat').value,
      pressed: [...document.querySelectorAll('[data-xf-cat][aria-pressed="true"]')].map(t => t.getAttribute('data-xf-cat')),
    }));
    eq(a.cat, 'Repairs & Maintenance');
    eq(JSON.stringify(a.pressed), JSON.stringify(['Repairs & Maintenance']));
    await app.page.fill('#f_cat', 'Cargo Insurance');
    const b = await app.page.evaluate(() => document.querySelectorAll('[data-xf-cat][aria-pressed="true"]').length);
    eq(b, 0, 'a typed category that is not a tile selects no tile');
    await app.page.fill('#f_cat', 'parking');
    const c = await app.page.evaluate(() => [...document.querySelectorAll('[data-xf-cat][aria-pressed="true"]')].map(t => t.getAttribute('data-xf-cat')));
    eq(JSON.stringify(c), JSON.stringify(['Parking']), 'typing a tile name (any case) selects that tile');
  } finally { await app.close(); }
});

test('[AE-03] tile + amount + Save writes one expense with that category', async () => {
  const app = await boot();
  try {
    const before = await expenseCount(app.page);
    await openAddExpense(app.page);
    await app.page.fill('#f_amt', '12.50');
    await app.page.click('[data-xf-cat="Tolls"]');
    await app.page.fill('#f_notes', 'I-94');
    await app.page.click('#f_save');
    await app.page.waitForFunction(() => !document.getElementById('f_amt'), null, { timeout: 5000 });
    const rows = await app.page.evaluate(async () => window.__FL_TESTS.dumpStore('expenses'));
    eq(rows.length, before + 1);
    const r = rows[rows.length - 1];
    eq(r.category, 'Tolls'); eq(r.amount, 12.5); eq(r.notes, 'I-94');
  } finally { await app.close(); }
});

test('[AE-04] the Fuel tile in Add mode hands off to the typed fuel form with the amount, writing no expense', async () => {
  const app = await boot();
  try {
    const before = await expenseCount(app.page);
    await openAddExpense(app.page);
    await app.page.fill('#f_amt', '64.70');
    await app.page.click('[data-xf-cat="Fuel"]');
    await app.page.waitForSelector('#f_gal', { timeout: 5000 });
    eq(await app.page.inputValue('#f_amt'), '64.7', 'the fuel form carries the amount');
    eq(await expenseCount(app.page), before, 'no expense record is written by the handoff');
  } finally { await app.close(); }
});

test('[AE-05] Edit keeps the same layout, preselects the saved category, and the Fuel tile only sets the category', async () => {
  const app = await boot();
  try {
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.addExpense({ date: '2026-10-01', amount: 40, category: 'Fuel', notes: 'legacy fuel row', type: 'expense' });
    });
    await app.page.evaluate(() => { location.hash = '#expenses'; });
    await app.page.waitForSelector('#view-expenses [data-act="edit"]', { timeout: 5000 });
    await app.page.click('#view-expenses [data-act="edit"]');
    await app.page.waitForSelector('#f_amt');
    const s = await app.page.evaluate(() => ({
      xf: !!document.getElementById('f_amt').closest('.xf'),
      pressed: [...document.querySelectorAll('[data-xf-cat][aria-pressed="true"]')].map(t => t.getAttribute('data-xf-cat')),
      del: !!document.getElementById('f_del'),
    }));
    ok(s.xf && s.del, 'edit uses the same form and keeps Delete');
    eq(JSON.stringify(s.pressed), JSON.stringify(['Fuel']));
    await app.page.click('[data-xf-cat="Fuel"]');
    await sleep(300);
    ok(await app.page.evaluate(() => !!document.getElementById('f_del') && !document.getElementById('f_gal')), 'editing never jumps to the fuel form');
  } finally { await app.close(); }
});

test('[AE-06] no error on open; the amount error appears only for a bad amount and clears when fixed; Save still refuses it', async () => {
  const app = await boot();
  try {
    const before = await expenseCount(app.page);
    await openAddExpense(app.page);
    const hint = () => app.page.evaluate(() => document.getElementById('f_hint').textContent.trim());
    eq(await hint(), '', 'a fresh form shows no error');
    await app.page.fill('#f_amt', '0');
    eq(await hint(), 'Amount must be > 0.');
    await app.page.fill('#f_amt', '9.99');
    eq(await hint(), '', 'a valid amount clears the error');
    await app.page.fill('#f_amt', '');
    await app.page.click('#f_save');
    await sleep(300);
    ok(await app.page.evaluate(() => !!document.getElementById('f_amt')), 'Save with no amount keeps the form open');
    eq(await expenseCount(app.page), before, 'nothing is written without an amount');
  } finally { await app.close(); }
});

export async function runSpec(){
  const r = await run();
  return r;
}
if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
