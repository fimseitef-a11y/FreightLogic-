// Issue #417 Slice C — unified Costs contracts.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/product-ia-slice-c.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot(){
  const app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout:10000 });
  await sleep(450);
  return app;
}

test('[UXIA-08] Money exposes one canonical Costs hub while legacy deep links remain valid', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#money'; });
    await app.page.waitForSelector('#moneyCostsHub', { timeout:5000 });
    const state=await app.page.evaluate(() => {
      const visible = (el) => !!el && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden';
      const quick=[...document.querySelectorAll('#homeKPICard .fl-quick-btn')].filter(visible).map(x => x.textContent.replace(/\s+/g,' ').trim());
      const hub=document.getElementById('moneyCostsHub');
      return {
        hasHub:!!hub,
        addCostVisible:visible(document.getElementById('btnAddCost')),
        links:[...hub.querySelectorAll('a[href]')].map(a => a.getAttribute('href')),
        quick,
      };
    });
    ok(state.hasHub, 'Money must own the canonical Costs hub');
    ok(state.addCostVisible, 'Costs hub must expose one visible Add Cost entry point');
    ok(state.links.includes('#expenses'), 'legacy Expenses history must remain reachable');
    ok(state.links.includes('#fuel'), 'legacy Fuel history must remain reachable');
    ok(state.quick.some(x => /Cost/i.test(x)), 'Today should expose one Cost quick action');
    ok(!state.quick.some(x => /^Fuel$/i.test(x)), 'Today must not expose Fuel as a parallel daily cost concept');
    ok(!state.quick.some(x => /^Expense$/i.test(x)), 'Today must not expose Expense as a parallel daily cost concept');

    await app.page.evaluate(() => { location.hash='#expenses'; });
    await app.page.waitForFunction(() => location.hash==='#expenses' && getComputedStyle(document.getElementById('view-expenses')).display !== 'none');
    await app.page.evaluate(() => { location.hash='#fuel'; });
    await app.page.waitForFunction(() => location.hash==='#fuel' && getComputedStyle(document.getElementById('view-fuel')).display !== 'none');
  } finally { await app.close(); }
});

test('[UXIA-08] Add Cost chooser delegates Fuel to the existing typed fuel store', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#money'; });
    await app.page.waitForSelector('#btnAddCost');
    await app.page.click('#btnAddCost');
    await app.page.waitForSelector('[data-cost-kind="fuel"]');
    const before=await app.page.evaluate(async () => ({
      fuel:(await window.__FL_TESTS.dumpStore('fuel')).length,
      expenses:(await window.__FL_TESTS.dumpStore('expenses')).length,
    }));
    await app.page.click('[data-cost-kind="fuel"]');
    await app.page.waitForSelector('#f_gal');
    await app.page.fill('#f_gal','12.5');
    await app.page.fill('#f_amt','50');
    await app.page.fill('#f_state','FL');
    await app.page.fill('#f_notes','Slice C typed fuel');
    await app.page.click('#f_save');
    await sleep(450);
    const after=await app.page.evaluate(async () => ({
      fuel:await window.__FL_TESTS.dumpStore('fuel'),
      expenses:await window.__FL_TESTS.dumpStore('expenses'),
    }));
    eq(after.fuel.length,before.fuel+1,'Fuel chooser path must add exactly one fuel record');
    eq(after.expenses.length,before.expenses,'Fuel chooser path must not flatten fuel into expenses');
    eq(after.fuel.at(-1)?.state,'FL','fuel-specific fields must survive the unified chooser');
    ok(Math.abs(Number(after.fuel.at(-1)?.gallons)-12.5)<0.001,'fuel gallons must remain typed fuel data');
  } finally { await app.close(); }
});

test('[UXIA-08] Add Cost chooser delegates general Expense to the existing expense store', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#money'; });
    await app.page.waitForSelector('#btnAddCost');
    await app.page.click('#btnAddCost');
    await app.page.waitForSelector('[data-cost-kind="expense"]');
    const before=await app.page.evaluate(async () => ({
      fuel:(await window.__FL_TESTS.dumpStore('fuel')).length,
      expenses:(await window.__FL_TESTS.dumpStore('expenses')).length,
    }));
    await app.page.click('[data-cost-kind="expense"]');
    await app.page.waitForSelector('#f_cat');
    await app.page.fill('#f_amt','18.25');
    await app.page.fill('#f_cat','Parking');
    await app.page.fill('#f_notes','Slice C general expense');
    await app.page.click('#f_save');
    await sleep(450);
    const after=await app.page.evaluate(async () => ({
      fuel:await window.__FL_TESTS.dumpStore('fuel'),
      expenses:await window.__FL_TESTS.dumpStore('expenses'),
    }));
    eq(after.expenses.length,before.expenses+1,'Expense chooser path must add exactly one expense record');
    eq(after.fuel.length,before.fuel,'Expense chooser path must not create a fuel record');
    eq(after.expenses.at(-1)?.category,'Parking','general expense category must remain intact');
  } finally { await app.close(); }
});

test('[UXIA-08] Maintenance chooser keeps service provenance and contributes exactly one expense', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#money'; });
    await app.page.waitForSelector('#btnAddCost');
    await app.page.click('#btnAddCost');
    await app.page.waitForSelector('[data-cost-kind="maintenance"]');
    const before=await app.page.evaluate(async () => ({
      fuel:(await window.__FL_TESTS.dumpStore('fuel')).length,
      expenses:(await window.__FL_TESTS.dumpStore('expenses')).length,
    }));
    await app.page.click('[data-cost-kind="maintenance"]');
    await app.page.waitForSelector('[data-maint-log="0"]', { timeout:5000 });
    await app.page.click('[data-maint-log="0"]');
    await app.page.waitForSelector('#maintLogCost');
    await app.page.fill('#maintLogCost','79.95');
    await app.page.fill('#maintLogNotes','Slice C oil service');
    await app.page.click('#maintLogSave');
    await sleep(550);
    const after=await app.page.evaluate(async () => ({
      fuel:await window.__FL_TESTS.dumpStore('fuel'),
      expenses:await window.__FL_TESTS.dumpStore('expenses'),
      schedule:await window.__FL_TESTS.getSetting('maintenanceSchedule',[]),
    }));
    eq(after.expenses.length,before.expenses+1,'maintenance with cost must contribute exactly one expense');
    eq(after.fuel.length,before.fuel,'maintenance must not create a fuel record');
    const rec=after.expenses.at(-1);
    eq(rec?.category,'Maintenance','maintenance contribution must retain Maintenance category');
    ok(Math.abs(Number(rec?.amount)-79.95)<0.001,'maintenance amount must reach expense totals exactly once');
    ok(Array.isArray(after.schedule) && after.schedule[0]?.lastCost===79.95,'maintenance schedule provenance must retain the service cost');
  } finally { await app.close(); }
});

test('[UXIA-14] Add Cost choices keep driver-sized targets and accessible names', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#money'; });
    await app.page.waitForSelector('#btnAddCost');
    await app.page.click('#btnAddCost');
    await app.page.waitForSelector('[data-cost-kind]');
    const rows=await app.page.locator('[data-cost-kind]').evaluateAll(els => els.map(el => ({
      h:el.getBoundingClientRect().height,
      name:(el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g,' ').trim(),
    })));
    ok(rows.length>=3,'chooser must expose Fuel, Maintenance, and Expense choices');
    for(const row of rows){
      ok(row.h>=44,'every Add Cost choice must be at least 44px tall');
      ok(row.name.length>0,'every Add Cost choice must have an accessible name');
    }
  } finally { await app.close(); }
});

export async function runSpec(){
  const r=await run();
  return r;
}
if (import.meta.url===`file://${process.argv[1]}`){
  const r=await runSpec();
  process.exit(r.fail>0?1:0);
}
