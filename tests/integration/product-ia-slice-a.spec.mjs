// Issue #417 Slice A — red-first product IA contracts.
import { readFileSync } from 'node:fs';
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/product-ia-slice-a.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot() {
  const app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
  await sleep(900);
  return app;
}

async function primaryNav(page) {
  return page.$$eval('.bottom .nav a', els => els.map(e => ({
    label: (e.querySelector('.nl')?.textContent || '').trim(),
    route: e.dataset.nav || '',
    href: e.getAttribute('href') || '',
    aria: e.getAttribute('aria-label') || '',
  })));
}

test('[UXIA-01] idle primary shell is five workflow destinations and History preserves #trips', async () => {
  const app = await boot();
  try {
    const tabs = await primaryNav(app.page);
    eq(tabs.length, 5, 'primary navigation must expose no more than five destinations');
    eq(tabs.map(t => t.label).join('/'), 'Today/Loads/Evaluate/History/Money',
      'idle shell must read Today / Loads / Evaluate / History / Money');
    const history = tabs.find(t => t.label === 'History');
    ok(history, 'History is a visible primary destination');
    eq(history?.href, '#trips', 'History must preserve the supported #trips deep link');
  } finally { await app.close(); }
});

test('[UXIA-02] Today has one stateful dominant action', async () => {
  const app = await boot();
  try {
    const idle = await app.page.$$eval('[data-today-primary-action]', els =>
      els.map(e => ({ text:(e.textContent||'').trim().replace(/\s+/g,' '), href:e.getAttribute('href')||'' })));
    eq(idle.length, 1, 'Today must have exactly one dominant action while idle');
    ok(/Review\s*\/\s*Scan Loads/i.test(idle[0]?.text || ''),
      'idle Today action must say Review / Scan Loads');
    eq(idle[0]?.href, '#loads', 'idle Today action must lead to Loads');

    await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.upsertTrip({
        orderNo:'UXIA-ACTIVE-1', customer:'Fixture Broker', broker:'Fixture Broker',
        pay:625, loadedMiles:300, emptyMiles:25, paymentStatusKnown:true, isPaid:false,
        origin:'Chicago, IL', destination:'Indianapolis, IN',
        pickupDate:new Date().toISOString().slice(0,10), deliveryDate:'',
        executionStatus:'PICKED_UP', created:Date.now(),
      });
      T.invalidateKPICache();
      location.hash='#trips';
    });
    await sleep(350);
    await app.page.evaluate(() => { location.hash='#home'; });
    await sleep(1200);
    const active = await app.page.$$eval('[data-today-primary-action]', els =>
      els.map(e => ({ text:(e.textContent||'').trim().replace(/\s+/g,' '), href:e.getAttribute('href')||'' })));
    eq(active.length, 1, 'Today must still have exactly one dominant action with an active execution');
    ok(/Current Load/i.test(active[0]?.text || ''), 'active Today action must become Current Load');
    eq(active[0]?.href, '#current', 'active Today action must lead to the dedicated execution route');
  } finally { await app.close(); }
});

test('[UXIA-06] Current Load is an isolated execution surface backed by trip lifecycle state', async () => {
  const app = await boot();
  try {
    await app.page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.upsertTrip({
        orderNo:'UXIA-CURRENT-1', customer:'Execution Fixture', broker:'Execution Fixture',
        pay:700, loadedMiles:325, emptyMiles:20, paymentStatusKnown:true, isPaid:false,
        origin:'Louisville, KY', destination:'Columbus, OH',
        pickupDate:new Date().toISOString().slice(0,10), deliveryDate:'',
        executionStatus:'PICKED_UP', created:Date.now(),
      });
      location.hash='#current';
    });
    await sleep(900);
    const s = await app.page.evaluate(() => {
      const view=document.getElementById('view-current');
      return {
        exists:!!view,
        visible:!!view && getComputedStyle(view).display!=='none',
        text:(view?.innerText||'').replace(/\s+/g,' ').trim(),
        hasBidControls:!!view?.querySelector('#mwRevenue,#mwLoadedMi,#mwDeadMi,#mwEvaluate'),
        deliveredButton:!!view?.querySelector('[data-current-action="delivered"]'),
      };
    });
    ok(s.exists && s.visible, '#current must open a dedicated visible execution surface');
    ok(/UXIA-CURRENT-1/.test(s.text), 'Current Load must identify the canonical trip');
    ok(/In transit|Picked up/i.test(s.text), 'Current Load must project canonical PICKED_UP execution state');
    eq(s.hasBidControls, false, 'bidding/evaluator controls must be absent from the execution surface');
    ok(s.deliveredButton, 'Delivered must be an explicit operator action, never an inference from viewing the surface');

    const before = await app.page.evaluate(async () =>
      (await window.__FL_TESTS.dumpStore('trips')).find(t => t.orderNo==='UXIA-CURRENT-1')?.executionStatus);
    eq(before, 'PICKED_UP', 'rendering Current Load must not auto-complete the trip');
  } finally { await app.close(); }
});

test('[UXIA-09] Settings is configuration-only and Reports owns operational output', async () => {
  const app = await boot();
  try {
    await app.page.evaluate(() => { location.hash='#insights'; });
    await sleep(650);
    const settings = (await app.page.locator('#view-insights').innerText()).replace(/\s+/g,' ');
    ok(!/Tax Quick View/i.test(settings), 'Tax Quick View must move out of Settings');
    ok(!/Export to Accountant/i.test(settings), 'Accountant report output must move out of Settings');

    await app.page.evaluate(() => { location.hash='#reports'; });
    await sleep(650);
    const report = await app.page.evaluate(() => {
      const v=document.getElementById('view-reports');
      return { exists:!!v, visible:!!v && getComputedStyle(v).display!=='none', text:(v?.innerText||'').replace(/\s+/g,' ') };
    });
    ok(report.exists && report.visible, '#reports must be a first-class reachable destination');
    ok(/Weekly/i.test(report.text) && /Tax/i.test(report.text) && /Accountant|CPA/i.test(report.text),
      'Reports must make weekly, tax and accountant/CPA output visibly findable');
  } finally { await app.close(); }
});

test('[UXIA-10] Reports delegates to existing canonical report engines', () => {
  const src = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
  const start = src.indexOf('async function renderReports()');
  const end = src.indexOf('\nasync function ', start + 1);
  ok(start >= 0, 'renderReports() must exist');
  const block = src.slice(start, end > start ? end : start + 9000);
  for (const fn of ['openWeeklyReports','generateWeeklyReport','generateAccountantPackage','openCPAPackage','openTaxSeasonExport']) {
    ok(block.includes(fn), `Reports must delegate to canonical ${fn} rather than duplicate its calculations`);
  }
  ok(!/grossRev\s*=|netIncome\s*=|totalLoadedMi\s*=/.test(block),
    'Reports renderer must not reimplement report arithmetic');
});

test('[UXIA-14] new primary controls retain road-usable geometry and accessible names', async () => {
  const app = await boot();
  try {
    const r = await app.page.evaluate(() => {
      const action=document.querySelector('[data-today-primary-action]');
      const tabs=[...document.querySelectorAll('.bottom .nav a')];
      return {
        action: action ? { h:action.getBoundingClientRect().height, aria:action.getAttribute('aria-label')||'' } : null,
        tabs: tabs.map(t => ({ h:t.getBoundingClientRect().height, aria:t.getAttribute('aria-label')||'' })),
      };
    });
    ok(r.action, 'Today dominant action exists');
    ok(r.action.h >= 44, `Today dominant action must be >=44px tall, got ${r.action?.h}`);
    ok(r.action.aria.length > 0, 'Today dominant action needs an accessible name');
    ok(r.tabs.every(t => t.h >= 44), 'every primary navigation target must remain >=44px tall');
    ok(r.tabs.every(t => t.aria.length > 0), 'every primary navigation target must have an accessible name');
  } finally { await app.close(); }
});

export async function runSpec(){ return run(); }
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const r=await runSpec();
  process.exit(r.fail ? 1 : 0);
}
