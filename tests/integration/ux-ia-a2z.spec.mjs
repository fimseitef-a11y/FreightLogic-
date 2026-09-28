// AIAG-TASK-0024 — operator-approved FreightLogic UX/IA A-to-Z contracts.
// Red-first: this spec intentionally describes the target driver shell before
// implementation. Canonical economics/data semantics are not changed here.
import { readFileSync } from 'node:fs';
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/ux-ia-a2z.spec.mjs');
const appSrc = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
const shell = readFileSync(new URL('../../modern-shell.js', import.meta.url), 'utf8');

async function boot(){
  const app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
  await app.page.waitForTimeout(500);
  return app;
}

test('[UXA2Z-01] primary shell is Today / Loads / Scan / History / Money', async () => {
  const app = await boot();
  try {
    const tabs = await app.page.$$eval('.bottom .nav a', els => els.map(e => (e.querySelector('.nl')?.textContent || '').trim()));
    eq(tabs.join('/'), 'Today/Loads/Scan/History/Money', 'driver shell must use Scan, not Evaluate');
    ok(/omega:\s*'Scan'/.test(shell), 'route title must identify omega as Scan');
  } finally { await app.close(); }
});

test('[UXA2Z-02] Scan is a persistent workspace with one screenshot entry and no redundant camera control', () => {
  ok(/<h2[^>]*>Scan Load<\/h2>/.test(html), 'Scan workspace heading must be Scan Load');
  ok(/id="btnLoadIntake"/.test(html), 'Scan workspace keeps one intake entry');
  ok(!/id="liPickImg"/.test(appSrc), 'Load Intake must not render a separate Camera button');
  ok(!/id="liImgCamera"/.test(appSrc), 'Load Intake must not keep a second capture-only input');
  ok(/clipboardData[\s\S]{0,500}startsWith\('image\/'\)/.test(appSrc), 'paste area must still accept clipboard images');
});

test('[UXA2Z-03] FreightLogic infers decision mode from whether a rate exists', () => {
  ok(/data-decision-mode="build-bid"/.test(appSrc), 'blank revenue path must render Build My Bid');
  ok(/data-decision-mode="evaluate-offer"/.test(appSrc), 'posted-rate path must render Evaluate Offer');
});

test('[UXA2Z-04] GPS deadhead is advisory and can never overwrite explicit zero', () => {
  const start=appSrc.indexOf('async function updateGPSDeadhead');
  const end=appSrc.indexOf('\n}', start)+2;
  ok(start >= 0 && end > start, 'GPS deadhead helper exists');
  const block=appSrc.slice(start,end+1200);
  ok(/Estimated deadhead/i.test(block), 'GPS hint must say Estimated deadhead');
  ok(/mwGpsUseEstimate/.test(block), 'operator must explicitly choose Use estimate');
  ok(!/deadEl\.value\s*=\s*miles/.test(block), 'estimator must never silently write canonical deadhead');
});

test('[UXA2Z-05] Loads owns Market Intel discovery', () => {
  ok(/id="btnLoadsMarket"[^>]+href="#intel"|href="#intel"[^>]+id="btnLoadsMarket"/.test(html),
    'Loads must expose Market Intel directly');
  const moreStart=appSrc.indexOf('const MORE_TILES = [');
  const moreEnd=appSrc.indexOf('];',moreStart);
  const more=appSrc.slice(moreStart,moreEnd+2);
  ok(!/title:'Market Intel'/.test(more), 'Market Intel must not be duplicated in More');
});

test('[UXA2Z-06] More is reduced to Documents and Settings', () => {
  const start=appSrc.indexOf('const MORE_TILES = [');
  const end=appSrc.indexOf('];',start);
  const block=appSrc.slice(start,end+2);
  const titles=[...block.matchAll(/title:'([^']+)'/g)].map(m=>m[1]);
  eq(titles.join('/'), 'Documents/Settings', 'More should expose only secondary document/config destinations');
});

test('[UXA2Z-07] Money owns Expenses, Fuel and Reports without a Settings shortcut', () => {
  const moneyStart=html.indexOf('id="view-money"');
  const fuelStart=html.indexOf('id="view-fuel"', moneyStart);
  const money=html.slice(moneyStart,fuelStart);
  ok(/href="#expenses"/.test(money) && /href="#fuel"/.test(money) && /href="#reports"/.test(money),
    'Money must link to Expenses, Fuel and Reports');
  ok(!/Settings/i.test(money), 'Money must not contain Settings');
});

test('[UXA2Z-08] History is records, not a Current / History / Reports navigation hub', () => {
  ok(!/function ensureTripsHistoryNav/.test(appSrc), 'History must not inject peer navigation');
  ok(!/id="tripsHistoryNav"/.test(appSrc), 'legacy History subnav must be removed');
});

test('[UXA2Z-09] Settings directory is seven configuration-only groups and onboarding is two stages', () => {
  for (const label of ['Vehicle &amp; Capacity','Money &amp; Accounting','Trip Planning','Connections &amp; Backup',
    'Notifications &amp; Display','Privacy &amp; Security','Advanced &amp; Diagnostics']) {
    ok(html.includes(label), `Settings directory must include ${label}`);
  }
  ok(!/<h3>Money &amp; AR<\/h3>/.test(html), 'Settings must not carry Money/AR operational navigation');
  const stepsStart=appSrc.indexOf('const STEPS = [', appSrc.indexOf('async function openSetupWizard'));
  const stepsEnd=appSrc.indexOf('];',stepsStart);
  const steps=appSrc.slice(stepsStart,stepsEnd+2);
  const ids=[...steps.matchAll(/id:'([^']+)'/g)].map(m=>m[1]);
  eq(ids.length,2,'first-run setup must be no more than two stages');
});

test('[UXA2Z-10] trip document workflow offers Scan Document', () => {
  ok(/id="addDvScan"/.test(appSrc), 'Add Document must offer Scan Document');
  ok(/id="addDvScanFile"[^>]+capture="environment"/.test(appSrc), 'Scan Document must use the rear-camera capture path on supported iPhone browsers');
});

test('[UXA2Z-11] explicit zero deadhead persists across reload', async () => {
  const app = await boot();
  try {
    await app.page.evaluate(async () => {
      const set=(id,v)=>{ const el=document.getElementById(id); if(el) el.value=v; };
      location.hash='#omega';
      set('mwLoadedMi','200'); set('mwDeadMi','0'); set('mwRevenue','350');
      await window.__FL_TESTS.mwEvaluateLoad();
    });
    await app.page.reload({ waitUntil:'load' });
    await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout:10000 });
    await app.page.waitForTimeout(800);
    await app.page.evaluate(() => { location.hash='#omega'; });
    await app.page.waitForTimeout(400);
    eq(await app.page.locator('#mwDeadMi').inputValue(), '0', 'known zero must survive a fresh app load');
  } finally { await app.close(); }
});

test('[UXA2Z-12] active execution suppresses idle Today cards', async () => {
  const app = await boot();
  try {
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.upsertTrip({
        orderNo:'UXA2Z-ACTIVE', customer:'Fixture', broker:'Fixture',
        pay:500, loadedMiles:250, emptyMiles:10, paymentStatusKnown:true, isPaid:false,
        origin:'Chicago, IL', destination:'Indianapolis, IN',
        pickupDate:new Date().toISOString().slice(0,10), deliveryDate:'',
        executionStatus:'PICKED_UP', created:Date.now(),
      });
      location.hash='#home';
    });
    await app.page.waitForTimeout(1000);
    const r=await app.page.evaluate(() => ({
      focus:document.getElementById('view-home')?.classList.contains('today-execution-focus'),
      recent:getComputedStyle(document.getElementById('homeRecentTripsCard')).display,
    }));
    ok(r.focus, 'Today must enter execution-focus state for an active load');
    eq(r.recent, 'none', 'idle Recent Trips card must be suppressed during active execution');
  } finally { await app.close(); }
});

export async function runSpec(){ return run(); }
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const r=await runSpec();
  process.exit(r.fail ? 1 : 0);
}
