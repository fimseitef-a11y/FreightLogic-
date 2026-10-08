// Issue #417 Slice B — Loads decision-inbox contracts.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/product-ia-slice-b.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot(){
  const app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout:10000 });
  await sleep(500);
  return app;
}

async function seed(page, raw, opts = {}){
  return page.evaluate(async ({raw,opts}) => {
    const T=window.__FL_TESTS;
    return T.intakeOpportunity(raw, { sourceType:'MANUAL', authority:'OPERATOR_ENTERED_UNVERIFIED', ...opts });
  }, {raw,opts});
}

test('[UXIA-03] pasted Loads intake becomes durable evidence before opening the evaluator', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(600);
    await app.page.fill('#f23Textarea',
      'Chicago IL to Detroit MI\n280 loaded miles\n$560 all-in\nPickup tomorrow 8am\nBroker: XPO Logistics');
    await app.page.click('#f23ScoreBtn');
    await app.page.waitForSelector('#f23ScoreLoad', { timeout:5000 });
    const before=await app.page.evaluate(async () => (await window.__FL_TESTS.listEvidence()).length);
    await app.page.click('#f23ScoreLoad');
    await sleep(850);
    const after=await app.page.evaluate(async () => {
      const T=window.__FL_TESTS;
      const rows=await T.listEvidence();
      const lifecycles=await T.listLifecycle();
      return {
        n:rows.length,
        latest:rows.slice().sort((a,b)=>b.recordedAt-a.recordedAt)[0]||null,
        lifecycles,
      };
    });
    ok(after.n > before, 'Score Load must durably record the reviewed opportunity before showing details');
    ok(after.latest?.lifecycleId, 'durable evidence should link to a lifecycle record');
    const lc=after.lifecycles.find(x => x.lifecycleId===after.latest.lifecycleId);
    eq(lc?.opportunity, 'SEEN', 'reviewing/scoring an offer must not fabricate BID, WON, or completed freight');
    eq(lc?.execution, 'NOT_STARTED', 'pre-award intake must not fabricate execution');
  } finally { await app.close(); }
});

test('[UXIA-03] durable inbox preserves unknown deadhead as UNKNOWN, never zero', async () => {
  const app=await boot();
  try{
    const res=await seed(app.page, {
      orderNo:'UXIA-B-UNKNOWN', broker:'Fixture Broker',
      origin:'Chicago, IL', destination:'Detroit, MI',
      loadedMi:280, deadMi:null, mileageSemantic:'LOADED_MILES',
      amount:560, priceSemantic:'UNKNOWN_PRICE_SEMANTIC',
    });
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    const card=app.page.locator(`[data-load-decision-card][data-evidence-id="${res.evidence.evidenceId}"]`);
    ok(await card.count()===1, 'a durable evidence row must materialize as one Loads decision card');
    const text=(await card.innerText()).replace(/\s+/g,' ');
    ok(/Deadhead\s+Unknown/i.test(text), 'unknown deadhead must be labelled Unknown');
    ok(!/Deadhead\s+0\b/i.test(text), 'unknown deadhead must never render as zero');
    ok(/SEEN/i.test(text), 'the card must project lifecycle state');
  } finally { await app.close(); }
});

test('[UXIA-04] decision-card economics are projected from canonical economics/grade authority', async () => {
  const app=await boot();
  try{
    const res=await seed(app.page, {
      orderNo:'UXIA-B-CANON', broker:'Fixture Broker',
      origin:'Milwaukee, WI', destination:'Indianapolis, IN',
      loadedMi:300, deadMi:50, mileageSemantic:'LOADED_MILES',
      amount:700, priceSemantic:'CARRIER_PAYOUT',
    });
    const expected=await app.page.evaluate(async () => {
      const T=window.__FL_TESTS;
      const p=await T.resolveCanonicalCostProfile();
      const e=T.deriveUnifiedEconomics({
        loadedMi:300, deadMi:50, revenue:700, effectiveRevenue:700,
        mpg:p.mpg, fuelPrice:p.fuelPrice, fuelCPM:p.fuelCPM,
        nonFuelVariableCPM:p.nonFuelVariableCPM, fixedCPM:p.fixedCPM,
        costProfileSource:p.modelVersion,
      });
      const g=T.deriveUnifiedGrade(e.trueRPM).display;
      return { rpm:e.trueRPM, grade:g.grade };
    });
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    const data=await app.page.locator(
      `[data-load-decision-card][data-evidence-id="${res.evidence.evidenceId}"]`
    ).evaluate(el => ({rpm:el.getAttribute('data-true-rpm'),grade:el.getAttribute('data-grade')}));
    ok(Math.abs(Number(data.rpm)-expected.rpm)<0.000001,
      'card True RPM must be the canonical economics result, not independent UI arithmetic');
    eq(data.grade, expected.grade, 'card grade must be the canonical grade result');
  } finally { await app.close(); }
});

test('[UXIA-05] Pursue/Pass are reversible inbox dispositions and do not manufacture lifecycle outcomes', async () => {
  const app=await boot();
  try{
    const res=await seed(app.page, {
      orderNo:'UXIA-B-PASS', broker:'Fixture Broker',
      origin:'Louisville, KY', destination:'Columbus, OH',
      loadedMi:325, deadMi:20, mileageSemantic:'LOADED_MILES',
      amount:650, priceSemantic:'UNKNOWN_PRICE_SEMANTIC',
    });
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    const id=res.evidence.evidenceId;
    await app.page.click(`[data-load-pursue="${id}"]`);
    await sleep(250);
    // v24.0.62: a pursued load moves to the Saved list.
    await app.page.click('[data-load-tab="SAVED"]');
    await sleep(250);
    await app.page.click(`[data-load-pass="${id}"]`);
    await sleep(350);
    const state=await app.page.evaluate(async ({id,lcid}) => {
      const T=window.__FL_TESTS;
      const d=await T.getSetting('loadsInboxDispositionV1',{});
      const lc=await T.getLifecycle(lcid);
      return {decision:d?.[id]?.decision||'', opportunity:lc?.opportunity||'', execution:lc?.execution||''};
    }, {id,lcid:res.evidence.lifecycleId});
    eq(state.decision,'PASS','Pass must be a durable/reversible inbox disposition');
    eq(state.opportunity,'SEEN','Pass must not manufacture LOST, EXPIRED, CANCELLED or DEACTIVATED');
    eq(state.execution,'NOT_STARTED','Pass must not create execution history');
  } finally { await app.close(); }
});

test('[UXIA-05] Awarded is operator-explicit and advances only the opportunity axis to WON', async () => {
  const app=await boot();
  try{
    const res=await seed(app.page, {
      orderNo:'UXIA-B-WON', broker:'Fixture Broker',
      origin:'Cincinnati, OH', destination:'Toledo, OH',
      loadedMi:220, deadMi:10, mileageSemantic:'LOADED_MILES',
      amount:500, priceSemantic:'CARRIER_PAYOUT',
    });
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    await app.page.click(`[data-load-award="${res.evidence.evidenceId}"]`);
    await sleep(450);
    const lc=await app.page.evaluate(async id => window.__FL_TESTS.getLifecycle(id),res.evidence.lifecycleId);
    eq(lc.opportunity,'WON','explicit Awarded must set the opportunity axis to WON');
    eq(lc.execution,'NOT_STARTED','an award must not fabricate pickup/delivery execution');
    eq(lc.settlement,'NOT_INVOICED','an award must not fabricate invoicing/payment');
  } finally { await app.close(); }
});

test('[UXIA-04] Open Details delegates to the existing canonical evaluator surface', async () => {
  const app=await boot();
  try{
    const res=await seed(app.page, {
      orderNo:'UXIA-B-DETAILS', broker:'Fixture Broker',
      origin:'Chicago, IL', destination:'Indianapolis, IN',
      loadedMi:300, deadMi:25, mileageSemantic:'LOADED_MILES',
      amount:650, priceSemantic:'CARRIER_PAYOUT',
    });
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    await app.page.click(`[data-load-open="${res.evidence.evidenceId}"]`);
    await app.page.waitForFunction(() => location.hash==='#omega', null, {timeout:5000});
    await sleep(650);
    const s=await app.page.evaluate(() => ({
      revenue:document.getElementById('mwRevenue')?.value||'',
      loaded:document.getElementById('mwLoadedMi')?.value||'',
      dead:document.getElementById('mwDeadMi')?.value||'',
      origin:document.getElementById('mwOrigin')?.value||'',
      out:(document.getElementById('mwEvalOutput')?.innerText||'').replace(/\s+/g,' '),
    }));
    eq(s.revenue,'650','Load Details must hydrate the canonical evaluator with observed carrier payout');
    eq(s.loaded,'300','loaded miles must survive into canonical details');
    eq(s.dead,'25','known deadhead must survive into canonical details');
    eq(s.origin,'Chicago, IL','route facts must survive into canonical details');
    ok(/True RPM|Grade|PREMIUM|ACCEPT|CONDITIONAL|NEGOTIATE|STRATEGIC|REJECT/i.test(s.out),
      'Load Details must render through the existing canonical evaluator output');
  } finally { await app.close(); }
});

test('[UXIA-06] Loads lists New/Saved/Won/Passed filter existing state and Market opens Market Intel', async () => {
  const app=await boot();
  try{
    const mk = (n, extra={}) => seed(app.page, {
      orderNo:'UXIA-06-'+n, broker:'Fixture Broker', origin:'Chicago, IL', destination:'Detroit, MI',
      loadedMi:280, deadMi:20, mileageSemantic:'LOADED_MILES', amount:600, priceSemantic:'CARRIER_PAYOUT', ...extra,
    });
    const a=(await mk('A')).evidence.evidenceId, b=(await mk('B')).evidence.evidenceId;
    const c=(await mk('C')).evidence.evidenceId, d=(await mk('D')).evidence.evidenceId;
    await app.page.evaluate(() => { location.hash='#loads'; });
    await sleep(850);
    const tabsOf = () => app.page.evaluate(() => [...document.querySelectorAll('[data-load-tab]')]
      .map(b => ({ id:b.getAttribute('data-load-tab'), sel:b.getAttribute('aria-selected'), text:b.innerText.replace(/\s+/g,' ').trim(), h:b.getBoundingClientRect().height })));
    let tabs=await tabsOf();
    eq(tabs.map(t=>t.id).join(','),'NEW,SAVED,WON,PASSED,MARKET','Loads lists must be New / Saved / Won / Passed / Market in that order');
    eq(tabs.find(t=>t.sel==='true')?.id,'NEW','New is the default list');
    ok(tabs.every(t=>t.h>=44),'every list tab must be a 44px touch target');
    const visible = () => app.page.evaluate(() => [...document.querySelectorAll('[data-load-decision-card]')].map(c => c.getAttribute('data-evidence-id')));
    let v=await visible();
    ok([a,b,c,d].every(id => v.includes(id)),'undecided loads are New');
    await app.page.click(`[data-load-pursue="${a}"]`); await sleep(300);
    await app.page.click(`[data-load-pass="${b}"]`); await sleep(300);
    await app.page.click(`[data-load-award="${c}"]`); await sleep(500);
    v=await visible();
    eq(v.join(','), d, 'only the undecided load stays in New');
    tabs=await tabsOf();
    ok(/New 1/.test(tabs[0].text) && /Saved 1/.test(tabs[1].text) && /Won 1/.test(tabs[2].text) && /Passed 1/.test(tabs[3].text),'each list shows its count: '+tabs.map(t=>t.text).join('|'));
    for (const [tab,id] of [['SAVED',a],['PASSED',b],['WON',c]]){
      await app.page.click(`[data-load-tab="${tab}"]`); await sleep(300);
      eq((await visible()).join(','), id, tab+' must show exactly its load');
    }
    const passLc=await app.page.evaluate(async id => { const T=window.__FL_TESTS; const ev=await T.getEvidence(id); return (await T.getLifecycle(ev.lifecycleId)).opportunity; }, b);
    eq(passLc,'SEEN','the Passed list is a disposition filter; it must never record Lost');
    await app.page.click('[data-load-tab="MARKET"]');
    await app.page.waitForFunction(() => location.hash==='#intel', null, {timeout:5000});
    ok(true,'Market opens the existing Market Intel route');
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
