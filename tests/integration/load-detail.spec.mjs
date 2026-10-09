// v24.5 redesign — Load Detail (UI_BRIEF_V24.5.md §6.3, §9 step 7).
// The Loads card's Details button opens a detail sheet that READS the same
// canonical projection the card reads. It computes no economics of its own, keeps
// Unknown as Unknown, puts warnings first, and offers Pass and Evaluate.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/load-detail.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot(){
  const app = await launchApp();
  await app.page.setViewportSize({ width: 390, height: 844 });
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout: 10000 });
  await sleep(450);
  return app;
}

async function seed(page, raw){
  return page.evaluate(async (raw) => window.__FL_TESTS.intakeOpportunity(raw,
    { sourceType: 'MANUAL', sourceName: 'Load Detail fixture', authority: 'OPERATOR_ENTERED_UNVERIFIED' }), raw);
}

async function openDetail(page, evidenceId){
  await page.evaluate(() => { location.hash = '#loads'; });
  await page.waitForSelector(`[data-load-open="${evidenceId}"]`, { timeout: 5000 });
  await page.click(`[data-load-open="${evidenceId}"]`);
  await page.waitForSelector(`[data-load-detail="${evidenceId}"]`, { timeout: 5000 });
  await sleep(250);
}

const COMPLETE = {
  orderNo: 'LD-COMPLETE', broker: 'Fixture Broker',
  origin: 'Chicago, IL', destination: 'Detroit, MI',
  loadedMi: 278, deadMi: 32, mileageSemantic: 'LOADED_MILES',
  amount: 575, priceSemantic: 'CARRIER_PAYOUT',
  pickupAt: '2026-10-12T08:00', deliveryAt: '2026-10-12T15:30',
};

const read = (page) => page.evaluate(() => {
  const root = document.querySelector('[data-load-detail]');
  const t = (sel) => (root.querySelector(sel)?.innerText || '').replace(/\s+/g, ' ').trim();
  const miles = root.querySelector('[data-ld-miles]');
  const rate = root.querySelector('[data-ld-rate]');
  return {
    hash: location.hash,
    order: [...root.children].map(c => Object.keys(c.dataset)[0] || c.tagName),
    warn: t('[data-ld-warn]'), status: t('[data-ld-status]'), lane: t('[data-ld-lane]'),
    miles: t('[data-ld-miles]'), rate: t('[data-ld-rate]'), timing: t('[data-ld-timing]'), facts: t('[data-ld-facts]'),
    loaded: miles?.getAttribute('data-loaded'), dead: miles?.getAttribute('data-dead'), all: miles?.getAttribute('data-all'),
    trueRpm: rate?.getAttribute('data-true-rpm'), grade: rate?.getAttribute('data-grade'),
    actions: [...root.querySelectorAll('[data-ld-actions] button')].map(b => b.textContent.trim()),
    actionHeights: [...root.querySelectorAll('[data-ld-actions] button')].map(b => b.getBoundingClientRect().height),
    media: root.querySelectorAll('img,iframe,canvas,[class*="map"]').length,
    overflow: document.documentElement.scrollWidth > window.innerWidth,
    modalTitle: document.getElementById('modalTitle')?.textContent || '',
  };
});

test('[LD-01] Details opens the Load Detail sheet and shows the canonical figures the card shows', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, COMPLETE);
    const id = res.evidence.evidenceId;
    await openDetail(app.page, id);
    const s = await read(app.page);
    const canon = await app.page.evaluate(async (id) => {
      const T = window.__FL_TESTS;
      const ev = await T.getEvidence(id);
      const p = await T.buildLoadDecisionProjection(ev, ev.lifecycleId ? await T.getLifecycle(ev.lifecycleId) : null);
      const card = document.querySelector(`[data-load-decision-card][data-evidence-id="${id}"]`);
      return { rpm: String(p.economics.trueRPM), grade: p.grade.grade,
        cardRpm: card.getAttribute('data-true-rpm'), cardGrade: card.getAttribute('data-grade') };
    }, id);
    eq(s.hash, '#loads', 'Details must open the sheet in place, not jump to the evaluator');
    eq(s.modalTitle, 'Load Detail');
    ok(/Chicago, IL/.test(s.lane) && /Detroit, MI/.test(s.lane), `lane must show both ends (got "${s.lane}")`);
    eq(s.loaded, '278'); eq(s.dead, '32'); eq(s.all, '310', 'all miles are loaded plus deadhead when both are known');
    ok(/\$575/.test(s.rate) && /Carrier payout/i.test(s.rate), `rate must be labelled as carrier payout (got "${s.rate}")`);
    eq(s.trueRpm, canon.rpm, 'the sheet must show the canonical True RPM, not a second calculation');
    eq(s.trueRpm, canon.cardRpm, 'the sheet and the Loads card must agree on True RPM');
    eq(s.grade, canon.grade); eq(s.grade, canon.cardGrade);
    ok(new RegExp('\\$' + Number(canon.rpm).toFixed(2)).test(s.rate), 'True RPM must be visible in the rate block');
  } finally { await app.close(); }
});

test('[LD-02] unknown deadhead stays Unknown: no all-miles, no True RPM, grade ?, and the warning comes first', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, { ...COMPLETE, orderNo: 'LD-NODH', deadMi: null });
    await openDetail(app.page, res.evidence.evidenceId);
    const s = await read(app.page);
    eq(s.dead, '', 'an unstated deadhead must not become a number');
    eq(s.all, '', 'all miles are not derivable without deadhead');
    ok(/Deadhead\s*Unknown|Unknown\s*deadhead/i.test(s.miles), `deadhead must read Unknown (got "${s.miles}")`);
    ok(!/\b0\s*mi/.test(s.miles), 'an unknown deadhead must never render as 0 mi');
    eq(s.trueRpm, '', 'True RPM is unavailable without deadhead');
    eq(s.grade, '?');
    ok(/deadhead is unknown/i.test(s.warn), `the deadhead warning must be shown (got "${s.warn}")`);
    eq(s.order[0], 'ldWarn', 'hard warnings must be the first block in the sheet');
  } finally { await app.close(); }
});

test('[LD-03] an explicit zero deadhead is a verified zero and still grades', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, { ...COMPLETE, orderNo: 'LD-ZERO', deadMi: 0 });
    await openDetail(app.page, res.evidence.evidenceId);
    const s = await read(app.page);
    eq(s.dead, '0'); eq(s.all, '278');
    ok(s.trueRpm !== '' && s.grade !== '?', 'a verified zero deadhead must produce True RPM and a grade');
    ok(!/deadhead is unknown/i.test(s.warn), 'no deadhead warning for a verified zero');
  } finally { await app.close(); }
});

test('[LD-04] an observed amount that is not proven payout is labelled so and produces no True RPM', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, { ...COMPLETE, orderNo: 'LD-POSTED', priceSemantic: 'POSTED_RATE' });
    await openDetail(app.page, res.evidence.evidenceId);
    const s = await read(app.page);
    ok(/Observed amount/i.test(s.rate) && !/Carrier payout/i.test(s.rate), `an unproven amount must not be called payout (got "${s.rate}")`);
    eq(s.trueRpm, '', 'no True RPM from an amount that is not canonical revenue');
    ok(/not proven carrier payout/i.test(s.warn), `the payout warning must be shown (got "${s.warn}")`);
  } finally { await app.close(); }
});

test('[LD-05] status, freshness, timing and evidence bullets are shown; no map and exactly Pass and Evaluate', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, COMPLETE);
    await openDetail(app.page, res.evidence.evidenceId);
    const s = await read(app.page);
    ok(/SEEN|QUOTED|BID|WON|UNLINKED|UNRESOLVED/.test(s.status), `status must show the lifecycle stage (got "${s.status}")`);
    ok(/ago/.test(s.status), `freshness must be shown (got "${s.status}")`);
    ok(/Load Detail fixture|MANUAL/.test(s.status), `the source must be named (got "${s.status}")`);
    ok(/Pickup/.test(s.timing) && /Delivery/.test(s.timing) && /2026-10-12/.test(s.timing), `timing must show pickup and delivery (got "${s.timing}")`);
    ok(/Grade [A-F]/.test(s.facts), `evidence bullets must name the canonical grade (got "${s.facts}")`);
    ok(/static classification/i.test(s.facts), 'a market tier must be labelled as static classification, not live strength');
    eq(s.media, 0, 'no map tile, image, iframe or canvas');
    eq(JSON.stringify(s.actions), JSON.stringify(['Pass', 'Evaluate']));
    ok(Math.min(...s.actionHeights) >= 48, `actions must be at least 48px tall (got ${s.actionHeights})`);
    ok(!s.overflow, 'no horizontal overflow at 390px');
  } finally { await app.close(); }
});

test('[LD-06] Evaluate hands the load to the existing canonical evaluator; unknown deadhead stays blank there', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, { ...COMPLETE, orderNo: 'LD-EVAL', deadMi: null });
    await openDetail(app.page, res.evidence.evidenceId);
    await app.page.click('[data-ld-eval]');
    await app.page.waitForFunction(() => location.hash === '#omega', null, { timeout: 5000 });
    await sleep(650);
    const s = await app.page.evaluate(() => ({
      revenue: document.getElementById('mwRevenue')?.value || '',
      loaded: document.getElementById('mwLoadedMi')?.value || '',
      dead: document.getElementById('mwDeadMi')?.value || '',
      origin: document.getElementById('mwOrigin')?.value || '',
      dest: document.getElementById('mwDest')?.value || '',
    }));
    eq(s.revenue, '575'); eq(s.loaded, '278'); eq(s.origin, 'Chicago, IL'); eq(s.dest, 'Detroit, MI');
    eq(s.dead, '', 'an unknown deadhead must reach the evaluator blank, never as 0');
  } finally { await app.close(); }
});

test('[LD-07] Pass records a PASS disposition, never a lifecycle loss, and the load moves to Passed', async () => {
  const app = await boot();
  try {
    const res = await seed(app.page, { ...COMPLETE, orderNo: 'LD-PASS' });
    const id = res.evidence.evidenceId;
    await openDetail(app.page, id);
    await app.page.click('[data-ld-pass]');
    await sleep(700);
    const s = await app.page.evaluate(async ({ id, lcId }) => {
      const T = window.__FL_TESTS;
      const map = await T.getSetting(T.LOADS_INBOX_DISPOSITION_KEY, {});
      const lc = lcId ? await T.getLifecycle(lcId) : null;
      return { decision: map?.[id]?.decision || '', opportunity: lc ? lc.opportunity : null,
        sheetOpen: !!document.querySelector('[data-load-detail]') && document.getElementById('modal').classList.contains('open'),
        hash: location.hash };
    }, { id, lcId: res.evidence.lifecycleId });
    eq(s.decision, 'PASS');
    ok(s.opportunity !== 'LOST', 'Pass must never be recorded as Lost');
    ok(!s.sheetOpen, 'the sheet closes after Pass');
    eq(s.hash, '#loads');
    await app.page.click('[data-load-tab="PASSED"]');
    await sleep(500);
    ok(await app.page.evaluate((id) => !!document.querySelector(`[data-load-decision-card][data-evidence-id="${id}"][data-load-bucket="PASSED"]`), id),
      'the passed load must be listed under Passed');
  } finally { await app.close(); }
});

export const runSpec = run;

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
