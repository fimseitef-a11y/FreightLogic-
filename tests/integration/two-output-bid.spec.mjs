// v24.0.45 — the operator's two-output bidding method (2026-09-25).
//
// Output 1, Baseline / Cost-Protected Bid = loaded miles x $1.25 + deadhead miles
// x the canonical MARGINAL cost ($0.296/mi at the dated profile defaults, never
// the $0.405 all-in). Output 2, Recommended Market Bid = the baseline plus only
// the adjustments the evaluator has evidence for, each named. Unknown miles fail
// closed with no dollar figure. Both outputs render in the canonical evaluator,
// on the scored card and on the no-pay quote card, outside Show Details.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/two-output-bid.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

const score = (l) => evalIn(async (l) => {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  location.hash = '#omega';
  set('mwOrigin', l.origin); set('mwDest', l.dest);
  set('mwLoadedMi', l.loaded); set('mwDeadMi', l.dead); set('mwRevenue', l.revenue);
  set('mwLoadNotes', l.notes || '');
  set('mwDayOfWeek', l.day || 'mon'); set('mwDeliveryDay', l.deliveryDay || '');
  await window.__FL_TESTS.mwEvaluateLoad();
  const out = document.getElementById('mwEvalOutput');
  const card = out?.querySelector('[data-two-bid]');
  const base = card?.querySelector('[data-two-bid-baseline]');
  const rec = card?.querySelector('[data-two-bid-recommended]');
  return {
    present: !!card,
    unavailable: !!out?.querySelector('[data-two-bid-unavailable]'),
    insideDetails: !!(card && card.closest('details')),
    baseline: base ? Number(base.dataset.twoBidBaseline) : null,
    recommended: rec ? Number(rec.dataset.twoBidRecommended) : null,
    text: (card?.textContent || '').replace(/\s+/g, ' ').trim(),
    quote: !!out?.querySelector('[data-eval-quote]'),
    evidence: card?.dataset.twoBidEvidence || null,
    limited: !!card?.querySelector('[data-two-bid-limited]'),
  };
}, l);

const two = (input) => evalIn((i) => JSON.parse(JSON.stringify(window.__FL_TESTS.deriveTwoOutputBid(i))), input);

test('[TOB-01] baseline = loaded x $1.25 + deadhead x marginal CPM; no evidence means recommended = baseline', async () => {
  const b = await two({ loadedMi: 355, deadMi: 40, deadheadCPM: 0.296 });
  ok(b.available, 'complete miles produce a bid');
  eq(b.baseline, 456, '355 x 1.25 + 40 x 0.296 = 455.59, rounded to $456');
  eq(b.recommended, b.baseline, 'no market signal: recommended equals baseline');
  eq(b.adjustments.length, 0, 'no adjustment is invented');
  eq(b.marketEvidence, false, 'marketEvidence is false with no signal');
  eq(b.evidence, 'LIMITED', 'no destination: the recommendation is qualified as LIMITED, not presented as market-adjusted');
  ok(/not market-adjusted/.test(b.notes.join(' ')), 'the qualification is stated');
});

test('[TOB-02] unknown loaded, deadhead or cost fails closed with no dollar figure', async () => {
  for (const input of [
    { loadedMi: 355, deadMi: null, deadheadCPM: 0.296 },
    { loadedMi: 355, deadMi: '', deadheadCPM: 0.296 },
    { loadedMi: null, deadMi: 40, deadheadCPM: 0.296 },
    { loadedMi: 355, deadMi: 40, deadheadCPM: null },
  ]) {
    const b = await two(input);
    eq(b.available, false, `unavailable for ${JSON.stringify(input)}`);
    eq(b.baseline, null, 'no baseline dollar figure');
    eq(b.recommended, null, 'no recommended dollar figure');
  }
});

test('[TOB-03] an explicit zero deadhead is a verified zero, not an unknown', async () => {
  const b = await two({ loadedMi: 200, deadMi: 0, deadheadCPM: 0.296 });
  ok(b.available, 'zero deadhead is known');
  eq(b.baseline, 250, '200 x 1.25 + 0');
});

test('[TOB-04] recommended adds only named evidence: urgency, cross-border, weekend hold', async () => {
  const b = await two({
    loadedMi: 300, deadMi: 100, deadheadCPM: 0.296, urgencyBoost: 0.15, crossBorder: true,
    weekendOverlay: { active: true, label: 'Weekend hold', rpmAdder: 0.15, holdPremium: { min: 150, max: 350 } },
  });
  eq(b.baseline, 405, '300 x 1.25 + 100 x 0.296 = 404.6');
  const keys = b.adjustments.map(a => a.key).join(',');
  eq(keys, 'urgency,crossBorder,weekend,weekendHold', 'each adjustment is named');
  // 400 total miles: urgency 60 + cross-border 40 + weekend 60 + hold 150 = 310
  eq(b.recommended, 405 + 310, 'recommended = baseline + the named adjustments');
  const capped = await two({ loadedMi: 300, deadMi: 100, deadheadCPM: 0.296, urgencyBoost: 5 });
  eq(capped.recommended - capped.baseline, 120, 'urgency is capped at $0.30/mi like the canonical bid range');
});

test('[TOB-05] the scored evaluator card shows both outputs, outside Show Details, on marginal (not all-in) cost', async () => {
  const r = await score({ origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '20', revenue: '400' });
  console.log(`    [evidence] ${JSON.stringify(r.text.slice(0, 200))}`);
  ok(r.present, 'the result carries the two-output bid');
  ok(!r.insideDetails, 'it is not buried in the collapsed Show Details');
  ok(/Baseline \/ Cost-Protected Bid/.test(r.text) && /Recommended Market Bid/.test(r.text), 'both outputs are labelled');
  eq(r.baseline, 231, '180 x 1.25 + 20 x 0.296 = 230.92 (all-in 0.405 would give 233)');
  eq(r.recommended, r.baseline, 'Tier 1 destination, weekday, no urgency: recommended equals baseline');
  ok(/Tier 1 destination/.test(r.text) && /no destination premium/.test(r.text), 'the card says the destination was assessed and carries no premium');
  eq(r.evidence, 'DESTINATION', 'a recognised destination is destination-evidenced');
});

test('[TOB-06] the no-pay quote card shows both outputs, and an urgency note raises only the recommendation', async () => {
  const r = await score({ origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '355', dead: '40', revenue: '', notes: 'ASAP' });
  ok(r.quote, 'no pay: the quote card renders');
  ok(r.present, 'the quote card carries the two-output bid');
  eq(r.baseline, 456, 'baseline is unaffected by the urgency note');
  eq(r.recommended, 456 + Math.round(0.15 * 395), 'ASAP adds $0.15/mi over 395 total miles');
  ok(/Urgent load/.test(r.text), 'the adjustment is named');
});

test('[TOB-07] a blank deadhead renders no dollar bid on the scored path', async () => {
  const r = await score({ origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '', revenue: '400' });
  ok(!r.present || r.unavailable, 'no two-output bid without the deadhead figure');
  eq(r.baseline, null, 'no baseline dollar figure');
});

test('[TOB-08] (#386) a recognised out-of-density destination carries the $0.20/mi doctrine gap; in-density does not', async () => {
  const weak = await two({ loadedMi: 300, deadMi: 100, deadheadCPM: 0.296,
    destination: { known: true, tier: 'OTHER', intoDensity: false, name: 'Atlanta, GA' } });
  eq(weak.evidence, 'DESTINATION', 'a known destination is destination evidence');
  const a = weak.adjustments.find(x => x.key === 'weakDestination');
  ok(a, 'out-of-density destination is a named adjustment');
  eq(a.amount, 80, '$0.20 (Strong 1.60 - normal 1.40) x 400 total miles');
  eq(weak.recommended, weak.baseline + 80, 'recommended = baseline + the destination premium');
  const t1 = await two({ loadedMi: 300, deadMi: 100, deadheadCPM: 0.296,
    destination: { known: true, tier: 'TIER1', intoDensity: true, name: 'Columbus, OH' } });
  eq(t1.recommended, t1.baseline, 'a Tier 1 destination adds nothing');
  ok(/no destination premium/.test(t1.notes.join(' ')), 'and says so');
  const unk = await two({ loadedMi: 300, deadMi: 100, deadheadCPM: 0.296,
    destination: { known: false, tier: null, intoDensity: false, name: 'Nowhereville' } });
  eq(unk.evidence, 'LIMITED', 'an unrecognised destination is LIMITED evidence, never an out-of-density premium');
  eq(unk.recommended, unk.baseline, 'no premium is invented for an unknown place');
});

test('[TOB-09] (#386) reload history prices only with 3+ outcomes, and only in density', async () => {
  const base = { loadedMi: 300, deadMi: 100, deadheadCPM: 0.296,
    destination: { known: true, tier: 'TIER2', intoDensity: true, name: 'Dayton, OH' } };
  const proven = await two({ ...base, reload: { grade: 'D', label: 'Dead zone', count: 4, avg: 60 } });
  const r = proven.adjustments.find(x => x.key === 'slowReload');
  ok(r && r.amount === 80, 'a proven slow reload (4 outcomes) adds $0.20/mi');
  const thin = await two({ ...base, reload: { grade: 'D', label: 'Dead zone', count: 2, avg: 60 } });
  eq(thin.recommended, thin.baseline, 'two outcomes are too few to price on');
  ok(/too few to price on/.test(thin.notes.join(' ')), 'and the card says why');
  const fast = await two({ ...base, reload: { grade: 'A', label: 'Hot market', count: 9, avg: 4 } });
  eq(fast.recommended, fast.baseline, 'a fast reload adds nothing');
});

test('[TOB-10] (#386) the evaluator prices a weekday out-of-density load above baseline, and flags an unknown destination', async () => {
  const weak = await score({ origin: 'Chicago, IL', dest: 'Atlanta, GA', loaded: '700', dead: '50', revenue: '1600' });
  console.log(`    [evidence] ${JSON.stringify(weak.text.slice(0, 260))}`);
  eq(weak.evidence, 'DESTINATION', 'Atlanta is a recognised market');
  ok(weak.recommended > weak.baseline, `recommended must exceed baseline into a weak destination — got ${weak.baseline} / ${weak.recommended}`);
  ok(/Out-of-density destination/.test(weak.text), 'the adjustment is named');
  const unk = await score({ origin: 'Chicago, IL', dest: 'Zzyzx Nowhere', loaded: '300', dead: '20', revenue: '700' });
  ok(unk.present, 'the bid still renders');
  ok(unk.limited, 'an unrecognised destination is visibly marked LIMITED EVIDENCE');
  eq(unk.recommended, unk.baseline, 'and no premium is invented');
});

test('[TOB-11] (#386) no-pay and scored paths agree on a cross-border load', async () => {
  const L = { origin: 'Detroit, MI', dest: 'Toronto, ON', loaded: '240', dead: '20' };
  const quote = await score({ ...L, revenue: '' });
  const scored = await score({ ...L, revenue: '700' });
  console.log(`    [evidence] quote=${quote.baseline}/${quote.recommended} scored=${scored.baseline}/${scored.recommended}`);
  ok(quote.quote, 'no pay: quote card');
  ok(/Cross-border/.test(quote.text), 'the no-pay quote card applies the cross-border adjustment');
  ok(/Cross-border/.test(scored.text), 'the scored card applies it too');
  eq(quote.baseline, scored.baseline, 'same baseline on both paths');
  eq(quote.recommended, scored.recommended, 'same recommended market bid on both paths');
});

export async function runSpec() {
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
