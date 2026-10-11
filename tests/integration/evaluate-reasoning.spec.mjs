// Evaluate reasoning slice (v24.0.66) — UI_BRIEF_V24.5.md §6.4 "reasoning + evidence up front".
//
// Before this slice the evaluator's result card gave a driver the grade, the
// verdict sentence, the bid triple and a four-cell fact strip, and kept every
// REASON for the verdict (the Freight Intelligence steps) and the Confidence
// line inside the collapsed "Show Details". A REJECT therefore said "no" and
// made the driver open a drawer to find out why.
//
// The Why block renders the canonical steps read-only, failing first, outside
// the collapsed details. It owns no economics: every row is a step the canonical
// authority already produced, so EVR-01 asserts agreement with the details'
// own copy of the same steps rather than a recomputation. Checks that could not
// run (no origin/destination, no weekly gross) are NAMED as not assessed — an
// unknown is never rendered as a pass. The Confidence line moves up with it
// (once, not duplicated), and the whole block uses the shared scalable
// presentation classes, never an inline font-size (SSI-18).
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/evaluate-reasoning.spec.mjs');
let app;
const evalIn = (fn, arg) => app.page.evaluate(fn, arg);

// Score one load through the real evaluator form and read what the card renders.
const score = (load) => evalIn(async (l) => {
  const T = window.__FL_TESTS;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  location.hash = '#omega';
  set('mwOrigin', l.origin); set('mwDest', l.dest);
  set('mwLoadedMi', l.loaded); set('mwDeadMi', l.dead); set('mwRevenue', l.revenue);
  await T.mwEvaluateLoad();
  const out = document.getElementById('mwEvalOutput');
  const why = out.querySelector('[data-eval-why]');
  const details = out.querySelector('#mwEvalDetails');
  const hero = out.querySelector('[data-decision-mode]');
  const norm = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const rows = why ? [...why.querySelectorAll('[data-eval-why-row]')].map(r => ({
    pass: r.dataset.pass,
    label: norm(r.querySelector('.fl-eval-fact-label')?.textContent),
    detail: norm(r.querySelector('.fl-eval-alert')?.textContent),
  })) : [];
  const confSummaries = [...out.querySelectorAll('details > summary')].filter(x => /^\s*Confidence:/.test(x.textContent));
  const FOLLOWING = Node.DOCUMENT_POSITION_FOLLOWING;
  return {
    hasOutput: !!out,
    whyCount: out.querySelectorAll('[data-eval-why]').length,
    insideDetails: !!(why && why.closest('details')),
    rows,
    notAssessed: norm(why?.querySelector('[data-eval-not-assessed]')?.textContent),
    detailsText: norm(details?.textContent),
    detailsOpen: details ? details.hasAttribute('open') : null,
    // The decision's confidence is the <summary> that starts "Confidence:". The
    // Next Move block prints its own, different "Confidence:" (move confidence)
    // as a plain div, so counting text would conflate two separate claims.
    confidenceOutside: confSummaries.filter(x => !x.closest('#mwEvalDetails')).length,
    confidenceInside: confSummaries.filter(x => x.closest('#mwEvalDetails')).length,
    confidenceInWhy: confSummaries.filter(x => x.closest('[data-eval-why]')).length,
    inlineFontSizeInWhy: why ? why.querySelectorAll('[style*="font-size"]').length : -1,
    afterHero: !!(hero && why && (hero.compareDocumentPosition(why) & FOLLOWING)),
    beforeDetails: !!(why && details && (why.compareDocumentPosition(details) & FOLLOWING)),
    ids: ['mwBookTrip', 'mwClearNext', 'mwAskAI', 'mwShareBid', 'mwEvalDetails']
      .filter(id => !document.getElementById(id)),
    text: norm(out.textContent),
  };
}, load);

const GOOD = { origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '20', revenue: '400' };
const BAD = { origin: 'Chicago, IL', dest: 'Indianapolis, IN', loaded: '180', dead: '20', revenue: '150' };
const NO_GEO = { origin: '', dest: '', loaded: '180', dead: '20', revenue: '400' };

test('[EVR-01] the reasons render outside Show Details and agree with the details\' own steps', async () => {
  const r = await score(GOOD);
  console.log(`    [evidence] rows=${JSON.stringify(r.rows.map(x => `${x.pass}:${x.label}`))}`);
  eq(r.whyCount, 1, 'exactly one Why block per result');
  ok(!r.insideDetails, 'the Why block must not be buried inside the collapsed Show Details');
  ok(r.rows.length >= 3, `a scored load carries its reasons — got ${r.rows.length}`);
  for (const row of r.rows) {
    ok(row.label && row.detail, `every row has a label and a detail — ${JSON.stringify(row)}`);
    ok(r.detailsText.includes(row.label) && r.detailsText.includes(row.detail),
      `row "${row.label}: ${row.detail}" must be the same canonical step the details list — not a recomputation`);
  }
  ok(r.rows.some(x => x.label === 'True RPM'), 'True RPM is always one of the reasons');
});

test('[EVR-02] a REJECT leads with what failed, then what passed', async () => {
  const r = await score(BAD);
  console.log(`    [evidence] order=${JSON.stringify(r.rows.map(x => `${x.pass}:${x.label}`))}`);
  ok(/REJECT/.test(r.text), 'fixture must be a REJECT');
  ok(r.rows.length > 0, 'the Why block exists on a REJECT');
  eq(r.rows[0].pass, 'false', 'the first reason is a failing one');
  const firstPass = r.rows.findIndex(x => x.pass === 'true');
  const lastFail = r.rows.map(x => x.pass).lastIndexOf('false');
  ok(firstPass === -1 || lastFail < firstPass, 'no passing reason is listed above a failing one');
  ok(r.rows.some(x => x.pass === 'true'), 'fixture must also carry a passing reason, or the ordering proves nothing');
});

test('[EVR-03] a check that could not run is named "Not assessed", never shown as a pass', async () => {
  const blank = await score(NO_GEO);
  console.log(`    [evidence] notAssessed=${JSON.stringify(blank.notAssessed)} rows=${JSON.stringify(blank.rows.map(x => x.label))}`);
  ok(/Not assessed/i.test(blank.notAssessed), 'a not-assessed line exists');
  ok(/Geography/.test(blank.notAssessed), 'no origin/destination → Geography is named as not assessed');
  ok(/Weekly Position/.test(blank.notAssessed), 'no weekly gross → Weekly Position is named as not assessed');
  ok(!blank.rows.some(x => x.label === 'Geography' || x.label === 'Weekly Position'),
    'an unassessed check is not also listed as a reason');
  const full = await score(GOOD);
  ok(!/Geography/.test(full.notAssessed), 'with a lane entered, Geography is assessed and not listed as missing');
  ok(full.rows.some(x => x.label === 'Geography'), 'and it appears as a reason');
});

test('[EVR-04] the Confidence line is on the primary card once, not duplicated in the details', async () => {
  const r = await score(GOOD);
  console.log(`    [evidence] outside=${r.confidenceOutside} inside=${r.confidenceInside} inWhy=${r.confidenceInWhy}`);
  eq(r.confidenceOutside, 1, 'exactly one Confidence line outside Show Details');
  eq(r.confidenceInWhy, 1, 'and it lives with the reasons');
  eq(r.confidenceInside, 0, 'moved, not copied — the details no longer repeat it');
});

test('[EVR-05] existing action IDs survive, details stay collapsed, and the Why block sits between hero and details', async () => {
  const r = await score(GOOD);
  eq(r.ids.length, 0, `these IDs must still exist: ${r.ids.join(', ')}`);
  eq(r.detailsOpen, false, 'Show Details still starts collapsed');
  ok(r.afterHero, 'the Why block follows the hero card');
  ok(r.beforeDetails, 'and precedes Show Details');
});

test('[EVR-06] unknown deadhead renders no reasons; an explicit 0 is a verified zero and does', async () => {
  const unknown = await score({ ...GOOD, dead: '' });
  console.log(`    [evidence] blank-deadhead text=${JSON.stringify(unknown.text.slice(0, 140))}`);
  eq(unknown.whyCount, 0, 'blank deadhead is UNKNOWN: no decision, therefore no reasons');
  ok(/dead ?head/i.test(unknown.text), 'and the card asks for the deadhead figure');
  const zero = await score({ ...GOOD, dead: '0' });
  eq(zero.whyCount, 1, 'an explicit 0 deadhead is a verified fact and is scored');
  const dh = zero.rows.find(x => x.label === 'Deadhead');
  ok(dh && /^0\.0% empty/.test(dh.detail), `the Deadhead reason reads the verified zero — got ${JSON.stringify(dh)}`);
});

test('[EVR-07] the block uses scalable presentation classes, never an inline font-size (SSI-18)', async () => {
  const r = await score(BAD);
  eq(r.whyCount, 1, 'the Why block exists to be measured');
  eq(r.inlineFontSizeInWhy, 0, 'no element inside the Why block carries an inline font-size');
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
