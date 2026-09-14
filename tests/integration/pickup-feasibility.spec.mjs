// v24.0.9 — physical-pickup feasibility. Drives the REAL evaluator UI.
//
// The finding this closes: the evaluator had no notion of time at all. It would
// grade, price and recommend a bid on a load whose pickup had already closed, or
// that sat further away in deadhead than the remaining window allowed. The
// 2026-09-12 operator dataset contained a real instance — a 225-mile deadhead
// against a 19:00 cutoff — and nothing in the app detected it.
//
// Two properties matter and both are asserted here, not inferred:
//
//   1. The gate is INERT until the operator sets their own planning average
//      speed. There is no default, deliberately: converting deadhead into drive
//      time needs an operator fact, and VAN_PROFILE_DEFAULT is the cautionary
//      precedent for guessing one — its brochure cargo length was wrong by nine
//      inches and every load between 122" and 130" scored as fitting. A guessed
//      speed fails the same way, except it REJECTS loads the driver could make.
//      So the pre-opt-in tests assert a normal grade still renders.
//   2. When it does apply, it blocks BEFORE economics — no grade, no verdict —
//      exactly like the 7D dimensional gate it sits beside.
//
// Times are computed relative to Date.now() inside the page rather than pinned
// to a literal, so this spec cannot become a date time-bomb (the failure mode
// recorded in gpt-to-claude-v2402-date-fixture-timebomb-2026-09-02.md).
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/pickup-feasibility.spec.mjs');
let app;

async function openEvaluatorAdvanced(page) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwPickupCutoff', { state: 'visible', timeout: 10000 });
}

/** Fill the cutoff field with a local datetime-local string N minutes from now.
 *  Computed in-page so it tracks the browser's own clock and timezone. */
async function setCutoffMinutesFromNow(page, minutes) {
  await page.evaluate((mins) => {
    const d = new Date(Date.now() + mins * 60000);
    const pad = (n) => String(n).padStart(2, '0');
    const local = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const el = document.querySelector('#mwPickupCutoff');
    el.value = local;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }, minutes);
}

async function evaluate(page) {
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(400);
  return await page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      text,
      blocked: text.includes("CAN'T TAKE") && text.includes('cannot reach the pickup in time'),
      anyBlock: text.includes("CAN'T TAKE"),
      gradeText: out?.querySelector('.fl-eval-grade')?.textContent || null,
    };
  });
}

test('setup: suppress first-run wizard and enter a baseline load', async () => {
  await skipFirstRunWizard(app.page);
  await openEvaluatorAdvanced(app.page);
  await app.page.fill('#mwLoadedMi', '300');
  await app.page.fill('#mwDeadMi', '225'); // the operator case's deadhead
  await app.page.fill('#mwRevenue', '600');
});

test('[PF-01] with no planning speed set, an impossible pickup still scores normally', async () => {
  // The inert-by-default property. 225 miles cannot be covered in 20 minutes at
  // ANY speed, but the app has not been told the driver's average, so it must
  // not pretend to know. A grade renders; nothing is blocked.
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', null); });
  await setCutoffMinutesFromNow(app.page, 20);
  const state = await evaluate(app.page);
  ok(!state.anyBlock,
    'with settings.planningAvgMph unset the gate must be completely inert — blocking here would ' +
    'mean the app invented an average speed, which is the VAN_PROFILE_DEFAULT failure mode');
  ok(state.gradeText && state.gradeText !== '✕',
    `expected a normal letter grade, got: ${JSON.stringify(state.gradeText)}`);
});

test('[PF-02] once the operator sets a planning speed, an unreachable pickup blocks before economics', async () => {
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', 55); });
  await setCutoffMinutesFromNow(app.page, 20); // 225 mi at 55 mph needs ~245 min
  const state = await evaluate(app.page);
  ok(state.blocked, `expected the "CAN'T TAKE — cannot reach the pickup in time" block; got: ${state.text.slice(0, 200)}`);
  eq(state.gradeText, '✕', 'economics must not render a letter grade for a load that cannot be reached');
  ok(/225 mi/.test(state.text) && /55 mph/.test(state.text),
    'the block must show the deadhead and the operator\'s own planning speed, so the verdict is never a mystery');
  ok(/Short by/.test(state.text), 'the block must state how far short the window falls');
});

test('[PF-03] a cutoff that has already passed is blocked and named as such', async () => {
  await setCutoffMinutesFromNow(app.page, -90);
  const state = await evaluate(app.page);
  ok(state.blocked, 'a pickup window that already closed must block');
  ok(/already closed/i.test(state.text) || /Cutoff passed/i.test(state.text),
    `an elapsed cutoff should say so rather than reading as a distance problem; got: ${state.text.slice(0, 200)}`);
});

test('[PF-04] a comfortably reachable pickup does not block', async () => {
  await setCutoffMinutesFromNow(app.page, 600); // 225 mi at 55 mph ≈ 245 min, so ~6h of slack
  const state = await evaluate(app.page);
  ok(!state.anyBlock, `a reachable pickup must score normally; got: ${state.text.slice(0, 200)}`);
  ok(state.gradeText && state.gradeText !== '✕',
    `expected a normal letter grade, got: ${JSON.stringify(state.gradeText)}`);
});

test('[PF-05] clearing the cutoff un-blocks the load, leaving economics alone', async () => {
  await setCutoffMinutesFromNow(app.page, 20); // re-block first, so the clear is a real transition
  const blockedAgain = await evaluate(app.page);
  ok(blockedAgain.blocked, 'precondition: the load should be blocked before the cutoff is cleared');

  await app.page.evaluate(() => {
    const el = document.querySelector('#mwPickupCutoff');
    el.value = '';
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const state = await evaluate(app.page);
  ok(!state.anyBlock, 'clearing the cutoff must restore a normal evaluation');
  ok(state.gradeText && state.gradeText !== '✕',
    `expected a normal letter grade after clearing the cutoff, got: ${JSON.stringify(state.gradeText)}`);
});

test('[PF-06] an out-of-range planning speed goes inert rather than clamping to a value the operator never chose', async () => {
  // A typo (655 instead of 65) must not silently become 85. Substituting a
  // bound would run the gate on a number nobody supplied — the same class of
  // defect as blank-deadhead-means-zero.
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', 655); });
  await setCutoffMinutesFromNow(app.page, 20);
  const state = await evaluate(app.page);
  ok(!state.anyBlock, 'an out-of-range planning speed must disable the gate, not clamp into range');
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', null); });
});

test('[PF-07] the gate never fires ahead of the dimensional gate it sits beside', async () => {
  // Ordering matters: a load that is BOTH over payload and unreachable should
  // report the dimensional conflict, because checkVanFit() runs first. This
  // pins the sequence so a later refactor cannot quietly reorder the two.
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', 55); });
  await app.page.fill('#mwLoadWeightLbs', '9000');
  await setCutoffMinutesFromNow(app.page, 20);
  const state = await evaluate(app.page);
  ok(state.anyBlock, 'a load failing both gates must still be blocked');
  ok(/dimensional\/payload conflict/.test(state.text),
    `the dimensional gate runs first, so it should own the message; got: ${state.text.slice(0, 200)}`);

  await app.page.fill('#mwLoadWeightLbs', '');
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('planningAvgMph', null); });
});

export async function runSpec() {
  app = await launchApp();
  try {
    return await run();
  } finally {
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
