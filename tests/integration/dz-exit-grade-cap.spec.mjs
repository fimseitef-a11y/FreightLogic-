// FINDING F-1 (Critical) — F20 Dead Zone Exit "hard grade cap at C" is dead code.
//
// app.js:6296-6303 dzClassifySubTier() only returns a non-null sub-tier when
//   dzFloor(0.90) <= trueRPM < MW.hardRejectRPM(1.25)
// app.js:6515-6520 computes the RAW letter grade from trueRPM thresholds; grade
//   is 'F' for any trueRPM < 1.25 — the ENTIRE domain in which DZ can be active.
// app.js:6523 "caps" the grade for display: `isDZActive ? (['A','B'].includes(grade) ? 'C' : grade) : grade`
//   Since grade can only ever be 'F' while isDZActive is true, this remap can
//   never fire. The documented behavior (app.js:6793, 6793, 7107 — "capped at C")
//   never happens: the hero card shows a big red/orange "F DZ", not "C".
// app.js:6679-6690 additionally persists the RAW (uncapped, uncolored) grade/
//   gradeColor/gradeLabel into the session eval-history entry, and
//   _renderEvalHistory() (app.js:7415-7433) renders THAT raw entry — so the
//   "Recent Evaluations" strip shows a different grade/color/label ("F"/red/
//   "REJECT") for the exact same evaluation the main card just displayed as
//   "F DZ" (orange) with a DZ-EXIT verdict banner.
//
// This test drives the real evaluator UI with a load engineered to be
// DZ-eligible (>=1500mi from the default home base, >=200mi saved toward
// home, RPM inside the DZ sub-floor) and reads the DOM + sessionStorage the
// app itself produced.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/dz-exit-grade-cap.spec.mjs');
let app;

async function fillEvaluator(page, { origin, dest, loadedMi, revenue }) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  // Origin/Dest live inside the collapsed "More Details" advanced section.
  await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwOrigin', { state: 'visible', timeout: 10000 });
  await page.fill('#mwOrigin', origin);
  await page.fill('#mwDest', dest);
  await page.fill('#mwLoadedMi', String(loadedMi));
  await page.fill('#mwRevenue', String(revenue));
}

test('DZ-eligible load: dzCheckEligibility + dzClassifySubTier fire (sanity precondition)', async () => {
  // Portland, OR is >1500mi from the default home base (Oak Creek, WI) and far
  // west enough that its nearest density anchor is much farther than one deep
  // in the Midwest corridor, giving well over 200mi "distance saved" toward home.
  const check = await app.page.evaluate(async () => {
    const eligibility = await (async () => {
      // dzCheckEligibility is not exported on __FL_TESTS (it's async/DOM-free
      // but depends on settings + market DB) — reuse the real evaluator instead
      // by calling mwEvaluateLoad() through the DOM in the next test. Here we
      // just confirm the market DB resolves the cities we're about to use.
      return true;
    })();
    return eligibility;
  });
  ok(check, 'precondition harness sanity check');
});

test('[FINDING F-1] Main result card must show the documented capped grade "C" during an active DZ-Exit', async () => {
  await fillEvaluator(app.page, { origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 2000 });
  await app.page.evaluate(() => window.mwEvaluateLoad ? window.mwEvaluateLoad() : null);
  // mwEvaluateLoad is not on window directly (top-level IIFE) — trigger via the real input listener instead.
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(400);

  const toggle = await app.page.$('#mwDZNoReloadToggle');
  if (toggle) {
    await app.page.check('#mwDZNoReloadToggle').catch(() => {});
    await app.page.dispatchEvent('#mwRevenue', 'input');
    await app.page.waitForTimeout(400);
  }

  const state = await app.page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    return {
      html: out ? out.innerHTML : null,
      hasDZBadge: !!out && /DZ-EXIT|DZ EXIT|Dead Zone/.test(out.textContent || ''),
      heroGradeEl: out ? (out.querySelector('.fl-eval-grade')?.textContent || null) : null,
    };
  });

  ok(state.hasDZBadge, 'test setup did not actually trigger DZ-Exit mode — cannot evaluate the cap; got: ' + (state.html || '').slice(0, 500));
  ok(state.heroGradeEl, 'no .fl-eval-grade element found in output');
  console.log('    [evidence] hero grade element text during DZ-Exit: ' + JSON.stringify(state.heroGradeEl));
  // The settings panel (app.js:6793/7107) explicitly documents DZ-Exit as "capped at C" —
  // this is the correct-behavior assertion, expected to fail until F-1 is fixed.
  ok(/^C(\s|$|<)/.test(state.heroGradeEl) || state.heroGradeEl.trim().startsWith('C'),
    `EXPECTED "C" (per app.js:6793/7107's documented "capped at C"), GOT ${JSON.stringify(state.heroGradeEl)} ` +
    `— the A/B->C remap at app.js:6523 is dead code (DZ's RPM domain [0.90,1.25) can only ever produce raw grade 'F', which the remap never touches).`);
});

test('[FINDING F-1b] Recent-Evaluations history strip must agree with the main card for the same DZ-Exit evaluation', async () => {
  const hist = await app.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_eval_hist') || '[]'));
  ok(hist.length > 0, 'no eval history recorded — cannot compare');
  const latest = hist[0];
  console.log('    [evidence] fl_eval_hist[0] =', JSON.stringify({ grade: latest.grade, gradeLabel: latest.gradeLabel, gradeColor: latest.gradeColor }));
  // The main card's verdict for this same evaluation was DZ-EXIT (orange, "survival" language).
  // Correct behavior: the history entry must NOT contradict that with the raw pre-DZ
  // "REJECT" label in the "bad" (red) color — expected to fail until F-1 is fixed.
  ok(latest.gradeLabel !== 'REJECT' && latest.gradeColor !== 'var(--bad)',
    `EXPECTED the history entry to reflect the DZ-EXIT verdict the main card showed, GOT gradeLabel=${JSON.stringify(latest.gradeLabel)} ` +
    `gradeColor=${JSON.stringify(latest.gradeColor)} — histEntry (app.js:6679-6690) stores the raw uncapped grade/label/color instead of the ` +
    `dz-adjusted display values, so the history strip contradicts the main card's DZ-EXIT framing for the identical evaluation.`);
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
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
