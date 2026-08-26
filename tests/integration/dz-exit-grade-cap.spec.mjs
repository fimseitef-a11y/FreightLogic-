// FINDING F-1 (Critical, FIXED) — F20 Dead Zone Exit "hard grade cap at C" was dead code.
//
// app.js:6296-6303 dzClassifySubTier() only returns a non-null sub-tier when
//   dzFloor(0.90) <= trueRPM < MW.hardRejectRPM(1.25)
// app.js:6515-6520 computes the RAW letter grade from trueRPM thresholds; grade
//   is 'F' for any trueRPM < 1.25 — the ENTIRE domain in which DZ can be active.
// The old cap logic — `isDZActive ? (['A','B'].includes(grade) ? 'C' : grade) : grade`
// — could only ever remap 'A'/'B', which DZ's RPM domain can never produce, so it
// was dead code: DZ-active loads showed a raw "F" instead of the documented "C"
// (app.js:6793/7107), and the session eval-history entry stored the same raw,
// uncapped grade/label/color, contradicting the main card's DZ-EXIT framing.
//
// FIX (this commit): `dzDisplayGrade = isDZActive ? 'C' : grade` — an
// unconditional cap, since isDZActive already implies raw grade 'F' by
// construction (see the structural fuzz test below). histEntry now stores
// the DZ-adjusted display values instead of the raw ones.
//
// METHODOLOGY NOTE (post-fix correction): the version of this spec that shipped
// with the original audit report drove the evaluator UI but never actually
// activated DZ mode — the confirmation checkbox (#mwDZNoReloadToggle) lives
// inside a collapsed native <details id="mwEvalDetails"> the test never
// expanded, so page.check() timed out and was silently swallowed by a
// .catch(()=>{}). The "F" grade that version captured as "evidence" was
// therefore just an ordinary REJECT verdict, unrelated to the DZ cap. The
// underlying finding was still real (confirmed below by re-running this
// corrected methodology against the pre-fix code — see commit message), but
// the original dynamic proof was not valid proof. This version fixes that:
// it explicitly opens <details id="mwEvalDetails">, does NOT swallow
// checkbox-click failures, and additionally suppresses the F26 First-Time
// Setup Wizard (which was intermittently stealing pointer events once this
// spec's interaction sequence got slow enough to cross its 800ms auto-open
// timer) via skipFirstRunWizard().

import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/dz-exit-grade-cap.spec.mjs');
let app;

async function evaluateLoad(page, { origin, dest, loadedMi, revenue, confirmNoReload }) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  // Origin/Dest live inside the collapsed "More Details" advanced section —
  // it's a plain toggle (not idempotent-open), so only click it if the
  // fields aren't already visible from a previous call in this same spec.
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwOrigin', { state: 'visible', timeout: 10000 });
  await page.fill('#mwOrigin', origin);
  await page.fill('#mwDest', dest);
  await page.fill('#mwLoadedMi', String(loadedMi));
  // M1: deadhead is a material fact — blank now means UNKNOWN, not zero.
  // This fixture always meant a zero-deadhead load, so it now says so
  // explicitly. No assertion below changed.
  await page.fill('#mwDeadMi', '0');
  await page.fill('#mwRevenue', String(revenue));
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(400);

  if (confirmNoReload) {
    // The DZ confirmation checkbox lives inside a collapsed native <details>
    // — must be expanded before Playwright will treat it as interactable.
    await page.evaluate(() => { const d = document.querySelector('#mwEvalDetails'); if (d) d.open = true; });
    await page.waitForSelector('#mwDZNoReloadToggle', { state: 'visible', timeout: 5000 });
    await page.check('#mwDZNoReloadToggle'); // intentionally NOT wrapped in .catch() — a failure here must fail the test
    await page.dispatchEvent('#mwRevenue', 'input');
    await page.waitForTimeout(400);
    await page.evaluate(() => { const d = document.querySelector('#mwEvalDetails'); if (d) d.open = true; });
  }

  return page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      // "Active: <sub-tier> — Grade capped at C" (app.js:7117) only renders
      // when isDZActive is genuinely true — unlike the eligibility banner
      // ("DEAD ZONE EXIT MODE", app.js:7100), which renders merely when the
      // lane is DZ-*eligible*, before the driver confirms no-reload. Using
      // this string (rather than a looser "Dead Zone" match) is what makes
      // this a real activation check, not a false positive on eligibility.
      isReallyActive: text.includes('Active:') && text.includes('SURVIVAL'),
      heroGradeEl: out ? (out.querySelector('.fl-eval-grade')?.textContent || null) : null,
      html: text.slice(0, 300),
    };
  });
}

test('setup: suppress first-run wizard so it cannot steal pointer events mid-test', async () => {
  await skipFirstRunWizard(app.page);
});

test('sanity: DZ-eligible-but-not-yet-confirmed does NOT count as active (guards against the original false positive)', async () => {
  // Portland, OR is >1500mi from the default home base (Oak Creek, WI) and far
  // west enough that its nearest density anchor is much farther than one deep
  // in the Midwest corridor, giving well over 200mi (and 500mi) "distance
  // saved" toward home — DZ-*eligible* the moment origin/dest resolve, before
  // any RPM or confirmation-checkbox state is considered.
  const state = await evaluateLoad(app.page, { origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 2000, confirmNoReload: false });
  eq(state.isReallyActive, false, 'without checking the no-reload confirmation box, DZ mode must not be active yet: ' + state.html);
});

test('[FINDING F-1] Main result card shows the documented capped grade "C" during a genuinely active DZ-Exit', async () => {
  const state = await evaluateLoad(app.page, { origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 2000, confirmNoReload: true });
  ok(state.isReallyActive, 'DZ-Exit mode did not genuinely activate (checked the "Active:...capped at C" marker, not just eligibility text) — cannot evaluate the cap: ' + state.html);
  console.log('    [evidence] hero grade element text during a genuinely active DZ-Exit: ' + JSON.stringify(state.heroGradeEl));
  ok(state.heroGradeEl && state.heroGradeEl.trim().startsWith('C'),
    `EXPECTED "C" (per app.js:6793/7107's documented "capped at C"), GOT ${JSON.stringify(state.heroGradeEl)}`);
});

test('[FINDING F-1b] Recent-Evaluations history strip agrees with the main card for the same DZ-Exit evaluation', async () => {
  const hist = await app.page.evaluate(() => JSON.parse(sessionStorage.getItem('fl_eval_hist') || '[]'));
  ok(hist.length > 0, 'no eval history recorded — cannot compare');
  const latest = hist[0];
  console.log('    [evidence] fl_eval_hist[0] =', JSON.stringify({ grade: latest.grade, gradeLabel: latest.gradeLabel, gradeColor: latest.gradeColor }));
  ok(latest.grade === 'C' && latest.gradeLabel !== 'REJECT' && latest.gradeColor !== 'var(--bad)',
    `EXPECTED the history entry to reflect the DZ-EXIT verdict the main card showed, GOT grade=${JSON.stringify(latest.grade)} ` +
    `gradeLabel=${JSON.stringify(latest.gradeLabel)} gradeColor=${JSON.stringify(latest.gradeColor)}`);
});

// ── Post-fix regression coverage: prove the cap can't be escaped by ANY
// combination of inputs, not just the one fixture above. ──

test('[F-1 fuzz] structural domain check: dzClassifySubTier only ever activates below MW.hardRejectRPM', async () => {
  // The fix makes dzDisplayGrade depend ONLY on isDZActive ('C' when active,
  // the raw grade otherwise) — it no longer looks at the magnitude of
  // trueRPM at all. That's only safe because isDZActive's activation domain
  // (dzFloor <= trueRPM < MW.hardRejectRPM) can never overlap grade
  // A/B/C/D/E's thresholds (all >= MW.hardRejectRPM). This sweeps a dense
  // grid of (trueRPM, dzFloor, distanceSaved) through the real
  // dzClassifySubTier() and checks that invariant — the guardrail against
  // someone later changing MW.hardRejectRPM or the grade thresholds
  // independently and silently reopening this exact bug class.
  const result = await app.page.evaluate(() => {
    const bad = [];
    const hardReject = window.__FL_TESTS.MW.hardRejectRPM;
    const dzFloors = [0.50, 0.70, 0.90, 1.00, 1.10, 1.24];
    const distances = [0, 199, 200, 350, 499, 500, 1000];
    let n = 0;
    for (const dzFloor of dzFloors) {
      for (let rpm = 0; rpm <= 3; rpm += 0.02) {
        const r = +rpm.toFixed(2);
        for (const dist of distances) {
          n++;
          const subTier = window.__FL_TESTS.dzClassifySubTier(r, dist, dzFloor);
          if (subTier !== null && !(r >= dzFloor && r < hardReject)) {
            bad.push({ r, dzFloor, dist, subTier, reason: 'activated outside [dzFloor, hardRejectRPM)' });
          }
        }
      }
    }
    return { bad, hardReject, n };
  });
  console.log(`    [evidence] swept dzClassifySubTier across ${result.n} (dzFloor x rpm x distanceSaved) combinations; MW.hardRejectRPM=${result.hardReject}`);
  eq(result.bad.length, 0, 'dzClassifySubTier activated outside its documented [dzFloor, hardRejectRPM) domain: ' + JSON.stringify(result.bad.slice(0, 5)));
});

test('[F-1 fuzz] all three DZ sub-tiers (FLOOR/ACCEPTABLE/STANDARD) show capped grade "C" end to end', async () => {
  // Same DZ-eligible lane (Portland,OR -> Chicago,IL saves >500mi toward
  // home, satisfying DZ-FLOOR's extra 500mi condition too), swept across
  // revenue so trueRPM lands in each of the three documented sub-tier
  // bands. This is the UI-level combination sweep the audit asked for.
  const cases = [
    { label: 'DZ-FLOOR ($0.90-$0.99, needs 500mi+ saved)', revenue: 1805 }, // trueRPM ~ 0.95
    { label: 'DZ-ACCEPTABLE ($1.00-$1.09)',                revenue: 1995 }, // trueRPM ~ 1.05
    { label: 'DZ-STANDARD ($1.10-$1.24)',                  revenue: 2280 }, // trueRPM ~ 1.20
  ];
  for (const c of cases) {
    const state = await evaluateLoad(app.page, { origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: c.revenue, confirmNoReload: true });
    console.log(`    [evidence] ${c.label}: isReallyActive=${state.isReallyActive} heroGrade=${JSON.stringify(state.heroGradeEl)}`);
    ok(state.isReallyActive, `${c.label}: DZ-Exit mode did not genuinely activate — fixture no longer lands in this sub-tier: ${state.html}`);
    ok(state.heroGradeEl && state.heroGradeEl.trim().startsWith('C'),
      `${c.label}: EXPECTED hero grade to start with "C", GOT ${JSON.stringify(state.heroGradeEl)}`);
  }
});

test('[F-1 regression] a load NOT DZ-eligible still shows its ordinary raw grade (cap only touches genuine DZ-Exit loads)', async () => {
  // A short, strong-RPM, non-DZ load near the default home base should be
  // completely unaffected by the DZ cap logic — grade A, not force-capped.
  const state = await evaluateLoad(app.page, { origin: 'Milwaukee, WI', dest: 'Chicago, IL', loadedMi: 90, revenue: 250, confirmNoReload: false });
  eq(state.isReallyActive, false, 'this fixture must not be DZ-eligible/active: ' + state.html);
  ok(state.heroGradeEl && !state.heroGradeEl.trim().startsWith('C'),
    `EXPECTED a non-DZ evaluation to show its own ordinary grade (not force-capped to "C"), GOT ${JSON.stringify(state.heroGradeEl)}`);
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
