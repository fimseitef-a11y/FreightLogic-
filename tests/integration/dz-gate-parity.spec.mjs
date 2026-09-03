// X-04 (v23.9 Phase 5) — extract ONE isDeadZoneEligible() and have both the
// main evaluator (app.js's mwEvaluateLoad) and the standalone
// midwest-stack-authority.js overlay call it, so the two panels can never
// disagree about whether Dead Zone Exit's survival floor ($0.91) may
// produce a TAKE_IF_LIVE verdict. Before this fix the standalone engine had
// NO gate at all — `trueRpm >= 0.91 && (tier1||tier2)` alone reached
// TAKE_IF_LIVE with no distance-from-home, distance-saved, or manual-
// confirmation check.
//
// This spec drives the REAL evaluator UI (same helper pattern as
// tests/integration/dz-exit-grade-cap.spec.mjs) to set up genuine DZ
// conditions and toggle the real #mwDZNoReloadToggle confirmation checkbox,
// then calls the REAL midwest-stack-authority.js `assessLoad()` (loaded via
// page.addScriptTag — the file is normally injected by service-worker.js,
// which requires a second navigation after SW activation to observe; adding
// the tag directly exercises the identical, unmodified file deterministically)
// with the same origin/destination/revenue/miles and mode:'DEAD_ZONE'. Both
// read the SAME live DOM checkbox and call the SAME window.isDeadZoneEligible/
// window.flDzGeoCheck, so this proves genuine shared-gate parity, not just
// that the two happen to agree by coincidence.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/dz-gate-parity.spec.mjs');
let app;

async function loadStandaloneEngine(page) {
  await page.addScriptTag({ url: '/midwest-stack-authority.js' });
  await page.waitForFunction(() => !!(window.FreightLogicMidwestStack && window.isDeadZoneEligible), { timeout: 5000 });
}

async function evaluateLoad(page, { origin, dest, loadedMi, revenue, confirmNoReload }) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwOrigin', { state: 'visible', timeout: 10000 });
  await page.fill('#mwOrigin', origin);
  await page.fill('#mwDest', dest);
  await page.fill('#mwLoadedMi', String(loadedMi));
  await page.fill('#mwDeadMi', '0'); // M1: blank deadhead is UNKNOWN; this fixture means a verified zero
  await page.fill('#mwRevenue', String(revenue));
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(400);

  await page.evaluate(() => { const d = document.querySelector('#mwEvalDetails'); if (d) d.open = true; });
  const toggleVisible = await page.isVisible('#mwDZNoReloadToggle').catch(() => false);
  if (toggleVisible) {
    const isChecked = await page.isChecked('#mwDZNoReloadToggle').catch(() => false);
    if (!!confirmNoReload !== isChecked) await page.setChecked('#mwDZNoReloadToggle', !!confirmNoReload);
    await page.dispatchEvent('#mwRevenue', 'input');
    await page.waitForTimeout(400);
    await page.evaluate(() => { const d = document.querySelector('#mwEvalDetails'); if (d) d.open = true; });
  }

  const mainEvaluator = await page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      isReallyActive: text.includes('Active:') && text.includes('SURVIVAL'),
      heroGradeEl: out ? (out.querySelector('.fl-eval-grade')?.textContent || null) : null,
    };
  });

  // Call the REAL standalone engine with the same inputs, mode forced to
  // DEAD_ZONE — this reads the SAME live #mwDZNoReloadToggle checkbox and
  // calls the SAME window.isDeadZoneEligible/window.flDzGeoCheck as the main
  // evaluator just did above.
  const standalone = await page.evaluate(({ origin, dest, loadedMi, revenue }) => {
    const r = window.FreightLogicMidwestStack.assessLoad({
      revenue, loadedMiles: loadedMi, deadheadMiles: 0, origin, destination: dest, mode: 'DEAD_ZONE',
    });
    // v24.0.4 item 3: the overlay no longer emits a verdict or grade — those are
    // canonical-only now. It reports the GATE OUTCOME instead, which is what X-04
    // actually promised: that this file and the main evaluator call the same
    // window.isDeadZoneEligible() and reach the same answer. Asserting the gate
    // directly is strictly stronger than inferring activation from a verdict
    // string, and the parity assertion below is unchanged.
    return { dzEligible: r.dzGate.eligible, gradeCap: r.dzGate.gradeCap,
             reasons: r.dzGate.reasons, trueRpm: r.posted.trueRpm };
  }, { origin, dest, loadedMi, revenue });

  return { mainEvaluator, standalone };
}

test('setup: suppress first-run wizard, load the real standalone engine', async () => {
  await skipFirstRunWizard(app.page);
  await loadStandaloneEngine(app.page);
});

const FIXTURES = [
  { label: 'DZ-FLOOR ($0.95/mi), confirmed',      origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 1805, confirmNoReload: true,  expectActive: true },
  { label: 'DZ-ACCEPTABLE ($1.00/mi), confirmed',  origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 1900, confirmNoReload: true,  expectActive: true },
  { label: 'DZ-STANDARD ($1.10/mi), confirmed',    origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 2090, confirmNoReload: true,  expectActive: true },
  { label: 'DZ-band RPM, NOT confirmed',           origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 1900, confirmNoReload: false, expectActive: false },
  { label: 'above hard-reject RPM ($1.32/mi) — does not need survival mode', origin: 'Portland, OR', dest: 'Chicago, IL', loadedMi: 1900, revenue: 2508, confirmNoReload: true, expectActive: false },
];

for (const f of FIXTURES) {
  test(`[X-04] ${f.label} — main evaluator and standalone engine agree`, async () => {
    const { mainEvaluator, standalone } = await evaluateLoad(app.page, f);
    // DZ activation in the standalone engine == the shared gate said eligible,
    // and (X-04 gate 5) it carries the structural grade cap of C with it.
    const standaloneActive = standalone.dzEligible === true && standalone.gradeCap === 'C';
    console.log(`    [evidence] ${f.label}: main.isReallyActive=${mainEvaluator.isReallyActive} (grade "${mainEvaluator.heroGradeEl}") | standalone.dzEligible=${standalone.dzEligible} gradeCap=${standalone.gradeCap} trueRpm=${standalone.trueRpm}`);
    eq(mainEvaluator.isReallyActive, f.expectActive, `main evaluator: expected isReallyActive=${f.expectActive} for ${f.label}`);
    eq(standaloneActive, f.expectActive, `standalone engine: expected gate eligible+gradeCap C=${f.expectActive} for ${f.label}, got eligible=${standalone.dzEligible} gradeCap=${standalone.gradeCap} reasons=${JSON.stringify(standalone.reasons)}`);
    eq(mainEvaluator.isReallyActive, standaloneActive, `PARITY FAILURE for ${f.label}: main evaluator and standalone engine disagree on DZ activation`);
  });
}

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
