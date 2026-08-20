// 7D (v23.9 Phase 7) — dimensional/payload pre-check. Drives the REAL
// evaluator UI: entering a load whose weight exceeds the configured van
// profile's payload must show "CAN'T TAKE — dimensional/payload conflict"
// and BLOCK economics from ever rendering (no grade, no verdict) — this is
// the actual finding: the check must run BEFORE scoring, not alongside it.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/van-fit-precheck.spec.mjs');
let app;

async function openEvaluatorAdvanced(page) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwLoadWeightLbs', { state: 'visible', timeout: 10000 });
}

test('setup: suppress first-run wizard', async () => {
  await skipFirstRunWizard(app.page);
});

test('[7D] a load over payload shows CAN\'T TAKE and never renders economics', async () => {
  await openEvaluatorAdvanced(app.page);
  await app.page.fill('#mwLoadedMi', '300');
  await app.page.fill('#mwRevenue', '600');
  await app.page.fill('#mwLoadWeightLbs', '9000'); // well over the 3800lb default payload
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(400);

  const state = await app.page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      showsCantTake: text.includes("CAN'T TAKE") && text.includes('dimensional/payload conflict'),
      hasGradeEl: !!out?.querySelector('.fl-eval-grade'),
      gradeText: out?.querySelector('.fl-eval-grade')?.textContent || null,
      mentionsWeight: /weight/i.test(text) && /payload/i.test(text),
    };
  });

  ok(state.showsCantTake, 'expected the "CAN\'T TAKE — dimensional/payload conflict" block to render');
  eq(state.gradeText, '✕', `economics must not render a normal letter grade — got grade element text: ${JSON.stringify(state.gradeText)}`);
  ok(state.mentionsWeight, 'the block should name weight/payload as the violated constraint');
});

test('[7D] clearing the over-limit weight lets a normal evaluation through again', async () => {
  await app.page.fill('#mwLoadWeightLbs', '');
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(400);

  const state = await app.page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return { showsCantTake: text.includes("CAN'T TAKE"), gradeText: out?.querySelector('.fl-eval-grade')?.textContent || null };
  });
  ok(!state.showsCantTake, 'the block must clear once the over-limit dimension is removed');
  ok(state.gradeText && state.gradeText !== '✕', `expected a normal letter grade to render again, got: ${JSON.stringify(state.gradeText)}`);
});

test('[7D] a load within a custom (tighter) van profile respects the configured limits, not just the defaults', async () => {
  // Set a custom, tighter payload via Settings and confirm the SAME weight
  // that passed against the default profile now fails against the custom one.
  await app.page.evaluate(async () => {
    await window.__FL_TESTS.setSetting('vanProfile', { ...window.__FL_TESTS.VAN_PROFILE_DEFAULT, payloadLbs: 1000 });
  });
  await app.page.fill('#mwLoadWeightLbs', '1500'); // under default 3800, over custom 1000
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(400);

  const state = await app.page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    return { showsCantTake: (out?.textContent || '').includes("CAN'T TAKE") };
  });
  ok(state.showsCantTake, 'a load within the DEFAULT payload but over a custom, tighter configured payload must still be blocked');

  // Clean up: restore the default profile for any later test relying on it.
  await app.page.evaluate(async () => {
    await window.__FL_TESTS.setSetting('vanProfile', window.__FL_TESTS.VAN_PROFILE_DEFAULT);
  });
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
