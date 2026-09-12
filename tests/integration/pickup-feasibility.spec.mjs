// Pickup feasibility — operator dataset 2026-09-12. Drives the REAL evaluator
// UI, because the pure function passing proves nothing about whether the gate
// is actually wired in ahead of scoring.
//
// The finding: quote 1079840 (West Plains MO -> Overland Park KS) carried 225
// miles of deadhead against a same-day 19:00 cutoff. It was physically
// unreachable from where the operator was, and the evaluator graded and priced
// it normally. A load that cannot be served has no rate worth grading, so the
// check must run BEFORE economics — not alongside them.
import { launchApp, createSuite, skipFirstRunWizard, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/pickup-feasibility.spec.mjs');
let app;

async function openEvaluatorAdvanced(page) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwPickupBy', { state: 'visible', timeout: 10000 });
}

/** A datetime-local string N minutes from now, in the browser's own local zone
 *  — which is what the field means and how production parses it. */
function localDateTimeIn(page, minutes) {
  return page.evaluate((m) => {
    const d = new Date(Date.now() + m * 60000);
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }, minutes);
}

async function readResult(page) {
  return page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    const text = out?.textContent || '';
    return {
      blocked: text.includes("CAN'T MAKE PICKUP"),
      gradeText: out?.querySelector('.fl-eval-grade')?.textContent || null,
      text,
    };
  });
}

test('setup: suppress first-run wizard', async () => {
  await skipFirstRunWizard(app.page);
});

test('[PF-E1] the operator load blocks in the real evaluator and renders no economics', async () => {
  await openEvaluatorAdvanced(app.page);
  await app.page.fill('#mwLoadedMi', '269');
  await app.page.fill('#mwDeadMi', '225');   // the real deadhead on quote 1079840
  await app.page.fill('#mwRevenue', '700');
  await app.page.fill('#mwPickupBy', await localDateTimeIn(app.page, 120)); // 2h to cutoff
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(500);

  const r = await readResult(app.page);
  ok(r.blocked, 'expected the "CAN\'T MAKE PICKUP" block to render');
  ok(/drive time needed/i.test(r.text), 'the block must state the drive time needed');
  ok(/time until cutoff/i.test(r.text), 'the block must state the time remaining');
  ok(!r.gradeText || r.gradeText === '✕',
    `economics must not render a letter grade for an unreachable load — got ${JSON.stringify(r.gradeText)}`);
  ok(!/True RPM/i.test(r.text), 'True RPM must never be computed for a load that cannot be served');
});

test('[PF-E2] clearing the cutoff evaluates the very same load normally', async () => {
  // Proves the gate is the thing blocking, and that it is opt-in: the identical
  // load with no stated cutoff must price normally rather than stay refused.
  await app.page.fill('#mwPickupBy', '');
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(500);

  const r = await readResult(app.page);
  ok(!r.blocked, 'the block must clear once no cutoff is stated');
  ok(r.gradeText && r.gradeText !== '✕',
    `the same load must grade normally with no cutoff — got ${JSON.stringify(r.gradeText)}`);
});

test('[PF-E3] a reachable pickup is not blocked', async () => {
  // Same load, same deadhead, enough time. The gate must not simply refuse
  // anything that carries a cutoff.
  await app.page.fill('#mwPickupBy', await localDateTimeIn(app.page, 600)); // 10h
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(500);

  const r = await readResult(app.page);
  ok(!r.blocked, '225 mi with 10 hours to the cutoff is comfortably reachable and must not block');
  ok(r.gradeText && r.gradeText !== '✕', `expected a normal grade, got ${JSON.stringify(r.gradeText)}`);
});

test('[PF-E4] an unknown deadhead never blocks, even with a tight cutoff', async () => {
  // M1 doctrine: blank deadhead is UNKNOWN, not zero. The gate must report
  // not-assessed rather than refuse a load on a fact nobody supplied.
  await app.page.fill('#mwDeadMi', '');
  await app.page.fill('#mwPickupBy', await localDateTimeIn(app.page, 5)); // 5 minutes
  await app.page.dispatchEvent('#mwRevenue', 'input');
  await app.page.waitForTimeout(500);

  const r = await readResult(app.page);
  ok(!r.blocked,
    'with the deadhead UNKNOWN the gate has no distance to judge and must not refuse the load — an unknown is never a block');
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
