// v24.1 — confidence surfaces in the REAL evaluator UI.
//
// The contract is only useful if a driver can actually see the label and drill
// into the evidence behind it. This drives the live evaluator rather than the
// helpers, and checks the two states the spec insists must look different:
// evidence that exists, and evidence that does not.
import { launchApp, createSuite, skipFirstRunWizard, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v24-1-confidence-ui.spec.mjs');
let app;

async function openEvaluatorAdvanced(page) {
  await page.evaluate(() => { location.hash = '#omega'; });
  await page.waitForSelector('#evalAdvToggle', { timeout: 10000 });
  const alreadyOpen = await page.isVisible('#mwOrigin').catch(() => false);
  if (!alreadyOpen) await page.click('#evalAdvToggle');
  await page.waitForSelector('#mwOrigin', { state: 'visible', timeout: 10000 });
}

async function evaluate(page) {
  await page.dispatchEvent('#mwRevenue', 'input');
  await page.waitForTimeout(500);
  return page.evaluate(() => {
    const out = document.querySelector('#mwEvalOutput');
    return { text: out?.textContent || '', html: out?.innerHTML || '' };
  });
}

test('setup: suppress first-run wizard', async () => {
  await skipFirstRunWizard(app.page);
});

test('[V241-U01] the evaluator renders a categorical confidence label, never a percentage', async () => {
  await openEvaluatorAdvanced(app.page);
  await app.page.fill('#mwOrigin', 'Chicago, IL');
  await app.page.fill('#mwDest', 'Indianapolis, IN');
  await app.page.fill('#mwLoadedMi', '180');
  await app.page.fill('#mwDeadMi', '20');
  await app.page.fill('#mwRevenue', '400');
  const r = await evaluate(app.page);

  ok(/CONFIDENCE:\s*(HIGH|MEDIUM|LOW)/.test(r.text), `expected a categorical confidence chip, got: ${r.text.slice(0, 300)}`);
  ok(!/confidence[^.]{0,40}\d+\s*%/i.test(r.text), 'the confidence chip must never imply calibrated odds');
});

test('[V241-U02] the evidence drill-down names sources, health and sample sizes', async () => {
  const r = await evaluate(app.page);
  ok(r.text.includes('Evidence & Confidence') || r.html.includes('Evidence &amp; Confidence'),
    'the evidence panel must be present behind the details disclosure');
  ok(r.text.includes('Show every evidence item'), 'individual evidence items must be inspectable');
  ok(/PERSONAL_LANE_HISTORY|DRIVER_SETTING|STATIC_BASELINE/.test(r.text),
    'each evidence item must name the source that produced it');
  ok(r.text.includes('never changes the verdict'),
    'the panel must state that confidence is descriptive, not authoritative');
});

test('[V241-U03] a fresh install with no history shows missing evidence as missing', async () => {
  const r = await evaluate(app.page);
  // A brand-new device has no lane history and no configured operating cost.
  ok(/No prior trips recorded on this lane/.test(r.text),
    'an unrun lane must say so explicitly rather than render as a neutral or favourable value');
  ok(/no data recorded/.test(r.text), 'missing evidence must be labelled as missing');
  ok(/CONFIDENCE:\s*LOW/.test(r.text),
    'with no lane history and no configured operating cost, confidence must be LOW, not optimistic');
});

test('[V241-U04] confidence does not alter the grade or verdict the driver sees', async () => {
  // Same load, evaluated with and without a configured operating cost. The
  // operating-cost evidence changes; True RPM and the grade must not.
  const before = await evaluate(app.page);
  const gradeBefore = await app.page.evaluate(() =>
    document.querySelector('#mwEvalOutput .fl-eval-grade')?.textContent?.trim() || null);

  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('opCostPerMile', 0.66); });
  const after = await evaluate(app.page);
  const gradeAfter = await app.page.evaluate(() =>
    document.querySelector('#mwEvalOutput .fl-eval-grade')?.textContent?.trim() || null);

  ok(gradeBefore !== null && gradeBefore === gradeAfter,
    `grade must be unchanged by evidence quality (before=${gradeBefore}, after=${gradeAfter})`);

  const rpmOf = t => (t.match(/True RPM:\s*\$([\d.]+)/) || [])[1] || null;
  ok(rpmOf(before.text) === rpmOf(after.text),
    'True RPM must be unchanged by evidence quality');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
