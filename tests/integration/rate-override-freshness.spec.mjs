// v24.0.0 audit — static rate-override freshness guard is a RATCHET, not a swap.
//
// v23.9.1's pre-v24 integrity gate introduced getRateOverrideFreshness() in
// midwest-stack-authority.js so a stale static band can never RELAX protective
// pricing (CURRENT <=14d, AGING <=30d, STALE >30d — see docs/V24_ROADMAP.md).
// The first implementation *replaced* the band-derived floor/win/ask with
// PROTECT_FLOOR's 1.40/1.50/1.65 whenever the override read STALE. That is only
// protective for bands priced BELOW the doctrine (mediumFeeder $1.35-1.65,
// longDisplacement $1.35-1.55). For the two bands priced ABOVE it — shortLocal
// ($1.80-2.40) and extremeLongLock ($1.50-1.90) — the "guard" silently cut the
// recommended ask, e.g. a 150mi core-Midwest run dropped from $2.40/mi ask to
// $1.65/mi (-31%). And because RATE_OVERRIDE_2026_07 carries a frozen
// effectiveDate of 2026-07-09 with no runtime refresh path, STALE is permanent:
// this was live on every short-haul evaluation, not a future edge case.
//
// The guard must therefore be max(band, protective) — raise a weak band, never
// lower a strong one. This spec drives the REAL, unmodified overlay file via
// page.addScriptTag (same pattern as dz-gate-parity.spec.mjs) so it asserts
// shipped behavior rather than source text.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/rate-override-freshness.spec.mjs');
let app;

async function loadEngine(page) {
  await page.addScriptTag({ url: '/midwest-stack-authority.js' });
  await page.waitForFunction(() => !!window.FreightLogicMidwestStack, { timeout: 5000 });
}

// Core Midwest (multiplier 1.00) keeps the arithmetic readable: the recommended
// rpms are the band values themselves, undistorted by a regional overlay.
const CORE_MIDWEST = { origin: 'Chicago, IL', destination: 'Indianapolis, IN' };

async function assess(page, load) {
  return await page.evaluate((l) => {
    const r = window.FreightLogicMidwestStack.assessLoad(l);
    return { ...r.recommendation, effectiveDate: window.FreightLogicMidwestStack.rateOverride.effectiveDate };
  }, { ...CORE_MIDWEST, deadheadMiles: 0, ...load });
}

test('the shipped July override is already past the 30-day STALE threshold (the guard is live, not theoretical)', async () => {
  const { effectiveDate } = await assess(app.page, { revenue: 300, loadedMiles: 150, mode: 'PROTECT_FLOOR' });
  const ageDays = Math.floor((Date.now() - Date.parse(effectiveDate + 'T00:00:00Z')) / 86400000);
  console.log(`    [evidence] RATE_OVERRIDE_2026_07.effectiveDate=${effectiveDate}, age=${ageDays}d, status=${ageDays <= 14 ? 'CURRENT' : ageDays <= 30 ? 'AGING' : 'STALE'}`);
  ok(ageDays > 30, `the shipped override reads STALE today (${ageDays}d) — every assertion below exercises the STALE path for real`);
});

test('[AUDIT-RF01] a STALE override never lowers a band priced ABOVE the protective doctrine (shortLocal)', async () => {
  // shortLocal realisticWin = [1.80, 2.40]; PROTECT_FLOOR doctrine = 1.40/1.50/1.65.
  const r = await assess(app.page, { revenue: 300, loadedMiles: 150, mode: 'PROTECT_FLOOR' });
  console.log(`    [evidence] 150mi shortLocal under a STALE override: floor=${r.floorRpm} win=${r.winRpm} ask=${r.askRpm} (floorBid=$${r.floorBid} askBid=$${r.askBid})`);
  eq(r.floorRpm, 1.80, 'stale guard must not drop the $1.80 shortLocal floor to the $1.40 protective floor');
  eq(r.winRpm, 2.10, 'stale guard must not drop the $2.10 shortLocal win to $1.50');
  eq(r.askRpm, 2.40, 'stale guard must not drop the $2.40 shortLocal ask to $1.65');
});

test('[AUDIT-RF02] a STALE override never lowers extremeLongLock either', async () => {
  // extremeLongLock realisticWin = [1.50, 1.90].
  const r = await assess(app.page, { revenue: 3000, loadedMiles: 1900, destination: 'Los Angeles, CA', mode: 'PROTECT_FLOOR' });
  console.log(`    [evidence] 1900mi extremeLongLock under a STALE override: floor=${r.floorRpm} win=${r.winRpm} ask=${r.askRpm}`);
  ok(r.floorRpm >= 1.50, `extremeLongLock floor must stay at or above its $1.50 band low — got ${r.floorRpm}`);
  ok(r.askRpm >= 1.90, `extremeLongLock ask must stay at or above its $1.90 premium floor — got ${r.askRpm}`);
});

test('[AUDIT-RF03] a STALE override still RAISES a band priced BELOW the protective doctrine', async () => {
  // longDisplacement realisticWin = [1.35, 1.55]; REALISTIC_WIN mode floor is
  // 1.15/1.25/1.40 — without the guard this is the case that would clear well
  // under the $1.40 normal floor on stale evidence.
  const r = await assess(app.page, { revenue: 1600, loadedMiles: 1200, destination: 'Dallas, TX', mode: 'REALISTIC_WIN' });
  console.log(`    [evidence] 1200mi longDisplacement REALISTIC_WIN under a STALE override: floor=${r.floorRpm} win=${r.winRpm} ask=${r.askRpm}`);
  ok(r.floorRpm >= 1.40, `stale bands must be ratcheted up to the $1.40 protective floor — got ${r.floorRpm}`);
  ok(r.winRpm >= 1.50, `stale bands must be ratcheted up to the $1.50 preferred floor — got ${r.winRpm}`);
});

test('[AUDIT-RF04] the STALE flag is surfaced to the driver, not applied silently', async () => {
  const flags = await app.page.evaluate(() => window.FreightLogicMidwestStack.assessLoad({
    origin: 'Chicago, IL', destination: 'Indianapolis, IN', revenue: 300, loadedMiles: 150, deadheadMiles: 0, mode: 'PROTECT_FLOOR',
  }).risk.flags);
  const joined = (Array.isArray(flags) ? flags : []).join(' | ');
  console.log(`    [evidence] risk.flags: ${joined}`);
  ok(/STALE/i.test(joined), `a stale static band must be disclosed in the advisory flags — got ${JSON.stringify(joined)}`);
});

export async function runSpec() {
  app = await launchApp();
  try {
    await loadEngine(app.page);
    return await run();
  } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
