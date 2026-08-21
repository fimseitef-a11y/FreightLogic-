// v24 Phase B — canonical hard-gate boundary tests.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v24-authority-boundaries.spec.mjs');
let app;

async function derive(overrides = {}) {
  return await app.page.evaluate((overrides) => {
    const T = window.__FL_TESTS;
    const base = {
      initialVerdict: 'ACCEPT',
      tierLabel: 'Professional',
      trueRPM: 1.50,
      totalMi: 200,
      floorRPM: 1.40,
      dzFloor: 0.90,
      isDZActive: false,
      dzSubTier: null,
      dzCheck: { distanceFromHome: 0, distanceSaved: 0 },
      effectiveStrategic: false,
      effectiveReason: '',
      opCPM: 0.66,
      profitMarginPct: 40,
      effectiveRevenue: 500,
      netAfterFuel: 450,
      deadheadPct: 10,
      weeklyGross: 0,
      weekTargetHigh: 4200,
      stabilizeFloor: 2000,
      surgeFloor: 3000,
      isMonWed: false,
      fatigue: 2,
      geo: { intoDensity: true, destDensity: 'Tier 1', dT1: true, dT2: false },
      origin: 'Chicago, IL',
      dest: 'Indianapolis, IN',
      personalScore: 0,
      personalBullets: [],
    };
    const merged = { ...base, ...overrides, geo: { ...base.geo, ...(overrides.geo || {}) }, dzCheck: { ...base.dzCheck, ...(overrides.dzCheck || {}) } };
    return T.deriveUnifiedAuthority(merged);
  }, overrides);
}

test('[V24-B01] normal floor boundary is exact: 1.39 rejects, 1.40 survives', async () => {
  eq((await derive({ trueRPM: 1.39, initialVerdict: 'ACCEPT' })).verdict, 'REJECT', '1.39 must be below normal floor');
  eq((await derive({ trueRPM: 1.40, initialVerdict: 'ACCEPT' })).verdict, 'ACCEPT', '1.40 must clear normal floor');
});

test('[V24-B02] out-of-density threshold is exact: 1.59 rejects, 1.60 survives', async () => {
  const geo = { intoDensity: false, destDensity: 'None', dT1: false, dT2: false };
  eq((await derive({ trueRPM: 1.59, geo })).verdict, 'REJECT', 'out-of-density 1.59 must reject');
  eq((await derive({ trueRPM: 1.60, geo })).verdict, 'ACCEPT', 'out-of-density 1.60 must clear strong threshold');
});

test('[V24-B03] explicit strategic band cannot rescue an out-of-density weak load', async () => {
  const inDensity = await derive({ trueRPM: 1.30, floorRPM: 1.25, initialVerdict: 'STRATEGIC', effectiveStrategic: true, effectiveReason: 'home' });
  eq(inDensity.verdict, 'STRATEGIC', 'explicit strategic load into density should survive');
  const outDensity = await derive({ trueRPM: 1.30, floorRPM: 1.25, initialVerdict: 'STRATEGIC', effectiveStrategic: true, effectiveReason: 'home', geo: { intoDensity: false, dT1: false, dT2: false } });
  eq(outDensity.verdict, 'REJECT', 'strategic must not rescue weak out-of-density load');
});

test('[V24-B04] long-haul floor and home/replace exception preserve legacy behavior', async () => {
  eq((await derive({ trueRPM: 1.44, totalMi: 500 })).verdict, 'REJECT', 'normal long haul under 1.45 must reject');
  eq((await derive({ trueRPM: 1.44, totalMi: 500, floorRPM: 1.25, effectiveStrategic: true, effectiveReason: 'home' })).verdict, 'ACCEPT', 'going-home strategic exception should allow 1.44 long haul');
});

test('[V24-B05] true-cost and fuel-only margin reject thresholds are exact', async () => {
  eq((await derive({ profitMarginPct: 9.99, opCPM: 0.66 })).verdict, 'REJECT', 'true margin below 10% must reject');
  eq((await derive({ profitMarginPct: 10, opCPM: 0.66 })).verdict, 'ACCEPT', '10% true margin is not a hard rejection');
  eq((await derive({ opCPM: 0, effectiveRevenue: 100, netAfterFuel: 19.99 })).verdict, 'REJECT', 'fuel-only margin below 20% must reject');
  eq((await derive({ opCPM: 0, effectiveRevenue: 100, netAfterFuel: 20 })).verdict, 'ACCEPT', '20% fuel-only margin is not a hard rejection');
});

test('[V24-B06] deadhead hard gate is exact around 35% / strong RPM', async () => {
  eq((await derive({ trueRPM: 1.59, deadheadPct: 35.01 })).verdict, 'REJECT', '35%+ deadhead with sub-strong RPM must reject');
  eq((await derive({ trueRPM: 1.60, deadheadPct: 50 })).verdict, 'ACCEPT', 'strong RPM clears the deadhead hard reject gate');
});

test('[V24-B07] mid-week stabilization downgrade remains deterministic', async () => {
  const r = await derive({ trueRPM: 1.45, weeklyGross: 1000, isMonWed: true });
  eq(r.verdict, 'STRATEGIC', 'below preferred floor + below stabilize floor mid-week should downgrade to strategic');
  ok(r.steps.some(s => s.label === 'Weekly Position' && s.pass === false), 'weekly-position evidence step missing');
});

test('[V24-B08] fatigue safety veto overrides otherwise valid economics and DZ survival', async () => {
  eq((await derive({ fatigue: 8 })).verdict, 'REJECT', 'fatigue 8 must reject normal load');
  const dz = await derive({ trueRPM: 0.95, floorRPM: 1.40, initialVerdict: 'REJECT', isDZActive: true, dzSubTier: 'DZ-FLOOR', dzCheck: { distanceFromHome: 1800, distanceSaved: 600 }, fatigue: 8 });
  eq(dz.verdict, 'REJECT', 'fatigue safety veto must still override DZ survival economics');
});

test('[V24-B09] Personal Intelligence can downgrade ACCEPT but never revive a hard reject', async () => {
  const negative = [{ icon: '✕', text: 'This broker/lane has underperformed in your history' }];
  eq((await derive({ personalScore: -6, personalBullets: negative })).verdict, 'STRATEGIC', 'negative personal evidence should downgrade accept');
  const positive = [{ icon: '✓', text: 'Historically strong' }];
  eq((await derive({ trueRPM: 1.39, personalScore: 10, personalBullets: positive })).verdict, 'REJECT', 'positive history must never revive below-floor load');
});

test('[V24-B10] valid DZ conditions activate DZ-EXIT before later safety gates', async () => {
  const r = await derive({ trueRPM: 0.95, initialVerdict: 'REJECT', isDZActive: true, dzSubTier: 'DZ-FLOOR', dzCheck: { distanceFromHome: 1800, distanceSaved: 600 }, fatigue: 2 });
  eq(r.verdict, 'DZ-EXIT', 'active DZ should own the survival verdict when no later safety veto fires');
  ok(r.steps.some(s => s.label === 'Dead Zone Exit' && s.pass === true), 'DZ evidence step missing');
});

test('[V24-B11] canonical authority is deterministic for identical inputs', async () => {
  const a = await derive({ trueRPM: 1.45, weeklyGross: 1000, isMonWed: true, personalScore: -2, personalBullets: [{ icon: '–', text: 'Neutral' }] });
  const b = await derive({ trueRPM: 1.45, weeklyGross: 1000, isMonWed: true, personalScore: -2, personalBullets: [{ icon: '–', text: 'Neutral' }] });
  eq(JSON.stringify(a), JSON.stringify(b), 'identical facts must yield byte-equivalent JSON');
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
