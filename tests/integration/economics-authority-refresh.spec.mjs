// Issue #278 — canonical operator economics authority refresh.
import { launchApp, createSuite, eq, ok, skipFirstRunWizard } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/economics-authority-refresh.spec.mjs');
let app;

async function deriveProfile(settings = {}){
  return app.page.evaluate(settings => window.__FL_TESTS.deriveCostProfile(settings), settings);
}
async function deriveEconomics(overrides = {}){
  return app.page.evaluate(overrides => window.__FL_TESTS.deriveUnifiedEconomics({
    revenue: 140,
    effectiveRevenue: 140,
    loadedMi: 100,
    deadMi: 0,
    mpg: 20,
    fuelPrice: 4,
    nonFuelVariableCPM: 0.10,
    fixedCPM: 0.15,
    borderAdminCost: 0,
    ...overrides,
  }), overrides);
}

test('[ECON278-01] dated operator profile derives fuel, marginal and all-in CPM without double counting', async () => {
  const p = await deriveProfile({});
  eq(p.available, true, 'profile available');
  eq(p.mpg, 16.7, 'operator MPG baseline');
  eq(p.fuelPrice, 3.79, 'operator fuel-price baseline');
  eq(p.fuelCPM, 0.227, 'exact fuel math rounded to 0.001');
  eq(p.nonFuelVariableCPM, 0.066, 'oil + tires + repair reserve');
  eq(p.marginalCPM, 0.293, 'fuel + non-fuel variable only');
  eq(p.fixedCPM, 0.109, 'fixed allocation only');
  eq(p.allInCPM, 0.402, 'marginal + fixed, fuel counted once');
  eq(p.fuelSource, 'PROFILE', 'profile provenance');
});

test('[ECON278-02] explicit operator overrides outrank profile defaults', async () => {
  const p = await deriveProfile({
    costModelVersion: 2,
    vehicleMpg: 20,
    fuelPrice: 4,
    nonFuelVariableCpm: 0.08,
    fixedCostPerMile: 0.12,
  });
  eq(p.fuelCPM, 0.2, 'override fuel CPM');
  eq(p.marginalCPM, 0.28, 'override marginal CPM');
  eq(p.allInCPM, 0.4, 'override all-in CPM');
  eq(p.mpgSource, 'USER', 'MPG source');
  eq(p.fuelSource, 'USER', 'fuel source');
});

test('[ECON278-03] fixed monthly allocation excludes maintenance reserve', async () => {
  const p = await deriveProfile({
    costModelVersion: 2,
    monthlyMiles: 10000,
    monthlyInsurance: 630,
    monthlyVehicle: 320,
    monthlyMaintenance: 660,
    monthlyOther: 140,
  });
  eq(p.fixedCPM, 0.109, 'insurance + vehicle + other only');
  eq(p.nonFuelVariableCPM, 0.066, 'maintenance does not replace or duplicate variable reserve');
  eq(p.allInCPM, 0.402, 'maintenance cannot be charged twice');
});

test('[ECON278-04] legacy auto-derived opCostPerMile migrates without fuel or maintenance double counting', async () => {
  const p = await deriveProfile({
    monthlyMiles: 10000,
    monthlyInsurance: 630,
    monthlyVehicle: 320,
    monthlyMaintenance: 660,
    monthlyOther: 140,
    opCostPerMile: 0.175,
  });
  eq(p.migration, 'LEGACY_AUTO_FIXED', 'recognizes the old monthly-derived setting');
  eq(p.fixedCPM, 0.109, 'fixed allocation excludes maintenance');
  eq(p.nonFuelVariableCPM, 0.066, 'variable reserve restored once');
  eq(p.allInCPM, 0.402, 'legacy migration preserves one fuel charge and one non-fuel charge');
});

test('[ECON278-05] legacy non-fuel total without monthly detail splits safely instead of adding it on top of itself', async () => {
  const p = await deriveProfile({ opCostPerMile: 0.175 });
  eq(p.migration, 'LEGACY_NON_FUEL_TOTAL_PROPORTIONAL_SPLIT', 'legacy no-detail split');
  eq(Number((p.nonFuelVariableCPM + p.fixedCPM).toFixed(3)), 0.175, 'legacy non-fuel total conserved');
  eq(p.allInCPM, 0.402, 'fuel added exactly once');
});

test('[ECON278-06] canonical economics exposes contribution and all-in profit separately', async () => {
  const e = await deriveEconomics();
  eq(e.fuelCPM, 0.2, 'fuel CPM');
  eq(e.marginalCPM, 0.3, 'fuel + variable CPM');
  eq(e.allInCPM, 0.45, 'marginal + fixed CPM');
  eq(e.fuel, 20, 'fuel dollars');
  eq(e.variableCost, 10, 'variable dollars');
  eq(e.fixedCost, 15, 'fixed allocation dollars');
  eq(e.marginalCost, 30, 'marginal dollars');
  eq(e.totalCost, 45, 'all-in dollars');
  eq(e.contributionAfterMarginal, 110, 'contribution');
  eq(e.trueProfit, 95, 'all-in profit');
  eq(e.breakEvenRPM, 0.45, 'all-in break-even');
});

test('[ECON278-07] operator economic bands honor exact boundary values', async () => {
  const rows = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return [0.85,0.86,0.99,1.00,1.14,1.15,1.35,1.36,1.39,1.40,1.50,1.51,1.64,1.65]
      .map(rpm => [rpm, T.classifyEconomicBand(rpm)?.key]);
  });
  const expected = [
    [0.85,'ESCAPE'],[0.86,'RECOVERY'],[0.99,'RECOVERY'],
    [1.00,'STRATEGIC'],[1.14,'STRATEGIC'],
    [1.15,'WORKABLE'],[1.35,'WORKABLE'],
    [1.36,'GOOD'],[1.39,'GOOD'],
    [1.40,'STRONG'],[1.50,'STRONG'],
    [1.51,'VERY_STRONG'],[1.64,'VERY_STRONG'],
    [1.65,'EXCELLENT'],
  ];
  eq(JSON.stringify(rows), JSON.stringify(expected), 'boundary map');
});

test('[ECON278-08] weekend and weekend-hold overlays are premiums, not hard rejects', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      hold: T.deriveWeekendOverlay({ pickupDay:'fri', deliveryDay:'mon', weakDestination:false, strategic:true, trueRPM:1.40 }),
      weak: T.deriveWeekendOverlay({ pickupDay:'sat', deliveryDay:'sun', weakDestination:true, trueRPM:1.20 }),
      ordinary: T.deriveWeekendOverlay({ pickupDay:'sun', deliveryDay:'sun', weakDestination:false, trueRPM:1.40 }),
    };
  });
  eq(r.hold.weekendHold, true, 'Fri to Monday hold detected');
  eq(r.hold.targetRPM, 1.55, 'hold applies protective premium / next-tier target');
  eq(r.hold.holdPremium.min, 150, 'hold dollar guide low');
  eq(r.hold.holdPremium.max, 350, 'hold dollar guide high');
  eq(r.hold.hardReject, false, 'hold is advisory, not a hard reject');
  eq(r.hold.strategicBridgeAllowed, true, 'strategic/homeward bridge remains allowed');
  eq(r.weak.targetRPM, 1.36, 'weak-destination weekend seeks at least one economic tier higher');
  eq(r.ordinary.targetRPM, 1.50, 'ordinary weekend adds about $0.10 RPM');
});

test('[ECON278-09] OMEGA net projection consumes the same canonical marginal/all-in profile', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const p = T.deriveCostProfile({
      costModelVersion:2,
      vehicleMpg:20,
      fuelPrice:4,
      nonFuelVariableCpm:0.08,
      fixedCostPerMile:0.12,
    });
    const n = T.omegaNetRange(100, { min:1.40, max:1.50 }, p);
    const round2 = x => Math.round(x * 100) / 100;
    return {
      profile:[p.marginalCPM,p.allInCPM],
      omega:[n.marginalCpm,n.costCpm,round2(n.contributionLow),round2(n.netLow)],
    };
  });
  eq(JSON.stringify(r.profile), JSON.stringify([0.28,0.4]), 'canonical profile');
  eq(JSON.stringify(r.omega), JSON.stringify([0.28,0.4,112,100]), 'OMEGA parity');
});

test('[ECON278-10] invalid explicit cost inputs fail closed rather than fabricating zero cost', async () => {
  for (const settings of [
    { vehicleMpg:-1 },
    { fuelPrice:-1 },
    { nonFuelVariableCpm:-0.01 },
    { fixedCostPerMile:-0.01 },
  ]){
    const p = await deriveProfile(settings);
    eq(p.available, false, JSON.stringify(settings));
    ok(p.unknownFacts.length > 0, 'invalid field named');
  }
});

test('[ECON278-11] evaluator renders Friday-to-Monday hold context from the actual driver form', async () => {
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    for (const key of ['vehicleMpg','fuelPrice','nonFuelVariableCpm','fixedCostPerMile','opCostPerMile','costModelVersion']){
      await T.setSetting(key, null);
    }
    location.hash = '#omega';
  });
  await app.page.waitForSelector('#mwEvalOutput');
  await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const set = (id, value) => { const el=document.getElementById(id); if(el) el.value=value; };
    set('mwOrigin','Chicago, IL');
    set('mwDest','Detroit, MI');
    set('mwLoadedMi','100');
    set('mwDeadMi','0');
    set('mwRevenue','150');
    set('mwDayOfWeek','fri');
    set('mwDeliveryDay','mon');
    await T.mwEvaluateLoad();
  });
  const text = await app.page.locator('#mwEvalOutput').textContent();
  ok(text.includes('Weekend hold'), 'rendered hold advisory');
  ok(text.includes('150') && text.includes('350'), 'rendered hold premium range');
});

test('[ECON278-12] settings surface names non-fuel variable cost and explains separated authority', async () => {
  const state = await app.page.evaluate(() => ({
    label: document.querySelector('label[for="opCostPerMile"]')?.textContent || '',
    hint: document.getElementById('costModelHint')?.textContent || '',
    delivery: !!document.getElementById('mwDeliveryDay'),
  }));
  ok(state.label.includes('Non-fuel variable'), 'cost input is no longer ambiguous');
  ok(state.hint.includes('separately') || state.hint.includes('marginal'), 'cost separation explained');
  eq(state.delivery, true, 'optional delivery-day context exists');
});

export async function runSpec(){
  app = await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.reload({ waitUntil:'load' });
  await app.page.waitForFunction(() => !!window.__FL_TESTS);
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const { stopServer } = await import('../lib/harness.mjs');
  const result = await runSpec();
  await stopServer();
  process.exit(result.fail > 0 ? 1 : 0);
}
