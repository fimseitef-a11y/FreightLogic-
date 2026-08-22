// v24 Phase C — canonical economics + bid authority tests.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v24-economics-bid.spec.mjs');
let app;

async function econ(overrides = {}){
  return await app.page.evaluate((overrides) => {
    const base = { revenue: 500, effectiveRevenue: 500, loadedMi: 80, deadMi: 20, mpg: 20, fuelPrice: 4, opCPM: 0.40, borderAdminCost: 0 };
    return window.__FL_TESTS.deriveUnifiedEconomics({ ...base, ...overrides });
  }, overrides);
}

async function bid(totalMiles, opts = {}){
  return await app.page.evaluate(({ totalMiles, opts }) => window.__FL_TESTS.deriveUnifiedBid(totalMiles, opts), { totalMiles, opts });
}

test('[V24-C01] economics uses supplied driver/live MPG and fuel price exactly', async () => {
  const e = await econ();
  eq(e.totalMi, 100, 'true miles');
  eq(e.fuel, 20, '100mi / 20mpg * $4 must equal $20');
  eq(e.fuelPrice, 4, 'fuel provenance value');
  eq(e.mpg, 20, 'MPG provenance value');
  eq(e.trueRPM, 5, 'true RPM');
  eq(e.loadedRPM, 6.25, 'loaded RPM');
  eq(e.deadheadPct, 20, 'deadhead percentage');
});

test('[V24-C02] operating and border costs reconcile to true profit and break-even', async () => {
  const e = await econ({ borderAdminCost: 25 });
  eq(e.operatingCost, 40, '100mi * $0.40 operating cost');
  eq(e.totalCost, 85, '$20 fuel + $40 op + $25 border');
  eq(e.trueProfit, 415, 'effective revenue less all cost');
  eq(e.breakEvenRPM, 0.85, 'all-in break-even per true mile');
  eq(e.profitMarginPct, 83, 'true margin percent');
});

test('[V24-C03] economics changes when fuel settings change; fixed MW defaults cannot override it', async () => {
  const cheap = await econ({ mpg: 20, fuelPrice: 3 });
  const expensive = await econ({ mpg: 10, fuelPrice: 5 });
  eq(cheap.fuel, 15, 'cheap-fuel case');
  eq(expensive.fuel, 50, 'high-consumption/high-price case');
  ok(expensive.trueProfit < cheap.trueProfit, 'economics must react to live/user fuel assumptions');
});

test('[V24-C04] economics derivation is deterministic', async () => {
  const a = await econ({ effectiveRevenue: 777, loadedMi: 333, deadMi: 44, mpg: 17.5, fuelPrice: 4.54, opCPM: 0.66 });
  const b = await econ({ effectiveRevenue: 777, loadedMi: 333, deadMi: 44, mpg: 17.5, fuelPrice: 4.54, opCPM: 0.66 });
  eq(JSON.stringify(a), JSON.stringify(b), 'identical economics facts must serialize identically');
});

test('[V24-C05] canonical bid minimum starts at $1.40/true-mile', async () => {
  const b = await bid(100, {});
  eq(b.authority, 'CLIENT_UNIFIED_DECISION_ENGINE', 'bid authority marker');
  eq(b.basis, 'TRUE_MILES', 'bid basis');
  eq(b.range.minimum.rpm, 1.40, 'normal minimum RPM');
  eq(b.range.minimum.amount, 140, '100 true miles * $1.40');
});

test('[V24-C06] urgency and border premiums are deterministic and urgency is capped', async () => {
  const urgent = await bid(100, { urgencyBoost: 0.20, crossBorder: true });
  eq(urgent.range.minimum.rpm, 1.70, '$1.40 + $0.20 urgency + $0.10 border');
  const capped = await bid(100, { urgencyBoost: 0.99, crossBorder: false });
  eq(capped.range.minimum.rpm, 1.70, 'urgency premium caps at $0.30');
  eq(capped.urgencyBoost, 0.30, 'canonical metadata records capped urgency');
});

test('[V24-C07] invalid or negative urgency can never reduce the protective bid floor', async () => {
  const negative = await bid(100, { urgencyBoost: -0.50, crossBorder: false });
  eq(negative.range.minimum.rpm, 1.40, 'negative urgency must clamp to zero, not discount the floor');
  eq(negative.urgencyBoost, 0, 'canonical urgency metadata must clamp negative values to zero');
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
