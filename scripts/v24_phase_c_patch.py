from pathlib import Path


def replace_once(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {count}")
    p.write_text(text.replace(old, new, 1))


def replace_between(path, start_marker, end_marker, replacement, label):
    p = Path(path)
    text = p.read_text()
    start = text.find(start_marker)
    if start < 0:
        raise SystemExit(f"{label}: start marker not found")
    if text.find(start_marker, start + 1) >= 0:
        raise SystemExit(f"{label}: start marker not unique")
    end = text.find(end_marker, start)
    if end < 0:
        raise SystemExit(f"{label}: end marker not found")
    p.write_text(text[:start] + replacement + text[end:])


# Retire the fixed-default evaluator fuel helper. It ignored the driver's
# fuelPrice/vehicleMpg settings (including an EIA price the user explicitly
# applied), creating a split economics authority.
replace_once(
    'app.js',
    "\nfunction mwFuelCost(totalMiles){\n  return roundCents((totalMiles / MW.mpg) * MW.fuelBaseline);\n}\n\n",
    "\n",
    'remove fixed-default mwFuelCost helper'
)

# Add pure canonical economics + bid derivation beside the existing canonical
# grade/verdict functions.
anchor = "const UNIFIED_DECISION_POLICY = Object.freeze({\n"
addition = r'''function deriveUnifiedEconomics(facts){
  const f = facts || {};
  const loadedMi = Math.max(0, Number(f.loadedMi || 0));
  const deadMi = Math.max(0, Number(f.deadMi || 0));
  const totalMi = loadedMi + deadMi;
  const revenue = Math.max(0, Number(f.revenue || 0));
  const effectiveRevenue = Math.max(0, Number(f.effectiveRevenue ?? revenue));
  const mpg = Number(f.mpg || 0);
  const fuelPrice = Math.max(0, Number(f.fuelPrice || 0));
  const opCPM = Math.max(0, Number(f.opCPM || 0));
  const borderAdminCost = Math.max(0, Number(f.borderAdminCost || 0));
  const trueRPM = totalMi > 0 ? roundCents(effectiveRevenue / totalMi) : 0;
  const loadedRPM = loadedMi > 0 ? roundCents(effectiveRevenue / loadedMi) : 0;
  const fuel = (totalMi > 0 && mpg > 0) ? roundCents((totalMi / mpg) * fuelPrice) : 0;
  const netAfterFuel = roundCents(effectiveRevenue - fuel);
  const operatingCost = roundCents(totalMi * opCPM);
  const totalCost = roundCents(fuel + operatingCost + borderAdminCost);
  const operationalProfit = netAfterFuel;
  const trueProfit = roundCents(effectiveRevenue - totalCost);
  const profitMarginPct = effectiveRevenue > 0 ? roundCents((trueProfit / effectiveRevenue) * 100) : 0;
  const breakEvenRPM = totalMi > 0 ? roundCents(totalCost / totalMi) : 0;
  const profitPerMile = totalMi > 0 ? roundCents(trueProfit / totalMi) : 0;
  const estHours = totalMi > 0 ? Math.max(1, Math.round(totalMi / 50)) : 1;
  const profitPerHour = roundCents(trueProfit / estHours);
  const fuelPerMile = totalMi > 0 ? roundCents(fuel / totalMi) : 0;
  const deadheadPct = totalMi > 0 ? roundCents((deadMi / totalMi) * 100) : 0;
  return Object.freeze({
    revenue, effectiveRevenue, loadedMi, deadMi, totalMi,
    trueRPM, loadedRPM, deadheadPct,
    mpg, fuelPrice, fuel, netAfterFuel,
    opCPM, operatingCost, borderAdminCost, totalCost,
    operationalProfit, trueProfit, profitMarginPct, breakEvenRPM,
    profitPerMile, estHours, profitPerHour, fuelPerMile,
  });
}

function deriveUnifiedBid(totalMiles, opts={}){
  const miles = Math.max(0, Number(totalMiles || 0));
  const urgencyBoost = Number(opts.urgencyBoost || 0);
  const crossBorder = !!opts.crossBorder;
  const rawRange = generateBidRange(miles, { urgencyBoost, crossBorder });
  let range = null;
  if (rawRange){
    const entries = Object.entries(rawRange).map(([key, value]) => [key, Object.freeze({ ...value })]);
    range = Object.freeze(Object.fromEntries(entries));
  }
  return Object.freeze({
    authority: 'CLIENT_UNIFIED_DECISION_ENGINE',
    basis: 'TRUE_MILES',
    totalMiles: miles,
    urgencyBoost: Math.min(0.30, urgencyBoost),
    crossBorder,
    range,
  });
}

'''
replace_once('app.js', anchor, addition + anchor, 'insert canonical economics and bid functions')

# Harden the final decision contract: economics and bid objects must come from
# canonical derivation, not arbitrary legacy scalars/ranges injected by callers.
replace_once(
    'app.js',
    "function buildUnifiedDecisionContract(input){\n  if (!input?.authorityResult?.verdict) throw new Error('Canonical authorityResult is required');\n  const authorityResult = input.authorityResult;\n  const economics = Object.freeze({\n    trueRPM: input.trueRPM, loadedRPM: input.loadedRPM, totalMi: input.totalMi,\n    loadedMi: input.loadedMi, deadMi: input.deadMi, deadheadPct: input.deadheadPct,\n    revenue: input.revenue, effectiveRevenue: input.effectiveRevenue,\n    fuel: input.fuel, netAfterFuel: input.netAfterFuel,\n    operatingCost: input.operatingCost, totalCost: input.totalCost,\n    operationalProfit: input.operationalProfit, trueProfit: input.trueProfit,\n    profitMarginPct: input.profitMarginPct, breakEvenRPM: input.breakEvenRPM,\n    profitPerMile: input.profitPerMile, profitPerHour: input.profitPerHour,\n    fuelPerMile: input.fuelPerMile, estHours: input.estHours, opCPM: input.opCPM,\n  });",
    "function buildUnifiedDecisionContract(input){\n  if (!input?.authorityResult?.verdict) throw new Error('Canonical authorityResult is required');\n  if (!input?.economicsResult) throw new Error('Canonical economicsResult is required');\n  if (!input?.bidResult) throw new Error('Canonical bidResult is required');\n  const authorityResult = input.authorityResult;\n  const economics = Object.freeze({ ...input.economicsResult });\n  const bid = Object.freeze({ ...input.bidResult });",
    'contract requires canonical economics and bid'
)
replace_once(
    'app.js',
    "    bid: Object.freeze({ range: input.bidRange || null }),",
    "    bid,",
    'contract uses canonical bid result'
)

# Replace evaluator economics with the pure canonical calculation and actual
# user/live settings. Cross-border conversion stays evidence preparation.
core_start = "  // ── Core calculations ──\n"
core_end = "  // Floor logic\n"
core_replacement = r'''  // ── Core calculations / v24 canonical economics inputs ──
  const origMarket = naLookupMarket(origin);
  const destMarket = naLookupMarket(dest);
  const gateway = caFindGateway(origMarket, destMarket);
  const caSettings = {
    cadUsdRate: Number(await getSetting('cadUsdRate', CA.DEFAULT_CAD_USD) || CA.DEFAULT_CAD_USD),
    borderAdminCost: Number(await getSetting('borderAdminCost', CA.BORDER_ADMIN_COST_DEFAULT) || CA.BORDER_ADMIN_COST_DEFAULT),
    canadaDocsReady: !!(await getSetting('canadaDocsReady', false)),
  };
  const crossBorder = applyCanadaSettingsToCrossBorder(caScoreCrossBorder(origMarket, destMarket, revenue, revenueCurrency, gateway), revenue, revenueCurrency, caSettings);
  const effectiveRevenue = (crossBorder.isCrossBorder && revenueCurrency === 'CAD') ? crossBorder.normalizedRevenue : revenue;
  const opCPM = Number(await getSetting('opCostPerMile', 0) || 0);
  const fuelPrice = Number(await getSetting('fuelPrice', MW.fuelBaseline) || MW.fuelBaseline);
  const vehicleMpg = Number(await getSetting('vehicleMpg', MW.mpg) || MW.mpg);
  const borderAdminCost = crossBorder?.isCrossBorder ? Number(crossBorder.borderAdminCost || caSettings.borderAdminCost || CA.BORDER_ADMIN_COST_DEFAULT) : 0;
  const economicsResult = deriveUnifiedEconomics({
    revenue, effectiveRevenue, loadedMi, deadMi,
    mpg: vehicleMpg, fuelPrice, opCPM, borderAdminCost,
  });
  const {
    totalMi, trueRPM, loadedRPM, deadheadPct,
    fuel, netAfterFuel, operatingCost, totalCost,
    operationalProfit, trueProfit, profitMarginPct, breakEvenRPM,
    profitPerMile, estHours, profitPerHour, fuelPerMile,
  } = economicsResult;
  const tier = mwClassifyRPM(trueRPM);
  const geo = mwGeoCheck(origin, dest);

'''
replace_between('app.js', core_start, core_end, core_replacement, 'replace evaluator core economics')

# The later cost/efficiency block is now duplicate authority; delete it.
replace_between(
    'app.js',
    "  // ── Operating cost (v14.5.0) ──\n",
    "  const isMonWed = ['mon','tue','wed'].includes(dayOfWeek);\n",
    "",
    'remove duplicate evaluator economics block'
)

# Move bid derivation behind the canonical v24 function.
replace_once(
    'app.js',
    "  // ── Collect decision data for render ──\n  // Generate bid range\n  const isCrossBorder = !!(usaResult?.crossBorder?.isCrossBorder);\n  const bidRange = generateBidRange(totalMi, { urgencyBoost: urgency.boost, crossBorder: isCrossBorder });",
    "  // ── Canonical bid authority ──\n  const isCrossBorder = !!(usaResult?.crossBorder?.isCrossBorder);\n  const bidResult = deriveUnifiedBid(totalMi, { urgencyBoost: urgency.boost, crossBorder: isCrossBorder });",
    'canonical bid call'
)

# Final contract gets canonical results only for economics/bid.
replace_once(
    'app.js',
    "  const unifiedDecision = buildUnifiedDecisionContract({\n    trueRPM, loadedRPM, totalMi, loadedMi, deadMi, deadheadPct, revenue, effectiveRevenue,\n    tier, authorityResult, verdictColors, verdictLabels,\n    fuel, netAfterFuel, operatingCost, totalCost, operationalProfit,\n    trueProfit, profitMarginPct, breakEvenRPM,\n    profitPerMile, profitPerHour, fuelPerMile, estHours, opCPM,\n    weeklyGross, geo, fatigue, origin, dest,",
    "  const unifiedDecision = buildUnifiedDecisionContract({\n    economicsResult, bidResult,\n    tier, authorityResult, verdictColors, verdictLabels,\n    weeklyGross, geo, fatigue, origin, dest,",
    'contract call canonical economics and bid'
)
replace_once(
    'app.js',
    "    usaResult, urgency, bidRange, crossBorder,",
    "    usaResult, urgency, crossBorder,",
    'remove legacy bid range injection'
)

# Worker review context should reflect the exact economics the canonical engine
# used, not static MW defaults.
replace_once(
    'app.js',
    "          mpg: MW.mpg, fuelPrice: MW.fuelBaseline,",
    "          mpg: d?._canonicalDecision?.economics?.mpg || MW.mpg, fuelPrice: d?._canonicalDecision?.economics?.fuelPrice || MW.fuelBaseline,",
    'AI payload canonical fuel assumptions'
)

# Expose pure v24 functions only in the gated test harness.
replace_once(
    'app.js',
    "    deriveUnifiedAuthority, deriveUnifiedGrade, UNIFIED_DECISION_POLICY,",
    "    deriveUnifiedAuthority, deriveUnifiedGrade, deriveUnifiedEconomics, deriveUnifiedBid, UNIFIED_DECISION_POLICY,",
    'export canonical economics and bid tests'
)

# ---------------------------------------------------------------------------
# Regression tests for canonical economics and bid ownership.
# ---------------------------------------------------------------------------
Path('tests/integration/v24-economics-bid.spec.mjs').write_text(r'''// v24 Phase C — canonical economics + bid authority tests.
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
''')

replace_once(
    'tests/run-all.mjs',
    "import { runSpec as v24AuthorityBoundaries } from './integration/v24-authority-boundaries.spec.mjs';\n",
    "import { runSpec as v24AuthorityBoundaries } from './integration/v24-authority-boundaries.spec.mjs';\nimport { runSpec as v24EconomicsBid } from './integration/v24-economics-bid.spec.mjs';\n",
    'register Phase C import'
)
replace_once(
    'tests/run-all.mjs',
    "  v24AuthorityBoundaries,\n];",
    "  v24AuthorityBoundaries,\n  v24EconomicsBid,\n];",
    'register Phase C spec'
)

# Static architecture/integration guards.
p = Path('tests/unit/v24-unified-decision.spec.mjs')
text = p.read_text()
needle = "  ok(!app.includes('let verdict = tier.verdict;'), 'legacy inline verdict authority must be removed');\n"
if text.count(needle) != 1:
    raise SystemExit('v24 static Phase C anchor mismatch')
text = text.replace(needle, needle + "  ok(app.includes('function deriveUnifiedEconomics(facts)'), 'canonical economics function missing');\n  ok(app.includes('function deriveUnifiedBid(totalMiles, opts={})'), 'canonical bid function missing');\n  ok(app.includes(\"if (!input?.economicsResult) throw new Error('Canonical economicsResult is required')\"), 'contract must reject legacy economics injection');\n  ok(app.includes(\"if (!input?.bidResult) throw new Error('Canonical bidResult is required')\"), 'contract must reject legacy bid injection');\n  ok(!app.includes('const fuel = mwFuelCost(totalMi);'), 'evaluator must not use fixed-default fuel economics');\n  ok(app.includes(\"getSetting('fuelPrice', MW.fuelBaseline)\"), 'evaluator must read current fuelPrice setting');\n  ok(app.includes(\"getSetting('vehicleMpg', MW.mpg)\"), 'evaluator must read current vehicleMpg setting');\n", 1)
p.write_text(text)

# Roadmap progress.
replace_once(
    'docs/V24_ROADMAP.md',
    "Phase B moves the full geography/RPM/long-haul/margin/deadhead/weekly/fatigue/personal hard-gate chain into `deriveUnifiedAuthority()` with boundary tests.",
    "Phase B moved the full geography/RPM/long-haul/margin/deadhead/weekly/fatigue/personal hard-gate chain into `deriveUnifiedAuthority()` with boundary tests. Phase C moves economics + bid ownership into pure canonical functions and makes evaluator fuel economics honor the actual `fuelPrice`/`vehicleMpg` settings used elsewhere in FreightLogic.",
    'roadmap Phase C progress'
)

Path('scripts/v24_phase_c_patch.py').unlink()
