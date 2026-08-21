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


# ---------------------------------------------------------------------------
# app.js — migrate the actual hard verdict chain into one pure authority fn.
# ---------------------------------------------------------------------------
insert_anchor = "function buildUnifiedDecisionContract(input){\n"
authority_fn = r'''const UNIFIED_DECISION_POLICY = Object.freeze({
  version: '24.0.0-hard-gates-1',
  normalFloorRPM: MW.normalFloorRPM,
  preferredFloorRPM: MW.preferredFloorRPM,
  strategicFloorRPM: MW.strategicFloorRPM,
  longHaulMinRPM: MW.longHaulMinRPM,
  longHaulMiles: 250,
  strongRPM: 1.60,
  healthyTrueMarginPct: 25,
  healthyFuelMarginPct: 30,
  rejectTrueMarginPct: 10,
  rejectFuelMarginPct: 20,
  healthyDeadheadPct: 20,
  rejectDeadheadPct: 35,
  fatigueOkayMax: 6,
  fatigueRejectAt: 8,
});

/**
 * v24 canonical verdict authority. Pure/deterministic: every external fact,
 * user setting and historical signal needed for the decision is passed in.
 * It does not read DOM/storage/time/network and it does not mutate its input.
 * The step order intentionally preserves v23.9 behavior while moving ownership
 * into one testable function.
 */
function deriveUnifiedAuthority(facts, policy = UNIFIED_DECISION_POLICY){
  const f = facts || {};
  const geo = f.geo || {};
  const steps = [];
  let verdict = f.initialVerdict || 'REJECT';
  let verdictReason = '';
  const trueRPM = Number(f.trueRPM || 0);
  const totalMi = Number(f.totalMi || 0);
  const deadheadPct = Number(f.deadheadPct || 0);
  const effectiveRevenue = Number(f.effectiveRevenue || 0);
  const netAfterFuel = Number(f.netAfterFuel || 0);
  const profitMarginPct = Number(f.profitMarginPct || 0);
  const opCPM = Number(f.opCPM || 0);
  const fatigue = Number(f.fatigue || 0);
  const weeklyGross = Number(f.weeklyGross || 0);
  const floorRPM = Number(f.floorRPM || policy.normalFloorRPM);
  const dzFloor = Number(f.dzFloor || 0);
  const isDZActive = !!f.isDZActive;
  const effectiveStrategic = !!f.effectiveStrategic;
  const effectiveReason = String(f.effectiveReason || '');
  const origin = String(f.origin || '');
  const dest = String(f.dest || '');

  // STEP 1: Geography
  if (geo.intoDensity){
    steps.push({ pass: true, label: 'Geography', detail: `→ ${geo.destDensity || 'known'} density (${dest})` });
  } else if (origin && dest){
    steps.push({ pass: false, label: 'Geography', detail: 'Out of density — rate must be strong' });
    if (trueRPM < policy.strongRPM){ verdict = 'REJECT'; verdictReason = 'Out of density + RPM below Strong'; }
  } else {
    steps.push({ pass: null, label: 'Geography', detail: 'No origin/dest — skipping geo check' });
  }

  // STEP 2: True RPM + survival gate result
  const rpmPass = isDZActive ? trueRPM >= dzFloor : trueRPM >= floorRPM;
  steps.push({ pass: rpmPass, label: 'True RPM', detail: `$${trueRPM.toFixed(2)} — ${isDZActive ? `${f.dzSubTier || 'DZ-EXIT'} (DZ mode)` : (f.tierLabel || '')}` });
  if (!isDZActive && trueRPM < floorRPM){
    verdict = 'REJECT';
    verdictReason = `Under $${floorRPM.toFixed(2)} floor`;
  }
  if (isDZActive){
    verdict = 'DZ-EXIT';
    verdictReason = `Dead Zone Exit — ${f.dzSubTier || 'DZ-EXIT'} (${Number(f.dzCheck?.distanceFromHome || 0)}mi from home)`;
    steps.push({ pass: true, label: 'Dead Zone Exit', detail: `${Number(f.dzCheck?.distanceSaved || 0)}mi saved toward home corridor • Survival scoring active` });
  }

  // Long-haul minimum — only home/replace strategic exceptions or active DZ.
  if (!isDZActive && totalMi > policy.longHaulMiles && trueRPM < policy.longHaulMinRPM){
    const allowLongHaulStrategic = effectiveStrategic && (effectiveReason === 'home' || effectiveReason === 'replace');
    if (!allowLongHaulStrategic){
      verdict = 'REJECT';
      verdictReason = `Long haul under $${policy.longHaulMinRPM}`;
    }
  }

  // Explicit strategic band.
  if (effectiveStrategic && trueRPM >= policy.strategicFloorRPM && trueRPM < policy.normalFloorRPM && verdict !== 'REJECT'){
    verdict = 'STRATEGIC';
    const reasonLabel = effectiveReason === 'home' ? 'Going home'
      : effectiveReason === 'slow' ? 'Escaping slow market'
      : effectiveReason === 'replace' ? 'Replacing deadhead'
      : 'Strategic mode';
    verdictReason = verdictReason || `${reasonLabel} — strategic floor active`;
  }

  if (!effectiveStrategic && trueRPM >= policy.normalFloorRPM && trueRPM < policy.preferredFloorRPM && verdict === 'ACCEPT'){
    verdictReason = verdictReason || `Below preferred $${policy.preferredFloorRPM.toFixed(2)} floor — acceptable only if it improves position or stabilizes the week`;
  }

  // STEP 3: Profit margin
  const fuelMarginPct = effectiveRevenue > 0 ? ((netAfterFuel / effectiveRevenue) * 100) : 0;
  const marginPass = opCPM > 0 ? profitMarginPct >= policy.healthyTrueMarginPct : fuelMarginPct >= policy.healthyFuelMarginPct;
  steps.push({
    pass: marginPass,
    label: 'Profit Margin',
    detail: opCPM > 0
      ? `${profitMarginPct.toFixed(0)}% true margin (after all costs)`
      : `${fuelMarginPct.toFixed(0)}% margin (fuel only — set op cost in settings for full analysis)`,
  });
  if (opCPM > 0 && profitMarginPct < policy.rejectTrueMarginPct){
    verdict = 'REJECT'; verdictReason = `True profit margin below ${policy.rejectTrueMarginPct}%`;
  } else if (!opCPM && effectiveRevenue > 0 && fuelMarginPct < policy.rejectFuelMarginPct){
    verdict = 'REJECT'; verdictReason = `Fuel margin below ${policy.rejectFuelMarginPct}%`;
  }

  // STEP 4: Deadhead
  const dhPass = deadheadPct <= policy.healthyDeadheadPct;
  steps.push({ pass: dhPass, label: 'Deadhead', detail: `${deadheadPct.toFixed(1)}% empty${deadheadPct > 30 ? ' — excessive' : deadheadPct > policy.healthyDeadheadPct ? ' — elevated' : ''}` });
  if (deadheadPct > policy.rejectDeadheadPct && trueRPM < policy.strongRPM){
    verdict = 'REJECT'; verdictReason = 'High deadhead + weak RPM';
  }

  // STEP 5: Weekly position
  if (weeklyGross > 0){
    const target = Math.max(1, Number(f.weekTargetHigh || 0));
    if (weeklyGross < Number(f.stabilizeFloor || 0) && !!f.isMonWed){
      const weekNote = `Below $${Number(f.stabilizeFloor || 0).toLocaleString()} by mid-week — STABILIZE`;
      if (verdict === 'ACCEPT' && trueRPM < policy.preferredFloorRPM){
        verdict = 'STRATEGIC'; verdictReason = 'Below preferred floor mid-week — take only if it positions into density';
      }
      steps.push({ pass: false, label: 'Weekly Position', detail: weekNote });
    } else if (weeklyGross >= Number(f.surgeFloor || 0) && !!f.isMonWed){
      steps.push({ pass: true, label: 'Weekly Position', detail: `Above $${Number(f.surgeFloor || 0).toLocaleString()} by mid-week — controlled push allowed` });
    } else {
      const pct = Math.min(100, Math.round((weeklyGross / target) * 100));
      steps.push({ pass: pct >= 50, label: 'Weekly Position', detail: `$${weeklyGross.toLocaleString()} / $${target.toLocaleString()} target (${pct}%)` });
    }
  } else {
    steps.push({ pass: null, label: 'Weekly Position', detail: 'No weekly gross entered' });
  }

  // STEP 6: Fatigue — safety may override economics/DZ.
  if (fatigue > 0){
    const fatigueOk = fatigue <= policy.fatigueOkayMax;
    steps.push({ pass: fatigueOk, label: 'Fatigue', detail: `Level ${fatigue}/10${fatigue >= 7 ? ' — DO NOT SIGN TIRED' : fatigue >= 5 ? ' — elevated' : ''}` });
    if (fatigue >= policy.fatigueRejectAt){ verdict = 'REJECT'; verdictReason = 'Fatigue too high — rest first'; }
  }

  // Strategic positioning check (survival DZ is handled separately).
  if (!isDZActive && verdict === 'STRATEGIC'){
    if (geo.intoDensity && trueRPM >= policy.normalFloorRPM){
      verdictReason = verdictReason || 'Strategic — positions into density';
    } else if (!geo.intoDensity){
      verdict = 'REJECT'; verdictReason = verdictReason || 'Strategic RPM but out of density';
    }
  }

  // STEP 7: Personal Intelligence is evidence and downgrade-only.
  const personalBullets = Array.isArray(f.personalBullets) ? f.personalBullets : [];
  const personalScore = Number(f.personalScore || 0);
  if ((verdict === 'ACCEPT' || verdict === 'STRATEGIC') && personalBullets.length){
    const negatives = personalBullets.filter(b => b?.icon === '✕').map(b => String(b?.text || '')).filter(Boolean);
    if (personalScore <= -6){
      steps.push({ pass: false, label: 'Personal Intelligence', detail: negatives.join(' • ') });
      if (verdict === 'ACCEPT'){
        verdict = 'STRATEGIC';
        verdictReason = `Downgraded from ACCEPT — your own history disagrees: ${negatives[0] || 'negative historical signal'}`;
      }
    } else if (personalScore >= 6){
      const positives = personalBullets.filter(b => b?.icon === '✓').map(b => String(b?.text || '')).filter(Boolean);
      steps.push({ pass: true, label: 'Personal Intelligence', detail: positives.join(' • ') });
    } else {
      steps.push({ pass: null, label: 'Personal Intelligence', detail: 'Your history on this lane/broker is roughly neutral' });
    }
  }

  const repoSuggestion = verdict === 'REJECT' && !geo.intoDensity
    ? 'Consider repositioning toward: Indianapolis, Chicago, Cleveland, or St. Louis corridor.'
    : '';

  return Object.freeze({
    policyVersion: policy.version,
    verdict,
    verdictReason,
    steps: Object.freeze(steps.map(s => Object.freeze({ ...s }))),
    repoSuggestion,
  });
}

'''
replace_once('app.js', insert_anchor, authority_fn + insert_anchor, 'insert unified hard authority function')

# Contract must consume the canonical authority result, not arbitrary legacy
# verdict fields. This makes the architecture enforceable instead of cosmetic.
replace_once(
    'app.js',
    "function buildUnifiedDecisionContract(input){\n  const economics = Object.freeze({",
    "function buildUnifiedDecisionContract(input){\n  if (!input?.authorityResult?.verdict) throw new Error('Canonical authorityResult is required');\n  const authorityResult = input.authorityResult;\n  const economics = Object.freeze({",
    'contract requires authorityResult'
)
replace_once(
    'app.js',
    "    source: 'CLIENT_UNIFIED_DECISION_ENGINE',\n    verdict: input.verdict,\n    reason: input.verdictReason || '',",
    "    source: 'CLIENT_UNIFIED_DECISION_ENGINE',\n    policyVersion: authorityResult.policyVersion || UNIFIED_DECISION_POLICY.version,\n    verdict: authorityResult.verdict,\n    reason: authorityResult.verdictReason || '',",
    'contract sources canonical authority'
)
replace_once(
    'app.js',
    "    risk: Object.freeze({\n      steps: Array.isArray(input.steps) ? input.steps.slice() : [],",
    "    risk: Object.freeze({\n      steps: Array.isArray(authorityResult.steps) ? authorityResult.steps.slice() : [],",
    'contract canonical steps'
)
replace_once(
    'app.js',
    "      repoSuggestion: input.repoSuggestion || '',",
    "      repoSuggestion: authorityResult.repoSuggestion || '',",
    'contract canonical repo suggestion'
)

# Remove the legacy inline hard verdict+grade chain. No decision variable is
# allowed to be authored here after Phase B.
hard_start = "  // ════════════════════════════════════════════════════\n  // FREIGHT INTELLIGENCE — Multi-factor decision engine\n"
hard_end = "  // Override display verdict with intelligence engine result\n"
replace_between(
    'app.js', hard_start, hard_end,
    "  // v24 Phase B: hard gates are derived once, after evidence prefetch, by deriveUnifiedAuthority().\n\n",
    'remove inline hard verdict authority'
)

# Replace the old post-USA personal-intel bridge with the one canonical call.
personal_start = "  // ════════════════════════════════════════════════════\n  // STEP 7 (v24.0.0): Personal Intelligence bridge\n"
personal_end = "  // ── Collect decision data for render ──\n"
canonical_call = r'''  // v24 Phase B: one deterministic authority call owns all hard gates plus
  // downgrade-only Personal Intelligence. External evidence is passed in;
  // none of these sources can publish a second verdict.
  const weekTargetForDecision = getMWWeekTarget();
  const authorityResult = deriveUnifiedAuthority({
    initialVerdict: tier.verdict,
    tierLabel: tier.label,
    trueRPM, totalMi, floorRPM,
    dzFloor, isDZActive, dzSubTier, dzCheck,
    effectiveStrategic, effectiveReason,
    opCPM, profitMarginPct, effectiveRevenue, netAfterFuel,
    deadheadPct,
    weeklyGross, weekTargetHigh: weekTargetForDecision.high,
    stabilizeFloor: MW.stabilizeFloor, surgeFloor: MW.surgeFloor, isMonWed,
    fatigue, geo, origin, dest,
    personalScore: usaResult?.personalScore || 0,
    personalBullets: usaResult?.personalBullets || [],
  });
  const { verdict, verdictReason, steps, repoSuggestion } = authorityResult;

  // Grade is a separate presentation classification but shares the same
  // canonical v24 module and keeps the DZ C-cap invariant.
  const gradeState = deriveUnifiedGrade(trueRPM, { isDZActive, dzSubTier });
  const { grade, gradeLabel, gradeColor, gradeEmoji } = gradeState.raw;
  const {
    grade: dzDisplayGrade,
    gradeLabel: dzDisplayGradeLabel,
    gradeColor: dzDisplayGradeColor,
    gradeEmoji: dzDisplayGradeEmoji,
  } = gradeState.display;

'''
replace_between('app.js', personal_start, personal_end, canonical_call, 'replace personal bridge with canonical authority call')

# Build the final decision from authorityResult, not duplicated verdict pieces.
replace_once(
    'app.js',
    "    tier, verdict, verdictReason, verdictColors, verdictLabels, steps,",
    "    tier, authorityResult, verdictColors, verdictLabels,",
    'contract call canonical authority result'
)
replace_once(
    'app.js',
    "    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,",
    "    weeklyGross, geo, fatigue, origin, dest,",
    'remove duplicate repo suggestion input'
)

# Test harness export for genuine boundary testing of the pure authority fn.
replace_once(
    'app.js',
    "    // X-04 (v23.9 Phase 5)\n    isDeadZoneEligible, dzCheckEligibilitySync, dzCheckEligibility,\n    // 7D (v23.9 Phase 7)",
    "    // X-04 (v23.9 Phase 5)\n    isDeadZoneEligible, dzCheckEligibilitySync, dzCheckEligibility,\n    // v24 Unified Decision Engine\n    deriveUnifiedAuthority, deriveUnifiedGrade, UNIFIED_DECISION_POLICY,\n    // 7D (v23.9 Phase 7)",
    'export v24 authority for tests'
)

# ---------------------------------------------------------------------------
# Boundary regression spec — drives the real loaded app's pure function.
# ---------------------------------------------------------------------------
Path('tests/integration/v24-authority-boundaries.spec.mjs').write_text(r'''// v24 Phase B — canonical hard-gate boundary tests.
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
''')

# Register integration boundary spec.
replace_once(
    'tests/run-all.mjs',
    "import { runSpec as v24UnifiedDecision } from './unit/v24-unified-decision.spec.mjs';\n",
    "import { runSpec as v24UnifiedDecision } from './unit/v24-unified-decision.spec.mjs';\nimport { runSpec as v24AuthorityBoundaries } from './integration/v24-authority-boundaries.spec.mjs';\n",
    'register v24 Phase B import'
)
replace_once(
    'tests/run-all.mjs',
    "  v24UnifiedDecision,\n];",
    "  v24UnifiedDecision,\n  v24AuthorityBoundaries,\n];",
    'register v24 Phase B spec'
)

# Strengthen static architecture guards: legacy inline verdict variables must be
# gone and the contract must require authorityResult.
p = Path('tests/unit/v24-unified-decision.spec.mjs')
text = p.read_text()
needle = "  ok(app.includes('_mwRenderDecision(out, unifiedDecisionToLegacy(unifiedDecision));'), 'renderer must consume canonical decision through adapter');\n"
if text.count(needle) != 1:
    raise SystemExit('v24 static test anchor mismatch')
text = text.replace(needle, needle + "  ok(app.includes('function deriveUnifiedAuthority(facts, policy = UNIFIED_DECISION_POLICY)'), 'canonical hard-gate authority function missing');\n  ok(app.includes(\"if (!input?.authorityResult?.verdict) throw new Error('Canonical authorityResult is required')\"), 'decision contract must reject legacy verdict injection');\n  ok(!app.includes('let verdict = tier.verdict;'), 'legacy inline verdict authority must be removed');\n", 1)
p.write_text(text)

# Roadmap progress marker.
replace_once(
    'docs/V24_ROADMAP.md',
    "**In progress:** canonical result contract + grade authority + legacy-render adapter + Worker AI authority separation are the first migration slice.",
    "**In progress:** canonical result contract + grade authority + legacy-render adapter + Worker AI authority separation are complete; Phase B moves the full geography/RPM/long-haul/margin/deadhead/weekly/fatigue/personal hard-gate chain into `deriveUnifiedAuthority()` with boundary tests.",
    'roadmap Phase B progress'
)

# Self-remove after guarded transformation.
Path('scripts/v24_phase_b_patch.py').unlink()
