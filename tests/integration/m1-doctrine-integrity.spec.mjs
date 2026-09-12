// Milestone 1 — doctrine and money-integrity certification.
//
// Covers the regression matrix in the operator-approved M1 packet:
// UNKNOWN-vs-zero across canonical economics/grade/authority, mileage
// provenance, Level X+ grade taxonomy parity, Cincinnati/Toledo Tier 1,
// the exact 0.90 DZ floor, and the approved ~17.5 MPG fallback with the
// explicit user-MPG override preserved.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/m1-doctrine-integrity.spec.mjs');
let app;

const econ = (o={}) => app.page.evaluate((o) => {
  const base = { revenue:500, effectiveRevenue:500, loadedMi:80, deadMi:20, mpg:20, fuelPrice:4, opCPM:0.40, borderAdminCost:0 };
  return window.__FL_TESTS.deriveUnifiedEconomics({ ...base, ...o });
}, o);

const grade = (rpm) => app.page.evaluate((rpm) => window.__FL_TESTS.deriveUnifiedGrade(rpm), rpm);

const authority = (o={}) => app.page.evaluate((o) => {
  const base = {
    initialVerdict:'ACCEPT', tierLabel:'Professional', trueRPM:1.50, totalMi:200, floorRPM:1.40,
    dzFloor:0.90, isDZActive:false, dzSubTier:null, dzCheck:{distanceFromHome:0,distanceSaved:0},
    effectiveStrategic:false, effectiveReason:'', opCPM:0.66, profitMarginPct:40,
    effectiveRevenue:500, netAfterFuel:450, deadheadPct:10, weeklyGross:0, fatigue:2,
    geo:{intoDensity:true,destDensity:'Tier 1',dT1:true,dT2:false},
    origin:'Chicago, IL', dest:'Indianapolis, IN', personalScore:0, personalBullets:[],
  };
  return window.__FL_TESTS.deriveUnifiedAuthority({ ...base, ...o });
}, o);

/* ---------------------------------------------- grade taxonomy (Level X+) */

test('[M1-01] grade thresholds are exact on both sides of every Level X+ boundary', async () => {
  const cases = [
    [1.24,'F'],[1.25,'E'],[1.39,'E'],[1.40,'D'],[1.49,'D'],
    [1.50,'C'],[1.59,'C'],[1.60,'B'],[1.74,'B'],[1.75,'A'],
  ];
  for (const [rpm, want] of cases){
    eq((await grade(rpm)).raw.grade, want, `$${rpm.toFixed(2)} must be grade ${want}`);
  }
});

test('[M1-02] MW.rpmTiers agrees with deriveUnifiedGrade at every band edge', async () => {
  const mismatches = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const expected = r => r >= 1.75 ? 'A' : r >= 1.60 ? 'B' : r >= 1.50 ? 'C' : r >= 1.40 ? 'D' : r >= 1.25 ? 'E' : 'F';
    const bad = [];
    for (const band of T.MW.rpmTiers){
      for (const rpm of [band.min, band.max]){
        if (rpm > 90) continue; // open-ended top band sentinel
        const g = T.deriveUnifiedGrade(rpm).raw.grade;
        if (g !== expected(rpm)) bad.push(`${rpm} -> ${g}, canonical says ${expected(rpm)}`);
      }
    }
    return bad;
  });
  eq(mismatches.length, 0, `MW.rpmTiers drifted from canonical grades: ${mismatches.join('; ')}`);
});

test('[M1-03] the stale $1.35 minimum-standard band is gone from data and rendered copy', async () => {
  const found = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      tierMin: T.MW.rpmTiers.some(b => b.min === 1.35),
      label: T.MW.rpmTiers.some(b => /minimum standard/i.test(b.label)),
    };
  });
  ok(!found.tierMin, 'no rpmTiers band may start at 1.35 — D starts at 1.40');
  ok(!found.label, '"Minimum Standard" band must be gone');
  const html = await app.page.content();
  ok(!html.includes('$1.35–$1.49'), 'rendered ladder must not advertise D as $1.35–$1.49');
});

/* ------------------------------------------------------------- geography */

test('[M1-04] Cincinnati and Toledo are Tier 1 in canonical geography', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      cincy: T.mwGeoCheck('Chicago, IL', 'Cincinnati, OH'),
      toledo: T.mwGeoCheck('Chicago, IL', 'Toledo, OH'),
      tier1: T.MW.tier1, tier2: T.MW.tier2,
    };
  });
  eq(r.cincy.destDensity, 'Tier 1', 'Cincinnati must be Tier 1');
  eq(r.toledo.destDensity, 'Tier 1', 'Toledo must be Tier 1');
  ok(!r.tier2.includes('cincinnati'), 'Cincinnati must not remain in tier2');
  ok(!r.tier2.includes('toledo'), 'Toledo must not remain in tier2');
});

test('[M1-05] the advisory overlay mirrors Tier 1 geography', async () => {
  const r = await app.page.evaluate(() => {
    const cfg = window.FreightLogicMidwestStack;
    if (!cfg) return null;
    const t1 = (cfg.config?.marketRoles?.tier1) || [];
    const t2 = (cfg.config?.marketRoles?.tier2) || [];
    return { t1, t2 };
  });
  if (!r){ ok(true, 'overlay not injected in this harness — canonical mirror covered by M1-04'); return; }
  ok(r.t1.includes('cincinnati'), 'overlay tier1 must include Cincinnati');
  ok(r.t1.includes('toledo'), 'overlay tier1 must include Toledo');
  ok(!r.t2.includes('cincinnati') && !r.t2.includes('toledo'), 'overlay tier2 must not still carry them');
});

/* ------------------------------------------------------- DZ / F20 floor */

test('[M1-06] the DZ absolute floor is exactly 0.90 in canonical and overlay', async () => {
  const r = await app.page.evaluate(() => ({
    canonical: window.__FL_TESTS.MW.dzFloorRPM,
    overlayFloor: window.FreightLogicMidwestStack?.config?.modes?.DEAD_ZONE?.floor ?? null,
    overlayHardStop: window.FreightLogicMidwestStack?.config?.hardStops?.absoluteTrueRpmReject ?? null,
  }));
  eq(r.canonical, 0.90, 'canonical MW.dzFloorRPM');
  if (r.overlayFloor !== null){
    eq(r.overlayFloor, 0.90, 'overlay DEAD_ZONE.floor must equal the canonical F20 floor, not 0.91');
    eq(r.overlayHardStop, 0.90, 'overlay absolute reject must equal the same floor');
  }
});

test('[M1-07] DZ boundary is exact: 0.89 below floor, 0.90 at floor', async () => {
  const below = await authority({ isDZActive:true, trueRPM:0.89, dzFloor:0.90, dzSubTier:'DZ-FLOOR' });
  const at = await authority({ isDZActive:true, trueRPM:0.90, dzFloor:0.90, dzSubTier:'DZ-FLOOR' });
  eq(at.verdict, 'DZ-EXIT', '0.90 is at the survival floor and stays DZ-EXIT');
  const rpmStepBelow = below.steps.find(s => s.label === 'True RPM');
  eq(rpmStepBelow.pass, false, '0.89 must fail the True RPM gate');
});

/* ------------------------------------------- UNKNOWN is never a real zero */

test('[M1-08] null, undefined, blank, NaN and Infinity mileage all stay UNKNOWN', async () => {
  for (const bad of [null, undefined, '', '   ', NaN, Infinity]){
    const e = await econ({ loadedMi: bad });
    eq(e.available, false, `loadedMi=${String(bad)} must make economics unavailable`);
    ok(e.unknownFacts.includes('loadedMi'), 'loadedMi must be named as unknown');
    eq(e.trueRPM, null, 'True RPM must be null, never 0');
  }
});

test('[M1-09] unknown revenue does not calculate precise economics', async () => {
  const e = await econ({ revenue: null, effectiveRevenue: null });
  eq(e.available, false, 'unavailable');
  ok(e.unknownFacts.includes('revenue'), 'revenue named');
  for (const k of ['trueRPM','loadedRPM','netAfterFuel','trueProfit','profitMarginPct','breakEvenRPM','profitPerMile']){
    eq(e[k], null, `${k} must be null, not a calculated-looking 0`);
  }
});

test('[M1-10] unknown deadhead does not calculate precise True RPM', async () => {
  const e = await econ({ deadMi: null });
  eq(e.available, false, 'unknown deadhead blocks economics');
  eq(e.trueRPM, null, 'True RPM must not be computed from loaded miles alone');
  eq(e.deadheadPct, null, 'deadhead percentage must not be 0%');
});

test('[M1-11] an explicit deadMi: 0 is a verified real zero, not unknown', async () => {
  const e = await econ({ deadMi: 0 });
  eq(e.available, true, 'a supplied zero is a known fact');
  eq(e.deadMi, 0, 'zero survives');
  eq(e.deadheadPct, 0, '0% deadhead is a real answer here');
  eq(e.totalMi, 80, 'total miles equal loaded miles');
  eq(e.mileageProvenance.deadhead, 'VERIFIED', 'an entered zero is VERIFIED, not UNKNOWN');
});

test('[M1-12] mileage provenance is explicit and keeps the four mileages distinct', async () => {
  const e = await econ({ loadedMiProvenance:'ESTIMATED', platformDisplayedMi: 77, repositionMi: 40 });
  eq(e.mileageProvenance.loaded, 'ESTIMATED', 'estimated loaded miles are labelled');
  eq(e.mileageProvenance.deadhead, 'VERIFIED', 'entered deadhead is verified');
  eq(e.mileageProvenance.platformDisplayedMi, 77, 'platform-displayed miles kept separately');
  eq(e.mileageProvenance.repositionMi, 40, 'post-delivery reposition miles kept separately');
  eq(e.loadedMi, 80, 'platform-displayed value must not overwrite loaded miles');
  const unknown = await econ({ loadedMi: null });
  eq(unknown.mileageProvenance.loaded, 'UNKNOWN', 'missing loaded miles report UNKNOWN provenance');
});

test('[M1-13] unknown True RPM does not become grade F by coercion', async () => {
  for (const bad of [null, undefined, '', NaN, Infinity]){
    const g = await grade(bad);
    eq(g.raw.grade, '?', `${String(bad)} must not grade as F`);
    eq(g.raw.known, false, 'grade must report itself as not known');
  }
  const real = await grade(1.10);
  eq(real.raw.grade, 'F', 'a genuinely low RPM is still a real F');
  eq(real.raw.known, true, 'a real grade reports known');
});

test('[M1-14] incomplete facts cannot produce an authoritative verdict', async () => {
  for (const [field, patch] of [
    ['trueRPM', { trueRPM: null }],
    ['totalMi', { totalMi: undefined }],
    ['deadheadPct', { deadheadPct: '' }],
    ['effectiveRevenue', { effectiveRevenue: NaN }],
  ]){
    const a = await authority(patch);
    eq(a.verdict, 'UNAVAILABLE', `${field} unknown must not yield a normal verdict`);
    eq(a.available, false, 'authority must report unavailable');
    ok(a.unknownFacts.includes(field), `${field} must be named`);
    ok(!['ACCEPT','REJECT','STRATEGIC','DZ-EXIT'].includes(a.verdict), 'no decisive verdict from holes');
  }
});

test('[M1-15] incomplete facts suppress the canonical bid payload', async () => {
  const d = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const economicsResult = T.deriveUnifiedEconomics({ revenue:null, loadedMi:80, deadMi:20 });
    const authorityResult = T.deriveUnifiedAuthority({ trueRPM:null, totalMi:100, deadheadPct:20, effectiveRevenue:null });
    const bidResult = T.deriveUnifiedBid(100, {});
    const c = T.buildUnifiedDecisionContract({ authorityResult, economicsResult, bidResult });
    return { factsComplete:c.factsComplete, unknown:c.unknownFacts, range:c.bid.range, suppressed:c.bid.suppressed, verdict:c.authority.verdict };
  });
  eq(d.factsComplete, false, 'contract must know its facts are incomplete');
  eq(d.verdict, 'UNAVAILABLE', 'verdict stays unavailable');
  eq(d.range, null, 'no bid range may be offered');
  eq(d.suppressed, true, 'bid must be explicitly suppressed, not silently empty');
  ok(d.unknown.length > 0, 'missing facts are named on the contract');
});

test('[M1-16] complete facts still produce a full, unchanged authoritative payload', async () => {
  const e = await econ();
  eq(e.available, true, 'valid input stays available');
  eq(e.totalMi, 100, 'true miles');
  eq(e.trueRPM, 5, 'True RPM computed exactly as before');
  eq(e.mileageProvenance.loaded, 'VERIFIED', 'supplied miles are verified');
  const a = await authority();
  eq(a.available, true, 'authority available');
  eq(a.unknownFacts.length, 0, 'nothing unknown');
  ok(['ACCEPT','STRATEGIC','REJECT','DZ-EXIT'].includes(a.verdict), 'a real verdict is still produced');
});

/* ------------------------------------------------- approved MPG parity */

test('[M1-17] the MW.mpg fallback matches the approved ~17.5 Gate 0 baseline', async () => {
  const mpg = await app.page.evaluate(() => window.__FL_TESTS.MW.mpg);
  eq(mpg, 17.5, 'stale 16.5 fallback must be reconciled to the operator-confirmed baseline');
});

test('[M1-18] an explicit user MPG still overrides the fallback exactly', async () => {
  const r = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const base = { revenue:500, effectiveRevenue:500, loadedMi:80, deadMi:20, fuelPrice:4, opCPM:0 };
    return {
      explicit: T.deriveUnifiedEconomics({ ...base, mpg: 12 }),
      fallback: T.deriveUnifiedEconomics({ ...base, mpg: T.MW.mpg }),
      mwMpg: T.MW.mpg,
    };
  });
  eq(r.explicit.mpg, 12, 'canonical economics must use the explicit user MPG exactly');
  eq(r.explicit.fuel, 33.33, '100mi / 12mpg * $4 — computed from the user value');
  eq(r.fallback.mpg, r.mwMpg, 'absent an explicit value the approved fallback is used');
  ok(r.explicit.fuel !== r.fallback.fuel, 'the override must actually change the economics');
});

test('[M1-19] the advisory overlay cannot own canonical verdict or bid', async () => {
  const r = await app.page.evaluate(() => {
    const stack = window.FreightLogicMidwestStack;
    if (!stack?.assessLoad) return null;
    return stack.assessLoad({ revenue:900, loadedMiles:400, deadheadMiles:50, origin:'Chicago, IL', destination:'Toledo, OH' });
  });
  if (!r){ ok(true, 'overlay not injected in this harness'); return; }
  eq(r.authorityRole, 'ADAPTER_ONLY', 'overlay must declare itself adapter-only');
  // v24.0.4 item 3: assert the ABSENCE structurally, not just the label. The
  // overlay used to declare itself ADAPTER_ONLY while returning floorBid/winBid/
  // askBid and its own verdict, and rendering them directly beneath the canonical
  // result — a $475 floor and TAKE_IF_LIVE under a canonical REJECT/F. A label is
  // not an authority boundary; the missing fields are.
  eq(r.recommendation, undefined, 'the overlay must not return a `recommendation` object at all');
  eq(r.posted.grade, undefined, 'the overlay must not derive a grade — grade is canonical-only');
  for (const k of ['floorBid','winBid','askBid','floorRpm','winRpm','askRpm','verdict']){
    ok(!(k in r), `the overlay must not expose "${k}" anywhere in its result`);
    ok(!(r.posted && k in r.posted), `the overlay must not expose "${k}" under posted`);
  }
  ok(r.market && r.risk, 'market role and risk flags survive — that is the evidence the overlay legitimately adds');
});

test('[M1-20] the overlay refuses to invent economics from missing facts', async () => {
  const r = await app.page.evaluate(() => {
    const stack = window.FreightLogicMidwestStack;
    if (!stack?.assessLoad) return null;
    return stack.assessLoad({ loadedMiles:400, deadheadMiles:50, origin:'Chicago, IL', destination:'Toledo, OH' });
  });
  if (!r){ ok(true, 'overlay not injected in this harness'); return; }
  eq(r.available, false, 'missing revenue must make the overlay unavailable');
  eq(r.trueRpm, null, 'no True RPM from a missing revenue');
  ok(r.unknownFacts.includes('revenue'), 'revenue named as unknown');
});

test('[M1-21] the overlay keeps an explicitly zero deadhead as a real zero', async () => {
  const r = await app.page.evaluate(() => {
    const stack = window.FreightLogicMidwestStack;
    if (!stack?.assessLoad) return null;
    return stack.assessLoad({ revenue:900, loadedMiles:400, deadheadMiles:0, origin:'Chicago, IL', destination:'Toledo, OH' });
  });
  if (!r){ ok(true, 'overlay not injected in this harness'); return; }
  eq(r.available, true, 'a supplied zero deadhead is a known fact');
  eq(r.input.deadheadMiles, 0, 'the explicit zero survives as a real zero');
  eq(r.posted.trueRpm, 2.25, '$900 / 400 true miles — computed from 400 loaded + a verified 0 deadhead');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); } finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
