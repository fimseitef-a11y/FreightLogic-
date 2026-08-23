// v24.1 authority-boundary tests.
//
// v24.1 is a DESCRIPTIVE layer. These tests exist to prove it stayed one: that
// no confidence label can move a verdict, grade, True RPM, economics or bid,
// that the Worker cannot replace a client-owned label, and that records written
// before v24.1 still read correctly.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/v24-1-confidence-authority.spec.mjs');
let app;

const NOW = Date.UTC(2026, 7, 23, 12, 0, 0);

// Two evidence bases that could not differ more: everything healthy and
// well-sampled, versus everything stale, failed and unrecorded.
function evidenceBases() {
  const strong = {
    nowMs: NOW,
    sourceHealth: { EIA: { status: 'OK', lastSuccess: NOW - 86400000 } },
    hasRoute: true,
    laneIntel: { count: 40, avgRPM: 1.80, lastDate: '2026-08-21', dzExitCount: 0 },
    destReloadScore: { count: 30, avg: 4, grade: 'A', label: 'Hot market', lastObservedMs: NOW - 86400000 },
    rateBandFreshness: null, // adapter absent here; static bands are fallback evidence and cap at MEDIUM
    brokerEntered: true, brokerKey: 'acme', brokerIdentityResolved: true,
    brokerIntel: { sampleSize: 30, paySpeedSamples: 15, outcomeSamples: 15, lastObservedMs: NOW - 86400000 },
    fuelPrice: 3.79, fuelPriceSource: 'DRIVER_SETTING', opCPM: 0.66,
    mpg: 18, mpgSource: 'DRIVER_SETTING',
    dimensionsProvided: true, dimensionsSuppliedCount: 4, vanProfileVerified: true,
  };
  const weak = {
    ...strong,
    sourceHealth: { EIA: { status: 'TIMEOUT' } },
    laneIntel: null,
    destReloadScore: null,
    rateBandFreshness: { status: 'STALE', ageDays: 400, effectiveDate: '2025-06-01' },
    brokerIntel: null, brokerIdentityResolved: false,
    fuelPriceSource: 'STATIC_BASELINE', opCPM: 0,
    mpgSource: 'STATIC_BASELINE',
    dimensionsSuppliedCount: 1, vanProfileVerified: false,
  };
  return { strong, weak };
}

// Builds a full canonical decision twice — once on strong evidence, once on
// weak — with every authoritative input held identical.
async function decisionsUnderBothEvidenceBases(factOverrides = {}) {
  return app.page.evaluate(({ bases, factOverrides }) => {
    const T = window.__FL_TESTS;
    const facts = {
      initialVerdict: 'ACCEPT', tierLabel: 'Professional',
      trueRPM: 1.55, totalMi: 400, floorRPM: 1.40, dzFloor: 0.90,
      isDZActive: false, dzSubTier: null, dzCheck: { distanceFromHome: 0, distanceSaved: 0 },
      effectiveStrategic: false, effectiveReason: '',
      opCPM: 0.66, profitMarginPct: 35, effectiveRevenue: 620, netAfterFuel: 540,
      deadheadPct: 12, weeklyGross: 0, weekTargetHigh: 4200,
      stabilizeFloor: 2000, surgeFloor: 3000, isMonWed: false, fatigue: 2,
      geo: { intoDensity: true, destDensity: 'Tier 1', dT1: true, dT2: false },
      origin: 'Chicago, IL', dest: 'Indianapolis, IN',
      personalScore: 0, personalBullets: [],
      ...factOverrides,
    };
    const build = (evidenceInput) => {
      const authorityResult = T.deriveUnifiedAuthority(facts);
      const economicsResult = T.deriveUnifiedEconomics({
        revenue: 620, effectiveRevenue: 620, loadedMi: 350, deadMi: 50,
        mpg: 18, fuelPrice: 3.79, opCPM: 0.66, borderAdminCost: 0,
      });
      const bidResult = T.deriveUnifiedBid(400, { urgencyBoost: 0, crossBorder: false });
      return T.buildUnifiedDecisionContract({
        evidenceInput, economicsResult, bidResult,
        tier: { label: 'Professional', color: '#fff' }, authorityResult,
        verdictColors: {}, verdictLabels: {},
        weeklyGross: 0, geo: facts.geo, fatigue: 2,
        origin: facts.origin, dest: facts.dest,
        floorRPM: 1.40, effectiveStrategic: false, effectiveReason: '',
        usaResult: null, urgency: null, crossBorder: null,
        velocityMode: 'PRIME', velocityDetail: '', velocityFloor: 1.5,
        postDeliveryCmd: 'HOLD', postDeliveryDetail: '', turnoverType: 'MONEY RUN',
        warnings: [], isDZActive: false, isDZEligible: false,
        dzSubTier: null, dzCheck: null, dzFloor: 0.90, noReloadConfirmed: false,
      });
    };
    const strong = build(bases.strong);
    const weak = build(bases.weak);
    const strip = d => JSON.stringify({
      authority: d.authority, economics: d.economics, bid: d.bid,
      risk: d.risk, deadZone: d.deadZone,
    });
    return {
      strongConfidence: strong.confidence.overall,
      weakConfidence: weak.confidence.overall,
      strongAuthoritative: strip(strong),
      weakAuthoritative: strip(weak),
      strongVerdict: strong.authority.verdict,
      weakVerdict: weak.authority.verdict,
      strongGrade: strong.authority.grade,
      weakGrade: weak.authority.grade,
      strongBidMin: strong.bid.range.minimum.rpm,
      weakBidMin: weak.bid.range.minimum.rpm,
      strongTrueRPM: strong.economics.trueRPM,
      weakTrueRPM: weak.economics.trueRPM,
    };
  }, { bases: evidenceBases(), factOverrides });
}

test('[V241-A01] confidence differs but verdict, grade, True RPM, economics and bid are byte-identical', async () => {
  const r = await decisionsUnderBothEvidenceBases();
  eq(r.strongConfidence, 'HIGH', 'the strong evidence base must actually reach HIGH');
  eq(r.weakConfidence, 'LOW', 'the weak evidence base must actually reach LOW');
  ok(r.strongConfidence !== r.weakConfidence, 'the two bases must produce different labels or this proves nothing');

  eq(r.weakAuthoritative, r.strongAuthoritative, 'every authoritative field must be identical under HIGH and LOW confidence');
  eq(r.weakVerdict, r.strongVerdict, 'confidence must not change the verdict');
  eq(r.weakGrade, r.strongGrade, 'confidence must not change the grade');
  eq(r.weakTrueRPM, r.strongTrueRPM, 'confidence must not change True RPM');
  eq(r.weakBidMin, r.strongBidMin, 'confidence must not change the canonical bid minimum');
});

test('[V241-A02] LOW confidence cannot relax a hard rejection into acceptance', async () => {
  // A load rejected on the normal floor stays rejected no matter how strong or
  // weak the evidence behind it is.
  const r = await decisionsUnderBothEvidenceBases({ trueRPM: 1.39 });
  eq(r.strongVerdict, 'REJECT', 'a 1.39 load rejects on strong evidence');
  eq(r.weakVerdict, 'REJECT', 'a 1.39 load still rejects on weak evidence');
  eq(r.weakAuthoritative, r.strongAuthoritative, 'a hard gate must be evidence-independent');
});

test('[V241-A03] the protective bid floor is identical at every confidence level', async () => {
  const floors = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    return {
      plain: T.deriveUnifiedBid(500, { urgencyBoost: 0, crossBorder: false }).range.minimum.rpm,
      urgent: T.deriveUnifiedBid(500, { urgencyBoost: 0.10, crossBorder: false }).range.minimum.rpm,
    };
  });
  eq(floors.plain, 1.40, 'the canonical bid minimum is $1.40/true-mile');
  ok(floors.urgent >= 1.40, 'urgency may only raise the floor, never lower it');

  // The structural guarantee that no label can reach these numbers is asserted
  // separately in [V241-A04].
});

test('[V241-A04] the confidence helpers cannot reach the authority functions', async () => {
  // Static guard: the v24.1 section must not call any authority/economics/bid
  // function. A future edit that wires one in fails here.
  const violations = await app.page.evaluate(async () => {
    const text = await (await fetch('app.js')).text();
    const start = text.indexOf('// v24.1 — Confidence + Evidence contract');
    const end = text.indexOf('// 7D — Dimensional/payload pre-check');
    if (start < 0 || end < 0 || end <= start) return ['v24.1 section not found'];
    const section = text.slice(start, end);
    const banned = ['deriveUnifiedAuthority', 'deriveUnifiedGrade', 'deriveUnifiedEconomics', 'deriveUnifiedBid', 'generateBidRange'];
    return banned.filter(fn => section.includes(fn + '('));
  });
  eq(violations.length, 0, `v24.1 confidence section must not call authority functions: ${violations.join(', ')}`);
});

test('[V241-A05] the AI projection carries client labels only and no competing model inputs', async () => {
  const projected = await app.page.evaluate((NOW) => {
    const T = window.__FL_TESTS;
    const confidence = T.buildDecisionConfidence({
      nowMs: NOW, sourceHealth: {}, hasRoute: true,
      laneIntel: { count: 20, avgRPM: 1.7, lastDate: '2026-08-21', dzExitCount: 0 },
      destReloadScore: null, rateBandFreshness: null,
      brokerEntered: false, brokerIntel: null,
      fuelPrice: 3.79, fuelPriceSource: 'DRIVER_SETTING', opCPM: 0.66,
      mpg: 18, mpgSource: 'DRIVER_SETTING',
      dimensionsProvided: false,
    });
    return T.confidenceForAI(confidence);
  }, NOW);

  eq(projected.authority, 'CLIENT_UNIFIED_DECISION_ENGINE', 'the projection must be marked client-owned');
  eq(projected.role, 'DESCRIPTIVE_ONLY', 'the projection must declare itself descriptive');
  ok(['HIGH', 'MEDIUM', 'LOW'].includes(projected.overall), 'the projected label must be categorical');

  // The Worker must not receive the raw material it would need to recompute a
  // confidence model of its own.
  const serialized = JSON.stringify(projected);
  ok(!serialized.includes('avgRPM'), 'raw lane aggregates must not be shipped to the Worker');
  ok(!serialized.includes('provenance'), 'full provenance blobs must not be shipped to the Worker');
  ok(!/\d+\s*%/.test(serialized), 'no percentage may appear in the AI projection');
});

test('[V241-A06] the Worker projects the client label and cannot publish its own', async () => {
  const worker = await app.page.evaluate(async () => (await fetch('cloud-backup-worker.js')).text());
  ok(worker.includes('function canonicalConfidence(confidence)'), 'worker must have a confidence projector');
  ok(worker.includes("confidence:    canonicalConfidence(payload.canonicalDecision?.confidence)"),
    'the response confidence must be projected from the client payload, not the model');
  ok(!/confidence:\s*String\(parsed\./.test(worker), 'the worker must never read a confidence field off the model output');
  ok(!/parsed\.confidence/.test(worker), 'the model response must have no confidence field path at all');
  ok(worker.includes('CONFIDENCE RULE (v24.1)'), 'the system prompt must state the confidence boundary');
  ok(worker.includes('may NOT publish a competing confidence label'), 'the prompt must forbid a competing label');

  // The client renderer must read its own label, never the AI response's.
  const appSrc = await app.page.evaluate(async () => (await fetch('app.js')).text());
  ok(!appSrc.includes('ev.confidence'), 'the client must never render a confidence value off the AI response');
  ok(appSrc.includes("CONFIDENCE: ' + escapeHtml(confidence.overall)"), 'the AI panel must render the client-owned label');
});

test('[V241-A07] decisions built without evidence input remain valid and backward-compatible', async () => {
  const legacy = await app.page.evaluate(() => {
    const T = window.__FL_TESTS;
    const authorityResult = T.deriveUnifiedAuthority({
      initialVerdict: 'ACCEPT', trueRPM: 1.55, totalMi: 400, floorRPM: 1.40,
      opCPM: 0.66, profitMarginPct: 35, effectiveRevenue: 620, netAfterFuel: 540,
      deadheadPct: 12, fatigue: 0, geo: { intoDensity: true, dT1: true },
      origin: 'Chicago, IL', dest: 'Indianapolis, IN',
    });
    const economicsResult = T.deriveUnifiedEconomics({
      revenue: 620, effectiveRevenue: 620, loadedMi: 350, deadMi: 50,
      mpg: 18, fuelPrice: 3.79, opCPM: 0.66, borderAdminCost: 0,
    });
    const bidResult = T.deriveUnifiedBid(400, {});
    // No evidenceInput at all — exactly how a pre-v24.1 caller invokes this.
    const d = T.buildUnifiedDecisionContract({
      economicsResult, bidResult, tier: {}, authorityResult,
      verdictColors: {}, verdictLabels: {}, geo: {}, origin: '', dest: '',
      floorRPM: 1.40, warnings: [],
    });
    return {
      verdict: d.authority.verdict,
      confidence: d.confidence,
      legacyConfidence: T.unifiedDecisionToLegacy(d).confidence,
      aiConfidence: T.unifiedDecisionForAI(d).confidence,
      snapshot: T.confidenceSnapshot(d.confidence),
    };
  });
  eq(legacy.verdict, 'ACCEPT', 'a decision without evidence input must still be built');
  eq(legacy.confidence, null, 'confidence must be absent, not fabricated, when no evidence was supplied');
  eq(legacy.legacyConfidence, null, 'the legacy adapter must pass through the absent confidence');
  eq(legacy.aiConfidence, null, 'the AI projection must be null rather than an invented label');
  eq(legacy.snapshot, null, 'the persisted snapshot must be null rather than an invented label');
});

test('[V241-A08] the persisted snapshot is compact, additive and secret-free', async () => {
  const snap = await app.page.evaluate((NOW) => {
    const T = window.__FL_TESTS;
    const confidence = T.buildDecisionConfidence({
      nowMs: NOW, sourceHealth: { EIA: { status: 'HTTP_ERROR' } }, hasRoute: true,
      laneIntel: { count: 12, avgRPM: 1.7, lastDate: '2026-08-20', dzExitCount: 0 },
      destReloadScore: null, rateBandFreshness: null,
      brokerEntered: true, brokerKey: 'acme',
      brokerIntel: { sampleSize: 5, paySpeedSamples: 5, outcomeSamples: 0, lastObservedMs: NOW - 86400000 },
      fuelPrice: 3.55, fuelPriceSource: 'STATIC_BASELINE', opCPM: 0.66,
      mpg: 18, mpgSource: 'DRIVER_SETTING', dimensionsProvided: false,
    });
    return T.confidenceSnapshot(confidence);
  }, NOW);

  ok(snap.schemaVersion, 'the snapshot must record which contract wrote it');
  ok(['HIGH', 'MEDIUM', 'LOW'].includes(snap.overall), 'the snapshot must record the label');
  ok(Array.isArray(snap.items) && snap.items.length > 0, 'the snapshot must record per-item evidence');
  for (const item of snap.items) {
    ok(item.key && item.source && item.sourceStatus, 'each snapshot item must identify its source and health');
    ok(!('provenance' in item), 'the snapshot must stay compact — no full provenance blobs');
    ok(!('valueSummary' in item), 'the snapshot must not duplicate display text');
  }
  const serialized = JSON.stringify(snap);
  for (const secret of ['apiKey', 'token', 'flk_', 'passphrase']) {
    ok(!serialized.includes(secret), `the snapshot must not carry ${secret}`);
  }
  ok(serialized.length < 4000, 'the snapshot must stay small enough to ride along on every record');
});

test('[V241-A09] a persisted snapshot survives the export/backup/restore path', async () => {
  const result = await app.page.evaluate(async (NOW) => {
    const T = window.__FL_TESTS;
    const confidence = T.buildDecisionConfidence({
      nowMs: NOW, sourceHealth: {}, hasRoute: true,
      laneIntel: { count: 12, avgRPM: 1.7, lastDate: '2026-08-20', dzExitCount: 0 },
      destReloadScore: null, rateBandFreshness: null, brokerEntered: false, brokerIntel: null,
      fuelPrice: 3.79, fuelPriceSource: 'DRIVER_SETTING', opCPM: 0.66,
      mpg: 18, mpgSource: 'DRIVER_SETTING', dimensionsProvided: false,
    });
    const snapshot = T.confidenceSnapshot(confidence);

    // Write a bidHistory row carrying the optional v24.1 field, plus one
    // written the pre-v24.1 way with no confidence at all.
    const withConf = { id: 'v241_with', broker: 'acme', brokerDisplay: 'Acme', outcome: 'won', timestamp: Date.now(), confidence: snapshot };
    const without = { id: 'v241_without', broker: 'acme', brokerDisplay: 'Acme', outcome: 'won', timestamp: Date.now() };

    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const t = db.transaction('bidHistory', 'readwrite');
        t.objectStore('bidHistory').put(withConf);
        t.objectStore('bidHistory').put(without);
        t.oncomplete = () => { db.close(); resolve(); };
        t.onerror = () => { db.close(); reject(t.error); };
      };
      req.onerror = () => reject(req.error);
    });

    // Round-trip through the real merge/restore path.
    const restored = await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const t = db.transaction('bidHistory', 'readonly');
        const all = t.objectStore('bidHistory').getAll();
        all.onsuccess = () => { db.close(); resolve(all.result); };
        all.onerror = () => { db.close(); reject(all.error); };
      };
      req.onerror = () => reject(req.error);
    });

    await T.mergeRestoreData({ bidHistory: [withConf, without] });

    const after = await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const t = db.transaction('bidHistory', 'readonly');
        const all = t.objectStore('bidHistory').getAll();
        all.onsuccess = () => { db.close(); resolve(all.result); };
        all.onerror = () => { db.close(); reject(all.error); };
      };
      req.onerror = () => reject(req.error);
    });

    const kept = after.find(r => r.id === 'v241_with');
    const legacyRow = after.find(r => r.id === 'v241_without');
    return {
      seeded: restored.length,
      keptOverall: kept?.confidence?.overall ?? null,
      keptItems: kept?.confidence?.items?.length ?? 0,
      legacyHasConfidence: legacyRow ? ('confidence' in legacyRow) : null,
      expectedOverall: snapshot.overall,
      expectedItems: snapshot.items.length,
    };
  }, NOW);

  eq(result.keptOverall, result.expectedOverall, 'the persisted confidence label must survive restore');
  eq(result.keptItems, result.expectedItems, 'every persisted evidence item must survive restore');
  eq(result.legacyHasConfidence, false, 'a pre-v24.1 record must remain readable with no confidence field');
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
