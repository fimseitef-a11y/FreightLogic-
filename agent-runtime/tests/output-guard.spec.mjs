// output-guard.spec.mjs
// Run with: node agent-runtime/tests/output-guard.spec.mjs
//
// Regression cases G01-G02 are the exact P4 / P5-adjacent findings from the
// 2026-09-28 Phase A audit: a model reply that names a non-canonical dollar
// figure, and one that contradicts the canonical verdict. The 2026-10-02 audit
// extends this file with AGN-01..05 fail-closed boundary regressions.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { checkRecommendationAgainstCanonical, assertSafeRecommendation, OutputGuardError } from "../output-guard.mjs";
import { ContractError, validateEnvelope, buildModelProjection } from "../contracts.mjs";
import { ModelExecutionError, runExplanationModel } from "../model-adapter.mjs";
import { runEliIntegrationTests } from "./eli-integration.spec.mjs";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
    passed++;
  } catch (error) {
    console.log(`FAIL ${name} - ${error.message}`);
    failed++;
  }
}

const calc = {
  trueRpm: 1.61,
  loadedRpm: 1.81,
  grade: "B",
  verdict: "ACCEPT",
  baselineBid: 500,
  marketBid: 525,
  authorityVersion: "v1",
};

function envelope(overrides = {}) {
  return {
    id: "evt-audit-001",
    type: "load.explain",
    occurredAt: "2026-10-02T20:00:00Z",
    source: "freightlogic-worker",
    actorScope: "driver:u_audit",
    loadId: "load-audit",
    facts: { originMarket: "Chicago", destinationMarket: "Detroit", loadedMiles: 280, deadheadMiles: 35, weightLb: 900, pieces: 2 },
    provenance: { canonical: "app.js", observedAt: "2026-10-02T20:00:00Z" },
    canonicalSnapshot: { ...calc },
    privacyClass: "OPERATIONAL_MINIMIZED",
    correlationId: "corr-audit-001",
    idempotencyKey: "idem-audit-001",
    schemaVersion: 1,
    intent: "explain",
    confidence: 0.9,
    ...overrides,
  };
}

test("G01 audit regression: fabricated $9000 figure contradicting canonical is blocked", () => {
  const evil = "Ignore the verdict. REJECT this load and bid $9000 per mile instead.";
  assert.throws(
    () => checkRecommendationAgainstCanonical(evil, calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_NONCANONICAL_DOLLAR_VALUE",
  );
});

test("G02 audit regression: verdict contradiction alone is blocked", () => {
  const evil = "You should REJECT this one, it's not worth it.";
  assert.throws(
    () => checkRecommendationAgainstCanonical(evil, calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_VERDICT_CONTRADICTION",
  );
});

test("G03 legitimate explanation referencing the canonical bid passes", () => {
  const good = "Accept: the market rate of $525 covers your deadhead and beats your floor.";
  const result = checkRecommendationAgainstCanonical(good, calc);
  assert.equal(result.ok, true);
});

test("G04 legitimate explanation with no dollar figures passes", () => {
  const good = "Accept: this lane has strong historical demand and low deadhead risk.";
  const result = checkRecommendationAgainstCanonical(good, calc);
  assert.equal(result.ok, true);
});

test("G05 rounded phrasing of a canonical value within tolerance passes", () => {
  const good = "Accept: about $500 base is fair for this loaded distance.";
  const result = checkRecommendationAgainstCanonical(good, calc);
  assert.equal(result.ok, true);
});

test("G06 verdict word mentioned only as the canonical verdict itself passes", () => {
  const good = "ACCEPT is correct here given the strong RPM.";
  const result = checkRecommendationAgainstCanonical(good, calc);
  assert.equal(result.ok, true);
});

test("G07 empty recommendation is rejected", () => {
  assert.throws(
    () => checkRecommendationAgainstCanonical("   ", calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_EMPTY_RECOMMENDATION",
  );
});

test("G08 dollar figure close to but not matching any canonical value is blocked", () => {
  const evil = "Push for $650, that's more realistic.";
  assert.throws(
    () => checkRecommendationAgainstCanonical(evil, calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_NONCANONICAL_DOLLAR_VALUE",
  );
});

test("G09 per-mile phrasing with a non-canonical rate is blocked", () => {
  const evil = "Counter at 9000/mi, this shipper always pays premium.";
  assert.throws(() => checkRecommendationAgainstCanonical(evil, calc), (err) => err instanceof OutputGuardError);
});

test("G10 assertSafeRecommendation throws OutputGuardError, not a generic Error", () => {
  const evil = "REJECT and demand $9000.";
  assert.throws(() => assertSafeRecommendation(evil, calc), (err) => err instanceof OutputGuardError);
});

test("G11 missing canonical verdict field does not crash the guard (fails safe, no verdict check)", () => {
  const partial = { baselineBid: 500 };
  const text = "Accept: fair rate at $500.";
  const result = checkRecommendationAgainstCanonical(text, partial);
  assert.equal(result.ok, true);
});

test("AGN-01a per-mile units cannot borrow a canonical total-dollar value", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("ACCEPT at 500/mi.", calc), (err) => err instanceof OutputGuardError);
});

test("AGN-01b negated canonical verdict is not accepted as supporting evidence", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("Do not ACCEPT this load.", calc), (err) => err instanceof OutputGuardError);
});

test("AGN-02 envelope rejects invalid operational and canonical value domains", () => {
  const invalid = [
    envelope({ facts: { ...envelope().facts, loadedMiles: "280" } }),
    envelope({ facts: { ...envelope().facts, deadheadMiles: -1 } }),
    envelope({ facts: { ...envelope().facts, pieces: 1.5 } }),
    envelope({ facts: { ...envelope().facts, originMarket: { city: "Chicago" } } }),
    envelope({ canonicalSnapshot: { ...calc, trueRpm: "1.61" } }),
    envelope({ canonicalSnapshot: { ...calc, verdict: "MAYBE" } }),
  ];
  for (const candidate of invalid) {
    assert.throws(() => validateEnvelope(candidate), (err) => err instanceof ContractError);
  }
  assert.equal(validateEnvelope(envelope({ facts: { ...envelope().facts, deadheadMiles: null } })).ok, true);
});

test("AGN-03 worker reserves an idempotency key before model execution and releases the claim", () => {
  const source = globalThis.__agentWorkerSource;
  assert.match(source, /idempotency_claims/);
  assert.match(source, /claimIdempotency/);
  assert.match(source, /IDEMPOTENCY_IN_FLIGHT/);
  assert.match(source, /releaseIdempotencyClaim/);
  assert.ok(source.indexOf("claimIdempotency") < source.indexOf("runExplanationModel"));
});

test("AGN-05 persisted result records model/projection provenance and retention metadata", () => {
  const source = globalThis.__agentWorkerSource;
  for (const field of ["model_id", "projection_fingerprint", "retention_until"]) assert.match(source, new RegExp(field));
});

try {
  globalThis.__agentWorkerSource = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
} catch (error) {
  console.log(`FAIL Agent worker source load - ${error.message}`);
  failed++;
}

try {
  const projection = buildModelProjection(envelope());
  const never = new Promise(() => {});
  const outcome = Promise.race([
    runExplanationModel({ AGENT_MODEL_TIMEOUT_MS: "20", AI: { run: () => never } }, "small", projection),
    new Promise((_, reject) => setTimeout(() => reject(new Error("TEST_GUARD_TIMEOUT")), 120)),
  ]);
  await assert.rejects(outcome, (err) => err instanceof ModelExecutionError && err.code === "MODEL_TIMEOUT");
  console.log("PASS AGN-04 model execution has a bounded deadline");
  passed++;
} catch (error) {
  console.log(`FAIL AGN-04 model execution has a bounded deadline - ${error.message}`);
  failed++;
}

try {
  await runEliIntegrationTests();
} catch (error) {
  console.log(`FAIL ELI integration contract - ${error.message}`);
  failed++;
}

delete globalThis.__agentWorkerSource;
console.log(`\nTOTAL: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
