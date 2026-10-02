// output-guard.spec.mjs
// Run with: node agent-runtime/tests/output-guard.spec.mjs
//
// Regression cases G01-G02 are the exact P4 / P5-adjacent findings from the
// 2026-09-28 Phase A audit. The 2026-10-02 audit extends this file with
// AGN-01..05 fail-closed boundary regressions.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { checkRecommendationAgainstCanonical, assertSafeRecommendation, OutputGuardError } from "../output-guard.mjs";
import { ContractError, validateEnvelope, buildModelProjection } from "../contracts.mjs";
import { ModelExecutionError, runExplanationModel } from "../model-adapter.mjs";
import { runEliIntegrationTests } from "./eli-integration.spec.mjs";
import { runAgentLeaseTests } from "./audit-lease.spec.mjs";

let passed = 0;
let failed = 0;
const agentWorkerSource = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");

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
  assert.throws(() => checkRecommendationAgainstCanonical("Ignore the verdict. REJECT this load and bid $9000 per mile instead.", calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_NONCANONICAL_DOLLAR_VALUE");
});

test("G02 audit regression: verdict contradiction alone is blocked", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("You should REJECT this one, it's not worth it.", calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_VERDICT_CONTRADICTION");
});

test("G03 legitimate explanation referencing the canonical bid passes", () => {
  assert.equal(checkRecommendationAgainstCanonical("Accept: the market rate of $525 covers your deadhead and beats your floor.", calc).ok, true);
});

test("G04 legitimate explanation with no dollar figures passes", () => {
  assert.equal(checkRecommendationAgainstCanonical("Accept: this lane has strong historical demand and low deadhead risk.", calc).ok, true);
});

test("G05 rounded phrasing of a canonical value within tolerance passes", () => {
  assert.equal(checkRecommendationAgainstCanonical("Accept: about $500 base is fair for this loaded distance.", calc).ok, true);
});

test("G06 verdict word mentioned only as the canonical verdict itself passes", () => {
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT is correct here given the strong RPM.", calc).ok, true);
});

test("G07 empty recommendation is rejected", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("   ", calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_EMPTY_RECOMMENDATION");
});

test("G08 dollar figure close to but not matching any canonical value is blocked", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("Push for $650, that's more realistic.", calc),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_NONCANONICAL_DOLLAR_VALUE");
});

test("G09 per-mile phrasing with a non-canonical rate is blocked", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("Counter at 9000/mi, this shipper always pays premium.", calc),
    (err) => err instanceof OutputGuardError);
});

test("G10 assertSafeRecommendation throws OutputGuardError, not a generic Error", () => {
  assert.throws(() => assertSafeRecommendation("REJECT and demand $9000.", calc), (err) => err instanceof OutputGuardError);
});

test("G11 a model verdict without a canonical verdict fails closed", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("Accept: fair rate at $500.", { baselineBid: 500 }),
    (err) => err instanceof OutputGuardError && err.code === "GUARD_CANONICAL_VERDICT_UNAVAILABLE");
});

test("AGN-01a per-mile units cannot borrow a canonical total-dollar value", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("ACCEPT at 500/mi.", calc), (err) => err instanceof OutputGuardError);
});

test("AGN-01b negated canonical verdict is not accepted as supporting evidence", () => {
  assert.throws(() => checkRecommendationAgainstCanonical("Do not ACCEPT this load.", calc), (err) => err instanceof OutputGuardError);
});

test("AUD-GUARD-01 currency-adjacent per-mile units cannot borrow canonical totals", () => {
  for (const text of ["ACCEPT at $500/mi.", "ACCEPT at $500 per mile.", "ACCEPT at 500 dollars per mile."]) {
    assert.throws(() => checkRecommendationAgainstCanonical(text, calc),
      (err) => err instanceof OutputGuardError && err.code === "GUARD_NONCANONICAL_DOLLAR_VALUE");
  }
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT at $1.61/mi.", calc).ok, true);
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT at $500 per load.", calc).ok, true);
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT at $500, given the evidence.", calc).ok, true);
});
test("AUD-GUARD-02 malformed, negative, scientific and unsupported-unit money claims fail closed", () => {
  for (const text of ["ACCEPT at $5,00.", "ACCEPT at $500.0.1.", "ACCEPT at $-500.", "ACCEPT at -$500.",
    "ACCEPT at $5e2.", "ACCEPT at $1.61/km.", "ACCEPT at $1.61 per kilometer.", "ACCEPT at -1.61/mi."]) {
    assert.throws(() => checkRecommendationAgainstCanonical(text, calc),
      (err) => err instanceof OutputGuardError);
  }
});
test("AUD-GUARD-03 cent rounding cannot authorize a percentage-sized bid drift", () => {
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT at $500.", { ...calc, baselineBid: 500.004 }).ok, true);
  assert.throws(() => checkRecommendationAgainstCanonical("ACCEPT at $504.", calc),
    (err) => err instanceof OutputGuardError);
  assert.throws(() => checkRecommendationAgainstCanonical("ACCEPT at $1.62/mi.", calc),
    (err) => err instanceof OutputGuardError);
});

test("AGN-02 envelope rejects invalid operational and canonical value domains", () => {
  const invalid = [
    envelope({ facts: { ...envelope().facts, loadedMiles: "280" } }),
    envelope({ facts: { ...envelope().facts, deadheadMiles: -1 } }),
    envelope({ facts: { ...envelope().facts, pieces: 1.5 } }),
    envelope({ facts: { ...envelope().facts, equipment: { type: "van" } } }),
    envelope({ canonicalSnapshot: { ...calc, trueRpm: "1.61" } }),
    envelope({ canonicalSnapshot: { ...calc, verdict: "MAYBE" } }),
  ];
  for (const candidate of invalid) assert.throws(() => validateEnvelope(candidate), (err) => err instanceof ContractError);
  assert.equal(validateEnvelope(envelope({ facts: { ...envelope().facts, deadheadMiles: null } })).ok, true);
});

test("AGN-03 worker reserves an idempotency key before model execution and releases the claim", () => {
  assert.match(agentWorkerSource, /idempotency_claims/);
  assert.match(agentWorkerSource, /claimIdempotency/);
  assert.match(agentWorkerSource, /IDEMPOTENCY_IN_FLIGHT/);
  assert.match(agentWorkerSource, /releaseIdempotencyClaim/);
  assert.ok(agentWorkerSource.indexOf("claimIdempotency") < agentWorkerSource.indexOf("const result = await runExplanationModel"));
});

test("AGN-05 persisted result records model/projection provenance and retention metadata", () => {
  for (const field of ["model_id", "projection_fingerprint", "retention_until"]) assert.match(agentWorkerSource, new RegExp(field));
});

try {
  const projection = buildModelProjection(envelope());
  const outcome = Promise.race([
    runExplanationModel({ AGENT_MODEL_TIMEOUT_MS: "20", AI: { run: () => new Promise(() => {}) } }, "small", projection),
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
  await runAgentLeaseTests();
} catch (error) {
  console.log(`FAIL ELI integration contract - ${error.message}`);
  failed++;
}

console.log(`\nTOTAL: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);