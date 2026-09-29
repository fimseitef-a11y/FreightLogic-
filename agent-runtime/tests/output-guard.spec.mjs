// output-guard.spec.mjs
// Run with: node agent-runtime/tests/output-guard.spec.mjs
//
// Regression cases G01-G02 are the exact P4 / P5-adjacent findings from the
// 2026-09-28 Phase A audit: a model reply that names a non-canonical dollar
// figure, and one that contradicts the canonical verdict. Before this guard
// existed, the worker returned both as ok:true.

import assert from "node:assert/strict";
import { checkRecommendationAgainstCanonical, assertSafeRecommendation, OutputGuardError } from "../output-guard.mjs";

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
  assert.throws(
    () => checkRecommendationAgainstCanonical(evil, calc),
    (err) => err instanceof OutputGuardError,
  );
});

test("G10 assertSafeRecommendation throws OutputGuardError, not a generic Error", () => {
  const evil = "REJECT and demand $9000.";
  assert.throws(
    () => assertSafeRecommendation(evil, calc),
    (err) => err instanceof OutputGuardError,
  );
});

test("G11 missing canonical verdict field does not crash the guard (fails safe, no verdict check)", () => {
  const partial = { baselineBid: 500 };
  const text = "Accept: fair rate at $500.";
  const result = checkRecommendationAgainstCanonical(text, partial);
  assert.equal(result.ok, true);
});

console.log(`\nTOTAL: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
