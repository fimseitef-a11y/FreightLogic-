import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  ContractError,
  validateEnvelope,
  classifyPrivacy,
  buildModelProjection,
} from "../contracts.mjs";
import { chooseModelTier } from "../router.mjs";
import { stateScope } from "../state-key.mjs";

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log("PASS", name);
  } catch (error) {
    failed += 1;
    console.error("FAIL", name, "-", error && error.stack || error);
  }
}

function baseEnvelope(overrides = {}) {
  return {
    id: "evt-001",
    type: "load.explain",
    occurredAt: "2026-09-27T09:15:00Z",
    source: "freightlogic-worker",
    actorScope: "driver:test",
    loadId: "load-42",
    facts: {
      originMarket: "Chicago",
      destinationMarket: "Detroit",
      loadedMiles: 280,
      deadheadMiles: 35,
      weightLb: 900,
      pieces: 2,
    },
    provenance: {
      canonical: "app.js",
      observedAt: "2026-09-27T09:15:00Z",
    },
    canonicalSnapshot: {
      trueRpm: 1.61,
      grade: "B",
      verdict: "ACCEPT",
      baselineBid: 500,
      marketBid: 525,
      authorityVersion: "24.0.47",
    },
    privacyClass: "OPERATIONAL_MINIMIZED",
    correlationId: "corr-001",
    idempotencyKey: "idem-001",
    schemaVersion: 1,
    intent: "explain",
    confidence: 0.9,
    ...overrides,
  };
}

await test("A01 valid minimized envelope passes", () => {
  const result = validateEnvelope(baseEnvelope());
  assert.equal(result.ok, true);
});

await test("A02 missing idempotency key fails closed", () => {
  assert.throws(
    () => validateEnvelope(baseEnvelope({ idempotencyKey: "" })),
    (error) => error instanceof ContractError && error.code === "MISSING_FIELD"
  );
});

await test("A03 unknown top-level field is rejected", () => {
  assert.throws(
    () => validateEnvelope({ ...baseEnvelope(), rawText: "do not accept arbitrary blobs" }),
    (error) => error instanceof ContractError && error.code === "UNKNOWN_FIELD"
  );
});

await test("A04 restricted nested key blocks model use", () => {
  const envelope = baseEnvelope({ facts: { ...baseEnvelope().facts, email: "driver@example.com" } });
  assert.equal(classifyPrivacy(envelope), "RESTRICTED");
});

await test("A05 unknown nested operational key fails to UNKNOWN", () => {
  const envelope = baseEnvelope({ facts: { ...baseEnvelope().facts, mysteryField: "x" } });
  assert.equal(classifyPrivacy(envelope), "UNKNOWN");
});

await test("A06 model projection strips identifiers and provenance", () => {
  const projection = buildModelProjection(baseEnvelope());
  assert.equal("id" in projection, false);
  assert.equal("loadId" in projection, false);
  assert.equal("actorScope" in projection, false);
  assert.equal("correlationId" in projection, false);
  assert.equal("provenance" in projection, false);
  assert.deepEqual(projection.facts, {
    originMarket: "Chicago",
    destinationMarket: "Detroit",
    loadedMiles: 280,
    deadheadMiles: 35,
    weightLb: 900,
    pieces: 2,
  });
  assert.deepEqual(projection.canonicalSnapshot, {
    trueRpm: 1.61,
    grade: "B",
    verdict: "ACCEPT",
    baselineBid: 500,
    marketBid: 525,
    authorityVersion: "24.0.47",
  });
});

await test("A07 feature flag off forces no-model", () => {
  const route = chooseModelTier(baseEnvelope(), { enabled: false });
  assert.deepEqual(route, { tier: "no-model", reason: "FEATURE_DISABLED" });
});

await test("A08 restricted privacy forces no-model", () => {
  const envelope = baseEnvelope({ facts: { ...baseEnvelope().facts, phone: "555-0100" } });
  const route = chooseModelTier(envelope, { enabled: true });
  assert.equal(route.tier, "no-model");
  assert.equal(route.reason, "PRIVACY_RESTRICTED");
});

await test("A09 high-confidence explanation may use small model", () => {
  const route = chooseModelTier(baseEnvelope({ confidence: 0.9 }), { enabled: true });
  assert.deepEqual(route, { tier: "small", reason: "EXPLANATION_HIGH_CONFIDENCE" });
});

await test("A10 ambiguous explanation escalates only to strong", () => {
  const route = chooseModelTier(baseEnvelope({ confidence: 0.6 }), { enabled: true });
  assert.deepEqual(route, { tier: "strong", reason: "EXPLANATION_AMBIGUOUS" });
});

await test("A11 very low confidence fails closed", () => {
  const route = chooseModelTier(baseEnvelope({ confidence: 0.3 }), { enabled: true });
  assert.deepEqual(route, { tier: "no-model", reason: "LOW_CONFIDENCE_FAIL_CLOSED" });
});

await test("A12 deterministic intent never calls a model", () => {
  const route = chooseModelTier(baseEnvelope({ intent: "canonical", confidence: 0.95 }), { enabled: true });
  assert.deepEqual(route, { tier: "no-model", reason: "DETERMINISTIC_INTENT" });
});

await test("A13 DO scope is user/task scoped, not global", () => {
  const one = stateScope(baseEnvelope());
  const two = stateScope(baseEnvelope({ actorScope: "driver:other" }));
  const three = stateScope(baseEnvelope({ idempotencyKey: "idem-002" }));
  assert.notEqual(one.objectName, two.objectName);
  assert.equal(one.objectName, three.objectName);
  assert.notEqual(one.idempotencyKey, three.idempotencyKey);
});

await test("A14 isolated Wrangler config is internet-dark and SQLite-backed", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.name, "freightlogic-agent-v1");
  assert.equal(config.main, "worker.mjs");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal("routes" in config, false);
  assert.equal("route" in config, false);
  assert.equal("assets" in config, false);
  assert.equal("queues" in config, false);
  assert.equal("workflows" in config, false);
  assert.equal(config.vars.AGENT_ENABLED, "false");
  assert.deepEqual(config.durable_objects.bindings, [
    { name: "AGENT_STATE", class_name: "FreightLogicAgentState" },
  ]);
  assert.deepEqual(config.exports.FreightLogicAgentState, {
    type: "durable-object",
    storage: "sqlite",
  });
});

await test("A15 worker remains Phase-A fail-closed with no model endpoint", async () => {
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  assert.equal(source.includes("AGENT_ENABLED"), true);
  assert.equal(source.includes('recommendation: "UNKNOWN"'), true);
  assert.equal(source.includes("AI_GATEWAY"), false);
  for (const secretName of ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROK_API_KEY", "XAI_API_KEY"]) {
    assert.equal(source.includes(secretName), false);
  }
});

await test("A16 excessive privacy nesting fails closed to UNKNOWN", () => {
  let nested = { value: "x" };
  for (let i = 0; i < 8; i += 1) nested = { nested };
  const envelope = baseEnvelope({
    facts: {
      ...baseEnvelope().facts,
      marketSignals: nested,
    },
  });
  assert.equal(classifyPrivacy(envelope), "UNKNOWN");
});

console.log(`TOTAL: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
