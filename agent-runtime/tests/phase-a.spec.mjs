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
import { fingerprintEnvelope, sameIdempotentEvent } from "../idempotency.mjs";
import {
  DEFAULT_SMALL_MODEL,
  DEFAULT_STRONG_MODEL,
  ModelExecutionError,
  buildModelMessages,
  runExplanationModel,
} from "../model-adapter.mjs";
import { OutputGuardError, checkRecommendationAgainstCanonical } from "../output-guard.mjs";

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

let backupWorkerModulePromise;
function backupWorkerModule() {
  if (!backupWorkerModulePromise) {
    backupWorkerModulePromise = readFile(new URL("../../cloud-backup-worker.js", import.meta.url), "utf8")
      .then((source) => import("data:text/javascript;base64," + Buffer.from(source).toString("base64")));
  }
  return backupWorkerModulePromise;
}

function memoryKv() {
  const store = new Map();
  return {
    store,
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, String(value)); },
  };
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
  const four = stateScope(baseEnvelope({ loadId: "load-99" }));
  const five = stateScope(baseEnvelope({ type: "load.other" }));
  assert.notEqual(one.objectName, two.objectName);
  assert.equal(one.objectName, three.objectName);
  assert.equal(one.objectName, four.objectName);
  assert.notEqual(one.objectName, five.objectName);
  assert.notEqual(one.idempotencyKey, three.idempotencyKey);
});

await test("A14 isolated Wrangler config is internet-dark and SQLite-backed", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.name, "freightlogic-agent-v1");
  assert.equal(config.main, "worker.mjs");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal(config.observability.enabled, false);
  assert.equal("routes" in config, false);
  assert.equal("route" in config, false);
  assert.equal("assets" in config, false);
  assert.equal("queues" in config, false);
  assert.equal("workflows" in config, false);
  assert.equal(config.vars.AGENT_ENABLED, "false");
  assert.equal(config.vars.AGENT_MODEL_SMALL, DEFAULT_SMALL_MODEL);
  assert.equal(config.vars.AGENT_MODEL_STRONG, DEFAULT_STRONG_MODEL);
  assert.deepEqual(config.ai, { binding: "AI" });
  assert.deepEqual(config.durable_objects.bindings, [
    { name: "AGENT_STATE", class_name: "FreightLogicAgentState" },
  ]);
  assert.deepEqual(config.exports.FreightLogicAgentState, {
    type: "durable-object",
    storage: "sqlite",
  });
});

await test("A15 worker model path uses private Workers AI and carries no external model secret", async () => {
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  const adapter = await readFile(new URL("../model-adapter.mjs", import.meta.url), "utf8");
  assert.equal(source.includes("AGENT_ENABLED"), true);
  assert.equal(source.includes("runExplanationModel"), true);
  assert.equal(adapter.includes("env.AI.run"), true);
  assert.equal(adapter.includes("AI_GATEWAY"), false);
  for (const secretName of ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROK_API_KEY", "XAI_API_KEY"]) {
    assert.equal(source.includes(secretName), false);
    assert.equal(adapter.includes(secretName), false);
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


await test("A17 free-form nested context is excluded from model projection", () => {
  const projection = buildModelProjection(baseEnvelope({
    facts: {
      ...baseEnvelope().facts,
      marketSignals: { note: "arbitrary text must never reach a model" },
      pickupWindow: { start: "2026-09-27T10:00:00Z" },
    },
    canonicalSnapshot: {
      ...baseEnvelope().canonicalSnapshot,
      marketContext: { note: "also excluded" },
      calculatedAt: "2026-09-27T09:15:00Z",
    },
  }));
  assert.equal("marketSignals" in projection.facts, false);
  assert.equal("pickupWindow" in projection.facts, false);
  assert.equal("marketContext" in projection.canonicalSnapshot, false);
  assert.equal("calculatedAt" in projection.canonicalSnapshot, false);
});

await test("A18 oversized envelopes are rejected before routing", () => {
  const envelope = baseEnvelope({
    facts: {
      ...baseEnvelope().facts,
      marketSignals: { note: "x".repeat(9000) },
    },
  });
  assert.throws(
    () => validateEnvelope(envelope),
    (error) => error instanceof ContractError && error.code === "ENVELOPE_TOO_LARGE"
  );
});

await test("A19 cyclic envelopes are rejected before privacy traversal", () => {
  const envelope = baseEnvelope();
  envelope.facts.marketSignals = {};
  envelope.facts.marketSignals.self = envelope.facts.marketSignals;
  assert.throws(
    () => validateEnvelope(envelope),
    (error) => error instanceof ContractError && error.code === "INVALID_ENVELOPE"
  );
});


await test("A20 idempotency identity accepts only exact event + correlation + payload", async () => {
  const envelope = baseEnvelope();
  const payloadFingerprint = await fingerprintEnvelope(envelope);
  const stored = {
    event_id: "evt-001",
    correlation_id: "corr-001",
    payload_fingerprint: payloadFingerprint,
  };
  assert.equal(sameIdempotentEvent(stored, envelope, payloadFingerprint), true);
  assert.equal(sameIdempotentEvent(stored, baseEnvelope({ id: "evt-002" }), payloadFingerprint), false);
  assert.equal(sameIdempotentEvent(stored, baseEnvelope({ correlationId: "corr-002" }), payloadFingerprint), false);
  assert.equal(sameIdempotentEvent(stored, envelope, "0".repeat(64)), false);
});

await test("A21 worker re-checks fingerprint identity after INSERT OR IGNORE", async () => {
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  assert.equal(source.includes("INSERT OR IGNORE"), true);
  assert.equal(source.includes("payload_fingerprint TEXT NOT NULL"), true);
  assert.equal(source.includes("payloadFingerprint = await fingerprintEnvelope(envelope)"), true);
  const checks = source.match(/sameIdempotentEvent\([^)]*payloadFingerprint\)/g) || [];
  assert.equal(checks.length, 2);
});

await test("A22 replay fingerprint is stable across object key order", async () => {
  const one = baseEnvelope({
    facts: {
      originMarket: "Chicago",
      destinationMarket: "Detroit",
      loadedMiles: 280,
      deadheadMiles: 35,
      weightLb: 900,
      pieces: 2,
    },
  });
  const two = baseEnvelope({
    facts: {
      pieces: 2,
      weightLb: 900,
      deadheadMiles: 35,
      loadedMiles: 280,
      destinationMarket: "Detroit",
      originMarket: "Chicago",
    },
  });
  assert.equal(await fingerprintEnvelope(one), await fingerprintEnvelope(two));
});

await test("A23 replay fingerprint changes when facts or canonical snapshot mutate", async () => {
  const base = baseEnvelope();
  const fingerprint = await fingerprintEnvelope(base);
  const changedFacts = baseEnvelope({
    facts: { ...base.facts, deadheadMiles: 36 },
  });
  const changedSnapshot = baseEnvelope({
    canonicalSnapshot: { ...base.canonicalSnapshot, marketBid: 550 },
  });
  assert.notEqual(await fingerprintEnvelope(changedFacts), fingerprint);
  assert.notEqual(await fingerprintEnvelope(changedSnapshot), fingerprint);
});

await test("A24 existing Worker Agent caller guard accepts only the authenticated actor scope", async () => {
  const { authorizeAgentRpcEnvelope } = await backupWorkerModule();
  const envelope = baseEnvelope({ actorScope: "driver:u_test" });
  const ok = authorizeAgentRpcEnvelope("u_test", { userId: "u_test", active: true, name: "must-not-leak" }, envelope);
  assert.deepEqual(ok, {
    ok: true,
    caller: { actorScope: "driver:u_test" },
    privacyClass: "OPERATIONAL_MINIMIZED",
  });
  assert.equal(JSON.stringify(ok).includes("must-not-leak"), false);
  assert.equal(authorizeAgentRpcEnvelope("u_test", { userId: "u_other", active: true }, envelope).code, "AGENT_CALLER_UNAUTHORIZED");
  assert.equal(authorizeAgentRpcEnvelope("u_test", { userId: "u_test", active: false }, envelope).code, "AGENT_CALLER_UNAUTHORIZED");
  assert.equal(authorizeAgentRpcEnvelope("u_test", { userId: "u_test", active: true }, baseEnvelope({ actorScope: "driver:u_other" })).code, "AGENT_CALLER_SCOPE_MISMATCH");
});

await test("A25 existing Worker Agent privacy boundary blocks restricted and unknown payloads", async () => {
  const { classifyAgentRpcPrivacy, authorizeAgentRpcEnvelope } = await backupWorkerModule();
  const user = { userId: "u_test", active: true };
  const restricted = baseEnvelope({
    actorScope: "driver:u_test",
    facts: { ...baseEnvelope().facts, marketSignals: { payment: { card: "do-not-forward" } } },
  });
  assert.equal(classifyAgentRpcPrivacy(restricted), "RESTRICTED");
  assert.equal(authorizeAgentRpcEnvelope("u_test", user, restricted).code, "AGENT_PRIVACY_BLOCKED");

  const unknown = baseEnvelope({ actorScope: "driver:u_test", privacyClass: "UNKNOWN" });
  assert.equal(classifyAgentRpcPrivacy(unknown), "UNKNOWN");
  assert.equal(authorizeAgentRpcEnvelope("u_test", user, unknown).code, "AGENT_PRIVACY_BLOCKED");
});

await test("A26 existing Worker Agent privacy boundary rejects unknown contract fields before RPC", async () => {
  const { classifyAgentRpcPrivacy, authorizeAgentRpcEnvelope } = await backupWorkerModule();
  const user = { userId: "u_test", active: true };

  const unknownTop = { ...baseEnvelope({ actorScope: "driver:u_test" }), harmlessLookingExtra: "x" };
  assert.equal(classifyAgentRpcPrivacy(unknownTop), "UNKNOWN");
  assert.equal(authorizeAgentRpcEnvelope("u_test", user, unknownTop).code, "AGENT_PRIVACY_BLOCKED");

  const unknownFact = baseEnvelope({
    actorScope: "driver:u_test",
    facts: { ...baseEnvelope().facts, customerReference: "opaque-but-unapproved" },
  });
  assert.equal(classifyAgentRpcPrivacy(unknownFact), "UNKNOWN");

  const unknownCanonical = baseEnvelope({
    actorScope: "driver:u_test",
    canonicalSnapshot: { ...baseEnvelope().canonicalSnapshot, internalNote: "unapproved" },
  });
  assert.equal(classifyAgentRpcPrivacy(unknownCanonical), "UNKNOWN");
});

await test("A27 existing Worker Agent privacy boundary fails closed on secrets, depth, and size", async () => {
  const { classifyAgentRpcPrivacy } = await backupWorkerModule();
  const secret = baseEnvelope({
    actorScope: "driver:u_test",
    facts: { ...baseEnvelope().facts, marketSignals: { nested: { token: "never-forward" } } },
  });
  assert.equal(classifyAgentRpcPrivacy(secret), "RESTRICTED");

  let nested = { value: "x" };
  for (let i = 0; i < 7; i += 1) nested = { nested };
  assert.equal(classifyAgentRpcPrivacy(baseEnvelope({ actorScope: "driver:u_test", facts: { ...baseEnvelope().facts, marketSignals: nested } })), "UNKNOWN");
  assert.equal(classifyAgentRpcPrivacy(baseEnvelope({ actorScope: "driver:u_test", facts: { ...baseEnvelope().facts, marketSignals: { note: "x".repeat(9000) } } })), "UNKNOWN");
});

await test("A28 existing Worker Agent caller guard rate-limits per authenticated caller", async () => {
  const { guardAgentRpcBeforeBinding } = await backupWorkerModule();
  const kv = memoryKv();
  const env = { BACKUPS: kv };
  const user = { userId: "u_test", active: true };
  const envelope = baseEnvelope({ actorScope: "driver:u_test" });
  for (let i = 0; i < 30; i += 1) {
    assert.equal((await guardAgentRpcBeforeBinding(env, "u_test", user, envelope)).ok, true);
  }
  const limited = await guardAgentRpcBeforeBinding(env, "u_test", user, envelope);
  assert.equal(limited.ok, false);
  assert.equal(limited.code, "AGENT_RATE_LIMITED");
  assert.equal((await guardAgentRpcBeforeBinding(env, "u_other", { userId: "u_other", active: true }, baseEnvelope({ actorScope: "driver:u_other" }))).ok, true);
});

await test("A29 existing Worker Agent caller guard denies when rate-limit storage is unavailable", async () => {
  const { guardAgentRpcBeforeBinding } = await backupWorkerModule();
  const result = await guardAgentRpcBeforeBinding({}, "u_test", { userId: "u_test", active: true }, baseEnvelope({ actorScope: "driver:u_test" }));
  assert.equal(result.ok, false);
  assert.equal(result.code, "AGENT_RATE_LIMIT_UNAVAILABLE");
});

await test("A30 production integration exposes Agent only through the authenticated API Worker", async () => {
  const workerSource = await readFile(new URL("../../cloud-backup-worker.js", import.meta.url), "utf8");
  const backupConfig = await readFile(new URL("../../scripts/wrangler.backup-worker.jsonc", import.meta.url), "utf8");
  const agentConfig = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));

  assert.equal(workerSource.includes("path === '/agent/evaluate'"), true);
  assert.match(backupConfig, /"binding"\s*:\s*"AGENT"/);
  assert.match(backupConfig, /"service"\s*:\s*"freightlogic-agent-v1"/);
  assert.equal(agentConfig.workers_dev, false);
  assert.equal(agentConfig.preview_urls, false);
  assert.equal("routes" in agentConfig, false);
  assert.equal("route" in agentConfig, false);
});

await test("A31 Agent HTTP ingress guards auth scope privacy and rate limit before private RPC", async () => {
  const source = await readFile(new URL("../../cloud-backup-worker.js", import.meta.url), "utf8");
  const start = source.indexOf("if (request.method === 'POST' && path === '/agent/evaluate')");
  const end = source.indexOf("// ── v24: Web Push subscriptions", start);
  assert.ok(start >= 0 && end > start);
  const route = source.slice(start, end);

  const guardAt = route.indexOf("guardAgentRpcBeforeBinding(");
  const bindAt = route.indexOf("env.AGENT.evaluate(envelope)");
  assert.ok(guardAt >= 0);
  assert.ok(bindAt > guardAt);
  assert.equal(route.includes("driverToken"), false);
  assert.equal(route.includes("tokenData.name"), false);
  assert.equal(route.includes("canonicalUser"), true);
  assert.equal(route.includes("AGENT_BINDING_UNAVAILABLE"), true);
  assert.equal(route.includes("AGENT_DISABLED"), true);
});

await test("A32 Agent runtime remains dark-by-default after private binding is wired", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  assert.equal(config.vars.AGENT_ENABLED, "false");
  assert.equal(source.includes("this.env.AGENT_ENABLED === \"true\""), true);
  assert.equal(source.includes('return new Response("Not Found"'), true);
});


await test("A33 small model adapter uses the minimized projection and default small model", async () => {
  const calls = [];
  const projection = buildModelProjection(baseEnvelope());
  const env = {
    AI: {
      async run(model, input) {
        calls.push({ model, input });
        return { response: "The canonical ACCEPT is supported; recheck deadhead only if the pickup position changes." };
      },
    },
  };
  const result = await runExplanationModel(env, "small", projection);
  assert.equal(result.model, DEFAULT_SMALL_MODEL);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].model, DEFAULT_SMALL_MODEL);
  assert.equal(calls[0].input.max_tokens, 96);
  assert.equal(calls[0].input.temperature, 0.1);
  const serialized = JSON.stringify(calls[0].input.messages);
  for (const forbidden of ["evt-001", "driver:test", "load-42", "corr-001", "idem-001", "provenance"]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  assert.match(result.recommendation, /canonical ACCEPT/);
});

await test("A34 strong model route uses the configured strong model only", async () => {
  const calls = [];
  const env = {
    AGENT_MODEL_STRONG: "@cf/test/strong",
    AI: {
      async run(model, input) {
        calls.push({ model, input });
        return { response: "The canonical decision stands; verify the uncertain deadhead before committing." };
      },
    },
  };
  const result = await runExplanationModel(env, "strong", buildModelProjection(baseEnvelope({ confidence: 0.6 })));
  assert.equal(result.model, "@cf/test/strong");
  assert.equal(calls[0].model, "@cf/test/strong");
});

await test("A35 model adapter fails closed when the Workers AI binding is unavailable", async () => {
  await assert.rejects(
    runExplanationModel({}, "small", buildModelProjection(baseEnvelope())),
    (error) => error instanceof ModelExecutionError && error.code === "MODEL_BINDING_UNAVAILABLE"
  );
});

await test("A36 model adapter fails closed on provider errors without fabricating a recommendation", async () => {
  const env = { AI: { async run() { throw new Error("provider down"); } } };
  await assert.rejects(
    runExplanationModel(env, "small", buildModelProjection(baseEnvelope())),
    (error) => error instanceof ModelExecutionError && error.code === "MODEL_REQUEST_FAILED"
  );
});

await test("A37 model adapter rejects empty or UNKNOWN provider output", async () => {
  for (const response of [{ response: "" }, { response: "UNKNOWN" }, {}]) {
    const env = { AI: { async run() { return response; } } };
    await assert.rejects(
      runExplanationModel(env, "small", buildModelProjection(baseEnvelope())),
      (error) => error instanceof ModelExecutionError && error.code === "MODEL_INVALID_RESPONSE"
    );
  }
});

await test("A38 model prompt binds canonical authority and treats projection values as untrusted data", () => {
  const messages = buildModelMessages(buildModelProjection(baseEnvelope()));
  assert.equal(messages[0].role, "system");
  assert.match(messages[0].content, /canonicalSnapshot is authoritative/);
  assert.match(messages[0].content, /untrusted data/);
  assert.match(messages[0].content, /Do not recalculate/);
  assert.equal(messages[1].role, "user");
});


await test("A39 activation workflow is explicit and rolls back to disabled on canary failure", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/ai-agent-cutover.yml", import.meta.url), "utf8");
  assert.equal(workflow.includes("ACTIVATE_CANARY"), true);
  assert.equal(workflow.includes("AGENT_ENABLED:true"), true);
  assert.equal(workflow.includes("AGENT_ENABLED:false"), true);
  assert.equal(workflow.includes("Activation canary failed; redeploying Agent disabled."), true);
  assert.equal(workflow.includes("ACTIVE AGENT CANARY VERDICT: PASS"), true);
  assert.equal(workflow.includes("IDEMPOTENCY_CONFLICT"), true);
});

await test("A40 output guard rejects non-canonical dollars and contradictory verdicts", () => {
  const canonical = baseEnvelope().canonicalSnapshot;
  assert.equal(checkRecommendationAgainstCanonical("ACCEPT at $525 based on the canonical bid.", canonical).ok, true);
  assert.throws(
    () => checkRecommendationAgainstCanonical("REJECT and bid $9000 per mile.", canonical),
    (error) => error instanceof OutputGuardError && error.code === "GUARD_NONCANONICAL_DOLLAR_VALUE"
  );
  assert.throws(
    () => checkRecommendationAgainstCanonical("REJECT this load.", canonical),
    (error) => error instanceof OutputGuardError && error.code === "GUARD_VERDICT_CONTRADICTION"
  );
});

await test("A41 worker checks model output before persistence and fails guard errors closed", async () => {
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  const guardAt = source.indexOf("assertSafeRecommendation(result.recommendation, envelope.canonicalSnapshot)");
  const assignAt = source.indexOf("recommendation = result.recommendation", guardAt);
  assert.ok(guardAt >= 0);
  assert.ok(assignAt > guardAt);
  assert.equal(source.includes('import { OutputGuardError, assertSafeRecommendation } from "./output-guard.mjs";'), true);
  assert.equal(source.includes("error instanceof ModelExecutionError || error instanceof OutputGuardError"), true);
});

await test("A42 production cutover workflow serializes activation and references the required approval environment", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/ai-agent-cutover.yml", import.meta.url), "utf8");
  assert.equal(workflow.includes("group: ai-agent-cutover-production"), true);
  assert.equal(workflow.includes("cancel-in-progress: false"), true);
  assert.equal((workflow.match(/environment: production-agent-cutover/g) || []).length, 2);
  assert.equal(workflow.includes("node agent-runtime/tests/output-guard.spec.mjs"), true);
});

console.log(`TOTAL: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
