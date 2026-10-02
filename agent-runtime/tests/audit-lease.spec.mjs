import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";

const base = new URL("../", import.meta.url);
const platform = "data:text/javascript," + encodeURIComponent(
  "export class WorkerEntrypoint { constructor(ctx, env) { this.ctx=ctx; this.env=env; } }\n" +
  "export class DurableObject { constructor(ctx, env) { this.ctx=ctx; this.env=env; } }");
const source = (await readFile(new URL("worker.mjs", base), "utf8"))
  .replace(/from\s+["']cloudflare:workers["']/g, () => "from " + JSON.stringify(platform))
  .replace(/from\s+["']\.\/([\w.-]+\.mjs)["']/g, (_, file) => "from " + JSON.stringify(new URL(file, base).href));
const { FreightLogicAgentState: State, default: Service } = await import(
  "data:text/javascript;base64," + Buffer.from(source).toString("base64"));

function fixture() {
  const db = new DatabaseSync(":memory:");
  const sql = { exec(query, ...bindings) { return db.prepare(query).all(...bindings); } };
  return { db, state: new State({ storage: { sql } }, {}) };
}
function record(token, recommendation = "Canonical ACCEPT holds.") {
  return {
    idempotencyKey: "key", eventId: "event", correlationId: "correlation",
    payloadFingerprint: "payload", claimToken: token, authorityVersion: "v-audit",
    routeTier: "small", recommendation, confidence: 0.9, reason: "audit",
    modelId: "model:audit", projectionFingerprint: "projection:audit",
    retentionUntil: new Date(Date.now() + 86400000).toISOString(),
    createdAt: new Date().toISOString(),
  };
}
function claim(token) {
  return { idempotencyKey: "key", eventId: "event", payloadFingerprint: "payload",
    claimToken: token, expiresAt: new Date(Date.now() + 60000).toISOString() };
}
function envelope() {
  return {
    id: "event", type: "load.explain", occurredAt: "2026-10-02T20:00:00Z",
    source: "freightlogic-worker", actorScope: "driver:audit", loadId: "load:audit",
    facts: { originMarket: "Chicago", destinationMarket: "Detroit", loadedMiles: 280, deadheadMiles: 35 },
    provenance: { canonical: "app.js", observedAt: "2026-10-02T20:00:00Z" },
    canonicalSnapshot: { trueRpm: 1.61, verdict: "ACCEPT", grade: "B", baselineBid: 500, authorityVersion: "v-audit" },
    privacyClass: "OPERATIONAL_MINIMIZED", correlationId: "correlation", idempotencyKey: "key",
    schemaVersion: 1, intent: "explain", confidence: 0.9,
  };
}

export async function runAgentLeaseTests() {
  let passed = 0;
  async function test(name, fn) { await fn(); passed++; console.log("PASS", name); }

  await test("AUD-AGENT-LEASE-01 replaced owner cannot persist or release its successor", async () => {
    const { db, state } = fixture();
    try {
      assert.equal((await state.claimIdempotency(claim("A"))).acquired, true);
      db.prepare("UPDATE idempotency_claims SET expires_at = ?").run("2000-01-01T00:00:00Z");
      assert.equal((await state.claimIdempotency(claim("B"))).acquired, true);
      assert.equal((await state.putIdempotency(record("A"))).code, "AGENT_CLAIM_LOST");
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM idempotency_results").get().n, 0);
      await state.releaseIdempotencyClaim("key", "A");
      assert.equal(db.prepare("SELECT claim_token FROM idempotency_claims").get().claim_token, "B");
      const stored = await state.putIdempotency(record("B", "Successor ACCEPT holds."));
      assert.equal(stored.recommendation, "Successor ACCEPT holds.");
      assert.equal(stored.model_id, "model:audit");
      assert.equal(stored.projection_fingerprint, "projection:audit");
      assert.equal((await state.putIdempotency(record("A", "Stale result"))).code, "AGENT_CLAIM_LOST");
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM idempotency_results").get().n, 1);
      assert.equal((await state.getIdempotency("key")).recommendation, "Successor ACCEPT holds.");
    } finally { db.close(); }
  });

  await test("AUD-AGENT-LEASE-02 expiry alone and mismatched event identity reject completion", async () => {
    const { db, state } = fixture();
    try {
      await state.claimIdempotency(claim("A"));
      assert.equal((await state.putIdempotency({ ...record("A"), eventId: "other" })).code, "AGENT_CLAIM_LOST");
      db.prepare("UPDATE idempotency_claims SET expires_at = ?").run("2000-01-01T00:00:00Z");
      assert.equal((await state.putIdempotency(record("A"))).code, "AGENT_CLAIM_LOST");
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM idempotency_results").get().n, 0);
    } finally { db.close(); }
  });

  await test("AUD-AGENT-LEASE-03 a model resolving after lease replacement fails closed", async () => {
    const { db, state } = fixture();
    let releaseModel, enteredModel;
    const started = new Promise(resolve => { enteredModel = resolve; });
    const model = new Promise(resolve => { releaseModel = resolve; });
    const env = {
      AGENT_ENABLED: "true", AGENT_STATE: { getByName() { return state; } },
      AI: { async run() { enteredModel(); return model; } },
    };
    try {
      const pending = new Service({}, env).evaluate(envelope());
      await started;
      const owner = db.prepare("SELECT * FROM idempotency_claims").get();
      db.prepare("UPDATE idempotency_claims SET expires_at = ?").run("2000-01-01T00:00:00Z");
      await state.claimIdempotency({
        idempotencyKey: owner.idempotency_key, eventId: owner.event_id,
        payloadFingerprint: owner.payload_fingerprint, claimToken: "successor",
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      });
      releaseModel({ response: "Canonical ACCEPT holds." });
      const result = await pending;
      assert.equal(result.ok, false);
      assert.equal(result.code, "AGENT_CLAIM_LOST");
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM idempotency_results").get().n, 0);
      assert.equal(db.prepare("SELECT claim_token FROM idempotency_claims").get().claim_token, "successor");
    } finally { releaseModel?.({ response: "Canonical ACCEPT holds." }); db.close(); }
  });

  await test("AUD-AGENT-LEASE-04 a state binding without claims cannot execute a model", async () => {
    let models = 0;
    const service = new Service({}, {
      AGENT_ENABLED: "true",
      AGENT_STATE: { getByName() { return { async getIdempotency() { return null; } }; } },
      AI: { async run() { models++; return { response: "ACCEPT" }; } },
    });
    const result = await service.evaluate(envelope());
    assert.equal(result.ok, false);
    assert.equal(result.code, "AGENT_STATE_UNAVAILABLE");
    assert.equal(models, 0);
  });
  console.log(`AGENT LEASE TOTAL: ${passed} passed, 0 failed`);
}
