import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { ContractError, validateEnvelope, classifyPrivacy, buildModelProjection } from "./contracts.mjs";
import { chooseModelTier } from "./router.mjs";
import { stateScope } from "./state-key.mjs";
import { fingerprintEnvelope, sameIdempotentEvent } from "./idempotency.mjs";
import { ModelExecutionError, runExplanationModel } from "./model-adapter.mjs";
import { OutputGuardError, assertSafeRecommendation } from "./output-guard.mjs";
import { augmentModelProjection, readEliLaneContext } from "./eli-client.mjs";

const DEFAULT_RESULT_RETENTION_DAYS = 7;
const MIN_RESULT_RETENTION_DAYS = 1;
const MAX_RESULT_RETENTION_DAYS = 30;
const CLAIM_LEASE_MS = 30000;

function failClosed(code, reason, extra = {}) {
  return { ok: false, code, fact: null, calculation: null, estimate: null, recommendation: "UNKNOWN", reason, ...extra };
}

function retentionDays(env) {
  const parsed = Number(env?.AGENT_RESULT_RETENTION_DAYS);
  if (!Number.isFinite(parsed)) return DEFAULT_RESULT_RETENTION_DAYS;
  return Math.min(MAX_RESULT_RETENTION_DAYS, Math.max(MIN_RESULT_RETENTION_DAYS, Math.trunc(parsed)));
}

function futureIso(ms) {
  return new Date(Date.now() + ms).toISOString();
}

async function fingerprintProjection(projection) {
  const bytes = new TextEncoder().encode(JSON.stringify(projection));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export class FreightLogicAgentState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS idempotency_results (
        idempotency_key TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        payload_fingerprint TEXT NOT NULL,
        authority_version TEXT,
        route_tier TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        confidence REAL NOT NULL,
        reason TEXT NOT NULL,
        model_id TEXT,
        projection_fingerprint TEXT,
        retention_until TEXT,
        created_at TEXT NOT NULL
      )
    `);
    this.ensureResultColumns();
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS idempotency_claims (
        idempotency_key TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        payload_fingerprint TEXT NOT NULL,
        claim_token TEXT NOT NULL,
        claimed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )
    `);
  }

  ensureResultColumns() {
    const columns = new Set([...this.sql.exec(`PRAGMA table_info(idempotency_results)`)].map((row) => row.name));
    for (const [name, type] of [
      ["model_id", "TEXT"],
      ["projection_fingerprint", "TEXT"],
      ["retention_until", "TEXT"],
    ]) {
      if (!columns.has(name)) this.sql.exec(`ALTER TABLE idempotency_results ADD COLUMN ${name} ${type}`);
    }
  }

  cleanup(now = new Date().toISOString()) {
    this.sql.exec(`DELETE FROM idempotency_claims WHERE expires_at <= ?`, now);
    this.sql.exec(`DELETE FROM idempotency_results WHERE retention_until IS NOT NULL AND retention_until <= ?`, now);
  }

  async getIdempotency(idempotencyKey) {
    this.cleanup();
    const cursor = this.sql.exec(
      `SELECT idempotency_key, event_id, correlation_id, payload_fingerprint,
              authority_version, route_tier, recommendation, confidence, reason,
              model_id, projection_fingerprint, retention_until, created_at
         FROM idempotency_results WHERE idempotency_key = ?`,
      idempotencyKey,
    );
    return [...cursor][0] || null;
  }

  async claimIdempotency(record) {
    const now = new Date().toISOString();
    this.cleanup(now);
    this.sql.exec(
      `INSERT OR IGNORE INTO idempotency_claims
        (idempotency_key, event_id, payload_fingerprint, claim_token, claimed_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      record.idempotencyKey,
      record.eventId,
      record.payloadFingerprint,
      record.claimToken,
      now,
      record.expiresAt,
    );
    const row = [...this.sql.exec(
      `SELECT idempotency_key, event_id, payload_fingerprint, claim_token, claimed_at, expires_at
         FROM idempotency_claims WHERE idempotency_key = ?`,
      record.idempotencyKey,
    )][0] || null;
    return { acquired: row?.claim_token === record.claimToken, claim: row };
  }

  async releaseIdempotencyClaim(idempotencyKey, claimToken) {
    this.sql.exec(`DELETE FROM idempotency_claims WHERE idempotency_key = ? AND claim_token = ?`, idempotencyKey, claimToken);
    return { ok: true };
  }

  async putIdempotency(record) {
    this.cleanup();
    this.sql.exec(
      `INSERT OR IGNORE INTO idempotency_results
        (idempotency_key, event_id, correlation_id, payload_fingerprint, authority_version,
         route_tier, recommendation, confidence, reason, model_id, projection_fingerprint,
         retention_until, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      record.idempotencyKey,
      record.eventId,
      record.correlationId,
      record.payloadFingerprint,
      record.authorityVersion || null,
      record.routeTier,
      record.recommendation,
      record.confidence,
      record.reason,
      record.modelId || null,
      record.projectionFingerprint || null,
      record.retentionUntil,
      record.createdAt,
    );
    return this.getIdempotency(record.idempotencyKey);
  }
}

export default class FreightLogicAgentService extends WorkerEntrypoint {
  async fetch() {
    return new Response("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  async evaluate(envelope) {
    try {
      validateEnvelope(envelope);
    } catch (error) {
      if (error instanceof ContractError) return failClosed(error.code, error.message);
      return failClosed("INVALID_ENVELOPE", "Envelope validation failed");
    }

    const enabled = this.env.AGENT_ENABLED === "true";
    if (!enabled) {
      return failClosed("AGENT_DISABLED", "FEATURE_DISABLED", {
        fact: { eventId: envelope.id, type: envelope.type },
        calculation: envelope.canonicalSnapshot,
      });
    }

    const privacyClass = classifyPrivacy(envelope);
    const route = chooseModelTier(envelope, { enabled: true });
    const payloadFingerprint = await fingerprintEnvelope(envelope);
    const scope = stateScope(envelope);
    const state = this.env.AGENT_STATE.getByName(scope.objectName);
    const existing = await state.getIdempotency(scope.idempotencyKey);

    if (existing) {
      if (!sameIdempotentEvent(existing, envelope, payloadFingerprint)) {
        return failClosed("IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_EVENT");
      }
      return {
        ok: true,
        replayed: true,
        fact: { eventId: envelope.id, type: envelope.type, privacyClass },
        calculation: envelope.canonicalSnapshot,
        estimate: null,
        recommendation: existing.recommendation,
        route: { tier: existing.route_tier, reason: existing.reason },
        confidence: existing.confidence,
      };
    }

    const claimToken = crypto.randomUUID();
    const claim = await state.claimIdempotency({
      idempotencyKey: scope.idempotencyKey,
      eventId: envelope.id,
      payloadFingerprint,
      claimToken,
      expiresAt: futureIso(CLAIM_LEASE_MS),
    });
    if (!claim.acquired) {
      const sameClaim = claim.claim?.event_id === envelope.id
        && claim.claim?.payload_fingerprint === payloadFingerprint;
      return failClosed(
        sameClaim ? "IDEMPOTENCY_IN_FLIGHT" : "IDEMPOTENCY_CONFLICT",
        sameClaim ? "EQUIVALENT_REQUEST_ALREADY_IN_FLIGHT" : "IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_EVENT",
      );
    }

    try {
      let recommendation = "UNKNOWN";
      let modelId = null;
      let projectionFingerprint = null;

      if (route.tier === "small" || route.tier === "strong") {
        const baseProjection = buildModelProjection(envelope);
        const eliContext = await readEliLaneContext(this.env, baseProjection);
        const projection = augmentModelProjection(baseProjection, eliContext);
        projectionFingerprint = await fingerprintProjection(projection);
        try {
          const result = await runExplanationModel(this.env, route.tier, projection);
          assertSafeRecommendation(result.recommendation, envelope.canonicalSnapshot);
          recommendation = result.recommendation;
          modelId = result.model;
        } catch (error) {
          if (error instanceof ModelExecutionError || error instanceof OutputGuardError) {
            return failClosed(error.code, error.message, {
              fact: { eventId: envelope.id, type: envelope.type, privacyClass },
              calculation: envelope.canonicalSnapshot,
              route,
            });
          }
          return failClosed("MODEL_REQUEST_FAILED", "Workers AI request failed", {
            fact: { eventId: envelope.id, type: envelope.type, privacyClass },
            calculation: envelope.canonicalSnapshot,
            route,
          });
        }
      }

      const stored = await state.putIdempotency({
        idempotencyKey: scope.idempotencyKey,
        eventId: envelope.id,
        correlationId: envelope.correlationId,
        payloadFingerprint,
        authorityVersion: envelope.canonicalSnapshot.authorityVersion || null,
        routeTier: route.tier,
        recommendation,
        confidence: envelope.confidence,
        reason: route.reason,
        modelId,
        projectionFingerprint,
        retentionUntil: futureIso(retentionDays(this.env) * 86400000),
        createdAt: new Date().toISOString(),
      });

      if (!sameIdempotentEvent(stored, envelope, payloadFingerprint)) {
        return failClosed("IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_EVENT");
      }

      return {
        ok: true,
        replayed: false,
        fact: { eventId: envelope.id, type: envelope.type, privacyClass },
        calculation: envelope.canonicalSnapshot,
        estimate: null,
        recommendation: stored.recommendation,
        route: { tier: stored.route_tier, reason: stored.reason },
        confidence: stored.confidence,
      };
    } finally {
      await state.releaseIdempotencyClaim(scope.idempotencyKey, claimToken);
    }
  }
}
