import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import {
  ContractError,
  validateEnvelope,
  classifyPrivacy,
  buildModelProjection,
} from "./contracts.mjs";
import { chooseModelTier } from "./router.mjs";
import { stateScope } from "./state-key.mjs";
import { fingerprintEnvelope, sameIdempotentEvent } from "./idempotency.mjs";
import { ModelExecutionError, runExplanationModel } from "./model-adapter.mjs";
import { OutputGuardError, assertSafeRecommendation } from "./output-guard.mjs";
import { augmentModelProjection, readEliLaneContext } from "./eli-client.mjs";

function failClosed(code, reason, extra = {}) {
  return {
    ok: false,
    code,
    fact: null,
    calculation: null,
    estimate: null,
    recommendation: "UNKNOWN",
    reason,
    ...extra,
  };
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
        created_at TEXT NOT NULL
      )
    `);
  }

  async getIdempotency(idempotencyKey) {
    const cursor = this.sql.exec(
      `SELECT idempotency_key, event_id, correlation_id, payload_fingerprint,
              authority_version, route_tier, recommendation, confidence, reason, created_at
         FROM idempotency_results
        WHERE idempotency_key = ?`,
      idempotencyKey,
    );
    return [...cursor][0] || null;
  }

  async putIdempotency(record) {
    this.sql.exec(
      `INSERT OR IGNORE INTO idempotency_results
        (idempotency_key, event_id, correlation_id, payload_fingerprint, authority_version,
         route_tier, recommendation, confidence, reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      record.idempotencyKey,
      record.eventId,
      record.correlationId,
      record.payloadFingerprint,
      record.authorityVersion || null,
      record.routeTier,
      record.recommendation,
      record.confidence,
      record.reason,
      record.createdAt,
    );
    return this.getIdempotency(record.idempotencyKey);
  }
}

export default class FreightLogicAgentService extends WorkerEntrypoint {
  async fetch() {
    return new Response("Not Found", {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  }

  async evaluate(envelope) {
    try {
      validateEnvelope(envelope);
    } catch (error) {
      if (error instanceof ContractError) {
        return failClosed(error.code, error.message);
      }
      return failClosed("INVALID_ENVELOPE", "Envelope validation failed");
    }

    const enabled = this.env.AGENT_ENABLED === "true";
    if (!enabled) {
      return failClosed("AGENT_DISABLED", "FEATURE_DISABLED", {
        fact: {
          eventId: envelope.id,
          type: envelope.type,
        },
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
        fact: {
          eventId: envelope.id,
          type: envelope.type,
          privacyClass,
        },
        calculation: envelope.canonicalSnapshot,
        estimate: null,
        recommendation: existing.recommendation,
        route: {
          tier: existing.route_tier,
          reason: existing.reason,
        },
        confidence: existing.confidence,
      };
    }

    let recommendation = "UNKNOWN";
    let reason = route.reason;

    if (route.tier === "small" || route.tier === "strong") {
      const eliContext = await readEliLaneContext(this.env, envelope);
      const projection = augmentModelProjection(buildModelProjection(envelope), eliContext);
      try {
        const result = await runExplanationModel(this.env, route.tier, projection);
        assertSafeRecommendation(result.recommendation, envelope.canonicalSnapshot);
        recommendation = result.recommendation;
      } catch (error) {
        if (error instanceof ModelExecutionError || error instanceof OutputGuardError) {
          return failClosed(error.code, error.message, {
            fact: {
              eventId: envelope.id,
              type: envelope.type,
              privacyClass,
            },
            calculation: envelope.canonicalSnapshot,
            route,
          });
        }
        return failClosed("MODEL_REQUEST_FAILED", "Workers AI request failed", {
          fact: {
            eventId: envelope.id,
            type: envelope.type,
            privacyClass,
          },
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
      reason,
      createdAt: new Date().toISOString(),
    });

    // A concurrent first-seen request may have won INSERT OR IGNORE after the
    // pre-insert read. Re-check identity against the row that actually exists.
    if (!sameIdempotentEvent(stored, envelope, payloadFingerprint)) {
      return failClosed("IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_EVENT");
    }

    return {
      ok: true,
      replayed: false,
      fact: {
        eventId: envelope.id,
        type: envelope.type,
        privacyClass,
      },
      calculation: envelope.canonicalSnapshot,
      estimate: null,
      recommendation: stored.recommendation,
      route: {
        tier: stored.route_tier,
        reason: stored.reason,
      },
      confidence: stored.confidence,
    };
  }
}
