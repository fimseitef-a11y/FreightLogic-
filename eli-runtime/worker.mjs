import { WorkerEntrypoint } from 'cloudflare:workers';
import { createPrivateApi } from './api.mjs';
import { consumeDeadLetterBatch } from './queue.mjs';
import { journalFailure } from './storage.mjs';
import { RUN_INGESTION_MESSAGE_TYPE, processEvidenceBatch, resolveMarketInDb, triggeredIngestion } from './pipeline.mjs';

function createD1Repository(db) {
  if (!db || typeof db.prepare !== 'function') return null;

  return {
    async resolveMarket(value) {
      return resolveMarketInDb(db, value);
    },

    async getLaneRow(originMarket, destinationMarket) {
      return db.prepare(`SELECT * FROM lane_read_model
        WHERE origin_market = ? AND destination_market = ?
        LIMIT 1`).bind(originMarket, destinationMarket).first();
    },

    async getMarketRows(market) {
      const result = await db.prepare(`SELECT * FROM lane_read_model
        WHERE origin_market = ? OR destination_market = ?
        ORDER BY origin_market, destination_market`).bind(market, market).all();
      return result?.results ?? [];
    },

    async getHealthSnapshot() {
      let newestSuccessfulRunAt = null;
      let modelVersions = null;
      try {
        const run = await db.prepare(`SELECT structural_version, expedite_version, confidence_version, created_at
          FROM model_runs
          ORDER BY created_at DESC
          LIMIT 1`).first();
        if (run) {
          newestSuccessfulRunAt = run.created_at ?? null;
          modelVersions = {
            structural: run.structural_version ?? null,
            expedite: run.expedite_version ?? null,
            confidence: run.confidence_version ?? null,
          };
        }
      } catch {
        // Health remains fail-closed and minimal before migrations/provisioning exist.
      }
      let lastIngest = null;
      let dlqJournaled = null;
      try {
        lastIngest = await db.prepare(`SELECT status, started_at, finished_at, counts_json, error
          FROM ingest_runs ORDER BY started_at DESC LIMIT 1`).first();
        const failures = await db.prepare('SELECT COUNT(*) AS n FROM ingest_failures').first();
        dlqJournaled = Number.isFinite(failures?.n) ? failures.n : null;
      } catch {
        // Ingestion tables absent until migration 0002 is applied.
      }
      let counts = {};
      try { counts = JSON.parse(lastIngest?.counts_json ?? '{}'); } catch { counts = {}; }
      return {
        schemaVersion: '1',
        serviceVersion: 'eli-v1',
        modelVersions,
        queue: lastIngest
          ? { state: 'CONFIGURED', lastRunStatus: lastIngest.status, lastRunAt: lastIngest.finished_at ?? lastIngest.started_at, lastRunError: lastIngest.error ?? null }
          : { state: 'NO_RUN_YET' },
        dlq: { state: dlqJournaled === null ? 'UNKNOWN' : 'CONFIGURED', journaledFailures: dlqJournaled },
        sourceHealthCounts: {
          aliasesVerified: counts.aliasesVerified ?? null,
          governedLanes: counts.governedLanes ?? null,
          loadHistoryRecords: counts.loadHistoryRecords ?? null,
          evidenceMarketUnresolved: counts.evidenceMarketUnresolved ?? null,
        },
        newestSuccessfulRunAt,
      };
    },
  };
}

export default class EliRuntime extends WorkerEntrypoint {
  #api() {
    if (this.env?.ELI_ENABLED !== 'true') return null;
    const repository = createD1Repository(this.env?.ELI_DB);
    return repository ? createPrivateApi(repository) : null;
  }

  #db() {
    if (this.env?.ELI_ENABLED !== 'true') return null;
    const db = this.env?.ELI_DB;
    return db && typeof db.prepare === 'function' ? db : null;
  }

  // ELI is reached only through the private Service Binding (RPC); it has no
  // HTTP handler by design. queue() is its registered event handler.

  // Queue consumer for the primary queue and its DLQ (wrangler.jsonc).
  // Design amendment 1: nothing is acknowledged unless it is durably handled.
  //  - Primary: the ingestion pipeline is not wired yet, so every message is
  //    retried (and reaches the DLQ after max_retries) instead of being lost.
  //  - DLQ: terminal failures are journaled to D1 before ack; while ELI is
  //    dark or has no D1, they are retried rather than dropped.
  async queue(batch) {
    const isDeadLetter = typeof batch?.queue === 'string' && batch.queue.endsWith('-dlq');
    const db = this.#db();

    // Dark or D1-less: nothing is acknowledged (design amendment 1).
    if (!db) {
      batch.retryAll();
      return;
    }

    if (!isDeadLetter) {
      const messages = Array.isArray(batch?.messages) ? batch.messages : [];
      const control = messages.filter((m) => m?.body?.type === RUN_INGESTION_MESSAGE_TYPE);
      const evidence = messages.filter((m) => m?.body?.type !== RUN_INGESTION_MESSAGE_TYPE);
      for (const message of control) {
        try {
          await triggeredIngestion(this.env, 'queue');
          message.ack();
        } catch {
          message.retry();
        }
      }
      if (evidence.length > 0) {
        try {
          await processEvidenceBatch({ ...batch, messages: evidence }, this.env);
        } catch {
          for (const message of evidence) message.retry();
        }
      }
      return;
    }

    try {
      await consumeDeadLetterBatch(batch, {
        journalFailure: async (failure) => {
          const result = await journalFailure(db, failure);
          if (result && result.success === false) throw new Error('DLQ journal write was not confirmed');
          return result;
        },
        now: () => new Date().toISOString(),
      });
    } catch {
      batch.retryAll();
    }
  }

  // Ingestion producer (cron in wrangler.jsonc). Inert unless ELI is enabled
  // with D1, its queue and an operator-supplied read-only AIRTABLE_TOKEN.
  async scheduled(controller, env, ctx) {
    const runtimeEnv = env ?? this.env;
    const work = triggeredIngestion(runtimeEnv, `cron:${controller?.cron ?? 'unknown'}`).then((result) => {
      console.log(JSON.stringify({ eliIngestion: { status: result.status, reason: result.reason ?? null, runId: result.runId ?? null, counts: result.counts ?? null, error: result.error ?? null } }));
      return result;
    });
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(work);
    else if (this.ctx && typeof this.ctx.waitUntil === 'function') this.ctx.waitUntil(work);
    return work;
  }

  async getLaneIntelligence(input) {
    const api = this.#api();
    if (!api) return { status: 'UNAVAILABLE', reason: 'ELI_DISABLED_OR_DB_UNAVAILABLE' };
    return api.getLaneIntelligence(input);
  }

  async getMarketIntelligence(input) {
    const api = this.#api();
    if (!api) return { status: 'UNAVAILABLE', reason: 'ELI_DISABLED_OR_DB_UNAVAILABLE' };
    return api.getMarketIntelligence(input);
  }

  async health() {
    const api = this.#api();
    if (!api) {
      return {
        serviceVersion: 'eli-v1',
        schemaVersion: '1',
        status: 'UNAVAILABLE',
        reason: 'ELI_DISABLED_OR_DB_UNAVAILABLE',
      };
    }
    return api.health();
  }
}
