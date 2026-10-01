import { WorkerEntrypoint } from 'cloudflare:workers';
import { createPrivateApi } from './api.mjs';
import { consumeDeadLetterBatch } from './queue.mjs';
import { journalFailure } from './storage.mjs';

function createD1Repository(db) {
  if (!db || typeof db.prepare !== 'function') return null;

  return {
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
      return {
        schemaVersion: '1',
        serviceVersion: 'eli-v1',
        modelVersions,
        queue: { state: 'NOT_CONFIGURED' },
        dlq: { state: 'NOT_CONFIGURED' },
        sourceHealthCounts: { unavailable: 0 },
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

    if (!isDeadLetter || !db) {
      batch.retryAll();
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
