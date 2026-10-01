import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Executes eli-runtime/worker.mjs with only the `cloudflare:workers` base
// class stubbed, so the deployable entrypoint's handlers are proven by
// execution. Cloudflare rejects an upload whose default export registers no
// event handler, and a queue consumer needs a queue() handler. ELI stays
// RPC-only: no fetch().

const STUB = 'data:text/javascript,' + encodeURIComponent(
  'export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }\n',
);

async function loadWorker() {
  const base = new URL('../', import.meta.url);
  const source = await readFile(new URL('worker.mjs', base), 'utf8');
  const rewritten = source
    .replace(/from\s+['"]cloudflare:workers['"]/g, `from ${JSON.stringify(STUB)}`)
    .replace(/from\s+['"]\.\/([\w.-]+\.mjs)['"]/g, (_, file) => `from ${JSON.stringify(new URL(file, base).href)}`);
  return (await import('data:text/javascript;base64,' + Buffer.from(rewritten).toString('base64'))).default;
}

function fakeBatch(queue, bodies) {
  const state = { acked: 0, retried: 0, retryAll: 0, ackAll: 0 };
  return {
    state,
    batch: {
      queue,
      messages: bodies.map((body, i) => ({
        id: `m${i}`,
        attempts: 1,
        body,
        ack() { state.acked += 1; },
        retry() { state.retried += 1; },
      })),
      retryAll() { state.retryAll += 1; },
      ackAll() { state.ackAll += 1; },
    },
  };
}

const MSG = { idempotencyKey: 'k1', type: 'evidence', snapshotFingerprint: 's1' };

test('W01 ELI entrypoint registers a queue handler so the upload is accepted', async () => {
  const Worker = await loadWorker();
  assert.equal(typeof Worker.prototype.queue, 'function');
});

test('W02 ELI keeps no HTTP handler (RPC-only private surface)', async () => {
  const Worker = await loadWorker();
  assert.equal(Object.hasOwn(Worker.prototype, 'fetch'), false);
});

test('W03 dark ELI never acknowledges (loses) primary queue messages', async () => {
  const Worker = await loadWorker();
  const { batch, state } = fakeBatch('freightlogic-eli-runtime-v1', [MSG, MSG]);
  await new Worker({}, { ELI_ENABLED: 'false' }).queue(batch);
  assert.equal(state.acked + state.ackAll, 0);
  assert.equal(state.retryAll, 1);
});

test('W04 dark ELI never acknowledges DLQ messages it cannot journal', async () => {
  const Worker = await loadWorker();
  const { batch, state } = fakeBatch('freightlogic-eli-runtime-v1-dlq', [MSG]);
  await new Worker({}, { ELI_ENABLED: 'false' }).queue(batch);
  assert.equal(state.acked + state.ackAll, 0);
  assert.equal(state.retryAll, 1);
});

test('W05 enabled ELI never acknowledges a primary message it cannot store', async () => {
  const Worker = await loadWorker();
  const { batch, state } = fakeBatch('freightlogic-eli-runtime-v1', [MSG]);
  const db = { prepare() { throw new Error('D1 unavailable'); } };
  await new Worker({}, { ELI_ENABLED: 'true', ELI_DB: db }).queue(batch);
  assert.equal(state.acked + state.ackAll, 0);
  assert.ok(state.retried + state.retryAll >= 1);
});

test('W06 enabled ELI with D1 journals DLQ failures durably before acknowledging', async () => {
  const Worker = await loadWorker();
  const writes = [];
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() { writes.push({ sql, args }); return { success: true, meta: { changes: 1 } }; },
            async first() { return writes.length ? { failure_id: 'dlq:k1' } : null; },
            async all() { return { results: [] }; },
          };
        },
      };
    },
  };
  const { batch, state } = fakeBatch('freightlogic-eli-runtime-v1-dlq', [MSG]);
  await new Worker({}, { ELI_ENABLED: 'true', ELI_DB: db }).queue(batch);
  assert.ok(writes.some((w) => /failure/i.test(w.sql)), 'DLQ failure was not journaled');
  assert.equal(state.acked, 1);
});

test('W07 a queue "run ingestion" message triggers ingestion and is acknowledged', async () => {
  const Worker = await loadWorker();
  const statements = [];
  const db = {
    prepare(sql) {
      const stmt = { bind: () => stmt, run: async () => { statements.push(sql); return { success: true }; }, first: async () => null, all: async () => ({ results: [] }) };
      return stmt;
    },
  };
  const { batch, state } = fakeBatch('freightlogic-eli-runtime-v1', [{ type: 'eli_run_ingestion' }]);
  await new Worker({}, { ELI_ENABLED: 'true', ELI_DB: db }).queue(batch);
  assert.equal(state.acked, 1);
  assert.equal(state.retried + state.retryAll, 0);
  assert.ok(statements.some((sql) => /INSERT INTO ingest_runs/.test(sql)), 'trigger was recorded');
});
