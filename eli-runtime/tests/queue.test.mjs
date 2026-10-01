import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildChangeSets,
  consumeDeadLetterBatch,
  consumePrimaryBatch,
} from '../queue.mjs';

function makeMessage(body, { id = 'msg-1', attempts = 1 } = {}) {
  const calls = [];
  return {
    id,
    body,
    attempts,
    calls,
    ack() { calls.push('ack'); },
    retry() { calls.push('retry'); },
  };
}

test('buildChangeSets batches by snapshot and deduplicates affected keys deterministically', () => {
  const result = buildChangeSets([
    { id: 'm2', body: { snapshotFingerprint: 'snap-b', affectedKeys: ['lane:ATL>BNA'] } },
    { id: 'm1', body: { snapshotFingerprint: 'snap-a', affectedKeys: ['market:ATL', 'lane:ATL>DTW', 'market:ATL'] } },
    { id: 'm3', body: { snapshotFingerprint: 'snap-a', affectedKeys: ['lane:DTW>ATL'] } },
  ]);

  assert.deepEqual(result, [
    {
      snapshotFingerprint: 'snap-a',
      affectedKeys: ['lane:ATL>DTW', 'lane:DTW>ATL', 'market:ATL'],
      messageIds: ['m1', 'm3'],
    },
    {
      snapshotFingerprint: 'snap-b',
      affectedKeys: ['lane:ATL>BNA'],
      messageIds: ['m2'],
    },
  ]);
});

test('primary consumer skips replayed receipts and acks without running side effects', async () => {
  const message = makeMessage({
    type: 'NORMALIZE_EVIDENCE',
    idempotencyKey: 'NORMALIZE_EVIDENCE:ev-001',
    evidenceId: 'ev-001',
  });
  let processed = 0;
  let recorded = 0;

  await consumePrimaryBatch({ messages: [message] }, {
    hasReceipt: async () => true,
    processMessage: async () => { processed += 1; },
    recordReceipt: async () => { recorded += 1; },
    now: () => '2026-10-01T03:30:00Z',
  });

  assert.equal(processed, 0);
  assert.equal(recorded, 0);
  assert.deepEqual(message.calls, ['ack']);
});

test('primary consumer records receipt before ack and retries failed work', async () => {
  const ok = makeMessage({
    type: 'NORMALIZE_EVIDENCE',
    idempotencyKey: 'NORMALIZE_EVIDENCE:ev-002',
    evidenceId: 'ev-002',
  }, { id: 'ok' });
  const bad = makeMessage({
    type: 'NORMALIZE_EVIDENCE',
    idempotencyKey: 'NORMALIZE_EVIDENCE:ev-003',
    evidenceId: 'ev-003',
  }, { id: 'bad' });
  const order = [];

  await consumePrimaryBatch({ messages: [ok, bad] }, {
    hasReceipt: async () => false,
    processMessage: async (body) => {
      order.push(`process:${body.evidenceId}`);
      if (body.evidenceId === 'ev-003') throw new Error('boom');
    },
    recordReceipt: async (receipt) => { order.push(`receipt:${receipt.evidenceId}`); },
    now: () => '2026-10-01T03:31:00Z',
  });

  assert.deepEqual(order, [
    'process:ev-002',
    'receipt:ev-002',
    'process:ev-003',
  ]);
  assert.deepEqual(ok.calls, ['ack']);
  assert.deepEqual(bad.calls, ['retry']);
});

test('DLQ consumer journals terminal failure before ack', async () => {
  const message = makeMessage({
    type: 'INGEST_SOURCE_SNAPSHOT',
    idempotencyKey: 'INGEST_SOURCE_SNAPSHOT:faf6-2022-v1',
    sourceId: 'faf6',
    snapshotId: 'faf6-2022-v1',
    adapterVersion: 'v1',
    payloadHash: 'sha256:abc',
    payloadRef: 'snapshot:faf6-2022-v1',
  }, { attempts: 5 });
  const order = [];

  await consumeDeadLetterBatch({ messages: [message] }, {
    journalFailure: async (failure) => {
      order.push('journal');
      assert.equal(failure.failureId, 'dlq:INGEST_SOURCE_SNAPSHOT:faf6-2022-v1');
      assert.equal(failure.attemptCount, 5);
    },
    now: () => '2026-10-01T03:32:00Z',
  });
  order.push(...message.calls);

  assert.deepEqual(order, ['journal', 'ack']);
});

test('DLQ journal failure does not ack the message', async () => {
  const message = makeMessage({
    type: 'INGEST_OBSERVATION',
    idempotencyKey: 'INGEST_OBSERVATION:ev-004',
  }, { attempts: 5 });

  await assert.rejects(
    consumeDeadLetterBatch({ messages: [message] }, {
      journalFailure: async () => { throw new Error('db unavailable'); },
      now: () => '2026-10-01T03:33:00Z',
    }),
    /db unavailable/,
  );

  assert.deepEqual(message.calls, []);
});

test('wrangler config uses bounded retries and a dead-letter queue without enabling ELI', async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const config = JSON.parse(await readFile(resolve(here, '../wrangler.jsonc'), 'utf8'));

  assert.equal(config.vars.ELI_ENABLED, 'false');
  assert.ok(config.queues.producers.some((producer) => producer.binding === 'ELI_QUEUE'));
  const primary = config.queues.consumers.find((consumer) => consumer.queue === 'freightlogic-eli-runtime-v1');
  assert.equal(primary.max_retries, 5);
  assert.equal(primary.dead_letter_queue, 'freightlogic-eli-runtime-v1-dlq');
  assert.ok(config.queues.consumers.some((consumer) => consumer.queue === 'freightlogic-eli-runtime-v1-dlq'));
});
