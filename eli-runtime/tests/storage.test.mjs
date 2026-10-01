import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  appendRawEvidence,
  journalFailure,
  recordReceipt,
} from '../storage.mjs';

function makeDb() {
  const calls = [];
  return {
    calls,
    prepare(sql) {
      const call = { sql, values: null };
      calls.push(call);
      return {
        bind(...values) {
          call.values = values;
          return this;
        },
        async run() {
          return { success: true, meta: { changes: 1 } };
        },
      };
    },
  };
}

test('appendRawEvidence inserts immutable evidence and never updates an existing row', async () => {
  const db = makeDb();
  const evidence = {
    evidenceId: 'ev-001',
    sourceId: 'dispatchland',
    adapterVersion: 'v1',
    sourceRecordId: '1242331',
    observedAt: '2026-09-30T20:00:00Z',
    retrievedAt: '2026-09-30T20:00:01Z',
    sourcePostedAt: null,
    payloadJson: '{"kind":"notification"}',
    payloadHash: 'sha256:abc',
    sourceRef: 'dispatchland:1242331',
    authorizationClass: 'OPERATOR_PRIVATE',
    scopeFingerprint: 'scope:operator',
    parentEvidenceId: null,
    supersedesEvidenceId: null,
    ingestRunId: 'run-001',
  };

  await appendRawEvidence(db, evidence);

  assert.equal(db.calls.length, 1);
  assert.match(db.calls[0].sql, /^INSERT\s+INTO\s+raw_evidence/i);
  assert.doesNotMatch(db.calls[0].sql, /\bUPDATE\b/i);
  assert.deepEqual(db.calls[0].values.slice(0, 3), ['ev-001', 'dispatchland', 'v1']);
});

test('journalFailure durably inserts terminal failure metadata', async () => {
  const db = makeDb();
  const failure = {
    failureId: 'fail-001',
    messageIdentity: 'INGEST_SOURCE_SNAPSHOT:run-001',
    sourceId: 'faf6',
    snapshotId: 'faf6-2022-v1',
    adapterVersion: 'v1',
    attemptCount: 5,
    failureClass: 'adapter_error',
    sanitizedError: 'download unavailable',
    firstFailedAt: '2026-09-30T20:00:00Z',
    lastFailedAt: '2026-09-30T20:05:00Z',
    payloadHash: 'sha256:def',
    payloadRef: 'snapshot:faf6-2022-v1',
  };

  await journalFailure(db, failure);

  assert.equal(db.calls.length, 1);
  assert.match(db.calls[0].sql, /^INSERT\s+INTO\s+ingest_failures/i);
  assert.equal(db.calls[0].values[0], 'fail-001');
  assert.equal(db.calls[0].values[5], 5);
});

test('recordReceipt inserts an idempotency receipt instead of mutating evidence', async () => {
  const db = makeDb();

  await recordReceipt(db, {
    idempotencyKey: 'NORMALIZE_EVIDENCE:ev-001',
    messageType: 'NORMALIZE_EVIDENCE',
    evidenceId: 'ev-001',
    processedAt: '2026-09-30T20:06:00Z',
  });

  assert.equal(db.calls.length, 1);
  assert.match(db.calls[0].sql, /^INSERT\s+INTO\s+ingest_receipts/i);
  assert.doesNotMatch(db.calls[0].sql, /\bUPDATE\b/i);
  assert.match(
    db.calls[0].sql,
    /ON\s+CONFLICT\s*\(\s*idempotency_key\s*\)\s+DO\s+NOTHING/i,
    'duplicate delivery must replay safely instead of failing the unique key',
  );
});

test('initial migration creates runtime tables and blocks raw evidence update/delete', async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const migration = await readFile(resolve(here, '../migrations/0001_init.sql'), 'utf8');

  for (const table of ['raw_evidence', 'ingest_receipts', 'ingest_failures', 'lane_read_model', 'model_runs']) {
    assert.match(migration, new RegExp(`CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${table}`, 'i'));
  }

  assert.match(migration, /BEFORE\s+UPDATE\s+ON\s+raw_evidence/i);
  assert.match(migration, /BEFORE\s+DELETE\s+ON\s+raw_evidence/i);
  assert.match(migration, /RAISE\s*\(\s*ABORT/i);
});
