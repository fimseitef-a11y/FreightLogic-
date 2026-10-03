import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { appendRawEvidence, claimReceipt, completeReceipt } from '../storage.mjs';
import { runIngestion, processEvidenceBatch, EVIDENCE_MESSAGE_TYPE } from '../pipeline.mjs';

async function d1() {
  let beforeRun = () => {};
  const db = new DatabaseSync(':memory:');
  for (const file of ['0001_init.sql', '0002_ingestion.sql', '0003_message_leases.sql']) {
    db.exec(await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8'));
  }
  const statement = (sql, args = []) => ({
    bind: (...next) => statement(sql, next),
    async first() { return db.prepare(sql).get(...args) ?? null; },
    async all() { return { results: db.prepare(sql).all(...args) }; },
    async run() { return this.runSync(); },
    runSync() { beforeRun(sql); const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    raw: db,
    setBeforeRun(fn) { beforeRun = fn; },
    prepare: (sql) => statement(sql),
    async batch(statements) {
      db.exec('BEGIN');
      try {
        const out = statements.map((s) => s.runSync());
        db.exec('COMMIT');
        return out;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
  };
}

function version(id, retrievedAt, statusKey = 'BOARD_LISTING') {
  return {
    evidence: {
      evidenceId: id,
      sourceId: 'airtable:load-history',
      adapterVersion: 'airtable-load-history-v1',
      sourceRecordId: 'rec1',
      observedAt: '2026-10-01',
      retrievedAt,
      sourcePostedAt: null,
      payloadJson: JSON.stringify({ id, statusKey }),
      payloadHash: `hash:${id}`,
      sourceRef: 'airtable:rec1',
      authorizationClass: 'OPERATOR_PRIVATE',
      scopeFingerprint: 'airtable:load-history',
      parentEvidenceId: null,
      supersedesEvidenceId: null,
      ingestRunId: `run:${retrievedAt}`,
    },
    index: {
      evidenceId: id,
      sourceRecordId: 'rec1',
      laneKey: 'MKT-ATL|MKT-DTW',
      originMarket: 'MKT-ATL',
      destinationMarket: 'MKT-DTW',
      statusKey,
      duplicateClass: 'NONE_KNOWN',
      observedAt: '2026-10-01',
    },
  };
}

const NOW = '2026-10-02T12:00:00.000Z';
async function receiptDb() {
  const db = await d1();
  // Completion receipts reference immutable evidence through the real FK.
  await appendRawEvidence(db, version('ev:audit', NOW).evidence);
  return db;
}
function claim(token, time = NOW) {
  return { idempotencyKey: 'receipt:audit', messageType: EVIDENCE_MESSAGE_TYPE,
    evidenceId: 'ev:audit', leaseToken: token, claimedAt: time,
    leaseExpiresAt: new Date(Date.parse(time) + 30000).toISOString(), attemptHint: 1 };
}
function completion(token, time = NOW) {
  return { idempotencyKey: 'receipt:audit', messageType: EVIDENCE_MESSAGE_TYPE,
    evidenceId: 'ev:audit', leaseToken: token, processedAt: time, attemptCount: 1 };
}

test('audit: stale receipt owner cannot complete or mutate its successor; legitimate completion replays', async () => {
  const db = await receiptDb();
  try {
    assert.equal((await claimReceipt(db, claim('A'))).status, 'ACQUIRED');
    const later = '2026-10-02T12:01:00.000Z';
    assert.equal((await claimReceipt(db, claim('B', later))).status, 'ACQUIRED');
    await assert.rejects(completeReceipt(db, completion('A', later)), /lost or expired/);
    assert.equal(db.raw.prepare('SELECT COUNT(*) AS n FROM ingest_receipts').get().n, 0);
    assert.equal(db.raw.prepare('SELECT lease_token FROM ingest_message_state').get().lease_token, 'B');
    assert.equal((await completeReceipt(db, completion('B', later))).status, 'COMPLETE');
    const before = db.raw.prepare('SELECT * FROM ingest_receipts').get();
    assert.equal((await completeReceipt(db, completion('B', later))).status, 'COMPLETE');
    assert.deepEqual(db.raw.prepare('SELECT * FROM ingest_receipts').get(), before);
    assert.equal(db.raw.prepare('SELECT COUNT(*) AS n FROM ingest_receipts').get().n, 1);
    await assert.rejects(completeReceipt(db, completion('A', later)), /lost or expired/);
  } finally { db.raw.close(); }
});

test('audit: expired receipt lease alone rejects completion without creating an orphan receipt', async () => {
  const db = await receiptDb();
  try {
    await claimReceipt(db, claim('A'));
    await assert.rejects(completeReceipt(db, completion('A', '2026-10-02T12:01:00.000Z')), /lost or expired/);
    assert.equal(db.raw.prepare('SELECT COUNT(*) AS n FROM ingest_receipts').get().n, 0);
    assert.equal(db.raw.prepare('SELECT state FROM ingest_message_state').get().state, 'PENDING');
  } finally { db.raw.close(); }
});

test('audit: a failed receipt transaction rolls back state and can be retried by its owner', async () => {
  const db = await receiptDb();
  try {
    await claimReceipt(db, claim('A'));
    db.setBeforeRun(sql => { if (/^INSERT INTO ingest_receipts/.test(sql)) throw new Error('injected receipt insert failure'); });
    await assert.rejects(completeReceipt(db, completion('A')), /injected receipt/);
    assert.equal(db.raw.prepare('SELECT COUNT(*) AS n FROM ingest_receipts').get().n, 0);
    const state = db.raw.prepare('SELECT state, lease_token FROM ingest_message_state').get();
    assert.equal(state.state, 'PENDING');
    assert.equal(state.lease_token, 'A');
    db.setBeforeRun(() => {});
    assert.equal((await completeReceipt(db, completion('A'))).status, 'COMPLETE');
  } finally { db.raw.close(); }
});

test('audit: route-correction materialization failure retries before ack and repairs both lanes', async () => {
  const db = await d1();
  try {
    // Seed real governance/model-run tables through the shipped ingestion path.
    const tables = {
      tblp0W75s9pqmrDmA: [],
      tblKD555nilZey3IQ: [
        { id: 'lane:old', fields: { fldIgOqICazHGCKOO: 'PILOT-ATL-DTW', fldsd4aK1WxerkJ8G: 'MKT-ATL', fldAyt9qI2ZDF80QS: 'MKT-DTW', fldgV0MZnbBpVlUOH: 'Pilot Candidate' } },
        { id: 'lane:new', fields: { fldIgOqICazHGCKOO: 'PILOT-ATL-BNA', fldsd4aK1WxerkJ8G: 'MKT-ATL', fldAyt9qI2ZDF80QS: 'MKT-BNA', fldgV0MZnbBpVlUOH: 'Pilot Candidate' } },
      ],
      tbl6Wof9SlTVotCEa: [],
    };
    const env = { ELI_ENABLED: 'true', ELI_DB: db, ELI_QUEUE: { async sendBatch() {} },
      AIRTABLE_TOKEN: 'test-only-audit', AIRTABLE_BASE_ID: 'appTestAudit12345' };
    const seeded = await runIngestion(env, {
      now: () => NOW, minIntervalMs: 0,
      fetchImpl: async url => {
        const table = new URL(url).pathname.split('/').at(-1);
        return new Response(JSON.stringify({ records: tables[table] ?? [] }), { status: 200 });
      },
    });
    assert.equal(seeded.status, 'OK');
    function msg(body) {
      const calls = [];
      return { body, calls, attempts: 1, ack() { calls.push('ack'); }, retry() { calls.push('retry'); } };
    }
    const old = version('ev:old', '2026-10-02T10:00:00.000Z', 'COMPLETED');
    const first = msg({ type: EVIDENCE_MESSAGE_TYPE, idempotencyKey: 'ev:old', evidenceId: 'ev:old', ...old });
    await processEvidenceBatch({ messages: [first] }, env, { now: () => NOW });
    assert.deepEqual(first.calls, ['ack']);
    const oldLane = () => db.raw.prepare("SELECT evidence_counts_json FROM lane_read_model WHERE lane_key = 'MKT-ATL|MKT-DTW'").get();
    assert.equal(JSON.parse(oldLane().evidence_counts_json).OPERATOR_COMPLETED, 1);

    const next = version('ev:new', '2026-10-02T11:00:00.000Z', 'COMPLETED');
    next.index.laneKey = 'MKT-ATL|MKT-BNA';
    next.index.destinationMarket = 'MKT-BNA';
    const body = { type: EVIDENCE_MESSAGE_TYPE, idempotencyKey: 'ev:new', evidenceId: 'ev:new', ...next };
    let injected = false;
    db.setBeforeRun(sql => {
      if (!injected && /^INSERT INTO lane_read_model/.test(sql)) {
        injected = true; throw new Error('injected lane upsert failure');
      }
    });
    const failed = msg(body);
    await processEvidenceBatch({ messages: [failed] }, env, { now: () => NOW });
    assert.equal(injected, true);
    assert.deepEqual(failed.calls, ['retry']);
    assert.equal(db.raw.prepare("SELECT COUNT(*) AS n FROM ingest_receipts WHERE idempotency_key = 'ev:new'").get().n, 0);
    db.setBeforeRun(() => {});
    const retried = msg(body);
    await processEvidenceBatch({ messages: [retried] }, env, { now: () => NOW });
    assert.deepEqual(retried.calls, ['ack']);
    assert.equal(db.raw.prepare("SELECT COUNT(*) AS n FROM ingest_receipts WHERE idempotency_key = 'ev:new'").get().n, 1);
    assert.equal(db.raw.prepare("SELECT COUNT(*) AS n FROM raw_evidence WHERE evidence_id = 'ev:new'").get().n, 1);
    assert.equal(JSON.parse(oldLane().evidence_counts_json).OPERATOR_COMPLETED, undefined);
    const newLane = db.raw.prepare("SELECT evidence_counts_json FROM lane_read_model WHERE lane_key = 'MKT-ATL|MKT-BNA'").get();
    assert.equal(JSON.parse(newLane.evidence_counts_json).OPERATOR_COMPLETED, 1);
  } finally { db.raw.close(); }
});
