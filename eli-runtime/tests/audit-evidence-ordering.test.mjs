import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

import { storeEvidenceVersion } from '../pipeline.mjs';
import { appendRawEvidence } from '../storage.mjs';

async function d1() {
  const db = new DatabaseSync(':memory:');
  for (const file of ['0001_init.sql', '0002_ingestion.sql']) {
    db.exec(await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8'));
  }
  const statement = (sql, args = []) => ({
    bind: (...next) => statement(sql, next),
    async first() { return db.prepare(sql).get(...args) ?? null; },
    async all() { return { results: db.prepare(sql).all(...args) }; },
    async run() { return this.runSync(); },
    runSync() { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    raw: db,
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

async function currentIds(db) {
  const rows = await db.prepare(`SELECT evidence_id FROM evidence_index
    WHERE source_record_id = 'rec1' AND superseded = 0 ORDER BY evidence_id`).all();
  return rows.results.map((row) => row.evidence_id);
}

test('AUD-ELI-01 delayed older evidence cannot replace the newer current source revision', async () => {
  const db = await d1();
  await storeEvidenceVersion(db, version('ev:a', '2026-10-01T10:00:00.000Z', 'BOARD_LISTING'));
  await storeEvidenceVersion(db, version('ev:b', '2026-10-01T11:00:00.000Z', 'COMPLETED'));
  await storeEvidenceVersion(db, version('ev:old-delayed', '2026-10-01T09:00:00.000Z', 'QUOTE_BID'));

  assert.deepEqual(await currentIds(db), ['ev:b']);
  const delayed = await db.prepare(`SELECT superseded FROM evidence_index WHERE evidence_id = 'ev:old-delayed'`).first();
  assert.equal(delayed?.superseded, 1, 'late historical evidence remains stored but not current');
});

test('AUD-ELI-02 A -> B -> A content reversion makes A current again when the later occurrence is newer', async () => {
  const db = await d1();
  await storeEvidenceVersion(db, version('ev:a', '2026-10-01T10:00:00.000Z', 'BOARD_LISTING'));
  await storeEvidenceVersion(db, version('ev:b', '2026-10-01T11:00:00.000Z', 'COMPLETED'));
  await storeEvidenceVersion(db, version('ev:a', '2026-10-01T12:00:00.000Z', 'BOARD_LISTING'));

  assert.deepEqual(await currentIds(db), ['ev:a']);
});

test('AUD-ELI-03 retry after raw-evidence persistence repairs the current-version index without two active rows', async () => {
  const db = await d1();
  await storeEvidenceVersion(db, version('ev:a', '2026-10-01T10:00:00.000Z', 'BOARD_LISTING'));

  const b = version('ev:b', '2026-10-01T11:00:00.000Z', 'COMPLETED');
  // Simulate an interruption after append-only raw evidence persisted but before
  // the mutable current-version index transaction completed.
  await appendRawEvidence(db, b.evidence);
  await storeEvidenceVersion(db, b);

  assert.deepEqual(await currentIds(db), ['ev:b']);
  const active = await db.prepare(`SELECT COUNT(*) AS n FROM evidence_index
    WHERE source_record_id = 'rec1' AND superseded = 0`).first();
  assert.equal(active.n, 1);
});
