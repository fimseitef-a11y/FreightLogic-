import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

import { runIngestion, processEvidenceBatch, resolveMarketInDb, ingestionReadiness } from '../pipeline.mjs';
import { buildAliasRows, buildGovernanceRows, resolveMarket, aliasMapFrom, normalizeMarketText } from '../ingest.mjs';
import { fetchAirtableRecords } from '../airtable.mjs';
import { createPrivateApi } from '../api.mjs';

// Real SQL: an in-memory SQLite database with ELI's real migrations, behind a
// D1-shaped adapter (prepare/bind/first/all/run/batch).
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

const ALIAS_TABLE = 'tblp0W75s9pqmrDmA';
const LANE_TABLE = 'tblKD555nilZey3IQ';
const LOAD_TABLE = 'tbl6Wof9SlTVotCEa';

function alias(id, text, market, status = 'Verified') {
  return { id, fields: { fldKR0KUzl6ozdA0n: text, fldXqOWA6L88MUUpy: market, fldh7mhLR93c2fJ19: status, fld51W8WPaKTgqei2: 'GEO-v0.1' } };
}
function lane(id, o, d, stage = 'Pilot Candidate', flags = ['INSUFFICIENT_OBSERVATIONS', 'EQUIPMENT_RELEVANCE_UNRESOLVED']) {
  return { id, fields: { fldIgOqICazHGCKOO: `PILOT-${o}-TO-${d}`, fldsd4aK1WxerkJ8G: o, fldAyt9qI2ZDF80QS: d, fldgV0MZnbBpVlUOH: stage, fld7OvKE2mOb7aW4M: flags } };
}
function load(id, { loadId = '1', status = 'Board / Listing', origin, destination, date = '2026-09-25', dup = 'None known', loaded = null, extra = {} } = {}) {
  return {
    id,
    fields: {
      fldcn3ICJoHqh4cul: loadId, fldOLL5VAvhn4aij6: 'DispatchLand', fldr421BJuQAedLrO: status,
      fldN33xbzUlNNmRE1: origin, fld60hboskYKlnq1P: destination, fld8rWQILiis5rnxl: date,
      fldNuXG7snnZjyxcD: dup, ...(loaded === null ? {} : { fldVznCz7rFq4ggWW: loaded }), ...extra,
    },
  };
}

function airtable(tables, { pageSize = 2, calls = [] } = {}) {
  return async (url, init) => {
    calls.push({ url, auth: init?.headers?.Authorization });
    const u = new URL(url);
    const table = u.pathname.split('/').pop();
    const rows = tables[table] ?? [];
    const start = Number(u.searchParams.get('offset') ?? 0);
    const page = rows.slice(start, start + pageSize);
    const next = start + pageSize < rows.length ? String(start + pageSize) : undefined;
    return new Response(JSON.stringify({ records: page, ...(next ? { offset: next } : {}) }), { status: 200 });
  };
}

function queueSink() {
  const sent = [];
  return { sent, async sendBatch(messages) { sent.push(...messages.map((m) => m.body)); } };
}

function batchOf(bodies) {
  const state = { acked: 0, retried: 0 };
  return {
    state,
    batch: {
      queue: 'freightlogic-eli-runtime-v1',
      messages: bodies.map((body, i) => ({ id: `m${i}`, attempts: 1, body, ack() { state.acked += 1; }, retry() { state.retried += 1; } })),
      retryAll() { state.retried += bodies.length; },
    },
  };
}

const NOW = '2026-10-01T05:00:00.000Z';

function baseTables() {
  return {
    [ALIAS_TABLE]: [
      alias('a1', 'Atlanta, GA', 'MKT-ATL'),
      alias('a2', 'Fairburn, GA', 'MKT-ATL'),
      alias('a3', 'Detroit, MI', 'MKT-DTW'),
      alias('a4', 'Chicago, IL', 'MKT-CHI'),
      alias('a5', 'Nashville, TN', 'MKT-BNA', 'Candidate'),
    ],
    [LANE_TABLE]: [
      lane('l1', 'MKT-ATL', 'MKT-DTW'),
      lane('l2', 'MKT-DTW', 'MKT-ATL', 'Validated Pilot', ['EXPOSURE_DENOMINATOR_MISSING']),
    ],
    [LOAD_TABLE]: [
      load('r1', { loadId: '100', origin: 'Atlanta, GA 30301', destination: 'Detroit, MI 48201', status: 'Board / Listing' }),
      load('r2', { loadId: '100', origin: 'Fairburn, GA', destination: 'Detroit, MI', status: 'Quote / Bid' }),
      load('r3', { loadId: '101', origin: 'Atlanta, GA', destination: 'Detroit, MI', dup: 'Exact duplicate evidence' }),
      load('r4', { loadId: '102', origin: 'Chicago, IL', destination: 'Atlanta, GA' }),
      load('r5', { loadId: '103', origin: 'Nashville, TN', destination: 'Atlanta, GA' }),
      load('r6', { loadId: '104', origin: 'Detroit, MI', destination: 'Atlanta, GA', date: '2026-07-01', loaded: 610 }),
    ],
  };
}

async function env(tables = baseTables(), extra = {}) {
  const db = await d1();
  return {
    db,
    queue: queueSink(),
    calls: [],
    get value() {
      return { ELI_ENABLED: 'true', ELI_DB: db, ELI_QUEUE: this.queue, AIRTABLE_TOKEN: 'patSECRET.value', AIRTABLE_BASE_ID: 'app8nbbqxfyP0uswo', ...extra };
    },
    tables,
  };
}

async function ingestAndConsume(e) {
  const result = await runIngestion(e.value, { fetchImpl: airtable(e.tables, { calls: e.calls }), now: () => NOW });
  const sent = e.queue.sent.splice(0);
  const { batch, state } = batchOf(sent);
  await processEvidenceBatch(batch, e.value, { now: () => NOW });
  return { result, sent, state };
}

async function laneRow(db, o, d) {
  return db.prepare('SELECT * FROM lane_read_model WHERE origin_market = ? AND destination_market = ?').bind(o, d).first();
}

test('P01 aliases: Verified only, ZIP stripped, exact match only, conflicting Verified aliases resolve to nothing', () => {
  const rows = buildAliasRows([
    alias('a', 'Atlanta, GA', 'MKT-ATL'),
    alias('b', 'Nashville, TN', 'MKT-BNA', 'Candidate'),
    alias('c', 'Springfield, IL', 'MKT-CHI'),
    alias('d', 'Springfield, IL', 'MKT-STL'),
  ], NOW);
  const map = aliasMapFrom(rows);
  assert.equal(resolveMarket('Atlanta, GA 30301', map), 'MKT-ATL');
  assert.equal(resolveMarket('ATLANTA,GA', map), 'MKT-ATL');
  assert.equal(resolveMarket('Nashville, TN', map), null, 'Candidate alias must not resolve');
  assert.equal(resolveMarket('Springfield, IL', map), null, 'conflicting Verified aliases must not resolve');
  assert.equal(resolveMarket('Atlanta Heights, GA', map), null, 'no fuzzy matching');
  assert.equal(resolveMarket('', map), null);
  assert.equal(normalizeMarketText('Lebanon, TN 37087-1234'), 'lebanon, tn');
});

test('P02 governance keeps only governed stages in the MKT geography', () => {
  const rows = buildGovernanceRows([
    lane('l1', 'MKT-ATL', 'MKT-DTW'),
    lane('l2', 'MKT-DTW', 'MKT-ATL', 'Validated Pilot'),
    { id: 'n1', fields: { fldIgOqICazHGCKOO: 'NAT2022|OPMKT-CFS22-17_99999|OPMKT-CFS22-482XX', fldsd4aK1WxerkJ8G: 'OPMKT-CFS22-17_99999', fldAyt9qI2ZDF80QS: 'OPMKT-CFS22-482XX', fldgV0MZnbBpVlUOH: 'Structural Candidate' } },
    lane('l3', 'Atlanta', 'MKT-DTW'),
  ], NOW);
  assert.deepEqual(rows.map((r) => [r.laneKey, r.stage]), [
    ['MKT-ATL|MKT-DTW', 'Pilot Candidate'],
    ['MKT-DTW|MKT-ATL', 'Validated Pilot'],
  ]);
});

test('P03 end-to-end: governed lanes materialize with per-status counts, governance flags and honest UNKNOWNs', async () => {
  const e = await env();
  const { result, state } = await ingestAndConsume(e);
  assert.equal(result.status, 'OK', result.error);
  assert.equal(state.retried, 0);
  assert.deepEqual(result.counts, {
    aliasesVerified: 4,
    governedLanes: 2,
    loadHistoryRecords: 6,
    evidenceBuilt: 6,
    evidenceQueued: 6,
    evidenceAlreadyStored: 0,
    evidenceOnGovernedLanes: 4,
    evidenceMarketUnresolved: 1,
    lanesMaterialized: 2,
  });

  const atlDtw = await laneRow(e.db, 'MKT-ATL', 'MKT-DTW');
  assert.equal(atlDtw.stage, 'Pilot Candidate');
  assert.deepEqual(JSON.parse(atlDtw.evidence_counts_json), {
    OPERATOR_BOARD_LISTING: 1,
    OPERATOR_QUOTE_BID: 1,
    OPERATOR_EXACT_DUPLICATES: 1,
  });
  assert.equal(atlDtw.structural_score, null, 'no structural evidence -> no score');
  assert.equal(atlDtw.structural_confidence, null);
  assert.deepEqual(JSON.parse(atlDtw.freshness_json), { OPERATOR_PRIVATE: 'FRESH' });
  const flags = JSON.parse(atlDtw.unknown_flags_json);
  for (const f of ['INSUFFICIENT_OBSERVATIONS', 'EQUIPMENT_RELEVANCE_UNRESOLVED', 'STRUCTURAL_EVIDENCE_MISSING', 'EXPEDITE_EVIDENCE_MISSING']) {
    assert.ok(flags.includes(f), `missing flag ${f}`);
  }

  const dtwAtl = await laneRow(e.db, 'MKT-DTW', 'MKT-ATL');
  assert.equal(dtwAtl.stage, 'Validated Pilot');
  assert.deepEqual(JSON.parse(dtwAtl.freshness_json), { OPERATOR_PRIVATE: 'STALE' }, '2026-07-01 evidence is stale on 2026-10-01');

  assert.equal(await laneRow(e.db, 'MKT-CHI', 'MKT-ATL'), null, 'a lane Airtable does not govern is never materialized');
  const stored = await e.db.prepare('SELECT COUNT(*) AS n FROM raw_evidence').first();
  assert.equal(stored.n, 6, 'evidence on ungoverned or unresolved lanes is still kept');
  const unresolved = await e.db.prepare('SELECT COUNT(*) AS n FROM evidence_index WHERE lane_key IS NULL').first();
  assert.equal(unresolved.n, 1, 'Nashville (Candidate alias) is stored but not forced onto a lane');
});

test('P04 a second unchanged run stores nothing new', async () => {
  const e = await env();
  await ingestAndConsume(e);
  const { result } = await ingestAndConsume(e);
  assert.equal(result.counts.evidenceQueued, 0);
  assert.equal(result.counts.evidenceAlreadyStored, 6);
  assert.equal((await e.db.prepare('SELECT COUNT(*) AS n FROM raw_evidence').first()).n, 6);
});

test('P05 an edited row becomes a new version that supersedes the old; raw evidence is never rewritten', async () => {
  const e = await env();
  await ingestAndConsume(e);
  e.tables[LOAD_TABLE][0] = load('r1', { loadId: '100', origin: 'Atlanta, GA 30301', destination: 'Detroit, MI 48201', status: 'Awarded / Accepted' });
  const { result } = await ingestAndConsume(e);
  assert.equal(result.counts.evidenceQueued, 1);
  assert.equal((await e.db.prepare('SELECT COUNT(*) AS n FROM raw_evidence WHERE source_record_id = ?').bind('r1').first()).n, 2);
  const newest = await e.db.prepare(`SELECT r.supersedes_evidence_id AS sup FROM raw_evidence r
    JOIN evidence_index i ON i.evidence_id = r.evidence_id WHERE i.source_record_id = 'r1' AND i.superseded = 0`).first();
  assert.ok(newest.sup, 'new version links to the version it supersedes');
  const counts = JSON.parse((await laneRow(e.db, 'MKT-ATL', 'MKT-DTW')).evidence_counts_json);
  assert.equal(counts.OPERATOR_BOARD_LISTING, undefined, 'superseded version no longer counted');
  assert.equal(counts.OPERATOR_AWARDED_ACCEPTED, 1);
  assert.throws(() => e.db.raw.prepare('UPDATE raw_evidence SET source_id = ?').run('x'), /append-only/);
});

test('P06 no rate is ever read or stored, and unknown miles stay unknown', async () => {
  const tables = baseTables();
  tables[LOAD_TABLE] = [load('rr', { origin: 'Atlanta, GA', destination: 'Detroit, MI', extra: { fldPhU0heXzHAqiFl: 850, fld45LT2qeqE1FzMP: 'Flat' } })];
  const e = await env(tables);
  await ingestAndConsume(e);
  const payload = (await e.db.prepare('SELECT payload_json FROM raw_evidence').first()).payload_json;
  assert.doesNotMatch(payload, /850|rate|Flat/i);
  assert.equal(JSON.parse(payload).loadedMiles, null);
  assert.equal(JSON.parse(payload).emptyMiles, null);
  const urls = e.calls.map((c) => c.url).filter((u) => u.includes(LOAD_TABLE));
  assert.ok(urls.every((u) => !u.includes('fldPhU0heXzHAqiFl')), 'rate field is never requested');
});

test('P07 a lane removed from Airtable governance stops being served', async () => {
  const e = await env();
  await ingestAndConsume(e);
  e.tables[LANE_TABLE] = [lane('l1', 'MKT-ATL', 'MKT-DTW')];
  await ingestAndConsume(e);
  assert.ok(await laneRow(e.db, 'MKT-ATL', 'MKT-DTW'));
  assert.equal(await laneRow(e.db, 'MKT-DTW', 'MKT-ATL'), null);
});

test('P08 an Airtable failure fails the run without leaking the token or touching served lanes', async () => {
  const e = await env();
  await ingestAndConsume(e);
  const before = await laneRow(e.db, 'MKT-ATL', 'MKT-DTW');
  const result = await runIngestion(e.value, {
    fetchImpl: async () => new Response('nope', { status: 401 }),
    now: () => NOW,
  });
  assert.equal(result.status, 'FAILED');
  assert.doesNotMatch(JSON.stringify(result), /patSECRET/);
  const run = await e.db.prepare(`SELECT status, error FROM ingest_runs WHERE run_id = ?`).bind(result.runId).first();
  assert.equal(run.status, 'FAILED');
  assert.doesNotMatch(run.error, /patSECRET/);
  assert.deepEqual(await laneRow(e.db, 'MKT-ATL', 'MKT-DTW'), before);
});

test('P09 the producer is inert unless ELI is enabled with D1, queue, token and base', async () => {
  const e = await env();
  let fetched = 0;
  for (const [patch, reason] of [
    [{ ELI_ENABLED: 'false' }, 'ELI_DISABLED'],
    [{ ELI_DB: undefined }, 'ELI_DB_UNAVAILABLE'],
    [{ ELI_QUEUE: undefined }, 'ELI_QUEUE_UNAVAILABLE'],
    [{ AIRTABLE_TOKEN: '' }, 'AIRTABLE_TOKEN_MISSING'],
    [{ AIRTABLE_BASE_ID: 'nope' }, 'AIRTABLE_BASE_ID_MISSING'],
  ]) {
    const result = await runIngestion({ ...e.value, ...patch }, { fetchImpl: async () => { fetched += 1; }, now: () => NOW });
    assert.deepEqual(result, { status: 'SKIPPED', reason });
  }
  assert.equal(fetched, 0);
  assert.equal(ingestionReadiness(e.value), null);
});

test('P10 RPC translates city names through Verified aliases only', async () => {
  const e = await env();
  await ingestAndConsume(e);
  const api = createPrivateApi({
    resolveMarket: (v) => resolveMarketInDb(e.db, v),
    getLaneRow: (o, d) => laneRow(e.db, o, d),
    getMarketRows: async () => [],
    getHealthSnapshot: async () => ({}),
  });
  const known = await api.getLaneIntelligence({ originMarket: 'Atlanta, GA', destinationMarket: 'Detroit, MI' });
  assert.equal(known.status, 'KNOWN');
  assert.deepEqual(known.resolved, { originMarket: 'MKT-ATL', destinationMarket: 'MKT-DTW' });
  assert.equal(known.intelligence.originMarket, 'MKT-ATL');
  assert.equal((await api.getLaneIntelligence({ originMarket: 'MKT-ATL', destinationMarket: 'MKT-DTW' })).status, 'KNOWN');
  assert.deepEqual(await api.getLaneIntelligence({ originMarket: 'Nashville, TN', destinationMarket: 'Atlanta, GA' }), {
    status: 'UNKNOWN', reason: 'MARKET_UNRESOLVED', originMarket: 'Nashville, TN', destinationMarket: 'Atlanta, GA',
  });
  assert.equal((await api.getLaneIntelligence({ originMarket: 'MKT-ZZZ', destinationMarket: 'MKT-ATL' })).reason, 'MARKET_UNRESOLVED');
  assert.equal((await api.getLaneIntelligence({ originMarket: 'Chicago, IL', destinationMarket: 'Atlanta, GA' })).reason, 'LANE_NOT_MATERIALIZED');
});

test('P11 Airtable client pages, sends the token only as a header, and never puts it in errors', async () => {
  const calls = [];
  const rows = Array.from({ length: 5 }, (_, i) => ({ id: `r${i}`, fields: {} }));
  const records = await fetchAirtableRecords({
    token: 'patSECRET.value', baseId: 'app8nbbqxfyP0uswo', tableId: LOAD_TABLE, fieldIds: ['fldcn3ICJoHqh4cul'],
    fetchImpl: airtable({ [LOAD_TABLE]: rows }, { calls }),
  });
  assert.equal(records.length, 5);
  assert.equal(calls.length, 3);
  assert.ok(calls.every((c) => c.auth === 'Bearer patSECRET.value' && !c.url.includes('patSECRET')));
  await assert.rejects(
    fetchAirtableRecords({ token: 'patSECRET.value', baseId: 'app8nbbqxfyP0uswo', tableId: LOAD_TABLE, fetchImpl: async () => new Response('', { status: 403 }) }),
    (error) => /AIRTABLE_HTTP_403/.test(error.message) && !/patSECRET/.test(error.message),
  );
  await assert.rejects(
    fetchAirtableRecords({ token: 't', baseId: 'app8nbbqxfyP0uswo', tableId: LOAD_TABLE, maxPages: 2, fetchImpl: airtable({ [LOAD_TABLE]: rows }) }),
    /AIRTABLE_PAGE_LIMIT/,
  );
});

test('P12 a message the consumer cannot store is retried, never acknowledged', async () => {
  const e = await env();
  const { batch, state } = batchOf([{ idempotencyKey: 'k', type: 'something_else', snapshotFingerprint: 's' }]);
  await processEvidenceBatch(batch, e.value, { now: () => NOW });
  assert.equal(state.acked, 0);
  assert.equal(state.retried, 1);
});
