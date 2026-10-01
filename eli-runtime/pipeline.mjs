// pipeline.mjs — ELI ingestion pipeline (D1 + queue). AIAG-TASK-0038.
//
//   scheduled() -> runIngestion(): mirror Verified market aliases and governed
//     lanes from Airtable, read Load History, enqueue each not-yet-stored
//     evidence version, and materialize every governed lane.
//   queue()     -> processEvidenceBatch(): store each evidence version
//     (append-only, superseding the previous version of the same Airtable
//     row), record a receipt, then re-materialize the affected lanes.
//
// Airtable is the authority for aliases, lane existence and stage (design
// amendment 7). A lane Airtable does not govern is never materialized.

import { appendRawEvidence, recordReceipt } from './storage.mjs';
import { consumePrimaryBatch } from './queue.mjs';
import { fetchAirtableRecords } from './airtable.mjs';
import { LOAD_HISTORY_TABLE_ID, getLoadHistoryReadFieldIds } from './adapters/airtable-load-history.mjs';
import {
  DERIVE_VERSION,
  DIRECTIONAL_LANE_FIELD_IDS,
  DIRECTIONAL_LANE_TABLE_ID,
  FRESHNESS_VERSION,
  GOVERNED_STAGES,
  MARKET_ALIAS_FIELD_IDS,
  MARKET_ALIAS_TABLE_ID,
  aliasMapFrom,
  buildAliasRows,
  buildEvidence,
  buildGovernanceRows,
  materializeLane,
  normalizeMarketText,
  isMarketId,
  sha256Hex,
} from './ingest.mjs';

const SEND_BATCH = 100;
const IN_CHUNK = 90; // stays under D1's bound-parameter limit

export const EVIDENCE_MESSAGE_TYPE = 'operator_load_history_evidence';

export function ingestionReadiness(env) {
  if (env?.ELI_ENABLED !== 'true') return 'ELI_DISABLED';
  if (!env?.ELI_DB || typeof env.ELI_DB.prepare !== 'function') return 'ELI_DB_UNAVAILABLE';
  if (!env?.ELI_QUEUE || typeof env.ELI_QUEUE.sendBatch !== 'function') return 'ELI_QUEUE_UNAVAILABLE';
  if (!env?.AIRTABLE_TOKEN) return 'AIRTABLE_TOKEN_MISSING';
  if (!/^app[A-Za-z0-9]{14}$/.test(env?.AIRTABLE_BASE_ID ?? '')) return 'AIRTABLE_BASE_ID_MISSING';
  return null;
}

async function replaceAliases(db, rows) {
  const statements = [db.prepare('DELETE FROM market_aliases')];
  for (const row of rows) {
    statements.push(db.prepare(`INSERT INTO market_aliases
      (alias_norm, alias_text, market_cluster, geography_version, airtable_record_id, synced_at)
      VALUES (?, ?, ?, ?, ?, ?)`).bind(
      row.aliasNorm, row.aliasText, row.marketCluster, row.geographyVersion ?? null, row.airtableRecordId, row.syncedAt,
    ));
  }
  await db.batch(statements);
}

async function replaceGovernance(db, rows) {
  const statements = [db.prepare('DELETE FROM lane_governance')];
  for (const row of rows) {
    statements.push(db.prepare(`INSERT INTO lane_governance
      (lane_key, directional_lane_id, origin_market, destination_market, stage, unknown_flags_json, airtable_record_id, synced_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      row.laneKey, row.directionalLaneId, row.originMarket, row.destinationMarket, row.stage,
      JSON.stringify(row.unknownFlags), row.airtableRecordId, row.syncedAt,
    ));
  }
  // A lane Airtable no longer governs stops being served.
  statements.push(db.prepare('DELETE FROM lane_read_model WHERE lane_key NOT IN (SELECT lane_key FROM lane_governance)'));
  await db.batch(statements);
}

async function existingReceipts(db, keys) {
  const found = new Set();
  for (let i = 0; i < keys.length; i += IN_CHUNK) {
    const chunk = keys.slice(i, i + IN_CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const result = await db.prepare(`SELECT idempotency_key FROM ingest_receipts WHERE idempotency_key IN (${placeholders})`)
      .bind(...chunk).all();
    for (const row of result?.results ?? []) found.add(row.idempotency_key);
  }
  return found;
}

async function latestModelRun(db) {
  return db.prepare('SELECT model_run_id, governance_fingerprint FROM model_runs ORDER BY created_at DESC LIMIT 1').first();
}

function governanceFromRow(row) {
  let flags = [];
  try { flags = JSON.parse(row.unknown_flags_json); } catch { flags = []; }
  return {
    laneKey: row.lane_key,
    originMarket: row.origin_market,
    destinationMarket: row.destination_market,
    stage: row.stage,
    unknownFlags: Array.isArray(flags) ? flags : [],
  };
}

export async function rematerializeLanes(db, laneKeys, { now, modelRunId, governanceFingerprint }) {
  const keys = [...new Set((laneKeys ?? []).filter(Boolean))];
  let materialized = 0;
  for (const laneKey of keys) {
    const governanceRow = await db.prepare('SELECT * FROM lane_governance WHERE lane_key = ?').bind(laneKey).first();
    if (!governanceRow) continue;
    const evidence = await db.prepare(`SELECT status_key, duplicate_class, observed_at FROM evidence_index
      WHERE lane_key = ? AND superseded = 0`).bind(laneKey).all();
    const lane = materializeLane(
      governanceFromRow(governanceRow),
      (evidence?.results ?? []).map((row) => ({
        statusKey: row.status_key,
        duplicateClass: row.duplicate_class,
        observedAt: row.observed_at,
      })),
      { now, modelRunId, governanceFingerprint },
    );
    await db.prepare(`INSERT INTO lane_read_model (
        lane_key, origin_market, destination_market, structural_score, expedite_relevance,
        structural_confidence, expedite_confidence, freshness_json, unknown_flags_json,
        conflict_flags_json, evidence_counts_json, latest_evidence_at, stage, model_run_id,
        governance_fingerprint, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(lane_key) DO UPDATE SET
        structural_score = excluded.structural_score,
        expedite_relevance = excluded.expedite_relevance,
        structural_confidence = excluded.structural_confidence,
        expedite_confidence = excluded.expedite_confidence,
        freshness_json = excluded.freshness_json,
        unknown_flags_json = excluded.unknown_flags_json,
        conflict_flags_json = excluded.conflict_flags_json,
        evidence_counts_json = excluded.evidence_counts_json,
        latest_evidence_at = excluded.latest_evidence_at,
        stage = excluded.stage,
        model_run_id = excluded.model_run_id,
        governance_fingerprint = excluded.governance_fingerprint,
        updated_at = excluded.updated_at`).bind(
      lane.laneKey, lane.originMarket, lane.destinationMarket, lane.structuralScore, lane.expediteRelevance,
      lane.structuralConfidence, lane.expediteConfidence, JSON.stringify(lane.freshness),
      JSON.stringify(lane.unknownFlags), JSON.stringify(lane.conflictFlags), JSON.stringify(lane.evidenceCounts),
      lane.latestEvidenceAt, lane.stage, lane.modelRunId, lane.governanceFingerprint, lane.updatedAt,
    ).run();
    materialized += 1;
  }
  return materialized;
}

// Airtable plans cap monthly API calls; a run spends ~5. However the cron is
// configured (including the on-demand every-minute trigger), at most one real
// run happens per interval.
export const MIN_RUN_INTERVAL_MS = 30 * 60 * 1000;

export async function runIngestion(env, deps = {}) {
  const now = (deps.now ?? (() => new Date().toISOString()))();
  const notReady = ingestionReadiness(env);
  if (notReady) {
    // Record WHY a run did not happen whenever ELI is enabled with D1, so a
    // missing token or binding is diagnosable without logs. A disabled ELI
    // writes nothing.
    if (notReady !== 'ELI_DISABLED' && notReady !== 'ELI_DB_UNAVAILABLE') {
      try {
        await env.ELI_DB.prepare(`INSERT INTO ingest_runs (run_id, started_at, finished_at, status, error)
          VALUES (?, ?, ?, 'SKIPPED', ?)`).bind(`skip:${now}:${crypto.randomUUID()}`, now, now, notReady).run();
      } catch {
        // Diagnostics must never turn a skip into a crash.
      }
    }
    return { status: 'SKIPPED', reason: notReady };
  }

  const db = env.ELI_DB;
  const minIntervalMs = deps.minIntervalMs ?? MIN_RUN_INTERVAL_MS;
  if (minIntervalMs > 0) {
    const recent = await db.prepare(`SELECT started_at FROM ingest_runs
      WHERE status IN ('OK', 'RUNNING') ORDER BY started_at DESC LIMIT 1`).first();
    const age = recent ? Date.parse(now) - Date.parse(recent.started_at) : Infinity;
    if (Number.isFinite(age) && age >= 0 && age < minIntervalMs) return { status: 'SKIPPED', reason: 'RECENT_RUN' };
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const runId = deps.runId ?? `run:${now}:${crypto.randomUUID()}`;
  const airtable = { token: env.AIRTABLE_TOKEN, baseId: env.AIRTABLE_BASE_ID, fetchImpl };

  await db.prepare(`INSERT INTO ingest_runs (run_id, started_at, status) VALUES (?, ?, 'RUNNING')`).bind(runId, now).run();
  try {
    const aliasRecords = await fetchAirtableRecords({
      ...airtable, tableId: MARKET_ALIAS_TABLE_ID, fieldIds: Object.values(MARKET_ALIAS_FIELD_IDS),
    });
    const stageFormula = `OR(${GOVERNED_STAGES.map((s) => `{Lane Stage}='${s}'`).join(',')})`;
    const laneRecords = await fetchAirtableRecords({
      ...airtable, tableId: DIRECTIONAL_LANE_TABLE_ID, fieldIds: Object.values(DIRECTIONAL_LANE_FIELD_IDS),
      filterByFormula: stageFormula,
    });
    const loadRecords = await fetchAirtableRecords({
      ...airtable, tableId: LOAD_HISTORY_TABLE_ID, fieldIds: getLoadHistoryReadFieldIds(),
    });

    const aliasRows = buildAliasRows(aliasRecords, now);
    const governanceRows = buildGovernanceRows(laneRecords, now);
    await replaceAliases(db, aliasRows);
    await replaceGovernance(db, governanceRows);

    const governanceFingerprint = `gov:${(await sha256Hex(JSON.stringify(
      governanceRows.map(({ syncedAt, ...row }) => row).sort((a, b) => a.laneKey.localeCompare(b.laneKey)),
    ))).slice(0, 32)}`;
    await db.prepare(`INSERT INTO model_runs (
        model_run_id, mode, source_snapshot_fingerprint, observation_as_of, structural_version,
        expedite_version, confidence_version, config_hash, governance_fingerprint, promoted)
      VALUES (?, 'OPERATOR_INGEST', ?, ?, ?, ?, ?, ?, ?, 0)`).bind(
      runId, runId, now, DERIVE_VERSION, DERIVE_VERSION, FRESHNESS_VERSION, `${DERIVE_VERSION}|${FRESHNESS_VERSION}`,
      governanceFingerprint,
    ).run();

    const aliasMap = aliasMapFrom(aliasRows);
    const built = [];
    for (const record of loadRecords) {
      const item = await buildEvidence(record, { aliasMap, runId, retrievedAt: now });
      if (item) built.push(item);
    }
    const already = await existingReceipts(db, built.map((item) => item.evidence.evidenceId));
    const fresh = built.filter((item) => !already.has(item.evidence.evidenceId));
    for (let i = 0; i < fresh.length; i += SEND_BATCH) {
      await env.ELI_QUEUE.sendBatch(fresh.slice(i, i + SEND_BATCH).map((item) => ({
        body: {
          idempotencyKey: item.evidence.evidenceId,
          type: EVIDENCE_MESSAGE_TYPE,
          snapshotFingerprint: runId,
          affectedKeys: item.index.laneKey ? [item.index.laneKey] : [],
          evidence: item.evidence,
          index: item.index,
        },
      })));
    }

    const materialized = await rematerializeLanes(db, governanceRows.map((row) => row.laneKey), {
      now, modelRunId: runId, governanceFingerprint,
    });
    const counts = {
      aliasesVerified: aliasRows.length,
      governedLanes: governanceRows.length,
      loadHistoryRecords: loadRecords.length,
      evidenceBuilt: built.length,
      evidenceQueued: fresh.length,
      evidenceAlreadyStored: built.length - fresh.length,
      evidenceOnGovernedLanes: built.filter((item) => governanceRows.some((g) => g.laneKey === item.index.laneKey)).length,
      evidenceMarketUnresolved: built.filter((item) => !item.index.laneKey).length,
      lanesMaterialized: materialized,
    };
    await db.prepare(`UPDATE ingest_runs SET finished_at = ?, status = 'OK', counts_json = ? WHERE run_id = ?`)
      .bind((deps.now ?? (() => new Date().toISOString()))(), JSON.stringify(counts), runId).run();
    return { status: 'OK', runId, counts };
  } catch (error) {
    const message = String(error?.message ?? error).slice(0, 200);
    await db.prepare(`UPDATE ingest_runs SET finished_at = ?, status = 'FAILED', error = ? WHERE run_id = ?`)
      .bind((deps.now ?? (() => new Date().toISOString()))(), message, runId).run();
    return { status: 'FAILED', runId, error: message };
  }
}

// Store one evidence version: append-only raw row, superseding the previous
// version of the same Airtable record, plus its mutable index row.
export async function storeEvidenceVersion(db, { evidence, index }) {
  const exists = await db.prepare('SELECT 1 AS present FROM raw_evidence WHERE evidence_id = ?').bind(evidence.evidenceId).first();
  if (exists) {
    await db.prepare(`INSERT OR IGNORE INTO evidence_index
      (evidence_id, source_record_id, lane_key, origin_market, destination_market, status_key, duplicate_class, observed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      index.evidenceId, index.sourceRecordId, index.laneKey ?? null, index.originMarket ?? null,
      index.destinationMarket ?? null, index.statusKey, index.duplicateClass, index.observedAt ?? null,
    ).run();
    return { stored: false };
  }
  const previous = await db.prepare(`SELECT evidence_id FROM evidence_index
    WHERE source_record_id = ? AND superseded = 0 ORDER BY created_at DESC LIMIT 1`).bind(index.sourceRecordId).first();
  await appendRawEvidence(db, { ...evidence, supersedesEvidenceId: previous?.evidence_id ?? null });
  await db.batch([
    db.prepare('UPDATE evidence_index SET superseded = 1 WHERE source_record_id = ? AND superseded = 0').bind(index.sourceRecordId),
    db.prepare(`INSERT INTO evidence_index
      (evidence_id, source_record_id, lane_key, origin_market, destination_market, status_key, duplicate_class, observed_at, superseded)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`).bind(
      index.evidenceId, index.sourceRecordId, index.laneKey ?? null, index.originMarket ?? null,
      index.destinationMarket ?? null, index.statusKey, index.duplicateClass, index.observedAt ?? null,
    ),
  ]);
  return { stored: true, supersededEvidenceId: previous?.evidence_id ?? null };
}

export async function processEvidenceBatch(batch, env, deps = {}) {
  const db = env.ELI_DB;
  const now = deps.now ?? (() => new Date().toISOString());
  const affected = new Set();

  await consumePrimaryBatch(batch, {
    hasReceipt: async (key) => Boolean(
      await db.prepare('SELECT 1 AS present FROM ingest_receipts WHERE idempotency_key = ?').bind(key).first(),
    ),
    processMessage: async (body) => {
      if (body.type !== EVIDENCE_MESSAGE_TYPE || !body.evidence || !body.index) {
        throw new Error(`unsupported ELI message: ${String(body.type)}`);
      }
      await storeEvidenceVersion(db, body);
      for (const key of body.affectedKeys ?? []) affected.add(key);
    },
    recordReceipt: (receipt) => recordReceipt(db, receipt),
    now,
  });

  if (affected.size > 0) {
    const run = await latestModelRun(db);
    if (run) {
      await rematerializeLanes(db, [...affected], {
        now: now(), modelRunId: run.model_run_id, governanceFingerprint: run.governance_fingerprint,
      });
    }
  }
}

// RPC-side market translation: a cluster id passes through only if it is
// known to ELI; a city name resolves only through a Verified alias.
export async function resolveMarketInDb(db, value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const s = value.trim();
  if (isMarketId(s)) {
    const known = await db.prepare(`SELECT 1 AS present FROM lane_governance
      WHERE origin_market = ? OR destination_market = ? LIMIT 1`).bind(s, s).first();
    if (known) return s;
  }
  const norm = normalizeMarketText(s);
  if (!norm) return null;
  const row = await db.prepare('SELECT market_cluster FROM market_aliases WHERE alias_norm = ?').bind(norm).first();
  return row?.market_cluster ?? null;
}

// On-demand trigger: a queue message of this type asks ELI to run ingestion.
// Queue delivery takes seconds, unlike a cron change (up to ~15 minutes).
export const RUN_INGESTION_MESSAGE_TYPE = 'eli_run_ingestion';

async function recordRunEvent(db, status, detail, now) {
  if (!db || typeof db.prepare !== 'function') return;
  try {
    await db.prepare(`INSERT INTO ingest_runs (run_id, started_at, finished_at, status, error)
      VALUES (?, ?, ?, ?, ?)`).bind(`${status.toLowerCase()}:${now}:${crypto.randomUUID()}`, now, now, status, String(detail).slice(0, 200)).run();
  } catch {
    // Diagnostics must never break the trigger.
  }
}

// Every trigger (cron or queue) leaves a TRIGGERED row before anything else,
// and an unexpected exception leaves a CRASHED row, so "nothing happened" is
// never ambiguous. Only when ELI is enabled with D1: a dark ELI writes nothing.
export async function triggeredIngestion(env, source, deps = {}) {
  const now = (deps.now ?? (() => new Date().toISOString()))();
  const db = env?.ELI_ENABLED === 'true' ? env?.ELI_DB : null;
  await recordRunEvent(db, 'TRIGGERED', source, now);
  try {
    return await (deps.run ?? runIngestion)(env, deps);
  } catch (error) {
    await recordRunEvent(db, 'CRASHED', `${source}: ${String(error?.message ?? error)}`, now);
    return { status: 'CRASHED', error: String(error?.message ?? error).slice(0, 200) };
  }
}
