// ingest.mjs — pure ingestion logic (no D1, no network). AIAG-TASK-0038.
//
// Operator data rules applied here (Claude memory: freight-data-rules):
//  - never invent a missing value: unknown stays null, never 0;
//  - never deduplicate by load ID alone: every Airtable row is its own
//    evidence, identified by its full content plus its record ID;
//  - keep statuses separate: counts are per status layer;
//  - keep correction lineage: an edited row becomes a new immutable version
//    that supersedes the previous one (raw evidence is never rewritten).
// No pricing field is read (the Load History adapter has no rate field).

import { projectLoadHistoryRecord } from './adapters/airtable-load-history.mjs';
import { classifyFreshness } from './freshness.mjs';
import { deriveLaneIntelligence } from './derive.mjs';

export const ADAPTER_VERSION = 'airtable-load-history-v1';
export const SOURCE_ID = 'airtable:load-history';
export const AUTHORIZATION_CLASS = 'OPERATOR_PRIVATE';
export const FRESHNESS_VERSION = 'operator-freshness-v0.1';
export const DERIVE_VERSION = 'derive-v1';

// Operator evidence freshness (provisional, versioned above).
export const OPERATOR_FRESH_MS = 14 * 86400000;
export const OPERATOR_STALE_AFTER_MS = 45 * 86400000;

export const MARKET_ALIAS_FIELD_IDS = Object.freeze({
  aliasText: 'fldKR0KUzl6ozdA0n',
  marketCluster: 'fldXqOWA6L88MUUpy',
  resolutionStatus: 'fldh7mhLR93c2fJ19',
  geographyVersion: 'fld51W8WPaKTgqei2',
});
export const MARKET_ALIAS_TABLE_ID = 'tblp0W75s9pqmrDmA';

export const DIRECTIONAL_LANE_FIELD_IDS = Object.freeze({
  laneId: 'fldIgOqICazHGCKOO',
  originMarket: 'fldsd4aK1WxerkJ8G',
  destinationMarket: 'fldAyt9qI2ZDF80QS',
  stage: 'fldgV0MZnbBpVlUOH',
  unknownStates: 'fld7OvKE2mOb7aW4M',
});
export const DIRECTIONAL_LANE_TABLE_ID = 'tblKD555nilZey3IQ';

// Only lanes Airtable has moved past bulk structural candidacy are governed
// for serving; the 7,250 national Structural Candidate rows use a different
// geography (OPMKT-CFS22) that no operator alias resolves to.
export const GOVERNED_STAGES = Object.freeze(['Pilot Candidate', 'Validated Pilot', 'Production']);

const MARKET_ID_PATTERN = /^[A-Z][A-Z0-9-]{1,40}$/;
const FLAG_PATTERN = /^[A-Z0-9_]{1,64}$/;

function text(value) {
  const v = value && typeof value === 'object' && !Array.isArray(value) && typeof value.name === 'string'
    ? value.name
    : value;
  if (v == null) return null;
  const s = String(v).trim();
  return s || null;
}

function names(value) {
  if (!Array.isArray(value)) return [];
  return value.map(text).filter(Boolean);
}

export function cellsOf(record) {
  if (record?.cellValuesByFieldId && typeof record.cellValuesByFieldId === 'object') return record.cellValuesByFieldId;
  if (record?.fields && typeof record.fields === 'object') return record.fields;
  return {};
}

// US state and Canadian province codes. Used only to recognise "City ST"
// written without the comma; it never guesses a state that is not written.
const REGION_CODES = new Set((
  'al ak az ar ca co ct de dc fl ga hi id il in ia ks ky la me md ma mi mn ms mo mt ne nv nh nj nm '
  + 'ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa wv wi wy '
  + 'ab bc mb nb nl ns nt nu on pe qc sk yt'
).split(' '));

// "Lebanon, TN 37087" -> "lebanon, tn"; "Milwaukee WI" -> "milwaukee, wi".
// Exact match only; no fuzzy matching. The comma is added only when the last
// word is a real state/province code, so "Unknown origin" stays as written.
export function normalizeMarketText(value) {
  const s = text(value);
  if (!s) return null;
  let n = s
    .toLowerCase()
    .replace(/\s+\d{5}(?:-\d{4})?\s*$/, '')
    .replace(/\s*,\s*/g, ', ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!n.includes(',')) {
    const m = /^(.+) ([a-z]{2})$/.exec(n);
    if (m && REGION_CODES.has(m[2])) n = `${m[1]}, ${m[2]}`;
  }
  return n || null;
}

export function isMarketId(value) {
  return typeof value === 'string' && MARKET_ID_PATTERN.test(value);
}

export function buildAliasRows(records = [], syncedAt) {
  const rows = [];
  const seen = new Map();
  for (const record of records) {
    const cells = cellsOf(record);
    if (text(cells[MARKET_ALIAS_FIELD_IDS.resolutionStatus]) !== 'Verified') continue;
    const aliasText = text(cells[MARKET_ALIAS_FIELD_IDS.aliasText]);
    const marketCluster = text(cells[MARKET_ALIAS_FIELD_IDS.marketCluster]);
    const aliasNorm = normalizeMarketText(aliasText);
    if (!aliasNorm || !isMarketId(marketCluster)) continue;
    const prior = seen.get(aliasNorm);
    if (prior && prior.marketCluster !== marketCluster) {
      // Two Verified aliases disagree: preserve ambiguity, resolve to nothing.
      prior.conflict = true;
      continue;
    }
    if (prior) continue;
    const row = {
      aliasNorm,
      aliasText,
      marketCluster,
      geographyVersion: text(cells[MARKET_ALIAS_FIELD_IDS.geographyVersion]),
      airtableRecordId: record.id,
      syncedAt,
    };
    seen.set(aliasNorm, row);
    rows.push(row);
  }
  return rows.filter((row) => !row.conflict).map(({ conflict, ...row }) => row);
}

export function aliasMapFrom(rows = []) {
  return new Map(rows.map((row) => [row.aliasNorm, row.marketCluster]));
}

export function resolveMarket(value, aliasMap) {
  const s = text(value);
  if (!s) return null;
  if (isMarketId(s)) return s;
  const norm = normalizeMarketText(s);
  return (norm && aliasMap.get(norm)) || null;
}

export function laneKeyOf(originMarket, destinationMarket) {
  return originMarket && destinationMarket ? `${originMarket}|${destinationMarket}` : null;
}

export function buildGovernanceRows(records = [], syncedAt) {
  const rows = [];
  for (const record of records) {
    const cells = cellsOf(record);
    const stage = text(cells[DIRECTIONAL_LANE_FIELD_IDS.stage]);
    const originMarket = text(cells[DIRECTIONAL_LANE_FIELD_IDS.originMarket]);
    const destinationMarket = text(cells[DIRECTIONAL_LANE_FIELD_IDS.destinationMarket]);
    if (!GOVERNED_STAGES.includes(stage) || !isMarketId(originMarket) || !isMarketId(destinationMarket)) continue;
    rows.push({
      laneKey: laneKeyOf(originMarket, destinationMarket),
      directionalLaneId: text(cells[DIRECTIONAL_LANE_FIELD_IDS.laneId]) ?? record.id,
      originMarket,
      destinationMarket,
      stage,
      unknownFlags: names(cells[DIRECTIONAL_LANE_FIELD_IDS.unknownStates]).filter((f) => FLAG_PATTERN.test(f)),
      airtableRecordId: record.id,
      syncedAt,
    });
  }
  return rows;
}

export function statusKey(value) {
  const s = text(value);
  if (!s) return 'STATUS_UNKNOWN';
  const key = s.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 48);
  return key || 'STATUS_UNKNOWN';
}

export function duplicateClass(value) {
  const s = text(value);
  if (s === 'Exact duplicate evidence') return 'EXACT_DUPLICATE';
  if (s && /repost|related/i.test(s)) return 'POSSIBLE_REPOST';
  return 'NONE_KNOWN';
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

export async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// One Airtable Load History record -> one evidence version + its index row.
export async function buildEvidence(record, { aliasMap, runId, retrievedAt }) {
  const projected = projectLoadHistoryRecord({ id: record.id, cellValuesByFieldId: cellsOf(record) });
  if (!projected.airtableRecordId) return null;
  const payloadJson = canonicalJson(projected);
  const payloadHash = await sha256Hex(payloadJson);
  const evidenceId = `ev:${await sha256Hex(`${SOURCE_ID}|${projected.airtableRecordId}|${payloadHash}`)}`;
  const originMarket = resolveMarket(projected.origin, aliasMap);
  const destinationMarket = resolveMarket(projected.destination, aliasMap);
  const observedAt = /^\d{4}-\d{2}-\d{2}/.test(projected.evidenceDate ?? '') ? projected.evidenceDate : null;
  return {
    evidence: {
      evidenceId,
      sourceId: SOURCE_ID,
      adapterVersion: ADAPTER_VERSION,
      sourceRecordId: projected.airtableRecordId,
      observedAt,
      retrievedAt,
      sourcePostedAt: null,
      payloadJson,
      payloadHash,
      sourceRef: `airtable:${projected.airtableRecordId}`,
      authorizationClass: AUTHORIZATION_CLASS,
      scopeFingerprint: SOURCE_ID,
      parentEvidenceId: null,
      supersedesEvidenceId: null,
      ingestRunId: runId,
    },
    index: {
      evidenceId,
      sourceRecordId: projected.airtableRecordId,
      laneKey: laneKeyOf(originMarket, destinationMarket),
      originMarket,
      destinationMarket,
      statusKey: statusKey(projected.statusLayer),
      duplicateClass: duplicateClass(projected.duplicateRepost),
      observedAt,
    },
  };
}

// Pure lane materialization from governance + current (non-superseded)
// evidence index rows for that lane.
export function materializeLane(governance, evidenceRows = [], { now, modelRunId, governanceFingerprint }) {
  const counted = evidenceRows.filter((row) => row.duplicateClass !== 'EXACT_DUPLICATE');
  const evidenceCounts = {};
  for (const row of counted) {
    const key = `OPERATOR_${row.statusKey}`.slice(0, 48);
    evidenceCounts[key] = (evidenceCounts[key] ?? 0) + 1;
  }
  const exactDuplicates = evidenceRows.length - counted.length;
  if (exactDuplicates > 0) evidenceCounts.OPERATOR_EXACT_DUPLICATES = exactDuplicates;

  const dates = counted.map((row) => row.observedAt).filter(Boolean).sort();
  const latestEvidenceAt = dates.length ? `${dates[dates.length - 1].slice(0, 10)}T00:00:00Z` : null;
  const operatorFreshness = classifyFreshness({
    sourceAsOf: latestEvidenceAt,
    now,
    freshForMs: OPERATOR_FRESH_MS,
    staleAfterMs: OPERATOR_STALE_AFTER_MS,
  });

  const derived = deriveLaneIntelligence(
    counted.map((row) => ({ sourceClass: 'OPERATOR_PRIVATE', sourceId: SOURCE_ID, asOf: row.observedAt })),
  );

  const unknownFlags = [...new Set([...governance.unknownFlags, ...derived.unknownFlags])];
  if (counted.length === 0) unknownFlags.push('OPERATOR_EVIDENCE_NONE');
  if (counted.some((row) => row.duplicateClass === 'POSSIBLE_REPOST')) unknownFlags.push('POSSIBLE_REPOSTS_PRESENT');

  return {
    laneKey: governance.laneKey,
    originMarket: governance.originMarket,
    destinationMarket: governance.destinationMarket,
    structuralScore: derived.structuralScore,
    expediteRelevance: derived.expediteRelevance,
    structuralConfidence: null,
    expediteConfidence: null,
    freshness: { OPERATOR_PRIVATE: operatorFreshness },
    unknownFlags: [...new Set(unknownFlags)].filter((f) => FLAG_PATTERN.test(f)),
    conflictFlags: derived.conflictFlags,
    evidenceCounts,
    latestEvidenceAt,
    stage: governance.stage,
    modelRunId,
    governanceFingerprint,
    updatedAt: now,
  };
}
