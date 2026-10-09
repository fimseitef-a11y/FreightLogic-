// ingest.mjs — ELI ingestion pipeline (D1 + queue). AIAG-TASK-0038.
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
export const FRESHNESS_VERSION = 'operator-freshness-v0.2';
export const DERIVE_VERSION = 'derive-v1';

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

const US_STATE_CODES = new Set((
  'al ak az ar ca co ct de dc fl ga hi id il in ia ks ky la me md ma mi mn ms mo mt ne nv nh nj nm '
  + 'ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa wv wi wy'
).split(' '));
const CA_PROVINCE_CODES = new Set('ab bc mb nb nl ns nt nu on pe qc sk yt'.split(' '));
const REGION_CODES = new Set([...US_STATE_CODES, ...CA_PROVINCE_CODES]);

// Text-only normalization: case, spacing, ZIP, country suffix, parenthetical
// notes, comma before a trailing region code, Saint/St and Mount/Mt spelling.
// It never guesses a state and never fuzzy-matches.
export function normalizeMarketText(value) {
  const s = text(value);
  if (!s) return null;
  let n = s
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  for (let i = 0; i < 2; i += 1) {
    n = n
      .replace(/[\s,]+(?:usa|u\.s\.a\.?|us|u\.s\.?)$/, '')
      .replace(/[\s,]+\d{5}(?:-\d{4})?$/, '')
      .trim();
  }
  n = n
    .replace(/\s*,\s*/g, ', ')
    .replace(/[,.\s]+$/, '')
    .replace(/(^|[\s,])(?:st\.?|saint)\s+/g, '$1saint ')
    .replace(/(^|[\s,])(?:mt\.?|mount)\s+/g, '$1mount ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!n.includes(',')) {
    const m = /^(.+) ([a-z]{2})$/.exec(n);
    if (m && REGION_CODES.has(m[2])) n = `${m[1]}, ${m[2]}`;
  }
  return n || null;
}

// Location strings that are not one US city. They stay UNKNOWN and are reported
// as data quality; they are never alias candidates.
export const LOCATION_FLAGS = Object.freeze({
  UNKNOWN_PLACEHOLDER: 'UNKNOWN_PLACEHOLDER',
  MULTI_LEG: 'MULTI_LEG',
  ROAD: 'ROAD',
  MULTI_CITY: 'MULTI_CITY',
  NON_US: 'NON_US',
  NO_STATE: 'NO_STATE',
});

export function locationDataQualityFlag(value) {
  const s = text(value);
  if (!s) return null;
  const raw = s.toLowerCase().replace(/\s+/g, ' ');
  if (/^unknown\b/.test(raw)) return LOCATION_FLAGS.UNKNOWN_PLACEHOLDER;
  if (/\bmulti[\s-]?(?:leg|stop)s?\b/.test(raw)) return LOCATION_FLAGS.MULTI_LEG;
  if (/->|=>|→|\/|\s&\s/.test(raw)) return LOCATION_FLAGS.MULTI_CITY;
  if (/\b(?:turnpike|tollway|interstate|expressway|freeway|highway|hwy)\b|\bi-\d+\b/.test(raw)) return LOCATION_FLAGS.ROAD;
  if (/\bcanada\b|\b[a-z]\d[a-z] ?\d[a-z]\d\b/.test(raw)) return LOCATION_FLAGS.NON_US;
  const n = normalizeMarketText(s);
  const region = /, ([a-z]{2})$/.exec(n ?? '')?.[1];
  if (region && CA_PROVINCE_CODES.has(region)) return LOCATION_FLAGS.NON_US;
  if (!region || !US_STATE_CODES.has(region)) return LOCATION_FLAGS.NO_STATE;
  return null;
}

// The one key used for BOTH alias_norm (from Airtable) and evidence lookup.
// Absent input is { key: null, flag: null }; a flagged input has no key.
export function marketLookupKey(value) {
  if (!text(value)) return { key: null, flag: null };
  const flag = locationDataQualityFlag(value);
  if (flag) return { key: null, flag };
  return { key: normalizeMarketText(value), flag: null };
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
    const aliasNorm = marketLookupKey(aliasText).key;
    if (!aliasNorm || !isMarketId(marketCluster)) continue;
    const prior = seen.get(aliasNorm);
    if (prior && prior.marketCluster !== marketCluster) {
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
  const { key } = marketLookupKey(s);
  return (key && aliasMap.get(key)) || null;
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

function rowFreshness(row, now) {
  const sourceAsOf = row?.observedAt && /^\d{4}-\d{2}-\d{2}/.test(row.observedAt)
    ? `${row.observedAt.slice(0, 10)}T00:00:00Z`
    : null;
  return {
    state: classifyFreshness({
      sourceAsOf,
      now,
      freshForMs: OPERATOR_FRESH_MS,
      staleAfterMs: OPERATOR_STALE_AFTER_MS,
    }),
  };
}

export function materializeLane(governance, evidenceRows = [], { now, modelRunId, governanceFingerprint }) {
  const deduped = evidenceRows.filter((row) => row.duplicateClass !== 'EXACT_DUPLICATE');
  const staleExcluded = deduped.filter((row) => rowFreshness(row, now).state === 'STALE');
  const counted = deduped.filter((row) => rowFreshness(row, now).state !== 'STALE');
  const evidenceCounts = {};
  for (const row of counted) {
    const key = `OPERATOR_${row.statusKey}`.slice(0, 48);
    evidenceCounts[key] = (evidenceCounts[key] ?? 0) + 1;
  }
  const exactDuplicates = evidenceRows.length - deduped.length;
  if (exactDuplicates > 0) evidenceCounts.OPERATOR_EXACT_DUPLICATES = exactDuplicates;
  if (staleExcluded.length > 0) evidenceCounts.OPERATOR_STALE_EXCLUDED = staleExcluded.length;

  const dates = deduped.map((row) => row.observedAt).filter(Boolean).sort();
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
  if (staleExcluded.length > 0) unknownFlags.push('OPERATOR_STALE_EVIDENCE_EXCLUDED');
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
