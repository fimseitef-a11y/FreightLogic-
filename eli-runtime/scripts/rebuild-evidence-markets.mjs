#!/usr/bin/env node
// rebuild-evidence-markets.mjs — re-resolve evidence_index origin/destination
// markets with the current marketLookupKey normalizer. AIAG-TASK-0038.
//
// evidence_index markets were computed at ingest time. This script recomputes
// them from the stored raw payload and the synced Verified aliases, and writes
// a SQL file of guarded UPDATEs. It never connects to D1 itself:
//   1. export evidence + aliases with the two SELECTs from --print-queries;
//   2. run this script (dry run: report only, or --out to write SQL);
//   3. review, then apply the SQL file with wrangler (separate owner gate).
// Idempotent: every UPDATE only changes a row whose stored value differs, and
// a second run over the post-apply export produces zero statements.
// UNKNOWN stays UNKNOWN: an input that does not resolve is written as NULL.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  MARKET_ALIAS_FIELD_IDS,
  aliasMapFrom,
  buildAliasRows,
  laneKeyOf,
  marketLookupKey,
  resolveMarket,
} from '../ingest.mjs';

export const EVIDENCE_QUERY = `SELECT i.evidence_id, json_extract(r.payload_json, '$.origin') AS origin,
  json_extract(r.payload_json, '$.destination') AS destination,
  i.origin_market, i.destination_market, i.lane_key
FROM evidence_index i JOIN raw_evidence r ON r.evidence_id = i.evidence_id
WHERE i.superseded = 0 ORDER BY i.evidence_id`;

export const ALIAS_QUERY = 'SELECT alias_text, market_cluster FROM market_aliases ORDER BY alias_norm';

export function rowsFrom(json) {
  const data = typeof json === 'string' ? JSON.parse(json) : json;
  if (Array.isArray(data) && data.length && Array.isArray(data[0]?.results)) {
    return data.flatMap((part) => part.results);
  }
  if (Array.isArray(data?.results)) return data.results;
  if (Array.isArray(data)) return data;
  throw new Error('expected wrangler d1 --json output or an array of rows');
}

export function aliasMapFromD1(aliasRows) {
  const records = aliasRows.map((row, i) => ({
    id: `d1-alias-${i}`,
    fields: {
      [MARKET_ALIAS_FIELD_IDS.aliasText]: row.alias_text,
      [MARKET_ALIAS_FIELD_IDS.marketCluster]: row.market_cluster,
      [MARKET_ALIAS_FIELD_IDS.resolutionStatus]: 'Verified',
    },
  }));
  return aliasMapFrom(buildAliasRows(records, null));
}

const sql = (v) => (v == null ? 'NULL' : `'${String(v).replace(/'/g, "''")}'`);

export function planRebuild(evidenceRows, aliasMap) {
  const report = {
    evidenceRows: evidenceRows.length,
    mentions: 0,
    realMentions: 0,
    matchedBefore: 0,
    matchedAfter: 0,
    bothResolvedBefore: 0,
    bothResolvedAfter: 0,
    rowsChanged: 0,
    mentionsLost: 0,
    flags: {},
  };
  const statements = [];
  for (const row of evidenceRows) {
    const originMarket = resolveMarket(row.origin, aliasMap);
    const destinationMarket = resolveMarket(row.destination, aliasMap);
    const laneKey = laneKeyOf(originMarket, destinationMarket);
    for (const [textValue, before, after] of [
      [row.origin, row.origin_market ?? null, originMarket],
      [row.destination, row.destination_market ?? null, destinationMarket],
    ]) {
      if (textValue == null || !String(textValue).trim()) continue;
      report.mentions += 1;
      const { flag } = marketLookupKey(textValue);
      if (flag) report.flags[flag] = (report.flags[flag] ?? 0) + 1;
      if (flag === 'UNKNOWN_PLACEHOLDER') continue;
      report.realMentions += 1;
      if (before) report.matchedBefore += 1;
      if (after) report.matchedAfter += 1;
      if (before && !after) report.mentionsLost += 1;
    }
    if (row.origin_market && row.destination_market) report.bothResolvedBefore += 1;
    if (originMarket && destinationMarket) report.bothResolvedAfter += 1;
    const same = (row.origin_market ?? null) === originMarket
      && (row.destination_market ?? null) === destinationMarket
      && (row.lane_key ?? null) === laneKey;
    if (same) continue;
    report.rowsChanged += 1;
    statements.push(`UPDATE evidence_index SET lane_key = ${sql(laneKey)}, origin_market = ${sql(originMarket)}, `
      + `destination_market = ${sql(destinationMarket)} WHERE evidence_id = ${sql(row.evidence_id)} AND superseded = 0 `
      + `AND (lane_key IS NOT ${sql(laneKey)} OR origin_market IS NOT ${sql(originMarket)} `
      + `OR destination_market IS NOT ${sql(destinationMarket)});`);
  }
  return { report, statements };
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
}

export function main(argv = process.argv.slice(2), log = console.log) {
  if (argv.includes('--print-queries')) {
    log(`-- evidence\n${EVIDENCE_QUERY};\n-- aliases\n${ALIAS_QUERY};`);
    return 0;
  }
  const evidencePath = arg(argv, '--evidence');
  const aliasPath = arg(argv, '--aliases');
  if (!evidencePath || !aliasPath) {
    log('usage: rebuild-evidence-markets.mjs --evidence evidence.json --aliases aliases.json [--out rebuild.sql] | --print-queries');
    return 2;
  }
  const aliasMap = aliasMapFromD1(rowsFrom(readFileSync(aliasPath, 'utf8')));
  const { report, statements } = planRebuild(rowsFrom(readFileSync(evidencePath, 'utf8')), aliasMap);
  log(JSON.stringify({ aliasKeys: aliasMap.size, ...report, statements: statements.length }, null, 2));
  const out = arg(argv, '--out');
  if (out) {
    writeFileSync(out, statements.length ? `${statements.join('\n')}\n` : '-- nothing to change\n');
    log(`wrote ${statements.length} statement(s) to ${out}`);
  } else {
    log('dry run: no SQL written (pass --out FILE to write it)');
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main();
}
