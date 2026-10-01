import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveFaf6Market } from '../geography.mjs';
import {
  LOAD_HISTORY_TABLE_ID,
  LOAD_HISTORY_FIELD_IDS,
  getLoadHistoryReadFieldIds,
  projectLoadHistoryRecord,
} from '../adapters/airtable-load-history.mjs';

test('FAF6 stable candidate resolves through Geography to a market cluster', () => {
  const result = resolveFaf6Market('123', [
    {
      marketCluster: 'Detroit / Toledo',
      faf6ZoneId: '123',
      geographyVersion: 'geo-v1',
      boundarySensitivityStatus: 'Stable Candidate',
    },
  ]);

  assert.deepEqual(result, {
    status: 'KNOWN',
    marketCluster: 'Detroit / Toledo',
    geographyVersion: 'geo-v1',
    boundarySensitivityStatus: 'Stable Candidate',
  });
});

test('FAF6 ambiguous or pending boundary mapping remains UNKNOWN', () => {
  const ambiguous = resolveFaf6Market('123', [
    {
      marketCluster: 'Detroit / Toledo',
      faf6ZoneId: '123',
      geographyVersion: 'geo-v1',
      boundarySensitivityStatus: 'Ambiguous',
    },
  ]);
  const missing = resolveFaf6Market('999', []);

  assert.equal(ambiguous.status, 'UNKNOWN');
  assert.equal(ambiguous.marketCluster, null);
  assert.equal(ambiguous.reason, 'BOUNDARY_SENSITIVE');
  assert.equal(missing.reason, 'FAF6_ZONE_UNMAPPED');
});

test('FAF6 zone mapping to multiple markets fails closed as UNKNOWN', () => {
  const result = resolveFaf6Market('123', [
    { marketCluster: 'Detroit', faf6ZoneId: '123', geographyVersion: 'geo-v1', boundarySensitivityStatus: 'Stable Candidate' },
    { marketCluster: 'Toledo', faf6ZoneId: '123', geographyVersion: 'geo-v1', boundarySensitivityStatus: 'Stable Candidate' },
  ]);

  assert.equal(result.status, 'UNKNOWN');
  assert.equal(result.reason, 'MARKET_MAPPING_CONFLICT');
});

test('Load History adapter is pinned to the actual authoritative table and excludes rate fields from reads', () => {
  assert.equal(LOAD_HISTORY_TABLE_ID, 'tbl6Wof9SlTVotCEa');
  const fields = getLoadHistoryReadFieldIds();

  assert.ok(fields.includes(LOAD_HISTORY_FIELD_IDS.loadId));
  assert.ok(fields.includes(LOAD_HISTORY_FIELD_IDS.source));
  assert.ok(fields.includes(LOAD_HISTORY_FIELD_IDS.statusLayer));
  assert.ok(!fields.includes('fldPhU0heXzHAqiFl'));
  assert.ok(!fields.includes('fld45LT2qeqE1FzMP'));
});

test('Load History projection preserves source/status layers and UNKNOWN deadhead while excluding economics', () => {
  const projected = projectLoadHistoryRecord({
    id: 'recExample',
    cellValuesByFieldId: {
      fldcn3ICJoHqh4cul: '#1242331',
      fldOLL5VAvhn4aij6: { id: 'sel6a7JtoUXLWHGoN', name: 'DispatchLand' },
      fldr421BJuQAedLrO: { id: 'selzKqUL9z74UhOnA', name: 'Board / Listing' },
      fldN33xbzUlNNmRE1: 'Hialeah, FL',
      fld60hboskYKlnq1P: 'Gloucester City, NJ',
      fldVznCz7rFq4ggWW: 1200,
      fldHj8pfXD6ixiNdw: null,
      fldBtvJkAaTqmqM2y: '2026-09-29 ASAP',
      fldoHpqhBU1VQ8YyI: '2026-10-01 08:00 ET',
      fldC4kvfowRLhh4ts: 500,
      fldmRqT3o2dH8tQHJ: '1 pallet',
      fldNuXG7snnZjyxcD: { id: 'sel0DxjTTPem6pfrx', name: 'None known' },
      fldrNpmORWv0TBdIR: '',
      fld8rWQILiis5rnxl: '2026-09-30',
      fldPhU0heXzHAqiFl: 850,
      fld45LT2qeqE1FzMP: { name: 'Agreed' },
    },
  });

  assert.deepEqual(projected, {
    airtableRecordId: 'recExample',
    loadId: '#1242331',
    source: 'DispatchLand',
    statusLayer: 'Board / Listing',
    origin: 'Hialeah, FL',
    destination: 'Gloucester City, NJ',
    loadedMiles: 1200,
    emptyMiles: null,
    pickup: '2026-09-29 ASAP',
    delivery: '2026-10-01 08:00 ET',
    weightLb: 500,
    pieces: '1 pallet',
    duplicateRepost: 'None known',
    relatedLoadIds: null,
    evidenceDate: '2026-09-30',
  });
  assert.equal(Object.hasOwn(projected, 'rate'), false);
  assert.equal(Object.hasOwn(projected, 'rateType'), false);
});
