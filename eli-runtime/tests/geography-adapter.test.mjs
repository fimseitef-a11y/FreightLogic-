import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveFaf6Market } from '../geography.mjs';
import {
  LOAD_HISTORY_FIELD_IDS,
  projectLoadHistoryRecord,
} from '../adapters/airtable-load-history.mjs';

test('FAF6 zone resolves only when one non-sensitive market mapping is supported', () => {
  const result = resolveFaf6Market('132', [
    {
      geoId: 'geo-atl-1',
      marketCluster: 'ATL',
      faf6ZoneId: '132',
      boundarySensitivityStatus: 'CLEAR',
      geographyVersion: 'geo-v1',
    },
  ]);

  assert.deepEqual(result, {
    status: 'KNOWN',
    marketCluster: 'ATL',
    faf6ZoneId: '132',
    geographyVersion: 'geo-v1',
    boundarySensitivityStatus: 'CLEAR',
    evidenceGeoIds: ['geo-atl-1'],
  });
});

test('boundary-sensitive FAF6 mapping remains UNKNOWN instead of silently choosing a market', () => {
  const result = resolveFaf6Market('132', [
    {
      geoId: 'geo-atl-edge',
      marketCluster: 'ATL',
      faf6ZoneId: '132',
      boundarySensitivityStatus: 'SENSITIVE',
      geographyVersion: 'geo-v1',
    },
  ]);

  assert.equal(result.status, 'UNKNOWN');
  assert.equal(result.marketCluster, null);
  assert.equal(result.reason, 'BOUNDARY_SENSITIVE');
});

test('conflicting FAF6-to-market mappings remain UNKNOWN', () => {
  const result = resolveFaf6Market('132', [
    { geoId: 'geo-a', marketCluster: 'ATL', faf6ZoneId: '132', boundarySensitivityStatus: 'CLEAR', geographyVersion: 'geo-v1' },
    { geoId: 'geo-b', marketCluster: 'BNA', faf6ZoneId: '132', boundarySensitivityStatus: 'CLEAR', geographyVersion: 'geo-v1' },
  ]);

  assert.equal(result.status, 'UNKNOWN');
  assert.equal(result.marketCluster, null);
  assert.equal(result.reason, 'AMBIGUOUS_MARKET_MAPPING');
});

test('unknown FAF6 zone remains UNKNOWN', () => {
  const result = resolveFaf6Market('999', []);
  assert.equal(result.status, 'UNKNOWN');
  assert.equal(result.marketCluster, null);
  assert.equal(result.reason, 'NO_GEOGRAPHY_MAPPING');
});

test('Load History adapter preserves status and unknown deadhead while excluding economics', () => {
  const cells = {
    [LOAD_HISTORY_FIELD_IDS.loadId]: '3350787',
    [LOAD_HISTORY_FIELD_IDS.source]: { name: 'Safe Capital Group' },
    [LOAD_HISTORY_FIELD_IDS.status]: { name: 'IN PROGRESS' },
    [LOAD_HISTORY_FIELD_IDS.origin]: 'Hialeah, FL',
    [LOAD_HISTORY_FIELD_IDS.destination]: 'Gloucester City, NJ',
    [LOAD_HISTORY_FIELD_IDS.loadedMiles]: 0,
    [LOAD_HISTORY_FIELD_IDS.emptyMiles]: null,
    [LOAD_HISTORY_FIELD_IDS.pickup]: '2026-09-29 ASAP',
    [LOAD_HISTORY_FIELD_IDS.delivery]: '2026-10-01 08:00 ET',
    [LOAD_HISTORY_FIELD_IDS.weightLb]: 500,
    [LOAD_HISTORY_FIELD_IDS.pieces]: '1',
    [LOAD_HISTORY_FIELD_IDS.duplicateRepost]: { name: 'No' },
    [LOAD_HISTORY_FIELD_IDS.relatedLoadIds]: '',
    [LOAD_HISTORY_FIELD_IDS.evidenceDate]: '2026-09-30',
    [LOAD_HISTORY_FIELD_IDS.rate]: 850,
    [LOAD_HISTORY_FIELD_IDS.rateType]: { name: 'Flat' },
    [LOAD_HISTORY_FIELD_IDS.notes]: 'private notes that must not cross the adapter',
  };

  const projected = projectLoadHistoryRecord({ id: 'rec-load', cellValuesByFieldId: cells });

  assert.equal(projected.status, 'IN PROGRESS');
  assert.equal(projected.deadheadMiles, null);
  assert.equal(projected.loadedMiles, 0);
  assert.equal(projected.loadId, '3350787');
  assert.equal(projected.source, 'Safe Capital Group');
  assert.equal(Object.hasOwn(projected, 'rate'), false);
  assert.equal(Object.hasOwn(projected, 'rateType'), false);
  assert.equal(Object.hasOwn(projected, 'notes'), false);
  assert.equal(JSON.stringify(projected).includes('850'), false);
  assert.equal(JSON.stringify(projected).includes('private notes'), false);
});

test('Load History adapter never converts missing deadhead to zero', () => {
  const projected = projectLoadHistoryRecord({
    id: 'rec-unknown-dh',
    cellValuesByFieldId: {
      [LOAD_HISTORY_FIELD_IDS.loadId]: 'listing-1',
      [LOAD_HISTORY_FIELD_IDS.status]: { name: 'BOARD / LISTING' },
      [LOAD_HISTORY_FIELD_IDS.emptyMiles]: undefined,
    },
  });

  assert.equal(projected.deadheadMiles, null);
  assert.equal(projected.status, 'BOARD / LISTING');
});
