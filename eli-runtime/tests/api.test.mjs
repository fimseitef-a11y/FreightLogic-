import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  createPrivateApi,
  projectLaneReadModel,
  reconcilePromotion,
} from '../api.mjs';
import { handlePrivateRequest } from '../worker.mjs';

test('lane read-model projection exposes deterministic intelligence but no economics/raw evidence', () => {
  const projected = projectLaneReadModel({
    lane_key: 'DTW|ATL',
    origin_market: 'Detroit / Toledo',
    destination_market: 'Atlanta',
    structural_score: 0.62,
    expedite_relevance: null,
    structural_confidence: 0.8,
    expedite_confidence: null,
    freshness_json: '{"structural":"FRESH","expedite":"UNAVAILABLE"}',
    unknown_flags_json: '["EXPEDITE_EVIDENCE_MISSING"]',
    conflict_flags_json: '[]',
    evidence_counts_json: '{"structural":2,"expedite":0}',
    latest_evidence_at: '2026-09-30T20:00:00Z',
    stage: 'Pilot Candidate',
    model_run_id: 'run-1',
    governance_fingerprint: 'gov-1',
    updated_at: '2026-09-30T20:01:00Z',
    rate: 850,
    raw_evidence_json: '{"private":true}',
  });

  assert.deepEqual(projected, {
    originMarket: 'Detroit / Toledo',
    destinationMarket: 'Atlanta',
    structuralScore: 0.62,
    expediteRelevance: null,
    structuralConfidence: 0.8,
    expediteConfidence: null,
    freshness: { structural: 'FRESH', expedite: 'UNAVAILABLE' },
    unknownFlags: ['EXPEDITE_EVIDENCE_MISSING'],
    conflictFlags: [],
    evidenceCounts: { structural: 2, expedite: 0 },
    latestEvidenceAt: '2026-09-30T20:00:00Z',
    stage: 'Pilot Candidate',
    modelRunId: 'run-1',
    governanceFingerprint: 'gov-1',
    updatedAt: '2026-09-30T20:01:00Z',
  });
  assert.equal(JSON.stringify(projected).includes('850'), false);
  assert.equal(JSON.stringify(projected).includes('private'), false);
});

test('promotion reconciliation fails closed on fingerprint mismatch or absent approval', () => {
  assert.deepEqual(
    reconcilePromotion({
      runtimeGovernanceFingerprint: 'runtime-gov',
      governance: { fingerprint: 'airtable-gov', approved: true, stage: 'Production' },
    }),
    { eligible: false, reason: 'GOVERNANCE_FINGERPRINT_MISMATCH' },
  );

  assert.deepEqual(
    reconcilePromotion({
      runtimeGovernanceFingerprint: 'gov-1',
      governance: { fingerprint: 'gov-1', approved: false, stage: 'Production' },
    }),
    { eligible: false, reason: 'GOVERNANCE_NOT_APPROVED' },
  );
});

test('promotion eligibility requires exact approved Airtable governance match and performs no promotion itself', () => {
  assert.deepEqual(
    reconcilePromotion({
      runtimeGovernanceFingerprint: 'gov-1',
      governance: { fingerprint: 'gov-1', approved: true, stage: 'Production' },
    }),
    { eligible: true, reason: null, approvedStage: 'Production' },
  );
});

test('private API returns UNKNOWN for an unmaterialized lane and safe projections for known lanes', async () => {
  const api = createPrivateApi({
    async getLaneRow(originMarket, destinationMarket) {
      if (originMarket === 'Detroit / Toledo' && destinationMarket === 'Atlanta') {
        return {
          origin_market: originMarket,
          destination_market: destinationMarket,
          structural_score: 0.62,
          expedite_relevance: null,
          structural_confidence: 0.8,
          expedite_confidence: null,
          freshness_json: '{"structural":"FRESH"}',
          unknown_flags_json: '["EXPEDITE_EVIDENCE_MISSING"]',
          conflict_flags_json: '[]',
          evidence_counts_json: '{"structural":2}',
          latest_evidence_at: '2026-09-30T20:00:00Z',
          stage: 'Pilot Candidate',
          model_run_id: 'run-1',
          governance_fingerprint: 'gov-1',
          updated_at: '2026-09-30T20:01:00Z',
        };
      }
      return null;
    },
    async getMarketRows() { return []; },
    async getHealthSnapshot() { return { schemaVersion: '1', serviceVersion: 'eli-v1', sourceHealthCounts: { healthy: 3 } }; },
  });

  const known = await api.getLaneIntelligence({ originMarket: 'Detroit / Toledo', destinationMarket: 'Atlanta' });
  assert.equal(known.status, 'KNOWN');
  assert.equal(known.intelligence.structuralScore, 0.62);

  const missing = await api.getLaneIntelligence({ originMarket: 'Detroit / Toledo', destinationMarket: 'Nowhere' });
  assert.deepEqual(missing, {
    status: 'UNKNOWN',
    reason: 'LANE_NOT_MATERIALIZED',
    originMarket: 'Detroit / Toledo',
    destinationMarket: 'Nowhere',
  });

  assert.deepEqual(await api.health(), {
    schemaVersion: '1',
    serviceVersion: 'eli-v1',
    sourceHealthCounts: { healthy: 3 },
  });
});

test('private request handler rejects unsupported paths and serves service-binding lane requests', async () => {
  const api = {
    async getLaneIntelligence(input) { return { status: 'KNOWN', input }; },
    async getMarketIntelligence(input) { return { status: 'KNOWN', input }; },
    async health() { return { status: 'ok' }; },
  };

  const unknown = await handlePrivateRequest(new Request('https://eli.invalid/public'), {}, api);
  assert.equal(unknown.status, 404);

  const lane = await handlePrivateRequest(new Request('https://eli.invalid/internal/lane', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ originMarket: 'Detroit / Toledo', destinationMarket: 'Atlanta' }),
  }), {}, api);
  assert.equal(lane.status, 200);
  assert.deepEqual(await lane.json(), {
    status: 'KNOWN',
    input: { originMarket: 'Detroit / Toledo', destinationMarket: 'Atlanta' },
  });
});

test('Wrangler config is dark/private with no public route', async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const config = await readFile(resolve(here, '../wrangler.jsonc'), 'utf8');

  assert.match(config, /"workers_dev"\s*:\s*false/);
  assert.match(config, /"preview_urls"\s*:\s*false/);
  assert.doesNotMatch(config, /"routes?"\s*:/);
});
