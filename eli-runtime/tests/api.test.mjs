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
    brokerContact: 'private@example.com',
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
  assert.equal(Object.hasOwn(projected, 'rate'), false);
  assert.equal(Object.hasOwn(projected, 'brokerContact'), false);
  assert.equal(Object.hasOwn(projected, 'rawEvidence'), false);
});

test('promotion reconciliation fails closed on shadow mode, mismatch, or absent approval', () => {
  assert.deepEqual(
    reconcilePromotion({ runMode: 'SHADOW', runtimeGovernanceFingerprint: 'gov-1', governance: { fingerprint: 'gov-1', approved: true, stage: 'Production' } }),
    { eligible: false, reason: 'SHADOW_RUN' },
  );
  assert.deepEqual(
    reconcilePromotion({ runMode: 'ACTIVE', runtimeGovernanceFingerprint: 'runtime-gov', governance: { fingerprint: 'airtable-gov', approved: true, stage: 'Production' } }),
    { eligible: false, reason: 'GOVERNANCE_FINGERPRINT_MISMATCH' },
  );
  assert.deepEqual(
    reconcilePromotion({ runMode: 'ACTIVE', runtimeGovernanceFingerprint: 'gov-1', governance: { fingerprint: 'gov-1', approved: false, stage: 'Production' } }),
    { eligible: false, reason: 'GOVERNANCE_NOT_APPROVED' },
  );
});

test('promotion eligibility requires exact approved Airtable governance match and performs no promotion itself', () => {
  assert.deepEqual(
    reconcilePromotion({ runMode: 'ACTIVE', runtimeGovernanceFingerprint: 'gov-1', governance: { fingerprint: 'gov-1', approved: true, stage: 'Production' } }),
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
          rate: 850,
        };
      }
      return null;
    },
    async getMarketRows() { return []; },
    async getHealthSnapshot() {
      return {
        schemaVersion: '1',
        serviceVersion: 'eli-v1',
        sourceHealthCounts: { healthy: 3 },
        credential: 'must-not-leak',
      };
    },
  });

  const known = await api.getLaneIntelligence({ originMarket: 'Detroit / Toledo', destinationMarket: 'Atlanta' });
  assert.equal(known.status, 'KNOWN');
  assert.equal(known.intelligence.structuralScore, 0.62);
  assert.equal(Object.hasOwn(known.intelligence, 'rate'), false);

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

test('private Worker exposes typed RPC methods only; config has no public route and remains disabled', async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const worker = await readFile(resolve(here, '../worker.mjs'), 'utf8');
  const config = JSON.parse(await readFile(resolve(here, '../wrangler.jsonc'), 'utf8'));

  assert.match(worker, /extends\s+WorkerEntrypoint/);
  assert.doesNotMatch(worker, /\bfetch\s*\(/);
  assert.match(worker, /getLaneIntelligence\s*\(/);
  assert.match(worker, /getMarketIntelligence\s*\(/);
  assert.match(worker, /health\s*\(/);
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal(config.vars.ELI_ENABLED, 'false');
  assert.equal(Object.hasOwn(config, 'routes'), false);
  assert.equal(Object.hasOwn(config, 'route'), false);
});

test('audit: lane and market reads age operator freshness without a new ingest or rewriting provenance', async () => {
  const row = {
    origin_market: 'MKT-ATL', destination_market: 'MKT-DTW',
    freshness_json: '{"OPERATOR_PRIVATE":"FRESH","structural":"UNAVAILABLE"}',
    evidence_counts_json: '{"OPERATOR_COMPLETED":3}', unknown_flags_json: '[]',
    latest_evidence_at: '2026-10-01T12:00:00Z', model_run_id: 'run:audit',
    governance_fingerprint: 'gov:audit', stage: 'Pilot Candidate',
  };
  const before = JSON.stringify(row);
  let current = '2026-10-02T12:00:00Z';
  const api = createPrivateApi({
    async getLaneRow() { return row; }, async getMarketRows() { return [row]; },
  }, { now: () => current });
  for (const [timestamp, state] of [
    ['2026-10-02T12:00:00Z', 'FRESH'], ['2026-10-20T12:00:00Z', 'AGING'],
    ['2026-11-20T12:00:00Z', 'STALE'], ['2026-09-30T12:00:00Z', 'UNAVAILABLE'],
  ]) {
    current = timestamp;
    const lane = (await api.getLaneIntelligence({ originMarket: 'MKT-ATL', destinationMarket: 'MKT-DTW' })).intelligence;
    const market = await api.getMarketIntelligence({ market: 'MKT-ATL' });
    assert.equal(lane.freshness.OPERATOR_PRIVATE, state);
    assert.equal(market.lanes[0].freshness.OPERATOR_PRIVATE, state);
    assert.deepEqual(lane.evidenceCounts, { OPERATOR_COMPLETED: 3 });
    assert.equal(lane.modelRunId, 'run:audit');
    assert.equal(lane.governanceFingerprint, 'gov:audit');
  }
  assert.equal(JSON.stringify(row), before, 'read projection cannot rewrite historical evidence');
});

test('audit: operator freshness fails closed without a valid evidence time; confidence obeys its domain', () => {
  for (const latest_evidence_at of [null, '', '2026-02-30', '2026-11-01']) {
    assert.equal(projectLaneReadModel({
      freshness_json: '{"OPERATOR_PRIVATE":"FRESH"}', latest_evidence_at,
    }, { now: '2026-10-02T12:00:00Z' }).freshness.OPERATOR_PRIVATE, 'UNAVAILABLE');
  }
  for (const value of [-0.1, 1.1, '0.8', Infinity, null]) {
    const row = projectLaneReadModel({ structural_confidence: value, expedite_confidence: value });
    assert.equal(row.structuralConfidence, null);
    assert.equal(row.expediteConfidence, null);
  }
  assert.equal(projectLaneReadModel({ structural_confidence: 0 }).structuralConfidence, 0);
  assert.equal(projectLaneReadModel({ expedite_confidence: 1 }).expediteConfidence, 1);
});
