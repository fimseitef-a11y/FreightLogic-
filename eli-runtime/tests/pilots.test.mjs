import test from 'node:test';
import assert from 'node:assert/strict';

import { revalidatePilotSet } from '../pilots.mjs';

const EXPECTED_UNKNOWN_FLAGS = Object.freeze([
  'INSUFFICIENT_OBSERVATIONS',
  'EQUIPMENT_RELEVANCE_UNRESOLVED',
  'EXPOSURE_DENOMINATOR_MISSING',
]);

const PILOTS = Object.freeze([
  { laneId: 'PILOT-MKT-DTW-TO-MKT-ATL', originMarket: 'MKT-DTW', destinationMarket: 'MKT-ATL', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
  { laneId: 'PILOT-MKT-ATL-TO-MKT-DTW', originMarket: 'MKT-ATL', destinationMarket: 'MKT-DTW', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
  { laneId: 'PILOT-MKT-ATL-TO-MKT-BNA', originMarket: 'MKT-ATL', destinationMarket: 'MKT-BNA', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
  { laneId: 'PILOT-MKT-BNA-TO-MKT-ATL', originMarket: 'MKT-BNA', destinationMarket: 'MKT-ATL', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
  { laneId: 'PILOT-MKT-BNA-TO-MKT-DTW', originMarket: 'MKT-BNA', destinationMarket: 'MKT-DTW', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
  { laneId: 'PILOT-MKT-DTW-TO-MKT-BNA', originMarket: 'MKT-DTW', destinationMarket: 'MKT-BNA', stage: 'Pilot Candidate', unknownFlags: EXPECTED_UNKNOWN_FLAGS },
]);

test('six-pilot harness preserves the exact frozen ATL/BNA/DTW directional set', () => {
  const result = revalidatePilotSet({
    pilots: PILOTS,
    snapshotFingerprint: 'snapshot-v1',
    modelVersion: 'eli-v1',
    resolvedEvidenceByLane: {},
  });

  assert.equal(result.length, 6);
  assert.deepEqual(result.map((lane) => lane.laneId).sort(), PILOTS.map((lane) => lane.laneId).sort());
});

test('unresolved equipment/exposure evidence remains Pilot Candidate with explicit UNKNOWN flags', () => {
  const result = revalidatePilotSet({
    pilots: PILOTS,
    snapshotFingerprint: 'snapshot-v1',
    modelVersion: 'eli-v1',
    resolvedEvidenceByLane: {},
  });

  for (const lane of result) {
    assert.equal(lane.stage, 'Pilot Candidate');
    assert.equal(lane.promotionEligible, false);
    assert.equal(lane.snapshotFingerprint, 'snapshot-v1');
    assert.equal(lane.modelVersion, 'eli-v1');
    for (const flag of EXPECTED_UNKNOWN_FLAGS) assert.ok(lane.unknownFlags.includes(flag));
  }
});

test('partial evidence cannot silently clear unrelated UNKNOWN flags or auto-promote', () => {
  const result = revalidatePilotSet({
    pilots: PILOTS,
    snapshotFingerprint: 'snapshot-v1',
    modelVersion: 'eli-v1',
    resolvedEvidenceByLane: {
      'PILOT-MKT-DTW-TO-MKT-ATL': ['INSUFFICIENT_OBSERVATIONS'],
    },
  });

  const lane = result.find((item) => item.laneId === 'PILOT-MKT-DTW-TO-MKT-ATL');
  assert.equal(lane.stage, 'Pilot Candidate');
  assert.equal(lane.promotionEligible, false);
  assert.equal(lane.unknownFlags.includes('INSUFFICIENT_OBSERVATIONS'), false);
  assert.ok(lane.unknownFlags.includes('EQUIPMENT_RELEVANCE_UNRESOLVED'));
  assert.ok(lane.unknownFlags.includes('EXPOSURE_DENOMINATOR_MISSING'));
});

test('pilot harness rejects a non-frozen route set instead of inventing a seventh pilot', () => {
  assert.throws(
    () => revalidatePilotSet({
      pilots: [...PILOTS, { laneId: 'PILOT-MKT-ATL-TO-MKT-ORD', originMarket: 'MKT-ATL', destinationMarket: 'MKT-ORD', stage: 'Pilot Candidate', unknownFlags: [] }],
      snapshotFingerprint: 'snapshot-v1',
      modelVersion: 'eli-v1',
      resolvedEvidenceByLane: {},
    }),
    /six-pilot|frozen/i,
  );
});
