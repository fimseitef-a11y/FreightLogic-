const FROZEN_PILOT_IDS = Object.freeze([
  'PILOT-MKT-DTW-TO-MKT-ATL',
  'PILOT-MKT-ATL-TO-MKT-DTW',
  'PILOT-MKT-ATL-TO-MKT-BNA',
  'PILOT-MKT-BNA-TO-MKT-ATL',
  'PILOT-MKT-BNA-TO-MKT-DTW',
  'PILOT-MKT-DTW-TO-MKT-BNA',
]);

function sameFrozenSet(pilots) {
  if (!Array.isArray(pilots) || pilots.length !== FROZEN_PILOT_IDS.length) return false;
  const actual = [...new Set(pilots.map((pilot) => pilot?.laneId))].sort();
  return actual.length === FROZEN_PILOT_IDS.length
    && actual.every((laneId, index) => laneId === [...FROZEN_PILOT_IDS].sort()[index]);
}

export function revalidatePilotSet({ pilots, snapshotFingerprint, modelVersion, resolvedEvidenceByLane = {} } = {}) {
  if (!sameFrozenSet(pilots)) {
    throw new Error('six-pilot frozen route set is required');
  }
  if (!snapshotFingerprint) throw new Error('snapshotFingerprint is required');
  if (!modelVersion) throw new Error('modelVersion is required');

  return pilots.map((pilot) => {
    const currentFlags = Array.isArray(pilot.unknownFlags) ? [...pilot.unknownFlags] : [];
    const resolvedFlags = new Set(
      Array.isArray(resolvedEvidenceByLane[pilot.laneId])
        ? resolvedEvidenceByLane[pilot.laneId]
        : [],
    );
    const unknownFlags = currentFlags.filter((flag) => !resolvedFlags.has(flag));

    return {
      laneId: pilot.laneId,
      originMarket: pilot.originMarket,
      destinationMarket: pilot.destinationMarket,
      stage: pilot.stage === 'Pilot Candidate' ? 'Pilot Candidate' : pilot.stage,
      unknownFlags,
      snapshotFingerprint,
      modelVersion,
      promotionEligible: false,
    };
  });
}

export { FROZEN_PILOT_IDS };
