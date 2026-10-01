export function applyFreshnessToConfidence({ baseConfidence, freshnessState }) {
  const state = freshnessState ?? 'UNAVAILABLE';
  if (!Number.isFinite(baseConfidence) || state === 'STALE' || state === 'UNAVAILABLE') {
    return { value: null, status: 'UNKNOWN', freshnessState: state };
  }

  return { value: baseConfidence, status: 'KNOWN', freshnessState: state };
}
