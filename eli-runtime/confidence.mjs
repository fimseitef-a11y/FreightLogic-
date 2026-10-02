export function applyFreshnessToConfidence({ baseConfidence, freshnessState }) {
  const state = ['FRESH', 'AGING', 'STALE', 'UNAVAILABLE'].includes(freshnessState) ? freshnessState : 'UNAVAILABLE';
  const value = Number.isFinite(baseConfidence) && baseConfidence >= 0 && baseConfidence <= 1 ? baseConfidence : null;
  if (value === null || !['FRESH', 'AGING'].includes(state)) {
    return { value: null, status: 'UNKNOWN', freshnessState: state };
  }
  return { value, status: 'KNOWN', freshnessState: state };
}
