const FRESHNESS_STATES = new Set(['FRESH', 'AGING', 'STALE', 'UNAVAILABLE']);

export function normalizeEvidence(input = {}) {
  const value = Number.isFinite(input.value) ? input.value : null;
  const asOf = input.asOf ? String(input.asOf) : null;
  const freshnessState = FRESHNESS_STATES.has(input.freshnessState)
    ? input.freshnessState
    : (asOf ? 'AGING' : 'UNAVAILABLE');

  return {
    sourceClass: input.sourceClass ?? null,
    sourceId: input.sourceId ?? null,
    component: input.component ?? null,
    value,
    asOf,
    freshnessState,
    eligible: input.eligible !== false,
  };
}
