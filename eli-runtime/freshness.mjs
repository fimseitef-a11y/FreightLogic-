export function classifyFreshness({ sourceAsOf, now, freshForMs, staleAfterMs }) {
  if (!sourceAsOf) return 'UNAVAILABLE';
  if (!Number.isFinite(freshForMs) || !Number.isFinite(staleAfterMs) || freshForMs < 0 || staleAfterMs < freshForMs) {
    throw new TypeError('valid freshness thresholds are required');
  }

  const sourceMs = Date.parse(sourceAsOf);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(nowMs)) return 'UNAVAILABLE';

  const ageMs = Math.max(0, nowMs - sourceMs);
  if (ageMs <= freshForMs) return 'FRESH';
  if (ageMs <= staleAfterMs) return 'AGING';
  return 'STALE';
}
