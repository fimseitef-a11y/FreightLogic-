// Reject impossible civil dates, rollover times and future evidence.
// Date.parse alone normalizes several invalid dates into apparently fresh facts.
function validSourceTimeISO(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2}))?$/.exec(value);
  if (!match || !Number.isFinite(Date.parse(value))) return false;
  const [, y, m, d, hh, mm, ss, , zone] = match;
  const civil = new Date(0);
  civil.setUTCFullYear(Number(y), Number(m) - 1, Number(d));
  civil.setUTCHours(0, 0, 0, 0);
  if (civil.getUTCFullYear() !== Number(y) || civil.getUTCMonth() + 1 !== Number(m)
    || civil.getUTCDate() !== Number(d)) return false;
  if (hh !== undefined && (Number(hh) > 23 || Number(mm) > 59 || Number(ss) > 59)) return false;
  if (zone && zone !== 'Z') {
    const hours = Number(zone.slice(1, 3)), minutes = Number(zone.slice(4, 6));
    if (hours > 14 || minutes > 59 || (hours === 14 && minutes !== 0)) return false;
  }
  return true;
}

export function classifyFreshness({ sourceAsOf, now, freshForMs, staleAfterMs }) {
  if (!sourceAsOf) return 'UNAVAILABLE';
  if (!Number.isFinite(freshForMs) || !Number.isFinite(staleAfterMs) || freshForMs < 0 || staleAfterMs < freshForMs) {
    throw new TypeError('valid freshness thresholds are required');
  }
  if (!validSourceTimeISO(sourceAsOf) || !validSourceTimeISO(now)) return 'UNAVAILABLE';
  const ageMs = Date.parse(now) - Date.parse(sourceAsOf);
  if (ageMs < 0) return 'UNAVAILABLE';
  if (ageMs <= freshForMs) return 'FRESH';
  if (ageMs <= staleAfterMs) return 'AGING';
  return 'STALE';
}
