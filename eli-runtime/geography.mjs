const STABLE_BOUNDARY_STATUS = 'Stable Candidate';

function unknown(reason) {
  return { status: 'UNKNOWN', marketCluster: null, reason };
}

export function resolveFaf6Market(faf6ZoneId, geographyRows = []) {
  if (!Array.isArray(geographyRows)) {
    throw new TypeError('geographyRows must be an array');
  }

  const zone = faf6ZoneId == null ? '' : String(faf6ZoneId).trim();
  const matches = geographyRows.filter(
    (row) => row && String(row.faf6ZoneId ?? '').trim() === zone,
  );

  if (!zone || matches.length === 0) return unknown('FAF6_ZONE_UNMAPPED');

  if (matches.some((row) => row.boundarySensitivityStatus !== STABLE_BOUNDARY_STATUS)) {
    return unknown('BOUNDARY_SENSITIVE');
  }

  const markets = [...new Set(matches.map((row) => row.marketCluster).filter(Boolean))];
  if (markets.length !== 1) return unknown('MARKET_MAPPING_CONFLICT');

  const versions = [...new Set(matches.map((row) => row.geographyVersion).filter(Boolean))];
  if (versions.length !== 1) return unknown('GEOGRAPHY_VERSION_CONFLICT');

  return {
    status: 'KNOWN',
    marketCluster: markets[0],
    geographyVersion: versions[0],
    boundarySensitivityStatus: STABLE_BOUNDARY_STATUS,
  };
}
