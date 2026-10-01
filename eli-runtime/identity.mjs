function normalizePart(value) {
  if (value === undefined || value === null || value === '') return '<unknown>';
  return String(value).trim().replace(/\s+/g, ' ').toLowerCase();
}

export function buildEvidenceIdentity(observation = {}) {
  const parts = [
    normalizePart(observation.platform),
    normalizePart(observation.lineage),
    normalizePart(observation.postingId),
    normalizePart(observation.origin),
    normalizePart(observation.destination),
    normalizePart(observation.pickup),
  ];

  return parts.join('|');
}
