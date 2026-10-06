// FreightLogic document-agent policy — pre-iPhone Review Import boundary.
//
// These are RESPONSIBILITY contracts, not extra authority. The four roles may
// observe or suggest inside the private pipeline, but none can mutate canonical
// trips/expenses/fuel, choose Business vs Personal on the operator's behalf, or
// bypass Review Import. The deterministic app remains the only writer after an
// explicit operator approval.
export const DOCUMENT_AGENT_ROLES = Object.freeze({
  EXTRACTION: Object.freeze({
    responsibility: 'Extract source text/rows with provenance; do not classify.',
    maySuggest: Object.freeze(['text', 'rows', 'sourcePage', 'confidence']),
    canonicalWrite: false,
    requiresReview: true,
  }),
  RECONCILIATION: Object.freeze({
    responsibility: 'Suggest duplicate/link relationships and preserve conflicting evidence.',
    maySuggest: Object.freeze(['duplicateOf', 'matchConfidence', 'provenance']),
    canonicalWrite: false,
    requiresReview: true,
  }),
  CLASSIFICATION: Object.freeze({
    responsibility: 'Suggest Business/Personal/Ignore and expense category; never decide.',
    maySuggest: Object.freeze(['classification', 'category', 'confidence']),
    canonicalWrite: false,
    requiresReview: true,
  }),
  QA_AUDIT: Object.freeze({
    responsibility: 'Flag malformed, contradictory, low-confidence, or unsafe candidates.',
    maySuggest: Object.freeze(['issues', 'confidence', 'rejectReason']),
    canonicalWrite: false,
    requiresReview: true,
  }),
});

export function documentRolePolicy(role) {
  const id = String(role || '').toUpperCase();
  return DOCUMENT_AGENT_ROLES[id] || null;
}

export function documentRoleMayWriteCanonical(role) {
  return documentRolePolicy(role)?.canonicalWrite === true;
}

function validIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ''))) return false;
  const [y,m,d] = String(value).split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

// This helper models the ONLY policy gate a Review Import UI may use before
// calling the app's existing typed expense writer. It does not perform a write.
export function reviewImportWriteAuthority(candidate = {}) {
  if (candidate.approved !== true) return { canWrite:false, reason:'REVIEW_REQUIRED' };
  if (String(candidate.classification || '').toUpperCase() !== 'BUSINESS') {
    return { canWrite:false, reason:'BUSINESS_ONLY' };
  }
  if (!validIsoDate(candidate.date)) return { canWrite:false, reason:'INVALID_DATE' };
  if (typeof candidate.amount !== 'number' || !Number.isFinite(candidate.amount) || candidate.amount <= 0) {
    return { canWrite:false, reason:'INVALID_AMOUNT' };
  }
  if (candidate.duplicate === true && candidate.duplicateConfirmed !== true) {
    return { canWrite:false, reason:'DUPLICATE_REQUIRES_CONFIRMATION' };
  }
  return { canWrite:true, reason:'EXPLICIT_REVIEW_APPROVAL' };
}
