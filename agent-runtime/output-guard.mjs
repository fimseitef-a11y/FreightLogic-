// output-guard.mjs
// Verifies an Agent recommendation against the canonical snapshot before it
// is allowed to reach a driver. This is a deterministic, non-model check.
//
// Why this exists: Phase A audit (2026-09-28) found that model text could
// contain a dollar figure or verdict that contradicts the canonical
// calculation (e.g. model says "REJECT, bid $9000/mi" while calculation.verdict
// is ACCEPT and baselineBid is 500), and the worker returned it as ok:true
// with no check. This module closes that gap. It does not change routing,
// idempotency, or privacy logic — it is inserted as one call right before the
// worker returns a model-derived recommendation to the caller.

const VERDICT_WORDS = ["ACCEPT", "REJECT", "COUNTER", "HOLD"];

// Matches $1234, $1,234.56, $1234.5, "1234 dollars", "1234 per mile", "9000/mi"
const MONEY_PATTERN = /\$\s?[\d,]+(?:\.\d+)?|\b[\d,]+(?:\.\d+)?\s*(?:dollars?|\/\s?mi(?:le)?|per\s+mile)\b/gi;

function extractNumbers(text) {
  const matches = text.match(MONEY_PATTERN) || [];
  return matches
    .map((m) => m.replace(/[^0-9.]/g, ""))
    .filter((m) => m.length > 0)
    .map(Number)
    .filter((n) => Number.isFinite(n));
}

function extractVerdictClaims(text) {
  const upper = text.toUpperCase();
  return VERDICT_WORDS.filter((word) => new RegExp(`\\b${word}\\b`).test(upper));
}

// Canonical dollar figures this recommendation is allowed to reference,
// pulled only from the allowlisted canonical fields already validated by
// contracts.mjs (SAFE_CANONICAL_FIELDS / MODEL_CANONICAL_FIELDS).
function canonicalDollarValues(calculation) {
  if (!calculation || typeof calculation !== "object") return [];
  const fields = ["baselineBid", "marketBid", "costPerMile", "fuelCost", "deadheadCost"];
  return fields
    .map((f) => calculation[f])
    .filter((v) => typeof v === "number" && Number.isFinite(v));
}

// A small relative tolerance absorbs rounding in the model's prose
// ("about $500" for 500.00) without opening the door to a fabricated
// nearby number.
const RELATIVE_TOLERANCE = 0.01; // 1%

function numberIsCanonical(n, canonicalValues) {
  return canonicalValues.some((c) => Math.abs(n - c) <= Math.max(1, c * RELATIVE_TOLERANCE));
}

export class OutputGuardError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "OutputGuardError";
    this.code = code;
    this.detail = detail;
  }
}

/**
 * Throws OutputGuardError if the recommendation text contradicts the
 * canonical snapshot. Returns { ok: true } if the text is safe to return.
 *
 * @param {string} recommendation - model output text
 * @param {object} calculation - envelope.canonicalSnapshot (already validated
 *   upstream by contracts.mjs)
 */
export function checkRecommendationAgainstCanonical(recommendation, calculation) {
  if (typeof recommendation !== "string" || !recommendation.trim()) {
    throw new OutputGuardError("GUARD_EMPTY_RECOMMENDATION", "Recommendation is empty");
  }

  const canonicalValues = canonicalDollarValues(calculation);
  const mentionedNumbers = extractNumbers(recommendation);
  const foreignNumbers = mentionedNumbers.filter((n) => !numberIsCanonical(n, canonicalValues));

  if (foreignNumbers.length > 0) {
    throw new OutputGuardError(
      "GUARD_NONCANONICAL_DOLLAR_VALUE",
      "Recommendation references a dollar figure not present in the canonical calculation",
      { foreignNumbers, canonicalValues },
    );
  }

  const canonicalVerdict = typeof calculation?.verdict === "string" ? calculation.verdict.toUpperCase() : null;
  const claimedVerdicts = extractVerdictClaims(recommendation);
  const contradicting = canonicalVerdict
    ? claimedVerdicts.filter((v) => v !== canonicalVerdict)
    : [];

  if (contradicting.length > 0) {
    throw new OutputGuardError(
      "GUARD_VERDICT_CONTRADICTION",
      "Recommendation states a verdict that contradicts the canonical verdict",
      { canonicalVerdict, contradicting },
    );
  }

  return { ok: true };
}

/**
 * Convenience wrapper matching the shape worker.mjs already uses for
 * ModelExecutionError, so the integration is a single try/catch addition.
 * See the worker integration call site.
 */
export function assertSafeRecommendation(recommendation, calculation) {
  try {
    checkRecommendationAgainstCanonical(recommendation, calculation);
  } catch (error) {
    if (error instanceof OutputGuardError) throw error;
    throw new OutputGuardError("GUARD_INTERNAL_ERROR", "Output guard failed to evaluate recommendation");
  }
}
