// output-guard.mjs
// Deterministically verifies model prose against canonical FreightLogic facts.

const VERDICT_WORDS = ["ACCEPT", "REJECT", "COUNTER", "HOLD"];
const MONEY_PATTERN = /\$\s?[\d,]+(?:\.\d+)?|\b[\d,]+(?:\.\d+)?\s*(?:dollars?|\/\s?mi(?:le)?|per\s+mile)\b/gi;
const PER_MILE_PATTERN = /(?:\/\s?mi(?:le)?|per\s+mile)\b/i;
const RELATIVE_TOLERANCE = 0.01;

function extractMoneyClaims(text) {
  const matches = text.match(MONEY_PATTERN) || [];
  return matches.map((raw) => ({
    raw,
    value: Number(raw.replace(/[^0-9.]/g, "")),
    dimension: PER_MILE_PATTERN.test(raw) ? "per_mile" : "total",
  })).filter((claim) => Number.isFinite(claim.value));
}

function extractVerdictClaims(text) {
  const upper = text.toUpperCase();
  return VERDICT_WORDS.filter((word) => new RegExp(`\\b${word}\\b`).test(upper));
}

function canonicalMoneyValues(calculation, dimension) {
  if (!calculation || typeof calculation !== "object") return [];
  const fields = dimension === "per_mile"
    ? ["trueRpm", "loadedRpm", "costPerMile"]
    : ["baselineBid", "marketBid", "fuelCost", "deadheadCost"];
  return fields.map((field) => calculation[field])
    .filter((value) => typeof value === "number" && Number.isFinite(value));
}

function numberIsCanonical(value, canonicalValues) {
  return canonicalValues.some((canonical) => (
    Math.abs(value - canonical) <= Math.max(0.01, Math.abs(canonical) * RELATIVE_TOLERANCE)
  ));
}

function hasNegatedVerdict(text, verdict) {
  if (!verdict) return false;
  const escaped = verdict.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\b(?:do\\s+not|don't|dont|never|not)\\s+${escaped}\\b`, "i").test(text);
}

export class OutputGuardError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "OutputGuardError";
    this.code = code;
    this.detail = detail;
  }
}

export function checkRecommendationAgainstCanonical(recommendation, calculation) {
  if (typeof recommendation !== "string" || !recommendation.trim()) {
    throw new OutputGuardError("GUARD_EMPTY_RECOMMENDATION", "Recommendation is empty");
  }

  const claims = extractMoneyClaims(recommendation);
  const foreignClaims = claims.filter((claim) => (
    !numberIsCanonical(claim.value, canonicalMoneyValues(calculation, claim.dimension))
  ));
  if (foreignClaims.length > 0) {
    throw new OutputGuardError(
      "GUARD_NONCANONICAL_DOLLAR_VALUE",
      "Recommendation references a monetary value outside the matching canonical dimension",
      { foreignClaims },
    );
  }

  const canonicalVerdict = typeof calculation?.verdict === "string"
    ? calculation.verdict.toUpperCase()
    : null;
  const claimedVerdicts = extractVerdictClaims(recommendation);
  const contradicting = canonicalVerdict
    ? claimedVerdicts.filter((verdict) => verdict !== canonicalVerdict)
    : [];
  if (canonicalVerdict && hasNegatedVerdict(recommendation, canonicalVerdict)) {
    contradicting.push(`NOT_${canonicalVerdict}`);
  }

  if (contradicting.length > 0) {
    throw new OutputGuardError(
      "GUARD_VERDICT_CONTRADICTION",
      "Recommendation states or negates a verdict contrary to the canonical verdict",
      { canonicalVerdict, contradicting },
    );
  }

  return { ok: true };
}

export function assertSafeRecommendation(recommendation, calculation) {
  try {
    checkRecommendationAgainstCanonical(recommendation, calculation);
  } catch (error) {
    if (error instanceof OutputGuardError) throw error;
    throw new OutputGuardError("GUARD_INTERNAL_ERROR", "Output guard failed to evaluate recommendation");
  }
}
