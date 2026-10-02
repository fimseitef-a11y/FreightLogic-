// output-guard.mjs
// Deterministically verifies model prose against canonical FreightLogic facts.

const VERDICT_WORDS = ["ACCEPT", "REJECT", "COUNTER", "HOLD"];
// Keep currency and its unit in one claim; "$500/mi" is not "$500" total.
const MONEY_PATTERN = /[+-]?\$\s*[+-]?[\d,.]+(?:e[+-]?\d+)?(?:\s*(?:\/\s*[a-z]+|per\s+[a-z]+))?|(?<![\w.,$+-])[+-]?[\d,.]+(?:e[+-]?\d+)?\s*(?:dollars?(?:\s*(?:\/\s*[a-z]+|per\s+[a-z]+))?|\/\s*[a-z]+|per\s+[a-z]+)\b/gi;
const PER_MILE_PATTERN = /(?:\/\s*(?:mi|mile|miles)|per\s+mile)\s*$/i;
// Permit cent rounding rather than a percentage-sized change in a bid.
const ROUNDING_TOLERANCE = 0.005000001;

function extractMoneyClaims(text) {
  return (text.match(MONEY_PATTERN) || []).map((raw) => {
    const unitMatch = /(?:\/\s*[a-z]+|per\s+[a-z]+)\s*$/i.exec(raw);
    const dimension = unitMatch
      ? (PER_MILE_PATTERN.test(unitMatch[0]) ? "per_mile"
        : /(?:\/\s*load|per\s+load)\s*$/i.test(unitMatch[0]) ? "total" : "unsupported_unit")
      : "total";
    const numberText = raw.replace(/^\+?\$\s*/, "")
      .replace(/(?:\s*dollars?)?(?:\s*(?:\/\s*[a-z]+|per\s+[a-z]+))?\s*$/i, "")
      .replace(/[.,]$/, ""); // Sentence punctuation; embedded extra decimals still fail.
    const valid = /^\+?(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d+)?$/.test(numberText);
    const value = valid ? Number(numberText.replaceAll(",", "")) : NaN;
    return { raw, value, dimension };
  });
}

function extractVerdictClaims(text) {
  const upper = text.toUpperCase();
  return VERDICT_WORDS.filter((word) => new RegExp(`\\b${word}\\b`).test(upper));
}

function canonicalMoneyValues(calculation, dimension) {
  if (!calculation || typeof calculation !== "object") return [];
  if (dimension === "unsupported_unit") return [];
  const fields = dimension === "per_mile"
    ? ["trueRpm", "loadedRpm", "costPerMile"]
    : ["baselineBid", "marketBid", "fuelCost", "deadheadCost"];
  return fields.map((field) => calculation[field])
    .filter((value) => typeof value === "number" && Number.isFinite(value) && value >= 0);
}

function numberIsCanonical(value, canonicalValues) {
  return canonicalValues.some((canonical) => (
    Math.abs(value - canonical) <= ROUNDING_TOLERANCE
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
  if (claimedVerdicts.length > 0 && !VERDICT_WORDS.includes(canonicalVerdict)) {
    throw new OutputGuardError("GUARD_CANONICAL_VERDICT_UNAVAILABLE",
      "Recommendation asserts a verdict without a valid canonical verdict");
  }
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
