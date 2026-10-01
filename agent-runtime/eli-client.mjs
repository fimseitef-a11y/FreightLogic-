// eli-client.mjs
// Private Agent -> ELI read seam (AIAG-TASK-0038 Task 8).
//
// Contract (docs/superpowers/specs/2026-09-30-eli-source-agnostic-service-design.md
// sections 13 and 16):
//   * the Agent sends ELI canonical market identifiers only;
//   * ELI failure, timeout or a malformed answer is non-fatal and explicit;
//   * only a bounded, allowlisted projection of ELI's deterministic answer may
//     reach the model; ELI never changes canonical FreightLogic economics.
//
// Callers must pass the already privacy-classified model projection (output of
// buildModelProjection), never the raw envelope, so non-scalar or restricted
// facts cannot reach the ELI RPC.

const DEFAULT_TIMEOUT_MS = 1500;
const MIN_TIMEOUT_MS = 10;
const MAX_TIMEOUT_MS = 5000;

const MAX_MARKET_LENGTH = 64;
const MAX_TEXT_LENGTH = 128;
const MAX_LIST_ITEMS = 16;
const MAX_MAP_ENTRIES = 16;

const FLAG_PATTERN = /^[A-Z0-9_]{1,64}$/;
const MAP_KEY_PATTERN = /^[A-Za-z0-9_]{1,48}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

const FRESHNESS_STATES = new Set(["FRESH", "AGING", "STALE", "UNAVAILABLE"]);

// Governed lane stages. Airtable remains the stage/promotion authority
// (design amendment 7); anything outside this vocabulary is dropped rather
// than passed to the model as free text.
const LANE_STAGES = new Set(["Structural Candidate", "Pilot Candidate", "Validated Pilot", "Stable Candidate", "Production"]);

function canonicalMarket(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_MARKET_LENGTH) return null;
  return trimmed;
}

function finiteOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function patternOrNull(value, pattern) {
  return typeof value === "string" && value.length <= MAX_TEXT_LENGTH && pattern.test(value) ? value : null;
}

function flagList(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const item of value) {
    if (typeof item === "string" && FLAG_PATTERN.test(item) && !out.includes(item)) out.push(item);
    if (out.length >= MAX_LIST_ITEMS) break;
  }
  return out;
}

function boundedMap(value, acceptValue) {
  const out = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return out;
  let count = 0;
  for (const [key, item] of Object.entries(value)) {
    if (count >= MAX_MAP_ENTRIES) break;
    if (!MAP_KEY_PATTERN.test(key) || !acceptValue(item)) continue;
    out[key] = item;
    count += 1;
  }
  return out;
}

function projectLaneIntelligence(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return {
    originMarket: canonicalMarket(value.originMarket),
    destinationMarket: canonicalMarket(value.destinationMarket),
    structuralScore: finiteOrNull(value.structuralScore),
    expediteRelevance: finiteOrNull(value.expediteRelevance),
    structuralConfidence: finiteOrNull(value.structuralConfidence),
    expediteConfidence: finiteOrNull(value.expediteConfidence),
    freshness: boundedMap(value.freshness, (state) => FRESHNESS_STATES.has(state)),
    unknownFlags: flagList(value.unknownFlags),
    conflictFlags: flagList(value.conflictFlags),
    evidenceCounts: boundedMap(value.evidenceCounts, (count) => Number.isSafeInteger(count) && count >= 0),
    latestEvidenceAt: patternOrNull(value.latestEvidenceAt, TIMESTAMP_PATTERN),
    stage: LANE_STAGES.has(value.stage) ? value.stage : null,
    modelRunId: patternOrNull(value.modelRunId, IDENTIFIER_PATTERN),
    governanceFingerprint: patternOrNull(value.governanceFingerprint, IDENTIFIER_PATTERN),
    updatedAt: patternOrNull(value.updatedAt, TIMESTAMP_PATTERN),
  };
}

function timeoutMs(env) {
  const configured = Number(env?.ELI_TIMEOUT_MS);
  if (!Number.isFinite(configured)) return DEFAULT_TIMEOUT_MS;
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, configured));
}

const TIMED_OUT = Symbol("ELI_TIMEOUT");

async function callWithTimeout(promiseFactory, ms) {
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), ms); });
  try {
    return await Promise.race([Promise.resolve().then(promiseFactory), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Reads deterministic lane intelligence from the private ELI binding.
 * Never throws; every failure mode is an explicit UNKNOWN/UNAVAILABLE object.
 *
 * @param {object} env - Worker env (expects optional env.ELI service binding)
 * @param {object} projection - privacy-classified model projection
 *   ({ facts: { originMarket, destinationMarket, ... } })
 */
export async function readEliLaneContext(env, projection) {
  const originMarket = canonicalMarket(projection?.facts?.originMarket);
  const destinationMarket = canonicalMarket(projection?.facts?.destinationMarket);
  const unavailable = (status, reason) => ({ status, reason, originMarket, destinationMarket });

  if (!originMarket || !destinationMarket) return unavailable("UNKNOWN", "CANONICAL_MARKETS_REQUIRED");

  const binding = env?.ELI;
  if (!binding || typeof binding.getLaneIntelligence !== "function") {
    return unavailable("UNAVAILABLE", "ELI_BINDING_UNAVAILABLE");
  }

  let result;
  try {
    result = await callWithTimeout(
      () => binding.getLaneIntelligence({ originMarket, destinationMarket }),
      timeoutMs(env),
    );
  } catch {
    return unavailable("UNAVAILABLE", "ELI_REQUEST_FAILED");
  }
  if (result === TIMED_OUT) return unavailable("UNAVAILABLE", "ELI_TIMEOUT");

  if (result?.status !== "KNOWN") {
    const reason = typeof result?.reason === "string" && FLAG_PATTERN.test(result.reason)
      ? result.reason
      : "ELI_RESULT_UNAVAILABLE";
    return unavailable(result?.status === "UNKNOWN" ? "UNKNOWN" : "UNAVAILABLE", reason);
  }

  const intelligence = projectLaneIntelligence(result.intelligence);
  if (!intelligence) return unavailable("UNAVAILABLE", "ELI_INVALID_RESPONSE");
  // ELI may translate a FreightLogic city name into its own market id and
  // must then declare that translation; the lane it answers for has to match
  // exactly what it declared (or, with no translation, what was asked).
  let expectedOrigin = originMarket;
  let expectedDestination = destinationMarket;
  if (result.resolved !== undefined) {
    expectedOrigin = canonicalMarket(result.resolved?.originMarket);
    expectedDestination = canonicalMarket(result.resolved?.destinationMarket);
    if (!expectedOrigin || !expectedDestination) return unavailable("UNAVAILABLE", "ELI_INVALID_RESPONSE");
  }
  if (intelligence.originMarket !== expectedOrigin || intelligence.destinationMarket !== expectedDestination) {
    return unavailable("UNAVAILABLE", "ELI_LANE_MISMATCH");
  }

  return { status: "KNOWN", intelligence };
}

export function augmentModelProjection(projection, eliContext) {
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    throw new TypeError("model projection must be an object");
  }
  return {
    ...projection,
    eli: eliContext ?? {
      status: "UNAVAILABLE",
      reason: "ELI_CONTEXT_UNAVAILABLE",
    },
  };
}
