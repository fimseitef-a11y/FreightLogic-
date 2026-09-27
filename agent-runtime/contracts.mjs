const TOP_LEVEL_FIELDS = new Set([
  "id", "type", "occurredAt", "source", "actorScope", "loadId",
  "facts", "provenance", "canonicalSnapshot", "privacyClass",
  "correlationId", "idempotencyKey", "schemaVersion", "intent", "confidence",
]);

const SAFE_FACT_FIELDS = new Set([
  "originMarket", "destinationMarket", "loadedMiles", "deadheadMiles",
  "weightLb", "pieces", "equipment", "pickupWindow", "deliveryWindow",
  "marketSignals",
]);

const SAFE_CANONICAL_FIELDS = new Set([
  "trueRpm", "loadedRpm", "grade", "verdict", "baselineBid", "marketBid",
  "costPerMile", "fuelCost", "deadheadCost", "positionClass",
  "marketContext", "calculatedAt", "authorityVersion",
]);

const PRIVACY_CLASSES = new Set([
  "PUBLIC", "OPERATIONAL_MINIMIZED", "RESTRICTED", "UNKNOWN",
]);

const RESTRICTED_KEY = /(email|phone|address|payment|bank|ssn|ein|token|secret|password|credential|authorization|cookie|backup|rawtext|chat|message|account)/i;

export class ContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ContractError";
    this.code = code;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireNonEmptyString(value, field) {
  if (typeof value !== "string" || !value.trim()) {
    throw new ContractError("MISSING_FIELD", `${field} is required`);
  }
}

function containsRestrictedKey(value) {
  if (Array.isArray(value)) return value.some(containsRestrictedKey);
  if (!isPlainObject(value)) return false;
  for (const [key, child] of Object.entries(value)) {
    if (RESTRICTED_KEY.test(key)) return true;
    if (containsRestrictedKey(child)) return true;
  }
  return false;
}

function hasUnknownKeys(value, allowlist) {
  if (!isPlainObject(value)) return true;
  return Object.keys(value).some((key) => !allowlist.has(key));
}

function pickAllowed(value, allowlist) {
  const out = {};
  for (const [key, item] of Object.entries(value || {})) {
    if (allowlist.has(key)) out[key] = item;
  }
  return out;
}

export function validateEnvelope(envelope) {
  if (!isPlainObject(envelope)) {
    throw new ContractError("INVALID_ENVELOPE", "Envelope must be an object");
  }

  for (const key of Object.keys(envelope)) {
    if (!TOP_LEVEL_FIELDS.has(key)) {
      throw new ContractError("UNKNOWN_FIELD", `Unknown envelope field: ${key}`);
    }
  }

  for (const field of [
    "id", "type", "occurredAt", "source", "actorScope",
    "correlationId", "idempotencyKey", "intent",
  ]) {
    requireNonEmptyString(envelope[field], field);
  }

  if (envelope.schemaVersion !== 1) {
    throw new ContractError("UNSUPPORTED_SCHEMA", "schemaVersion must be 1");
  }

  if (!PRIVACY_CLASSES.has(envelope.privacyClass)) {
    throw new ContractError("INVALID_PRIVACY_CLASS", "privacyClass is invalid");
  }

  if (!isPlainObject(envelope.facts)) {
    throw new ContractError("INVALID_FACTS", "facts must be an object");
  }

  if (!isPlainObject(envelope.provenance)) {
    throw new ContractError("INVALID_PROVENANCE", "provenance must be an object");
  }

  if (!isPlainObject(envelope.canonicalSnapshot)) {
    throw new ContractError("INVALID_CANONICAL_SNAPSHOT", "canonicalSnapshot must be an object");
  }

  if (typeof envelope.confidence !== "number" || !Number.isFinite(envelope.confidence)
      || envelope.confidence < 0 || envelope.confidence > 1) {
    throw new ContractError("INVALID_CONFIDENCE", "confidence must be between 0 and 1");
  }

  if (Number.isNaN(Date.parse(envelope.occurredAt))) {
    throw new ContractError("INVALID_OCCURRED_AT", "occurredAt must be an ISO timestamp");
  }

  return { ok: true };
}

export function classifyPrivacy(envelope) {
  if (!isPlainObject(envelope)) return "UNKNOWN";
  if (envelope.privacyClass === "RESTRICTED") return "RESTRICTED";
  if (envelope.privacyClass === "UNKNOWN") return "UNKNOWN";
  if (containsRestrictedKey(envelope)) return "RESTRICTED";
  if (hasUnknownKeys(envelope.facts, SAFE_FACT_FIELDS)) return "UNKNOWN";
  if (hasUnknownKeys(envelope.canonicalSnapshot, SAFE_CANONICAL_FIELDS)) return "UNKNOWN";
  return PRIVACY_CLASSES.has(envelope.privacyClass)
    ? envelope.privacyClass
    : "UNKNOWN";
}

export function buildModelProjection(envelope) {
  validateEnvelope(envelope);
  const privacy = classifyPrivacy(envelope);
  if (privacy !== "PUBLIC" && privacy !== "OPERATIONAL_MINIMIZED") {
    throw new ContractError("PRIVACY_BLOCKED", `Model projection blocked for ${privacy}`);
  }

  return {
    intent: envelope.intent,
    facts: pickAllowed(envelope.facts, SAFE_FACT_FIELDS),
    canonicalSnapshot: pickAllowed(envelope.canonicalSnapshot, SAFE_CANONICAL_FIELDS),
  };
}
