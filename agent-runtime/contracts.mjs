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

const PRIVACY_CLASSES = new Set(["PUBLIC", "OPERATIONAL_MINIMIZED", "RESTRICTED", "UNKNOWN"]);
const VERDICTS = new Set(["ACCEPT", "REJECT", "COUNTER", "HOLD", "UNKNOWN"]);
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

function optionalString(value, field) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new ContractError("INVALID_FIELD_VALUE", `${field} must be a string or null`);
  }
}

function optionalNumber(value, field, { integer = false, nonNegative = false } = {}) {
  if (value === undefined || value === null) return;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ContractError("INVALID_FIELD_VALUE", `${field} must be a finite number or null`);
  }
  if (integer && !Number.isInteger(value)) {
    throw new ContractError("INVALID_FIELD_VALUE", `${field} must be an integer or null`);
  }
  if (nonNegative && value < 0) {
    throw new ContractError("INVALID_FIELD_VALUE", `${field} cannot be negative`);
  }
}

const MAX_PRIVACY_NODES = 128;
const MAX_PRIVACY_DEPTH = 4;
const MAX_ENVELOPE_BYTES = 8192;

const MODEL_FACT_FIELDS = new Set([
  "originMarket", "destinationMarket", "loadedMiles", "deadheadMiles",
  "weightLb", "pieces", "equipment",
]);

const MODEL_CANONICAL_FIELDS = new Set([
  "trueRpm", "loadedRpm", "grade", "verdict", "baselineBid", "marketBid",
  "costPerMile", "fuelCost", "deadheadCost", "positionClass", "authorityVersion",
]);

function inspectPrivacyShape(value) {
  const stack = [{ value, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const current = stack.pop();
    visited += 1;
    if (visited > MAX_PRIVACY_NODES) return "UNKNOWN";
    const node = current.value;
    if (!node || typeof node !== "object") continue;
    const entries = Array.isArray(node)
      ? node.map((child, index) => [String(index), child])
      : Object.entries(node);
    for (const [key, child] of entries) {
      if (!Array.isArray(node) && RESTRICTED_KEY.test(key)) return "RESTRICTED";
      if (!child || typeof child !== "object") continue;
      if (current.depth >= MAX_PRIVACY_DEPTH) return "UNKNOWN";
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
  return "CLEAR";
}

function hasUnknownKeys(value, allowlist) {
  if (!isPlainObject(value)) return true;
  return Object.keys(value).some((key) => !allowlist.has(key));
}

function projectAllowedScalars(value, allowlist) {
  const out = {};
  for (const [key, item] of Object.entries(value || {})) {
    if (!allowlist.has(key)) continue;
    if (item === null || ["string", "number", "boolean"].includes(typeof item)) out[key] = item;
  }
  return out;
}

function validateFactDomains(facts) {
  for (const field of ["originMarket", "destinationMarket", "equipment", "pickupWindow", "deliveryWindow"]) {
    optionalString(facts[field], `facts.${field}`);
  }
  for (const field of ["loadedMiles", "deadheadMiles", "weightLb"]) {
    optionalNumber(facts[field], `facts.${field}`, { nonNegative: true });
  }
  optionalNumber(facts.pieces, "facts.pieces", { integer: true, nonNegative: true });
  if (facts.marketSignals !== undefined && facts.marketSignals !== null
      && !isPlainObject(facts.marketSignals) && !Array.isArray(facts.marketSignals)) {
    throw new ContractError("INVALID_FIELD_VALUE", "facts.marketSignals must be structured data or null");
  }
}

function validateCanonicalDomains(snapshot) {
  for (const field of ["trueRpm", "loadedRpm", "baselineBid", "marketBid", "costPerMile", "fuelCost", "deadheadCost"]) {
    optionalNumber(snapshot[field], `canonicalSnapshot.${field}`, { nonNegative: true });
  }
  for (const field of ["grade", "positionClass", "marketContext", "calculatedAt", "authorityVersion"]) {
    optionalString(snapshot[field], `canonicalSnapshot.${field}`);
  }
  if (snapshot.verdict !== undefined && snapshot.verdict !== null) {
    if (typeof snapshot.verdict !== "string" || !VERDICTS.has(snapshot.verdict.toUpperCase())) {
      throw new ContractError("INVALID_FIELD_VALUE", "canonicalSnapshot.verdict is invalid");
    }
  }
}

export function validateEnvelope(envelope) {
  if (!isPlainObject(envelope)) throw new ContractError("INVALID_ENVELOPE", "Envelope must be an object");
  for (const key of Object.keys(envelope)) {
    if (!TOP_LEVEL_FIELDS.has(key)) throw new ContractError("UNKNOWN_FIELD", `Unknown envelope field: ${key}`);
  }

  let serialized;
  try { serialized = JSON.stringify(envelope); }
  catch { throw new ContractError("INVALID_ENVELOPE", "Envelope must be JSON-serializable"); }
  if (new TextEncoder().encode(serialized).byteLength > MAX_ENVELOPE_BYTES) {
    throw new ContractError("ENVELOPE_TOO_LARGE", "Envelope exceeds Phase A size limit");
  }

  for (const field of ["id", "type", "occurredAt", "source", "actorScope", "correlationId", "idempotencyKey", "intent"]) {
    requireNonEmptyString(envelope[field], field);
  }
  optionalString(envelope.loadId, "loadId");

  if (envelope.schemaVersion !== 1) throw new ContractError("UNSUPPORTED_SCHEMA", "schemaVersion must be 1");
  if (!PRIVACY_CLASSES.has(envelope.privacyClass)) throw new ContractError("INVALID_PRIVACY_CLASS", "privacyClass is invalid");
  if (!isPlainObject(envelope.facts)) throw new ContractError("INVALID_FACTS", "facts must be an object");
  if (!isPlainObject(envelope.provenance)) throw new ContractError("INVALID_PROVENANCE", "provenance must be an object");
  if (!isPlainObject(envelope.canonicalSnapshot)) throw new ContractError("INVALID_CANONICAL_SNAPSHOT", "canonicalSnapshot must be an object");
  if (hasUnknownKeys(envelope.facts, SAFE_FACT_FIELDS)) throw new ContractError("UNKNOWN_FACT_FIELD", "facts contains unsupported fields");
  if (hasUnknownKeys(envelope.canonicalSnapshot, SAFE_CANONICAL_FIELDS)) throw new ContractError("UNKNOWN_CANONICAL_FIELD", "canonicalSnapshot contains unsupported fields");

  validateFactDomains(envelope.facts);
  validateCanonicalDomains(envelope.canonicalSnapshot);

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
  const shape = inspectPrivacyShape(envelope);
  if (shape === "RESTRICTED") return "RESTRICTED";
  if (shape === "UNKNOWN") return "UNKNOWN";
  if (hasUnknownKeys(envelope.facts, SAFE_FACT_FIELDS)) return "UNKNOWN";
  if (hasUnknownKeys(envelope.canonicalSnapshot, SAFE_CANONICAL_FIELDS)) return "UNKNOWN";
  return PRIVACY_CLASSES.has(envelope.privacyClass) ? envelope.privacyClass : "UNKNOWN";
}

export function buildModelProjection(envelope) {
  validateEnvelope(envelope);
  const privacy = classifyPrivacy(envelope);
  if (privacy !== "PUBLIC" && privacy !== "OPERATIONAL_MINIMIZED") {
    throw new ContractError("PRIVACY_BLOCKED", `Model projection blocked for ${privacy}`);
  }
  return {
    intent: envelope.intent,
    facts: projectAllowedScalars(envelope.facts, MODEL_FACT_FIELDS),
    canonicalSnapshot: projectAllowedScalars(envelope.canonicalSnapshot, MODEL_CANONICAL_FIELDS),
  };
}
