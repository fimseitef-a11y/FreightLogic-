function canonicalize(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);

  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canonicalize(value[key]);
  }
  return out;
}

export function replayFingerprintPayload(envelope) {
  return canonicalize({
    type: envelope.type,
    occurredAt: envelope.occurredAt,
    source: envelope.source,
    actorScope: envelope.actorScope,
    loadId: envelope.loadId ?? null,
    facts: envelope.facts,
    provenance: envelope.provenance,
    canonicalSnapshot: envelope.canonicalSnapshot,
    privacyClass: envelope.privacyClass,
    schemaVersion: envelope.schemaVersion,
    intent: envelope.intent,
    confidence: envelope.confidence,
  });
}

export async function fingerprintEnvelope(envelope) {
  const bytes = new TextEncoder().encode(JSON.stringify(replayFingerprintPayload(envelope)));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function sameIdempotentEvent(stored, envelope, payloadFingerprint) {
  if (!stored || !envelope || !payloadFingerprint) return false;
  return stored.event_id === envelope.id
    && stored.correlation_id === envelope.correlationId
    && stored.payload_fingerprint === payloadFingerprint;
}
