export function sameIdempotentEvent(stored, envelope) {
  if (!stored || !envelope) return false;
  return stored.event_id === envelope.id
    && stored.correlation_id === envelope.correlationId;
}
