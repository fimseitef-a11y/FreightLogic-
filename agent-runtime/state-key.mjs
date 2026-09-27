export function stateScope(envelope) {
  const actorScope = typeof envelope?.actorScope === "string" ? envelope.actorScope.trim() : "";
  const loadScope = typeof envelope?.loadId === "string" && envelope.loadId.trim()
    ? envelope.loadId.trim()
    : "no-load";
  const idempotencyKey = typeof envelope?.idempotencyKey === "string"
    ? envelope.idempotencyKey.trim()
    : "";

  if (!actorScope || !idempotencyKey) {
    throw new Error("actorScope and idempotencyKey are required for state scope");
  }

  return {
    objectName: `actor:${actorScope}|load:${loadScope}`,
    idempotencyKey,
  };
}
