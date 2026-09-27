export function stateScope(envelope) {
  const actorScope = typeof envelope?.actorScope === "string" ? envelope.actorScope.trim() : "";
  const taskScope = typeof envelope?.type === "string" ? envelope.type.trim() : "";
  const idempotencyKey = typeof envelope?.idempotencyKey === "string"
    ? envelope.idempotencyKey.trim()
    : "";

  if (!actorScope || !taskScope || !idempotencyKey) {
    throw new Error("actorScope, type and idempotencyKey are required for state scope");
  }

  return {
    objectName: `actor:${actorScope}|task:${taskScope}`,
    idempotencyKey,
  };
}
