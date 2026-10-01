function requiredFunction(value, name) {
  if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  return value;
}

function messageList(batch) {
  if (!batch || !Array.isArray(batch.messages)) throw new TypeError('batch.messages must be an array');
  return batch.messages;
}

function messageBody(message) {
  const body = message?.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new TypeError('queue message body must be an object');
  }
  return body;
}

export function buildChangeSets(messages = []) {
  if (!Array.isArray(messages)) throw new TypeError('messages must be an array');
  const groups = new Map();

  for (const message of messages) {
    const body = messageBody(message);
    const snapshotFingerprint = String(body.snapshotFingerprint ?? '');
    if (!snapshotFingerprint) throw new Error('snapshotFingerprint is required');

    let group = groups.get(snapshotFingerprint);
    if (!group) {
      group = { affectedKeys: new Set(), messageIds: new Set() };
      groups.set(snapshotFingerprint, group);
    }

    for (const key of Array.isArray(body.affectedKeys) ? body.affectedKeys : []) {
      const normalized = String(key);
      if (normalized) group.affectedKeys.add(normalized);
    }
    if (message?.id != null && String(message.id)) group.messageIds.add(String(message.id));
  }

  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([snapshotFingerprint, group]) => ({
      snapshotFingerprint,
      affectedKeys: [...group.affectedKeys].sort(),
      messageIds: [...group.messageIds].sort(),
    }));
}

export async function consumePrimaryBatch(batch, deps = {}) {
  const hasReceipt = requiredFunction(deps.hasReceipt, 'hasReceipt');
  const processMessage = requiredFunction(deps.processMessage, 'processMessage');
  const recordReceipt = requiredFunction(deps.recordReceipt, 'recordReceipt');
  const now = requiredFunction(deps.now, 'now');

  for (const message of messageList(batch)) {
    try {
      const body = messageBody(message);
      if (!body.idempotencyKey) throw new Error('idempotencyKey is required');
      if (!body.type) throw new Error('message type is required');

      if (await hasReceipt(body.idempotencyKey)) {
        message.ack();
        continue;
      }

      await processMessage(body);
      await recordReceipt({
        idempotencyKey: body.idempotencyKey,
        messageType: body.type,
        evidenceId: body.evidenceId ?? null,
        processedAt: now(),
      });
      message.ack();
    } catch {
      message.retry();
    }
  }
}

export async function consumeDeadLetterBatch(batch, deps = {}) {
  const journalFailure = requiredFunction(deps.journalFailure, 'journalFailure');
  const now = requiredFunction(deps.now, 'now');

  for (const message of messageList(batch)) {
    const body = messageBody(message);
    if (!body.idempotencyKey) throw new Error('idempotencyKey is required');
    const failedAt = now();

    await journalFailure({
      failureId: `dlq:${body.idempotencyKey}`,
      messageIdentity: body.idempotencyKey,
      sourceId: body.sourceId ?? null,
      snapshotId: body.snapshotId ?? null,
      adapterVersion: body.adapterVersion ?? null,
      attemptCount: Number.isFinite(message.attempts) ? message.attempts : 0,
      failureClass: 'queue_terminal_failure',
      sanitizedError: body.lastError ?? 'queue retry limit exhausted',
      firstFailedAt: body.firstFailedAt ?? failedAt,
      lastFailedAt: failedAt,
      payloadHash: body.payloadHash ?? null,
      payloadRef: body.payloadRef ?? null,
    });
    message.ack();
  }
}
