function requireDb(db) {
  if (!db || typeof db.prepare !== 'function') {
    throw new TypeError('D1 database binding with prepare() is required');
  }
  return db;
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function changed(result) {
  const n = Number(result?.meta?.changes);
  return Number.isFinite(n) ? n : null;
}

async function ensureMessageState(db) {
  const table = await db.prepare(`CREATE TABLE IF NOT EXISTS ingest_message_state (
    idempotency_key TEXT PRIMARY KEY,
    message_type TEXT NOT NULL,
    evidence_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'FAILED', 'COMPLETE')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_token TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
  )`).run();
  if (table?.success === false) throw new Error('ingest message-state table was not confirmed');
  const index = await db.prepare(`CREATE INDEX IF NOT EXISTS idx_ingest_message_state_lease
    ON ingest_message_state(state, lease_expires_at)`).run();
  if (index?.success === false) throw new Error('ingest message-state index was not confirmed');
}

export async function appendRawEvidence(db, evidence) {
  requireDb(db);
  requireObject(evidence, 'evidence');

  const statement = db.prepare(`INSERT INTO raw_evidence (
    evidence_id,
    source_id,
    adapter_version,
    source_record_id,
    observed_at,
    retrieved_at,
    source_posted_at,
    payload_json,
    payload_hash,
    source_ref,
    authorization_class,
    scope_fingerprint,
    parent_evidence_id,
    supersedes_evidence_id,
    ingest_run_id
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  return statement.bind(
    evidence.evidenceId,
    evidence.sourceId,
    evidence.adapterVersion,
    evidence.sourceRecordId ?? null,
    evidence.observedAt ?? null,
    evidence.retrievedAt,
    evidence.sourcePostedAt ?? null,
    evidence.payloadJson,
    evidence.payloadHash,
    evidence.sourceRef ?? null,
    evidence.authorizationClass,
    evidence.scopeFingerprint,
    evidence.parentEvidenceId ?? null,
    evidence.supersedesEvidenceId ?? null,
    evidence.ingestRunId,
  ).run();
}

export async function journalFailure(db, failure) {
  requireDb(db);
  requireObject(failure, 'failure');

  const statement = db.prepare(`INSERT INTO ingest_failures (
    failure_id,
    message_identity,
    source_id,
    snapshot_id,
    adapter_version,
    attempt_count,
    failure_class,
    sanitized_error,
    first_failed_at,
    last_failed_at,
    payload_hash,
    payload_ref
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(failure_id) DO NOTHING`);

  return statement.bind(
    failure.failureId,
    failure.messageIdentity,
    failure.sourceId ?? null,
    failure.snapshotId ?? null,
    failure.adapterVersion ?? null,
    failure.attemptCount,
    failure.failureClass,
    failure.sanitizedError,
    failure.firstFailedAt,
    failure.lastFailedAt,
    failure.payloadHash ?? null,
    failure.payloadRef ?? null,
  ).run();
}

export async function recordReceipt(db, receipt) {
  requireDb(db);
  requireObject(receipt, 'receipt');

  const statement = db.prepare(`INSERT INTO ingest_receipts (
    idempotency_key,
    message_type,
    evidence_id,
    processed_at
  ) VALUES (?, ?, ?, ?)
  ON CONFLICT(idempotency_key) DO NOTHING`);

  return statement.bind(
    receipt.idempotencyKey,
    receipt.messageType,
    receipt.evidenceId ?? null,
    receipt.processedAt,
  ).run();
}

export async function claimReceipt(db, claim) {
  requireDb(db);
  requireObject(claim, 'claim');
  if (!claim.idempotencyKey || !claim.messageType || !claim.claimedAt || !claim.leaseToken || !claim.leaseExpiresAt) {
    throw new Error('receipt claim requires key, type, timestamps and lease token');
  }

  const receipt = await db.prepare('SELECT 1 AS present FROM ingest_receipts WHERE idempotency_key = ?')
    .bind(claim.idempotencyKey).first();
  if (receipt) return { status: 'COMPLETE', attemptCount: Math.max(1, Number(claim.attemptHint) || 1) };

  await ensureMessageState(db);
  const attemptHint = Math.max(1, Math.trunc(Number(claim.attemptHint) || 1));
  const inserted = await db.prepare(`INSERT OR IGNORE INTO ingest_message_state
    (idempotency_key, message_type, evidence_id, state, attempt_count, lease_token, lease_expires_at, last_error, updated_at)
    VALUES (?, ?, ?, 'PENDING', ?, ?, ?, NULL, ?)`)
    .bind(claim.idempotencyKey, claim.messageType, claim.evidenceId ?? null, attemptHint, claim.leaseToken, claim.leaseExpiresAt, claim.claimedAt)
    .run();
  if (inserted?.success === false) throw new Error('receipt claim insert was not confirmed');

  if (changed(inserted) === 0) {
    const updated = await db.prepare(`UPDATE ingest_message_state SET
        message_type = ?, evidence_id = ?, state = 'PENDING',
        attempt_count = CASE WHEN attempt_count < ? THEN ? ELSE attempt_count + 1 END,
        lease_token = ?, lease_expires_at = ?, last_error = NULL, updated_at = ?
      WHERE idempotency_key = ? AND state != 'COMPLETE'
        AND (state = 'FAILED' OR lease_expires_at IS NULL OR lease_expires_at <= ?)`)
      .bind(
        claim.messageType, claim.evidenceId ?? null, attemptHint, attemptHint,
        claim.leaseToken, claim.leaseExpiresAt, claim.claimedAt,
        claim.idempotencyKey, claim.claimedAt,
      ).run();
    if (updated?.success === false) throw new Error('receipt lease update was not confirmed');
  }

  const row = await db.prepare(`SELECT state, attempt_count, lease_token, lease_expires_at
    FROM ingest_message_state WHERE idempotency_key = ?`).bind(claim.idempotencyKey).first();
  if (!row) throw new Error('receipt claim was not durably observable');
  if (row.state === 'COMPLETE') return { status: 'COMPLETE', attemptCount: row.attempt_count };
  if (row.lease_token === claim.leaseToken) {
    return { status: 'ACQUIRED', leaseToken: claim.leaseToken, attemptCount: row.attempt_count };
  }
  return { status: 'IN_FLIGHT', attemptCount: row.attempt_count, leaseExpiresAt: row.lease_expires_at ?? null };
}

export async function completeReceipt(db, completion) {
  requireDb(db);
  requireObject(completion, 'completion');
  if (typeof db.batch !== 'function') throw new TypeError('transactional D1 batch is required for completion');
  if (!completion.idempotencyKey || !completion.messageType || !completion.leaseToken || !completion.processedAt) {
    throw new Error('receipt completion requires key, type, token and timestamp');
  }
  await ensureMessageState(db);
  const matchingComplete = async () => {
    const row = await db.prepare(`SELECT s.attempt_count FROM ingest_message_state s
      JOIN ingest_receipts r ON r.idempotency_key = s.idempotency_key
      WHERE s.idempotency_key = ? AND s.state = 'COMPLETE' AND s.lease_token = ?
        AND r.message_type = ? AND r.evidence_id IS ?`)
      .bind(completion.idempotencyKey, completion.leaseToken, completion.messageType, completion.evidenceId ?? null).first();
    return row ? { status: 'COMPLETE', attemptCount: row.attempt_count } : null;
  };
  const replay = await matchingComplete();
  if (replay) return replay;

  // State and receipt commit atomically. The UPDATE itself checks ownership;
  // retaining the completion token permits a same-owner replay without giving
  // an expired/replaced claimant authority over a successor's receipt.
  const results = await db.batch([
    db.prepare(`UPDATE ingest_message_state SET
        state = 'COMPLETE', lease_expires_at = NULL, last_error = NULL, updated_at = ?
      WHERE idempotency_key = ? AND state = 'PENDING' AND lease_token = ?
        AND lease_expires_at > ? AND message_type = ? AND evidence_id IS ?
        AND NOT EXISTS (SELECT 1 FROM ingest_receipts WHERE idempotency_key = ?)`)
      .bind(completion.processedAt, completion.idempotencyKey, completion.leaseToken,
        completion.processedAt, completion.messageType, completion.evidenceId ?? null, completion.idempotencyKey),
    db.prepare(`INSERT INTO ingest_receipts (idempotency_key, message_type, evidence_id, processed_at)
      SELECT ?, ?, ?, ? WHERE EXISTS (
        SELECT 1 FROM ingest_message_state WHERE idempotency_key = ?
          AND state = 'COMPLETE' AND lease_token = ? AND updated_at = ?
          AND message_type = ? AND evidence_id IS ?
      ) ON CONFLICT(idempotency_key) DO NOTHING`)
      .bind(completion.idempotencyKey, completion.messageType, completion.evidenceId ?? null, completion.processedAt,
        completion.idempotencyKey, completion.leaseToken, completion.processedAt,
        completion.messageType, completion.evidenceId ?? null),
  ]);
  if (!Array.isArray(results) || results.length !== 2 || results.some(r => r?.success === false)) {
    throw new Error('receipt completion transaction was not confirmed');
  }
  if (changed(results[0]) !== 1 || changed(results[1]) !== 1) {
    const sameOwnerReplay = await matchingComplete();
    if (sameOwnerReplay) return sameOwnerReplay;
    throw new Error('receipt completion lost or expired its lease');
  }
  const durable = await matchingComplete();
  if (!durable) throw new Error('completed receipt was not durably observable');
  return durable;
}

export async function abandonReceipt(db, failure) {
  requireDb(db);
  requireObject(failure, 'failure');
  await ensureMessageState(db);
  const result = await db.prepare(`UPDATE ingest_message_state SET
      state = 'FAILED', lease_token = NULL, lease_expires_at = NULL,
      last_error = ?, updated_at = ?
    WHERE idempotency_key = ? AND lease_token = ? AND state = 'PENDING'`)
    .bind(String(failure.error ?? 'processing failed').slice(0, 200), failure.failedAt, failure.idempotencyKey, failure.leaseToken)
    .run();
  if (result?.success === false) throw new Error('receipt failure state was not confirmed');
  return { status: 'FAILED' };
}
