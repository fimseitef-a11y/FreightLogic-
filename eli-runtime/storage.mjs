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
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

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
  ) VALUES (?, ?, ?, ?)`);

  return statement.bind(
    receipt.idempotencyKey,
    receipt.messageType,
    receipt.evidenceId ?? null,
    receipt.processedAt,
  ).run();
}
