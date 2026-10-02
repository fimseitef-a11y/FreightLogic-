-- Stateful idempotency leases for ELI queue processing.
-- Existing ingest_receipts remain the durable completion authority; this table
-- prevents concurrent duplicate side effects and preserves retry attempts.

CREATE TABLE IF NOT EXISTS ingest_message_state (
  idempotency_key TEXT PRIMARY KEY,
  message_type TEXT NOT NULL,
  evidence_id TEXT,
  state TEXT NOT NULL CHECK (state IN ('PENDING', 'FAILED', 'COMPLETE')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  lease_token TEXT,
  lease_expires_at TEXT,
  last_error TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_message_state_lease
  ON ingest_message_state(state, lease_expires_at);
