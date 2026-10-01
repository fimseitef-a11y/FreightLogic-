PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS raw_evidence (
  evidence_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  source_record_id TEXT,
  observed_at TEXT,
  retrieved_at TEXT NOT NULL,
  source_posted_at TEXT,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  source_ref TEXT,
  authorization_class TEXT NOT NULL,
  scope_fingerprint TEXT NOT NULL,
  parent_evidence_id TEXT,
  supersedes_evidence_id TEXT,
  ingest_run_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (parent_evidence_id) REFERENCES raw_evidence(evidence_id),
  FOREIGN KEY (supersedes_evidence_id) REFERENCES raw_evidence(evidence_id)
);

CREATE TRIGGER IF NOT EXISTS raw_evidence_no_update
BEFORE UPDATE ON raw_evidence
BEGIN
  SELECT RAISE(ABORT, 'raw_evidence is append-only');
END;

CREATE TRIGGER IF NOT EXISTS raw_evidence_no_delete
BEFORE DELETE ON raw_evidence
BEGIN
  SELECT RAISE(ABORT, 'raw_evidence is append-only');
END;

CREATE TABLE IF NOT EXISTS ingest_receipts (
  idempotency_key TEXT PRIMARY KEY,
  message_type TEXT NOT NULL,
  evidence_id TEXT,
  processed_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (evidence_id) REFERENCES raw_evidence(evidence_id)
);

CREATE TABLE IF NOT EXISTS ingest_failures (
  failure_id TEXT PRIMARY KEY,
  message_identity TEXT NOT NULL,
  source_id TEXT,
  snapshot_id TEXT,
  adapter_version TEXT,
  attempt_count INTEGER NOT NULL,
  failure_class TEXT NOT NULL,
  sanitized_error TEXT NOT NULL,
  first_failed_at TEXT NOT NULL,
  last_failed_at TEXT NOT NULL,
  payload_hash TEXT,
  payload_ref TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS lane_read_model (
  lane_key TEXT PRIMARY KEY,
  origin_market TEXT NOT NULL,
  destination_market TEXT NOT NULL,
  structural_score REAL,
  expedite_relevance REAL,
  structural_confidence REAL,
  expedite_confidence REAL,
  freshness_json TEXT NOT NULL,
  unknown_flags_json TEXT NOT NULL,
  conflict_flags_json TEXT NOT NULL,
  evidence_counts_json TEXT NOT NULL,
  latest_evidence_at TEXT,
  stage TEXT NOT NULL,
  model_run_id TEXT NOT NULL,
  governance_fingerprint TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_runs (
  model_run_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL,
  source_snapshot_fingerprint TEXT NOT NULL,
  observation_as_of TEXT NOT NULL,
  structural_version TEXT NOT NULL,
  expedite_version TEXT NOT NULL,
  confidence_version TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  governance_fingerprint TEXT NOT NULL,
  promoted INTEGER NOT NULL DEFAULT 0 CHECK (promoted IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_raw_evidence_source_run
  ON raw_evidence(source_id, ingest_run_id);

CREATE INDEX IF NOT EXISTS idx_raw_evidence_supersedes
  ON raw_evidence(supersedes_evidence_id);

CREATE INDEX IF NOT EXISTS idx_ingest_failures_source_snapshot
  ON ingest_failures(source_id, snapshot_id);
