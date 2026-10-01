-- ELI ingestion pipeline (AIAG-TASK-0038). Operator-approved 2026-10-01 00:41 ET.
-- Airtable remains the authority for market aliases and lane governance
-- (design amendment 7); these tables are D1 mirrors refreshed each run.

CREATE TABLE IF NOT EXISTS market_aliases (
  alias_norm TEXT PRIMARY KEY,
  alias_text TEXT NOT NULL,
  market_cluster TEXT NOT NULL,
  geography_version TEXT,
  airtable_record_id TEXT NOT NULL,
  synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lane_governance (
  lane_key TEXT PRIMARY KEY,
  directional_lane_id TEXT NOT NULL,
  origin_market TEXT NOT NULL,
  destination_market TEXT NOT NULL,
  stage TEXT NOT NULL,
  unknown_flags_json TEXT NOT NULL,
  airtable_record_id TEXT NOT NULL,
  synced_at TEXT NOT NULL
);

-- One row per stored evidence version. Lane columns are NULL when either
-- market is unresolved (kept as evidence, never forced onto a lane).
CREATE TABLE IF NOT EXISTS evidence_index (
  evidence_id TEXT PRIMARY KEY,
  source_record_id TEXT NOT NULL,
  lane_key TEXT,
  origin_market TEXT,
  destination_market TEXT,
  status_key TEXT NOT NULL,
  duplicate_class TEXT NOT NULL,
  observed_at TEXT,
  superseded INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (evidence_id) REFERENCES raw_evidence(evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_index_lane
  ON evidence_index(lane_key, superseded);

CREATE INDEX IF NOT EXISTS idx_evidence_index_record
  ON evidence_index(source_record_id, superseded);

CREATE TABLE IF NOT EXISTS ingest_runs (
  run_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  counts_json TEXT NOT NULL DEFAULT '{}',
  error TEXT
);
