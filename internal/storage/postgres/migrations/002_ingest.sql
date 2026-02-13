CREATE TABLE IF NOT EXISTS ingest_bundles (
  bundle_id TEXT PRIMARY KEY,
  machine_id TEXT NOT NULL,
  precinct_id TEXT NOT NULL,
  election_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  bundle_sha256 TEXT NOT NULL,
  bundle_integrity_hash TEXT NOT NULL,
  verification_status TEXT NOT NULL,
  verification_json JSONB NOT NULL,
  bundle_json JSONB NOT NULL,
  ingest_event_hash TEXT NOT NULL,
  previous_event_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_bundles_machine_election ON ingest_bundles (machine_id, election_id);

CREATE TABLE IF NOT EXISTS ingest_receipts (
  receipt_id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES ingest_bundles(bundle_id) ON DELETE CASCADE,
  election_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  ballot_hash TEXT NOT NULL,
  bb_leaf_hash TEXT NOT NULL,
  tx_id TEXT NOT NULL,
  receipt_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_receipts_bundle_id ON ingest_receipts (bundle_id);
CREATE INDEX IF NOT EXISTS idx_ingest_receipts_ballot_hash ON ingest_receipts (ballot_hash);

CREATE TABLE IF NOT EXISTS anchor_outbox (
  id BIGSERIAL PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES ingest_bundles(bundle_id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_attempt_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anchor_outbox_status_next_attempt ON anchor_outbox (status, next_attempt_at);
