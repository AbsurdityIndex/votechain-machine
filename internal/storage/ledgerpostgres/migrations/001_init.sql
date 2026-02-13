CREATE TABLE IF NOT EXISTS ledger_entries (
  entry_index BIGSERIAL PRIMARY KEY,
  node_role TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  previous_hash TEXT,
  event_id TEXT NOT NULL UNIQUE,
  bundle_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_bundle_id ON ledger_entries(bundle_id);
CREATE INDEX IF NOT EXISTS idx_ledger_entries_created_at ON ledger_entries(created_at);
