CREATE TABLE IF NOT EXISTS state_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS election_manifest (
  id SMALLINT PRIMARY KEY,
  election_id TEXT NOT NULL,
  jurisdiction_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  loaded_at TIMESTAMPTZ NOT NULL,
  manifest_json JSONB NOT NULL,
  CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
  idempotency_key TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  response_json JSONB NOT NULL,
  stored_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS bb_leaves (
  idx BIGSERIAL PRIMARY KEY,
  leaf_hash TEXT NOT NULL UNIQUE,
  payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS bb_sth (
  id BIGSERIAL PRIMARY KEY,
  tree_size INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  sth_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS ballots (
  receipt_id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL UNIQUE,
  ballot_hash TEXT NOT NULL UNIQUE,
  ballot_id TEXT NOT NULL,
  nullifier TEXT NOT NULL UNIQUE,
  leaf_hash TEXT NOT NULL UNIQUE,
  ciphertext TEXT NOT NULL,
  wrapped_ballot_key TEXT NOT NULL,
  wrapped_ballot_key_epk TEXT NOT NULL,
  cast_at TIMESTAMPTZ NOT NULL,
  receipt_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
  bundle_id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  file_path TEXT NOT NULL,
  bundle_sha256 TEXT NOT NULL,
  bundle_json JSONB NOT NULL
);
