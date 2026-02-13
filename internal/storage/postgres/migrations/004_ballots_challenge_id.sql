ALTER TABLE ballots ADD COLUMN IF NOT EXISTS challenge_id TEXT;
UPDATE ballots SET challenge_id = COALESCE(challenge_id, 'legacy_' || receipt_id);
ALTER TABLE ballots ALTER COLUMN challenge_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ballots_challenge_id ON ballots (challenge_id);
