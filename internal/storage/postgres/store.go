package postgres

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage"
)

//go:embed migrations/001_init.sql
var migration001 string

//go:embed migrations/002_ingest.sql
var migration002 string

//go:embed migrations/003_outbox_columns.sql
var migration003 string

//go:embed migrations/004_ballots_challenge_id.sql
var migration004 string

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string, maxConns, minConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if minConns >= 0 {
		cfg.MinConns = minConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	store := &Store{pool: pool}
	if err := store.applyMigrations(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) applyMigrations(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migration001)
	if err != nil {
		return fmt.Errorf("apply migration 001: %w", err)
	}
	_, err = s.pool.Exec(ctx, migration002)
	if err != nil {
		return fmt.Errorf("apply migration 002: %w", err)
	}
	_, err = s.pool.Exec(ctx, migration003)
	if err != nil {
		return fmt.Errorf("apply migration 003: %w", err)
	}
	_, err = s.pool.Exec(ctx, migration004)
	if err != nil {
		return fmt.Errorf("apply migration 004: %w", err)
	}
	return nil
}

func (s *Store) SetElectionManifest(ctx context.Context, m protocol.ElectionManifest) error {
	raw, err := protocol.CanonicalJSON(m)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO election_manifest (id, election_id, jurisdiction_id, manifest_id, not_before, not_after, loaded_at, manifest_json)
VALUES (1, $1, $2, $3, $4, $5, NOW(), $6::jsonb)
ON CONFLICT (id) DO UPDATE SET
  election_id = EXCLUDED.election_id,
  jurisdiction_id = EXCLUDED.jurisdiction_id,
  manifest_id = EXCLUDED.manifest_id,
  not_before = EXCLUDED.not_before,
  not_after = EXCLUDED.not_after,
  loaded_at = EXCLUDED.loaded_at,
  manifest_json = EXCLUDED.manifest_json
`, m.ElectionID, m.JurisdictionID, m.ManifestID, m.NotBefore.UTC(), m.NotAfter.UTC(), raw)
	if err != nil {
		return err
	}
	return s.SetMeta(ctx, "polls_closed", "false")
}

func (s *Store) GetElectionManifest(ctx context.Context) (protocol.ElectionManifest, bool, error) {
	var raw []byte
	var out protocol.ElectionManifest
	err := s.pool.QueryRow(ctx, `SELECT manifest_json FROM election_manifest WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (s *Store) CreateChallenge(ctx context.Context, challengeID, challenge string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO challenges (challenge_id, challenge, expires_at, created_at)
VALUES ($1, $2, $3, NOW())
`, challengeID, challenge, expiresAt.UTC())
	return err
}

func (s *Store) GetChallenge(ctx context.Context, challengeID string) (storage.ChallengeRecord, bool, error) {
	var out storage.ChallengeRecord
	var usedAt *time.Time
	err := s.pool.QueryRow(ctx, `
SELECT challenge_id, challenge, expires_at, used_at
FROM challenges
WHERE challenge_id = $1
`, challengeID).Scan(&out.ChallengeID, &out.Challenge, &out.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out.ExpiresAt = out.ExpiresAt.UTC()
	if usedAt != nil {
		t := usedAt.UTC()
		out.UsedAt = &t
	}
	return out, true, nil
}

func (s *Store) MarkChallengeUsed(ctx context.Context, challengeID string, usedAt time.Time) error {
	cmd, err := s.pool.Exec(ctx, `
UPDATE challenges
SET used_at = $2
WHERE challenge_id = $1 AND used_at IS NULL
`, challengeID, usedAt.UTC())
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return storage.ErrChallengeUsed
	}
	return nil
}

func (s *Store) LookupIdempotency(ctx context.Context, idempotencyKey string) (requestHash, responseJSON string, ok bool, err error) {
	var response []byte
	err = s.pool.QueryRow(ctx, `
SELECT request_hash, response_json
FROM idempotency
WHERE idempotency_key = $1
`, idempotencyKey).Scan(&requestHash, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return requestHash, string(response), true, nil
}

func (s *Store) SaveIdempotency(ctx context.Context, idempotencyKey, requestHash, responseJSON string) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO idempotency (idempotency_key, request_hash, response_json, stored_at)
VALUES ($1, $2, $3::jsonb, NOW())
ON CONFLICT (idempotency_key) DO UPDATE SET
  request_hash = EXCLUDED.request_hash,
  response_json = EXCLUDED.response_json,
  stored_at = EXCLUDED.stored_at
`, idempotencyKey, requestHash, responseJSON)
	return err
}

func (s *Store) InsertLeaf(ctx context.Context, leafHash, payloadJSON string) (int, error) {
	var idx int
	err := s.pool.QueryRow(ctx, `
INSERT INTO bb_leaves (leaf_hash, payload_json, created_at)
VALUES ($1, $2::jsonb, NOW())
RETURNING idx
`, leafHash, payloadJSON).Scan(&idx)
	if err != nil {
		if isUniqueViolationFor(err, "leaf_hash") {
			return 0, storage.ErrLeafExists
		}
		return 0, err
	}
	return idx, nil
}

func (s *Store) ListLeafHashes(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf_hash FROM bb_leaves ORDER BY idx ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) FindLeafIndex(ctx context.Context, leafHash string) (int, bool, error) {
	var idx int
	err := s.pool.QueryRow(ctx, `
WITH ordered AS (
  SELECT leaf_hash, (ROW_NUMBER() OVER (ORDER BY idx) - 1) AS pos
  FROM bb_leaves
)
SELECT pos
FROM ordered
WHERE leaf_hash = $1
`, leafHash).Scan(&idx)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return idx, true, nil
}

func (s *Store) SaveSTH(ctx context.Context, sth protocol.SignedTreeHead) error {
	raw, err := protocol.CanonicalJSON(sth)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO bb_sth (tree_size, root_hash, created_at, sth_json)
VALUES ($1, $2, NOW(), $3::jsonb)
`, sth.TreeSize, sth.RootHash, raw)
	return err
}

func (s *Store) LatestSTH(ctx context.Context) (protocol.SignedTreeHead, bool, error) {
	var out protocol.SignedTreeHead
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT sth_json FROM bb_sth ORDER BY id DESC LIMIT 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (s *Store) SaveBallotReceipt(ctx context.Context, receipt protocol.CastReceipt, ballot protocol.EncryptedBallot, nullifier, leafHash string) error {
	raw, err := protocol.CanonicalJSON(receipt)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO ballots (
  receipt_id,
  challenge_id,
  ballot_hash,
  ballot_id,
  nullifier,
  leaf_hash,
  ciphertext,
  wrapped_ballot_key,
  wrapped_ballot_key_epk,
  cast_at,
  receipt_json
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
`,
		receipt.ReceiptID,
		receipt.ReceiptID,
		receipt.BallotHash,
		ballot.BallotID,
		nullifier,
		leafHash,
		ballot.Ciphertext,
		ballot.WrappedBallotKey,
		ballot.WrappedBallotKeyEP,
		receipt.IssuedAt.UTC(),
		raw,
	)
	if err != nil {
		switch {
		case isUniqueViolationFor(err, "challenge_id"):
			return storage.ErrChallengeUsed
		case isUniqueViolationFor(err, "nullifier"):
			return storage.ErrNullifierExists
		case isUniqueViolationFor(err, "ballot_hash"):
			return storage.ErrBallotHashExists
		case isUniqueViolationFor(err, "leaf_hash"):
			return storage.ErrLeafExists
		case isUniqueViolationFor(err, "receipt_id"):
			return storage.ErrReceiptExists
		default:
			return err
		}
	}
	return nil
}

func (s *Store) HasNullifier(ctx context.Context, nullifier string) (bool, error) {
	var exists int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM ballots WHERE nullifier = $1 LIMIT 1`, nullifier).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) HasBallotHash(ctx context.Context, ballotHash string) (bool, error) {
	var exists int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM ballots WHERE ballot_hash = $1 LIMIT 1`, ballotHash).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) GetReceipt(ctx context.Context, receiptID string) (protocol.CastReceipt, bool, error) {
	var out protocol.CastReceipt
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT receipt_json FROM ballots WHERE receipt_id = $1`, receiptID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (s *Store) GetReceiptByChallenge(ctx context.Context, challengeID string) (protocol.CastReceipt, bool, error) {
	var out protocol.CastReceipt
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT receipt_json FROM ballots WHERE challenge_id = $1`, challengeID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (s *Store) ListReceipts(ctx context.Context) ([]protocol.CastReceipt, error) {
	rows, err := s.pool.Query(ctx, `SELECT receipt_json FROM ballots ORDER BY cast_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]protocol.CastReceipt, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rec protocol.CastReceipt
		if err := decodeStrict(raw, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) CountBallots(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ballots`).Scan(&count)
	return count, err
}

func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO state_meta (key, value)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
`, key, value)
	return err
}

func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.pool.QueryRow(ctx, `SELECT value FROM state_meta WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *Store) SaveExportBundle(ctx context.Context, bundle protocol.ExportBundle, filePath, bundleSHA string) error {
	raw, err := protocol.CanonicalJSON(bundle)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO exports (bundle_id, created_at, file_path, bundle_sha256, bundle_json)
VALUES ($1, $2, $3, $4, $5::jsonb)
`, bundle.BundleID, bundle.CreatedAt.UTC(), filePath, bundleSHA, raw)
	return err
}

func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("json payload must contain a single object")
	}
	return nil
}

func isUniqueViolationFor(err error, field string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	if pgErr.Code != "23505" {
		return false
	}
	if strings.Contains(pgErr.ConstraintName, field) {
		return true
	}
	detail := strings.ToLower(pgErr.Detail)
	if detail == "" {
		return false
	}
	return strings.Contains(detail, "("+strings.ToLower(field)+")")
}
