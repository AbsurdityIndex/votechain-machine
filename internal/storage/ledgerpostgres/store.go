package ledgerpostgres

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/votechain/votechain-machine/internal/protocol"
)

//go:embed migrations/001_init.sql
var migration001 string

type Store struct {
	pool     *pgxpool.Pool
	nodeRole string
}

func Open(ctx context.Context, dsn string, maxConns, minConns int32, nodeRole string) (*Store, error) {
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
	store := &Store{pool: pool, nodeRole: nodeRole}
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
	return nil
}

func (s *Store) AppendEvent(ctx context.Context, req protocol.LedgerAppendRequest) (protocol.LedgerEntry, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return protocol.LedgerEntry{}, false, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	entry, exists, err := s.getByEventIDTx(ctx, tx, req.EventID)
	if err != nil {
		return protocol.LedgerEntry{}, false, err
	}
	if exists {
		if err := tx.Commit(ctx); err != nil {
			return protocol.LedgerEntry{}, false, err
		}
		return entry, true, nil
	}

	var previousHash string
	_ = tx.QueryRow(ctx, `SELECT entry_hash FROM ledger_entries ORDER BY entry_index DESC LIMIT 1`).Scan(&previousHash)

	eventHash, err := computeEntryHash(req, previousHash)
	if err != nil {
		return protocol.LedgerEntry{}, false, err
	}

	var createdAt time.Time
	var index int64
	var payloadRaw []byte
	err = tx.QueryRow(ctx, `
INSERT INTO ledger_entries (
  node_role,
  entry_hash,
  previous_hash,
  event_id,
  bundle_id,
  event_type,
  payload_json,
  recorded_at,
  created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,NOW())
RETURNING entry_index, payload_json, created_at
`, s.nodeRole, eventHash, nullableString(previousHash), req.EventID, req.BundleID, req.EventType, req.Payload, req.RecordedAt.UTC()).Scan(&index, &payloadRaw, &createdAt)
	if err != nil {
		return protocol.LedgerEntry{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return protocol.LedgerEntry{}, false, err
	}

	return protocol.LedgerEntry{
		NodeRole:     s.nodeRole,
		EntryIndex:   index,
		EntryHash:    eventHash,
		PreviousHash: previousHash,
		EventID:      req.EventID,
		BundleID:     req.BundleID,
		EventType:    req.EventType,
		Payload:      json.RawMessage(payloadRaw),
		RecordedAt:   req.RecordedAt.UTC(),
		CreatedAt:    createdAt.UTC(),
	}, false, nil
}

func (s *Store) GetEntryByIndex(ctx context.Context, index int64) (protocol.LedgerEntry, bool, error) {
	var out protocol.LedgerEntry
	var payloadRaw []byte
	err := s.pool.QueryRow(ctx, `
SELECT node_role, entry_index, entry_hash, COALESCE(previous_hash,''), event_id, bundle_id, event_type, payload_json, recorded_at, created_at
FROM ledger_entries WHERE entry_index = $1
`, index).Scan(
		&out.NodeRole,
		&out.EntryIndex,
		&out.EntryHash,
		&out.PreviousHash,
		&out.EventID,
		&out.BundleID,
		&out.EventType,
		&payloadRaw,
		&out.RecordedAt,
		&out.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out.Payload = json.RawMessage(payloadRaw)
	out.RecordedAt = out.RecordedAt.UTC()
	out.CreatedAt = out.CreatedAt.UTC()
	return out, true, nil
}

func (s *Store) LatestEntry(ctx context.Context) (protocol.LedgerEntry, bool, error) {
	var out protocol.LedgerEntry
	var payloadRaw []byte
	err := s.pool.QueryRow(ctx, `
SELECT node_role, entry_index, entry_hash, COALESCE(previous_hash,''), event_id, bundle_id, event_type, payload_json, recorded_at, created_at
FROM ledger_entries ORDER BY entry_index DESC LIMIT 1
`).Scan(
		&out.NodeRole,
		&out.EntryIndex,
		&out.EntryHash,
		&out.PreviousHash,
		&out.EventID,
		&out.BundleID,
		&out.EventType,
		&payloadRaw,
		&out.RecordedAt,
		&out.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out.Payload = json.RawMessage(payloadRaw)
	out.RecordedAt = out.RecordedAt.UTC()
	out.CreatedAt = out.CreatedAt.UTC()
	return out, true, nil
}

func (s *Store) getByEventIDTx(ctx context.Context, tx pgx.Tx, eventID string) (protocol.LedgerEntry, bool, error) {
	var out protocol.LedgerEntry
	var payloadRaw []byte
	err := tx.QueryRow(ctx, `
SELECT node_role, entry_index, entry_hash, COALESCE(previous_hash,''), event_id, bundle_id, event_type, payload_json, recorded_at, created_at
FROM ledger_entries WHERE event_id = $1
`, eventID).Scan(
		&out.NodeRole,
		&out.EntryIndex,
		&out.EntryHash,
		&out.PreviousHash,
		&out.EventID,
		&out.BundleID,
		&out.EventType,
		&payloadRaw,
		&out.RecordedAt,
		&out.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out.Payload = json.RawMessage(payloadRaw)
	out.RecordedAt = out.RecordedAt.UTC()
	out.CreatedAt = out.CreatedAt.UTC()
	return out, true, nil
}

func computeEntryHash(req protocol.LedgerAppendRequest, previousHash string) (string, error) {
	payloadHash := protocol.SHA256B64u(req.Payload)
	shape := struct {
		EventID      string    `json:"event_id"`
		BundleID     string    `json:"bundle_id"`
		EventType    string    `json:"event_type"`
		PayloadHash  string    `json:"payload_hash"`
		PreviousHash string    `json:"previous_hash"`
		RecordedAt   time.Time `json:"recorded_at"`
		Source       string    `json:"source"`
	}{
		EventID:      req.EventID,
		BundleID:     req.BundleID,
		EventType:    req.EventType,
		PayloadHash:  payloadHash,
		PreviousHash: previousHash,
		RecordedAt:   req.RecordedAt.UTC(),
		Source:       req.Source,
	}
	raw, err := protocol.CanonicalJSON(shape)
	if err != nil {
		return "", err
	}
	return protocol.SHA256Hex(raw), nil
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
