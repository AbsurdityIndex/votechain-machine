package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type IngestSnapshot struct {
	BundleCount    int
	ReceiptCount   int
	OutboxPending  int
	OutboxSent     int
	LatestBundleID string
	LatestBundleAt *time.Time
}

func (s *Store) GetIngestSnapshot(ctx context.Context) (IngestSnapshot, error) {
	var snap IngestSnapshot
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ingest_bundles`).Scan(&snap.BundleCount); err != nil {
		return snap, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ingest_receipts`).Scan(&snap.ReceiptCount); err != nil {
		return snap, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM anchor_outbox WHERE status = 'pending'`).Scan(&snap.OutboxPending); err != nil {
		return snap, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM anchor_outbox WHERE status = 'sent'`).Scan(&snap.OutboxSent); err != nil {
		return snap, err
	}

	var latestAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT bundle_id, received_at FROM ingest_bundles ORDER BY received_at DESC LIMIT 1`).Scan(&snap.LatestBundleID, &latestAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return snap, nil
	}
	if err != nil {
		return snap, err
	}
	t := latestAt.UTC()
	snap.LatestBundleAt = &t
	return snap, nil
}
