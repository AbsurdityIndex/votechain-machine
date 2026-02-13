package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type AnchorOutboxItem struct {
	ID            int64
	BundleID      string
	EventType     string
	Payload       json.RawMessage
	Status        string
	Attempts      int
	LastError     string
	NextAttemptAt *time.Time
	CreatedAt     time.Time
}

func (s *Store) FetchPendingOutbox(ctx context.Context, limit int) ([]AnchorOutboxItem, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
SELECT id, bundle_id, event_type, payload_json, status, attempts, COALESCE(last_error,''), next_attempt_at, created_at
FROM anchor_outbox
WHERE status = 'pending'
  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
ORDER BY created_at ASC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AnchorOutboxItem, 0)
	for rows.Next() {
		var item AnchorOutboxItem
		var next *time.Time
		if err := rows.Scan(&item.ID, &item.BundleID, &item.EventType, &item.Payload, &item.Status, &item.Attempts, &item.LastError, &next, &item.CreatedAt); err != nil {
			return nil, err
		}
		if next != nil {
			t := next.UTC()
			item.NextAttemptAt = &t
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) MarkOutboxSent(ctx context.Context, id int64, ackSummary any) error {
	raw, err := json.Marshal(ackSummary)
	if err != nil {
		return fmt.Errorf("marshal outbox ack summary: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
UPDATE anchor_outbox
SET status = 'sent',
    last_error = NULL,
    next_attempt_at = NULL,
    sent_at = NOW(),
    ack_summary = $2::jsonb,
    updated_at = NOW()
WHERE id = $1
`, id, raw)
	return err
}

func (s *Store) MarkOutboxRetry(ctx context.Context, id int64, attempts int, nextAttempt time.Time, lastError string) error {
	_, err := s.pool.Exec(ctx, `
UPDATE anchor_outbox
SET status = 'pending',
    attempts = $2,
    last_error = $3,
    next_attempt_at = $4,
    updated_at = NOW()
WHERE id = $1
`, id, attempts, lastError, nextAttempt.UTC())
	return err
}
