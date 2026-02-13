package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/votechain/votechain-machine/internal/protocol"
)

var ErrBundleAlreadyIngested = errors.New("bundle already ingested")
var ErrBundleConflict = errors.New("bundle conflict")

type BundleIngestRecord struct {
	Bundle             protocol.ExportBundle
	BundleSHA256       string
	VerificationStatus string
	VerificationChecks []protocol.VerifyCheck
	ReceivedAt         time.Time
}

func (s *Store) SaveVerifiedBundle(ctx context.Context, rec BundleIngestRecord) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	verificationRaw, err := protocol.CanonicalJSON(rec.VerificationChecks)
	if err != nil {
		return err
	}
	bundleRaw, err := protocol.CanonicalJSON(rec.Bundle)
	if err != nil {
		return err
	}

	previousHash := ""
	if err := tx.QueryRow(ctx, `SELECT ingest_event_hash FROM ingest_bundles ORDER BY created_at DESC LIMIT 1`).Scan(&previousHash); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		previousHash = ""
	}
	chainPayload := map[string]any{
		"bundle_id":           rec.Bundle.BundleID,
		"bundle_sha256":       rec.BundleSHA256,
		"bundle_integrity":    rec.Bundle.IntegrityHash,
		"received_at":         rec.ReceivedAt.UTC(),
		"previous_event_hash": previousHash,
	}
	eventRaw, err := protocol.CanonicalJSON(chainPayload)
	if err != nil {
		return err
	}
	ingestEventHash := protocol.SHA256Hex(eventRaw)

	cmd, err := tx.Exec(ctx, `
INSERT INTO ingest_bundles (
  bundle_id,
  machine_id,
  precinct_id,
  election_id,
  manifest_id,
  received_at,
  bundle_sha256,
  bundle_integrity_hash,
  verification_status,
  verification_json,
  bundle_json,
  ingest_event_hash,
  previous_event_hash,
  created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, NOW())
ON CONFLICT (bundle_id) DO NOTHING
`,
		rec.Bundle.BundleID,
		rec.Bundle.MachineID,
		rec.Bundle.PrecinctID,
		rec.Bundle.ElectionID,
		rec.Bundle.ManifestID,
		rec.ReceivedAt.UTC(),
		rec.BundleSHA256,
		rec.Bundle.IntegrityHash,
		rec.VerificationStatus,
		verificationRaw,
		bundleRaw,
		ingestEventHash,
		nullableString(previousHash),
	)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		var existingHash, existingMachine string
		err := tx.QueryRow(ctx, `SELECT bundle_sha256, machine_id FROM ingest_bundles WHERE bundle_id = $1`, rec.Bundle.BundleID).Scan(&existingHash, &existingMachine)
		if err != nil {
			return err
		}
		if existingHash == rec.BundleSHA256 && existingMachine == rec.Bundle.MachineID {
			return ErrBundleAlreadyIngested
		}
		return ErrBundleConflict
	}

	for i := range rec.Bundle.Receipts {
		r := rec.Bundle.Receipts[i]
		raw, err := protocol.CanonicalJSON(r)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO ingest_receipts (
  receipt_id,
  bundle_id,
  election_id,
  manifest_id,
  ballot_hash,
  bb_leaf_hash,
  tx_id,
  receipt_json,
  created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW())
`,
			r.ReceiptID,
			rec.Bundle.BundleID,
			r.ElectionID,
			r.ManifestID,
			r.BallotHash,
			r.BBLeafHash,
			r.Anchor.TxID,
			raw,
		)
		if err != nil {
			return fmt.Errorf("insert ingest receipt %s: %w", r.ReceiptID, err)
		}
	}

	anchorPayload := map[string]any{
		"bundle_id":     rec.Bundle.BundleID,
		"machine_id":    rec.Bundle.MachineID,
		"election_id":   rec.Bundle.ElectionID,
		"manifest_id":   rec.Bundle.ManifestID,
		"bundle_sha":    rec.BundleSHA256,
		"integrity":     rec.Bundle.IntegrityHash,
		"final_sth":     rec.Bundle.FinalSTH,
		"receipt_count": len(rec.Bundle.Receipts),
	}
	anchorRaw, err := protocol.CanonicalJSON(anchorPayload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO anchor_outbox (bundle_id, event_type, payload_json, status, attempts, created_at, updated_at)
VALUES ($1, $2, $3::jsonb, 'pending', 0, NOW(), NOW())
`, rec.Bundle.BundleID, "ingest_bundle_verified", anchorRaw)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
