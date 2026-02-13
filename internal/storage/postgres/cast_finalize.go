package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage"
)

func (s *Store) FinalizeCast(
	ctx context.Context,
	in storage.FinalizeCastInput,
	signSTH storage.SignSTHFunc,
	signReceipt storage.SignReceiptFunc,
) (protocol.CastReceipt, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	now := time.Now().UTC()
	var challenge string
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
SELECT challenge, expires_at, used_at
FROM challenges
WHERE challenge_id = $1
FOR UPDATE
`, in.Request.ChallengeID).Scan(&challenge, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.CastReceipt{}, storage.ErrChallengeMissing
	}
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	if challenge != in.Request.Challenge {
		return protocol.CastReceipt{}, storage.ErrChallengeInvalid
	}
	if usedAt != nil {
		return protocol.CastReceipt{}, storage.ErrChallengeUsed
	}
	if now.After(expiresAt.UTC()) {
		return protocol.CastReceipt{}, storage.ErrChallengeExpired
	}

	cmd, err := tx.Exec(ctx, `
UPDATE challenges
SET used_at = $2
WHERE challenge_id = $1 AND used_at IS NULL
`, in.Request.ChallengeID, now)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	if cmd.RowsAffected() == 0 {
		return protocol.CastReceipt{}, storage.ErrChallengeUsed
	}

	receivedAt := now
	leafPayload := map[string]any{
		"election_id":      in.Request.ElectionID,
		"manifest_id":      in.Request.ManifestID,
		"challenge_id":     in.Request.ChallengeID,
		"nullifier":        in.Request.Nullifier,
		"encrypted_ballot": in.Request.Ballot,
		"received_at":      receivedAt,
		"machine_id":       in.MachineID,
	}
	leafHash, err := protocol.BallotLeafHash(leafPayload)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	leafPayloadRaw, err := protocol.CanonicalJSON(leafPayload)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO bb_leaves (leaf_hash, payload_json, created_at)
VALUES ($1, $2::jsonb, NOW())
`, leafHash, leafPayloadRaw)
	if err != nil {
		if isUniqueViolationFor(err, "leaf_hash") {
			return protocol.CastReceipt{}, storage.ErrLeafExists
		}
		return protocol.CastReceipt{}, err
	}

	leafHashes, err := listLeafHashesTx(ctx, tx)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	rootHash, err := protocol.ComputeMerkleRoot(leafHashes)
	if err != nil {
		return protocol.CastReceipt{}, err
	}

	sth := protocol.SignedTreeHead{
		TreeSize:  len(leafHashes),
		RootHash:  rootHash,
		Timestamp: time.Now().UTC(),
		KeyID:     in.KeyID,
	}
	sthSig, err := signSTH(sth)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	sth.Signature = sthSig
	sthRaw, err := protocol.CanonicalJSON(sth)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO bb_sth (tree_size, root_hash, created_at, sth_json)
VALUES ($1, $2, NOW(), $3::jsonb)
`, sth.TreeSize, sth.RootHash, sthRaw)
	if err != nil {
		return protocol.CastReceipt{}, err
	}

	receiptID, err := protocol.RandomID("receipt")
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	txID := "0x" + protocol.SHA256Hex([]byte(receiptID+":"+leafHash+":"+rootHash))
	receipt := protocol.CastReceipt{
		ReceiptID:  receiptID,
		MachineID:  in.MachineID,
		PrecinctID: in.PrecinctID,
		ElectionID: in.Request.ElectionID,
		ManifestID: in.Request.ManifestID,
		BallotHash: in.Request.Ballot.BallotHash,
		BBLeafHash: leafHash,
		BBSTH:      sth,
		Anchor: protocol.VotechainAnchor{
			EventType:   "ewp_ballot_cast",
			TxID:        txID,
			STHRootHash: rootHash,
		},
		IssuedAt: time.Now().UTC(),
		KeyID:    in.KeyID,
	}
	receiptSig, err := signReceipt(receipt)
	if err != nil {
		return protocol.CastReceipt{}, err
	}
	receipt.Signature = receiptSig
	receiptRaw, err := protocol.CanonicalJSON(receipt)
	if err != nil {
		return protocol.CastReceipt{}, err
	}

	_, err = tx.Exec(ctx, `
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
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
`,
		receipt.ReceiptID,
		in.Request.ChallengeID,
		receipt.BallotHash,
		in.Request.Ballot.BallotID,
		in.Request.Nullifier,
		leafHash,
		in.Request.Ballot.Ciphertext,
		in.Request.Ballot.WrappedBallotKey,
		in.Request.Ballot.WrappedBallotKeyEP,
		receipt.IssuedAt.UTC(),
		receiptRaw,
	)
	if err != nil {
		switch {
		case isUniqueViolationFor(err, "challenge_id"):
			return protocol.CastReceipt{}, storage.ErrChallengeUsed
		case isUniqueViolationFor(err, "nullifier"):
			return protocol.CastReceipt{}, storage.ErrNullifierExists
		case isUniqueViolationFor(err, "ballot_hash"):
			return protocol.CastReceipt{}, storage.ErrBallotHashExists
		case isUniqueViolationFor(err, "leaf_hash"):
			return protocol.CastReceipt{}, storage.ErrLeafExists
		case isUniqueViolationFor(err, "receipt_id"):
			return protocol.CastReceipt{}, storage.ErrReceiptExists
		default:
			return protocol.CastReceipt{}, fmt.Errorf("insert ballot receipt: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return protocol.CastReceipt{}, err
	}
	return receipt, nil
}

func listLeafHashesTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT leaf_hash FROM bb_leaves ORDER BY idx ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	leafHashes := make([]string, 0)
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		leafHashes = append(leafHashes, h)
	}
	return leafHashes, rows.Err()
}
