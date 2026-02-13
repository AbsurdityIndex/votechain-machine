package storage

import (
	"context"
	"errors"
	"time"

	"github.com/votechain/votechain-machine/internal/protocol"
)

var (
	ErrChallengeUsed    = errors.New("challenge already used")
	ErrChallengeMissing = errors.New("challenge missing")
	ErrChallengeInvalid = errors.New("challenge mismatch")
	ErrChallengeExpired = errors.New("challenge expired")
	ErrNullifierExists  = errors.New("nullifier already exists")
	ErrBallotHashExists = errors.New("ballot hash already exists")
	ErrLeafExists       = errors.New("leaf hash already exists")
	ErrReceiptExists    = errors.New("receipt already exists")
)

type SignSTHFunc func(sth protocol.SignedTreeHead) (string, error)
type SignReceiptFunc func(receipt protocol.CastReceipt) (string, error)

type FinalizeCastInput struct {
	Request    protocol.CastBallotRequest
	MachineID  string
	PrecinctID string
	KeyID      string
}

type ChallengeRecord struct {
	ChallengeID string
	Challenge   string
	ExpiresAt   time.Time
	UsedAt      *time.Time
}

type Store interface {
	Close()

	SetElectionManifest(ctx context.Context, m protocol.ElectionManifest) error
	GetElectionManifest(ctx context.Context) (protocol.ElectionManifest, bool, error)

	CreateChallenge(ctx context.Context, challengeID, challenge string, expiresAt time.Time) error
	GetChallenge(ctx context.Context, challengeID string) (ChallengeRecord, bool, error)
	MarkChallengeUsed(ctx context.Context, challengeID string, usedAt time.Time) error

	LookupIdempotency(ctx context.Context, idempotencyKey string) (requestHash, responseJSON string, ok bool, err error)
	SaveIdempotency(ctx context.Context, idempotencyKey, requestHash, responseJSON string) error

	InsertLeaf(ctx context.Context, leafHash, payloadJSON string) (int, error)
	ListLeafHashes(ctx context.Context) ([]string, error)
	FindLeafIndex(ctx context.Context, leafHash string) (int, bool, error)
	FinalizeCast(ctx context.Context, in FinalizeCastInput, signSTH SignSTHFunc, signReceipt SignReceiptFunc) (protocol.CastReceipt, error)

	SaveSTH(ctx context.Context, sth protocol.SignedTreeHead) error
	LatestSTH(ctx context.Context) (protocol.SignedTreeHead, bool, error)

	SaveBallotReceipt(ctx context.Context, receipt protocol.CastReceipt, ballot protocol.EncryptedBallot, nullifier, leafHash string) error
	HasNullifier(ctx context.Context, nullifier string) (bool, error)
	HasBallotHash(ctx context.Context, ballotHash string) (bool, error)
	GetReceiptByChallenge(ctx context.Context, challengeID string) (protocol.CastReceipt, bool, error)
	GetReceipt(ctx context.Context, receiptID string) (protocol.CastReceipt, bool, error)
	ListReceipts(ctx context.Context) ([]protocol.CastReceipt, error)
	CountBallots(ctx context.Context) (int, error)

	SetMeta(ctx context.Context, key, value string) error
	GetMeta(ctx context.Context, key string) (string, bool, error)

	SaveExportBundle(ctx context.Context, bundle protocol.ExportBundle, filePath, bundleSHA string) error
}
