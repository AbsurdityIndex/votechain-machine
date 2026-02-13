package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage/ledgerpostgres"
)

type LedgerNodeService struct {
	store      *ledgerpostgres.Store
	signer     *machinecrypto.Signer
	nodeRole   string
	writeToken string
	service    string
	version    string
}

type LedgerNodeParams struct {
	Store      *ledgerpostgres.Store
	Signer     *machinecrypto.Signer
	NodeRole   string
	WriteToken string
	Service    string
	Version    string
}

func NewLedgerNode(params LedgerNodeParams) (*LedgerNodeService, error) {
	if params.Store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if params.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if params.NodeRole == "" {
		return nil, fmt.Errorf("node role is required")
	}
	if params.WriteToken == "" {
		return nil, fmt.Errorf("write token is required")
	}
	if params.Service == "" {
		params.Service = "votechain-ledger-node"
	}
	if params.Version == "" {
		params.Version = "dev"
	}
	return &LedgerNodeService{
		store:      params.Store,
		signer:     params.Signer,
		nodeRole:   params.NodeRole,
		writeToken: params.WriteToken,
		service:    params.Service,
		version:    params.Version,
	}, nil
}

func (s *LedgerNodeService) VerifyWriteToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" || s.writeToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.writeToken)) == 1
}

func (s *LedgerNodeService) Append(ctx context.Context, req protocol.LedgerAppendRequest) (protocol.LedgerAppendResponse, error) {
	if req.EventID == "" || req.BundleID == "" || req.EventType == "" {
		return protocol.LedgerAppendResponse{}, NewAppError(http.StatusBadRequest, "LEDGER_BAD_REQUEST", "event_id, bundle_id, and event_type are required", false, nil)
	}
	if len(req.Payload) == 0 {
		return protocol.LedgerAppendResponse{}, NewAppError(http.StatusBadRequest, "LEDGER_BAD_REQUEST", "payload is required", false, nil)
	}
	if req.RecordedAt.IsZero() {
		req.RecordedAt = time.Now().UTC()
	}
	entry, _, err := s.store.AppendEvent(ctx, req)
	if err != nil {
		return protocol.LedgerAppendResponse{}, Internal("append ledger event", err)
	}
	if ok, err := sameLedgerEvent(entry, req); err != nil {
		return protocol.LedgerAppendResponse{}, Internal("validate existing ledger event", err)
	} else if !ok {
		return protocol.LedgerAppendResponse{}, NewAppError(
			http.StatusConflict,
			"LEDGER_EVENT_CONFLICT",
			"event_id already exists with different payload",
			false,
			nil,
		)
	}
	ackPayload := struct {
		NodeRole   string    `json:"node_role"`
		EntryIndex int64     `json:"entry_index"`
		EntryHash  string    `json:"entry_hash"`
		EventID    string    `json:"event_id"`
		RecordedAt time.Time `json:"recorded_at"`
		KeyID      string    `json:"kid"`
	}{
		NodeRole:   s.nodeRole,
		EntryIndex: entry.EntryIndex,
		EntryHash:  entry.EntryHash,
		EventID:    entry.EventID,
		RecordedAt: entry.RecordedAt,
		KeyID:      s.signer.KeyID,
	}
	raw, err := protocol.CanonicalJSON(ackPayload)
	if err != nil {
		return protocol.LedgerAppendResponse{}, Internal("encode ledger ack payload", err)
	}
	sig := s.signer.Sign(raw)
	return protocol.LedgerAppendResponse{
		NodeRole:   s.nodeRole,
		EntryIndex: entry.EntryIndex,
		EntryHash:  entry.EntryHash,
		RecordedAt: entry.RecordedAt,
		Ack: protocol.LedgerAck{
			Alg: "ed25519",
			Kid: s.signer.KeyID,
			Sig: sig,
		},
	}, nil
}

func sameLedgerEvent(entry protocol.LedgerEntry, req protocol.LedgerAppendRequest) (bool, error) {
	if entry.BundleID != req.BundleID || entry.EventType != req.EventType {
		return false, nil
	}
	existingHash, err := canonicalPayloadHash(entry.Payload)
	if err != nil {
		return false, err
	}
	incomingHash, err := canonicalPayloadHash(req.Payload)
	if err != nil {
		return false, err
	}
	return existingHash == incomingHash, nil
}

func canonicalPayloadHash(raw json.RawMessage) (string, error) {
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	canon, err := protocol.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return protocol.SHA256B64u(canon), nil
}

func (s *LedgerNodeService) GetEntry(ctx context.Context, index int64) (protocol.LedgerEntry, bool, error) {
	entry, found, err := s.store.GetEntryByIndex(ctx, index)
	if err != nil {
		return protocol.LedgerEntry{}, false, Internal("get ledger entry", err)
	}
	return entry, found, nil
}

func (s *LedgerNodeService) Health(ctx context.Context) (map[string]any, error) {
	latest, found, err := s.store.LatestEntry(ctx)
	if err != nil {
		return nil, Internal("get latest entry", err)
	}
	out := map[string]any{
		"service":   s.service,
		"version":   s.version,
		"status":    "ok",
		"node_role": s.nodeRole,
		"time":      time.Now().UTC(),
	}
	if found {
		out["latest_index"] = latest.EntryIndex
		out["latest_hash"] = latest.EntryHash
	}
	return out, nil
}
