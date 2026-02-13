package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/protocol"
)

func TestRelayVerifyAckValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	r := &AnchorRelay{
		nodePublicKey: map[string]ed25519.PublicKey{"state": pub},
		nodeAckKeyID:  map[string]string{"state": "ed25519:test"},
	}
	req := protocol.LedgerAppendRequest{EventID: "outbox_1"}
	recorded := time.Now().UTC()
	resp := protocol.LedgerAppendResponse{
		NodeRole:   "state",
		EntryIndex: 3,
		EntryHash:  "hash123",
		RecordedAt: recorded,
		Ack: protocol.LedgerAck{
			Alg: "ed25519",
			Kid: "ed25519:test",
		},
	}
	payload := struct {
		NodeRole   string    `json:"node_role"`
		EntryIndex int64     `json:"entry_index"`
		EntryHash  string    `json:"entry_hash"`
		EventID    string    `json:"event_id"`
		RecordedAt time.Time `json:"recorded_at"`
		KeyID      string    `json:"kid"`
	}{
		NodeRole:   resp.NodeRole,
		EntryIndex: resp.EntryIndex,
		EntryHash:  resp.EntryHash,
		EventID:    req.EventID,
		RecordedAt: resp.RecordedAt,
		KeyID:      resp.Ack.Kid,
	}
	raw, err := protocol.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	resp.Ack.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))

	node := config.RelayNode{Role: "state", AckKeyID: "ed25519:test"}
	if err := r.verifyAck(node, req, resp); err != nil {
		t.Fatalf("verifyAck failed: %v", err)
	}
}

func TestRelayVerifyAckKeyIDMismatch(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	r := &AnchorRelay{
		nodePublicKey: map[string]ed25519.PublicKey{"state": pub},
		nodeAckKeyID:  map[string]string{"state": "ed25519:expected"},
	}
	req := protocol.LedgerAppendRequest{EventID: "outbox_1"}
	resp := protocol.LedgerAppendResponse{
		NodeRole:   "state",
		EntryIndex: 1,
		EntryHash:  "hash",
		RecordedAt: time.Now().UTC(),
		Ack: protocol.LedgerAck{
			Alg: "ed25519",
			Kid: "ed25519:wrong",
			Sig: "not-used",
		},
	}
	node := config.RelayNode{Role: "state", AckKeyID: "ed25519:expected"}
	if err := r.verifyAck(node, req, resp); err == nil {
		t.Fatalf("expected key id mismatch error")
	}
}
