package service

import (
	"testing"

	"github.com/votechain/votechain-machine/internal/protocol"
)

func TestSameLedgerEvent(t *testing.T) {
	entry := protocol.LedgerEntry{
		EventID:   "evt_1",
		BundleID:  "bundle_1",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"a":1,"b":2}`),
	}
	req := protocol.LedgerAppendRequest{
		EventID:   "evt_1",
		BundleID:  "bundle_1",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"b":2,"a":1}`),
	}
	ok, err := sameLedgerEvent(entry, req)
	if err != nil {
		t.Fatalf("sameLedgerEvent returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected event payloads to match canonically")
	}
}

func TestSameLedgerEventRejectsDifferentPayload(t *testing.T) {
	entry := protocol.LedgerEntry{
		EventID:   "evt_1",
		BundleID:  "bundle_1",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"a":1}`),
	}
	req := protocol.LedgerAppendRequest{
		EventID:   "evt_1",
		BundleID:  "bundle_1",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"a":2}`),
	}
	ok, err := sameLedgerEvent(entry, req)
	if err != nil {
		t.Fatalf("sameLedgerEvent returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected event payload mismatch")
	}
}

func TestSameLedgerEventRejectsDifferentMeta(t *testing.T) {
	entry := protocol.LedgerEntry{
		EventID:   "evt_1",
		BundleID:  "bundle_1",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"a":1}`),
	}
	req := protocol.LedgerAppendRequest{
		EventID:   "evt_1",
		BundleID:  "bundle_2",
		EventType: "ingest_bundle_verified",
		Payload:   []byte(`{"a":1}`),
	}
	ok, err := sameLedgerEvent(entry, req)
	if err != nil {
		t.Fatalf("sameLedgerEvent returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected metadata mismatch")
	}
}

func TestCanonicalPayloadHashInvalidJSON(t *testing.T) {
	if _, err := canonicalPayloadHash([]byte(`{"a":`)); err == nil {
		t.Fatalf("expected invalid json error")
	}
}

func TestVerifyWriteToken(t *testing.T) {
	svc := &LedgerNodeService{writeToken: "secret-token"}
	if !svc.VerifyWriteToken("secret-token") {
		t.Fatalf("expected exact token match")
	}
	if !svc.VerifyWriteToken("  secret-token ") {
		t.Fatalf("expected token match with whitespace")
	}
	if svc.VerifyWriteToken("wrong-token") {
		t.Fatalf("expected mismatch token to fail")
	}
	if svc.VerifyWriteToken("") {
		t.Fatalf("expected empty token to fail")
	}
}
