package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/votechain/votechain-machine/internal/protocol"
)

func TestBundleVerifierValidBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	leafHash := protocol.SHA256B64u([]byte("leaf-1"))
	rootHash, err := protocol.ComputeMerkleRoot([]string{leafHash})
	if err != nil {
		t.Fatalf("ComputeMerkleRoot: %v", err)
	}

	finalSTH := protocol.SignedTreeHead{
		TreeSize:  1,
		RootHash:  rootHash,
		Timestamp: time.Now().UTC(),
		KeyID:     "ed25519:test",
	}
	sthPayload, err := protocol.STHSignaturePayload(finalSTH)
	if err != nil {
		t.Fatalf("STHSignaturePayload: %v", err)
	}
	finalSTH.Signature = b64u(ed25519.Sign(priv, sthPayload))

	receipt := protocol.CastReceipt{
		ReceiptID:  "receipt-1",
		MachineID:  "machine-1",
		PrecinctID: "precinct-1",
		ElectionID: "election-1",
		ManifestID: "manifest-1",
		BallotHash: protocol.SHA256B64u([]byte("ballot-1")),
		BBLeafHash: leafHash,
		BBSTH:      finalSTH,
		Anchor: protocol.VotechainAnchor{
			EventType:   "ewp_ballot_cast",
			TxID:        "0xabc123",
			STHRootHash: rootHash,
		},
		IssuedAt: time.Now().UTC(),
		KeyID:    "ed25519:test",
	}
	receiptPayload, err := protocol.ReceiptSignaturePayload(receipt)
	if err != nil {
		t.Fatalf("ReceiptSignaturePayload: %v", err)
	}
	receipt.Signature = b64u(ed25519.Sign(priv, receiptPayload))

	bundle := protocol.ExportBundle{
		BundleID:   "bundle-1",
		CreatedAt:  time.Now().UTC(),
		MachineID:  "machine-1",
		PrecinctID: "precinct-1",
		ElectionID: "election-1",
		ManifestID: "manifest-1",
		FinalSTH:   finalSTH,
		LeafHashes: []string{leafHash},
		Receipts:   []protocol.CastReceipt{receipt},
		KeyID:      "ed25519:test",
	}
	integrity, err := protocol.ComputeExportBundleIntegrity(bundle)
	if err != nil {
		t.Fatalf("ComputeExportBundleIntegrity: %v", err)
	}
	bundle.IntegrityHash = integrity
	bundlePayload, err := protocol.ExportBundleSignaturePayload(bundle)
	if err != nil {
		t.Fatalf("ExportBundleSignaturePayload: %v", err)
	}
	bundle.Signature = b64u(ed25519.Sign(priv, bundlePayload))

	verifier := &BundleVerifier{RequireMachineKeyID: true}
	result, err := verifier.Verify(bundle, MachineIdentity{
		MachineID:  "machine-1",
		PrecinctID: "precinct-1",
		KeyID:      "ed25519:test",
		PublicKey:  pub,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected ok, got %s checks=%+v", result.Status, result.Checks)
	}
}

func TestBundleVerifierDetectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafHash := protocol.SHA256B64u([]byte("leaf-1"))
	rootHash, err := protocol.ComputeMerkleRoot([]string{leafHash})
	if err != nil {
		t.Fatalf("ComputeMerkleRoot: %v", err)
	}
	finalSTH := protocol.SignedTreeHead{TreeSize: 1, RootHash: rootHash, Timestamp: time.Now().UTC(), KeyID: "ed25519:test"}
	sthPayload, _ := protocol.STHSignaturePayload(finalSTH)
	finalSTH.Signature = b64u(ed25519.Sign(priv, sthPayload))

	receipt := protocol.CastReceipt{
		ReceiptID:  "receipt-1",
		MachineID:  "machine-1",
		PrecinctID: "precinct-1",
		ElectionID: "election-1",
		ManifestID: "manifest-1",
		BallotHash: protocol.SHA256B64u([]byte("ballot-1")),
		BBLeafHash: leafHash,
		BBSTH:      finalSTH,
		Anchor:     protocol.VotechainAnchor{EventType: "ewp_ballot_cast", TxID: "0xabc123", STHRootHash: rootHash},
		IssuedAt:   time.Now().UTC(),
		KeyID:      "ed25519:test",
	}
	rp, _ := protocol.ReceiptSignaturePayload(receipt)
	receipt.Signature = b64u(ed25519.Sign(priv, rp))

	bundle := protocol.ExportBundle{
		BundleID:      "bundle-1",
		CreatedAt:     time.Now().UTC(),
		MachineID:     "machine-1",
		PrecinctID:    "precinct-1",
		ElectionID:    "election-1",
		ManifestID:    "manifest-1",
		FinalSTH:      finalSTH,
		LeafHashes:    []string{leafHash},
		Receipts:      []protocol.CastReceipt{receipt},
		IntegrityHash: "tampered",
		KeyID:         "ed25519:test",
	}
	bp, _ := protocol.ExportBundleSignaturePayload(bundle)
	bundle.Signature = b64u(ed25519.Sign(priv, bp))

	verifier := &BundleVerifier{RequireMachineKeyID: true}
	result, err := verifier.Verify(bundle, MachineIdentity{MachineID: "machine-1", PrecinctID: "precinct-1", KeyID: "ed25519:test", PublicKey: pub})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != "fail" {
		t.Fatalf("expected fail for tampered bundle, got %s", result.Status)
	}
}

func b64u(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
