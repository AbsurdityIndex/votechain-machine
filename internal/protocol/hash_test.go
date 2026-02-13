package protocol

import "testing"

func TestComputeNullifierDeterministic(t *testing.T) {
	got1 := ComputeNullifier("pubkey123", "electionA")
	got2 := ComputeNullifier("pubkey123", "electionA")
	if got1 != got2 {
		t.Fatalf("expected deterministic nullifier, got %q and %q", got1, got2)
	}
	if got1[:2] != "0x" {
		t.Fatalf("expected 0x prefix, got %q", got1)
	}
}

func TestBallotLeafHashDeterministic(t *testing.T) {
	payload := map[string]any{
		"election_id": "e1",
		"manifest_id": "m1",
		"ballot":      map[string]any{"ciphertext": "abc"},
	}
	h1, err := BallotLeafHash(payload)
	if err != nil {
		t.Fatalf("BallotLeafHash error: %v", err)
	}
	h2, err := BallotLeafHash(payload)
	if err != nil {
		t.Fatalf("BallotLeafHash error: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected deterministic leaf hash, got %q and %q", h1, h2)
	}
}
