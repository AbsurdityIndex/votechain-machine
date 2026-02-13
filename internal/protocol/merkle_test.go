package protocol

import "testing"

func TestMerkleProofRoundTrip(t *testing.T) {
	leaves := []string{
		SHA256B64u([]byte("leaf-1")),
		SHA256B64u([]byte("leaf-2")),
		SHA256B64u([]byte("leaf-3")),
		SHA256B64u([]byte("leaf-4")),
	}
	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("ComputeMerkleRoot error: %v", err)
	}

	proof, err := ComputeInclusionProof(leaves, 2)
	if err != nil {
		t.Fatalf("ComputeInclusionProof error: %v", err)
	}
	if proof.RootHash != root {
		t.Fatalf("proof root %q does not match root %q", proof.RootHash, root)
	}
	ok, err := VerifyInclusionProof(proof)
	if err != nil {
		t.Fatalf("VerifyInclusionProof error: %v", err)
	}
	if !ok {
		t.Fatalf("expected proof to verify")
	}
}

func TestEmptyMerkleRootIsStable(t *testing.T) {
	r1, err := ComputeMerkleRoot(nil)
	if err != nil {
		t.Fatalf("ComputeMerkleRoot error: %v", err)
	}
	r2, err := ComputeMerkleRoot([]string{})
	if err != nil {
		t.Fatalf("ComputeMerkleRoot error: %v", err)
	}
	if r1 != r2 {
		t.Fatalf("empty roots differ: %q %q", r1, r2)
	}
}
