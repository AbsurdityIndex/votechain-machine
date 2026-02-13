package protocol

import "time"

func ReceiptSignaturePayload(receipt CastReceipt) ([]byte, error) {
	type payload struct {
		ReceiptID  string          `json:"receipt_id"`
		MachineID  string          `json:"machine_id"`
		PrecinctID string          `json:"precinct_id"`
		ElectionID string          `json:"election_id"`
		ManifestID string          `json:"manifest_id"`
		BallotHash string          `json:"ballot_hash"`
		BBLeafHash string          `json:"bb_leaf_hash"`
		BBSTH      SignedTreeHead  `json:"bb_sth"`
		Anchor     VotechainAnchor `json:"votechain_anchor"`
		IssuedAt   time.Time       `json:"issued_at"`
		KeyID      string          `json:"kid"`
	}
	return CanonicalJSON(payload{
		ReceiptID:  receipt.ReceiptID,
		MachineID:  receipt.MachineID,
		PrecinctID: receipt.PrecinctID,
		ElectionID: receipt.ElectionID,
		ManifestID: receipt.ManifestID,
		BallotHash: receipt.BallotHash,
		BBLeafHash: receipt.BBLeafHash,
		BBSTH: SignedTreeHead{
			TreeSize:  receipt.BBSTH.TreeSize,
			RootHash:  receipt.BBSTH.RootHash,
			Timestamp: receipt.BBSTH.Timestamp,
			KeyID:     receipt.BBSTH.KeyID,
		},
		Anchor:   receipt.Anchor,
		IssuedAt: receipt.IssuedAt,
		KeyID:    receipt.KeyID,
	})
}

func STHSignaturePayload(sth SignedTreeHead) ([]byte, error) {
	type payload struct {
		TreeSize  int       `json:"tree_size"`
		RootHash  string    `json:"root_hash"`
		Timestamp time.Time `json:"timestamp"`
		KeyID     string    `json:"kid"`
	}
	return CanonicalJSON(payload{
		TreeSize:  sth.TreeSize,
		RootHash:  sth.RootHash,
		Timestamp: sth.Timestamp,
		KeyID:     sth.KeyID,
	})
}

func ComputeExportBundleIntegrity(bundle ExportBundle) (string, error) {
	payload := struct {
		BundleID   string         `json:"bundle_id"`
		CreatedAt  time.Time      `json:"created_at"`
		MachineID  string         `json:"machine_id"`
		PrecinctID string         `json:"precinct_id"`
		ElectionID string         `json:"election_id"`
		ManifestID string         `json:"manifest_id"`
		FinalSTH   SignedTreeHead `json:"final_sth"`
		LeafHashes []string       `json:"leaf_hashes"`
		Receipts   []CastReceipt  `json:"receipts"`
		KeyID      string         `json:"kid"`
	}{
		BundleID:   bundle.BundleID,
		CreatedAt:  bundle.CreatedAt,
		MachineID:  bundle.MachineID,
		PrecinctID: bundle.PrecinctID,
		ElectionID: bundle.ElectionID,
		ManifestID: bundle.ManifestID,
		FinalSTH:   bundle.FinalSTH,
		LeafHashes: bundle.LeafHashes,
		Receipts:   bundle.Receipts,
		KeyID:      bundle.KeyID,
	}
	return HashCanonical(payload)
}

func ExportBundleSignaturePayload(bundle ExportBundle) ([]byte, error) {
	type payload struct {
		BundleID      string         `json:"bundle_id"`
		CreatedAt     time.Time      `json:"created_at"`
		MachineID     string         `json:"machine_id"`
		PrecinctID    string         `json:"precinct_id"`
		ElectionID    string         `json:"election_id"`
		ManifestID    string         `json:"manifest_id"`
		FinalSTH      SignedTreeHead `json:"final_sth"`
		LeafHashes    []string       `json:"leaf_hashes"`
		Receipts      []CastReceipt  `json:"receipts"`
		IntegrityHash string         `json:"integrity_hash"`
		KeyID         string         `json:"kid"`
	}
	return CanonicalJSON(payload{
		BundleID:      bundle.BundleID,
		CreatedAt:     bundle.CreatedAt,
		MachineID:     bundle.MachineID,
		PrecinctID:    bundle.PrecinctID,
		ElectionID:    bundle.ElectionID,
		ManifestID:    bundle.ManifestID,
		FinalSTH:      bundle.FinalSTH,
		LeafHashes:    bundle.LeafHashes,
		Receipts:      bundle.Receipts,
		IntegrityHash: bundle.IntegrityHash,
		KeyID:         bundle.KeyID,
	})
}
