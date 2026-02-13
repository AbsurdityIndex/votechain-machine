package service

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/protocol"
)

type BundleVerification struct {
	Status string
	Checks []protocol.VerifyCheck
}

type BundleVerifier struct {
	RequireMachineKeyID bool
}

func (v *BundleVerifier) Verify(bundle protocol.ExportBundle, machine MachineIdentity) (BundleVerification, error) {
	checks := make([]protocol.VerifyCheck, 0, 12)

	if bundle.BundleID != "" {
		checks = append(checks, okCheck("bundle_id", bundle.BundleID))
	} else {
		checks = append(checks, failCheck("bundle_id", "missing bundle_id"))
	}

	if bundle.MachineID == machine.MachineID {
		checks = append(checks, okCheck("machine_id", bundle.MachineID))
	} else {
		checks = append(checks, failCheck("machine_id", "machine_id does not match trusted registry"))
	}
	if bundle.PrecinctID == machine.PrecinctID {
		checks = append(checks, okCheck("precinct_id", bundle.PrecinctID))
	} else {
		checks = append(checks, failCheck("precinct_id", "precinct_id does not match trusted registry"))
	}

	if v.RequireMachineKeyID {
		if bundle.KeyID == machine.KeyID {
			checks = append(checks, okCheck("bundle_key_id", bundle.KeyID))
		} else {
			checks = append(checks, failCheck("bundle_key_id", "bundle key id does not match trusted machine key id"))
		}
		if bundle.FinalSTH.KeyID == machine.KeyID {
			checks = append(checks, okCheck("final_sth_key_id", bundle.FinalSTH.KeyID))
		} else {
			checks = append(checks, failCheck("final_sth_key_id", "final_sth key id does not match trusted machine key id"))
		}
	}

	leafIndexByHash := make(map[string]int, len(bundle.LeafHashes))
	duplicateLeaf := false
	for i, h := range bundle.LeafHashes {
		if _, exists := leafIndexByHash[h]; exists {
			duplicateLeaf = true
			break
		}
		leafIndexByHash[h] = i
	}
	if duplicateLeaf {
		checks = append(checks, failCheck("leaf_hashes", "duplicate leaf hash detected"))
	} else {
		checks = append(checks, okCheck("leaf_hashes", fmt.Sprintf("count=%d", len(bundle.LeafHashes))))
	}

	root, err := protocol.ComputeMerkleRoot(bundle.LeafHashes)
	if err != nil {
		checks = append(checks, failCheck("merkle_root", "failed to compute merkle root"))
	} else if root == bundle.FinalSTH.RootHash && bundle.FinalSTH.TreeSize == len(bundle.LeafHashes) {
		checks = append(checks, okCheck("merkle_root", root))
	} else {
		checks = append(checks, failCheck("merkle_root", "root or tree_size mismatch with final_sth"))
	}

	if sthPayload, err := protocol.STHSignaturePayload(bundle.FinalSTH); err != nil {
		checks = append(checks, failCheck("final_sth_signature", "cannot build sth signature payload"))
	} else if machinecrypto.Verify(machine.PublicKey, sthPayload, bundle.FinalSTH.Signature) {
		checks = append(checks, okCheck("final_sth_signature", bundle.FinalSTH.KeyID))
	} else {
		checks = append(checks, failCheck("final_sth_signature", "signature invalid"))
	}

	integrity, err := protocol.ComputeExportBundleIntegrity(bundle)
	if err != nil {
		checks = append(checks, failCheck("bundle_integrity", "failed to compute integrity hash"))
	} else if integrity == bundle.IntegrityHash {
		checks = append(checks, okCheck("bundle_integrity", integrity))
	} else {
		checks = append(checks, failCheck("bundle_integrity", "integrity hash mismatch"))
	}

	if payload, err := protocol.ExportBundleSignaturePayload(bundle); err != nil {
		checks = append(checks, failCheck("bundle_signature", "cannot build bundle signature payload"))
	} else if machinecrypto.Verify(machine.PublicKey, payload, bundle.Signature) {
		checks = append(checks, okCheck("bundle_signature", bundle.KeyID))
	} else {
		checks = append(checks, failCheck("bundle_signature", "bundle signature invalid"))
	}

	receiptIDs := make(map[string]struct{}, len(bundle.Receipts))
	ballotHashes := make(map[string]struct{}, len(bundle.Receipts))
	receiptsValid := true
	for i := range bundle.Receipts {
		r := bundle.Receipts[i]
		if _, exists := receiptIDs[r.ReceiptID]; exists {
			receiptsValid = false
			break
		}
		receiptIDs[r.ReceiptID] = struct{}{}
		if _, exists := ballotHashes[r.BallotHash]; exists {
			receiptsValid = false
			break
		}
		ballotHashes[r.BallotHash] = struct{}{}

		if r.MachineID != bundle.MachineID || r.PrecinctID != bundle.PrecinctID || r.ElectionID != bundle.ElectionID || r.ManifestID != bundle.ManifestID {
			receiptsValid = false
			break
		}
		if v.RequireMachineKeyID && r.KeyID != machine.KeyID {
			receiptsValid = false
			break
		}
		if payload, err := protocol.ReceiptSignaturePayload(r); err != nil || !machinecrypto.Verify(machine.PublicKey, payload, r.Signature) {
			receiptsValid = false
			break
		}
		if payload, err := protocol.STHSignaturePayload(r.BBSTH); err != nil || !machinecrypto.Verify(machine.PublicKey, payload, r.BBSTH.Signature) {
			receiptsValid = false
			break
		}
		idx, exists := leafIndexByHash[r.BBLeafHash]
		if !exists {
			receiptsValid = false
			break
		}
		proof, err := protocol.ComputeInclusionProof(bundle.LeafHashes, idx)
		if err != nil {
			receiptsValid = false
			break
		}
		ok, err := protocol.VerifyInclusionProof(proof)
		if err != nil || !ok || proof.RootHash != bundle.FinalSTH.RootHash {
			receiptsValid = false
			break
		}
		if r.Anchor.EventType != "ewp_ballot_cast" {
			receiptsValid = false
			break
		}
		if r.Anchor.STHRootHash != r.BBSTH.RootHash {
			receiptsValid = false
			break
		}
		if !strings.HasPrefix(r.Anchor.TxID, "0x") {
			receiptsValid = false
			break
		}
	}
	if receiptsValid {
		checks = append(checks, okCheck("receipts", fmt.Sprintf("count=%d", len(bundle.Receipts))))
	} else {
		checks = append(checks, failCheck("receipts", "one or more receipts are invalid"))
	}

	status := "ok"
	for _, c := range checks {
		if c.Status != "ok" {
			status = "fail"
			break
		}
	}
	return BundleVerification{Status: status, Checks: checks}, nil
}

func VerifyBundleWithPublicKey(bundle protocol.ExportBundle, pub ed25519.PublicKey, requireKeyID bool) (BundleVerification, error) {
	verifier := &BundleVerifier{RequireMachineKeyID: requireKeyID}
	return verifier.Verify(bundle, MachineIdentity{
		MachineID:  bundle.MachineID,
		PrecinctID: bundle.PrecinctID,
		KeyID:      bundle.KeyID,
		PublicKey:  pub,
	})
}

func okCheck(name, details string) protocol.VerifyCheck {
	return protocol.VerifyCheck{Name: name, Status: "ok", Details: details}
}

func failCheck(name, details string) protocol.VerifyCheck {
	return protocol.VerifyCheck{Name: name, Status: "fail", Details: details}
}
