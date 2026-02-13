package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	machinecrypto "github.com/votechain/votechain-machine/internal/crypto"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage"
)

type MachineService struct {
	store        storage.Store
	signer       *machinecrypto.Signer
	machineID    string
	precinctID   string
	jurisdiction string
	mode         string
	service      string
	version      string
	exportDir    string
	challengeTTL time.Duration
}

type Params struct {
	Store          storage.Store
	Signer         *machinecrypto.Signer
	MachineID      string
	PrecinctID     string
	JurisdictionID string
	Mode           string
	ServiceName    string
	Version        string
	ExportDir      string
	ChallengeTTL   time.Duration
}

func New(params Params) (*MachineService, error) {
	if params.Store == nil {
		return nil, errors.New("store is required")
	}
	if params.Signer == nil {
		return nil, errors.New("signer is required")
	}
	if params.MachineID == "" {
		return nil, errors.New("machine id is required")
	}
	if params.PrecinctID == "" {
		return nil, errors.New("precinct id is required")
	}
	if params.JurisdictionID == "" {
		return nil, errors.New("jurisdiction id is required")
	}
	if params.ExportDir == "" {
		return nil, errors.New("export directory is required")
	}
	if params.ChallengeTTL <= 0 {
		params.ChallengeTTL = 2 * time.Minute
	}
	if params.Mode == "" {
		params.Mode = "air-gapped"
	}
	if params.ServiceName == "" {
		params.ServiceName = "votechain-machine"
	}
	if params.Version == "" {
		params.Version = "dev"
	}
	return &MachineService{
		store:        params.Store,
		signer:       params.Signer,
		machineID:    params.MachineID,
		precinctID:   params.PrecinctID,
		jurisdiction: params.JurisdictionID,
		mode:         params.Mode,
		service:      params.ServiceName,
		version:      params.Version,
		exportDir:    params.ExportDir,
		challengeTTL: params.ChallengeTTL,
	}, nil
}

func (s *MachineService) LoadElection(ctx context.Context, req protocol.LoadElectionRequest) (protocol.LoadElectionResponse, error) {
	if err := validateManifest(req.Manifest); err != nil {
		return protocol.LoadElectionResponse{}, NewAppError(http.StatusBadRequest, "ELECTION_BAD_MANIFEST", err.Error(), false, err)
	}
	if req.Manifest.JurisdictionID != s.jurisdiction {
		return protocol.LoadElectionResponse{}, NewAppError(
			http.StatusBadRequest,
			"ELECTION_JURISDICTION_MISMATCH",
			"manifest jurisdiction does not match machine jurisdiction",
			false,
			nil,
		)
	}
	if req.Manifest.ReceiptKeyID != "" && req.Manifest.ReceiptKeyID != s.signer.KeyID {
		return protocol.LoadElectionResponse{}, NewAppError(
			http.StatusBadRequest,
			"ELECTION_RECEIPT_KEY_MISMATCH",
			"manifest receipt key id does not match machine signing key",
			false,
			nil,
		)
	}
	if req.Manifest.ReceiptKeyID == "" {
		req.Manifest.ReceiptKeyID = s.signer.KeyID
	}
	if err := s.store.SetElectionManifest(ctx, req.Manifest); err != nil {
		return protocol.LoadElectionResponse{}, Internal("persist election manifest", err)
	}
	loaded := time.Now().UTC()
	return protocol.LoadElectionResponse{
		Status:         "election_loaded",
		ElectionID:     req.Manifest.ElectionID,
		ManifestID:     req.Manifest.ManifestID,
		JurisdictionID: req.Manifest.JurisdictionID,
		LoadedAt:       loaded,
	}, nil
}

func (s *MachineService) IssueChallenge(ctx context.Context) (protocol.ChallengeResponse, error) {
	manifest, err := s.activeManifest(ctx)
	if err != nil {
		return protocol.ChallengeResponse{}, err
	}
	if err := enforceElectionWindow(manifest, time.Now().UTC()); err != nil {
		return protocol.ChallengeResponse{}, err
	}
	closed, err := s.pollsClosed(ctx)
	if err != nil {
		return protocol.ChallengeResponse{}, Internal("read polling state", err)
	}
	if closed {
		return protocol.ChallengeResponse{}, NewAppError(http.StatusConflict, "ELECTION_CLOSED", "polls are closed on this machine", false, nil)
	}
	challengeID, err := protocol.RandomID("chlg")
	if err != nil {
		return protocol.ChallengeResponse{}, Internal("generate challenge id", err)
	}
	nonce, err := protocol.RandomID("nonce")
	if err != nil {
		return protocol.ChallengeResponse{}, Internal("generate challenge nonce", err)
	}
	expires := time.Now().UTC().Add(s.challengeTTL)
	if err := s.store.CreateChallenge(ctx, challengeID, nonce, expires); err != nil {
		return protocol.ChallengeResponse{}, Internal("persist challenge", err)
	}
	return protocol.ChallengeResponse{ChallengeID: challengeID, Challenge: nonce, ExpiresAt: expires}, nil
}

func (s *MachineService) CastBallot(ctx context.Context, req protocol.CastBallotRequest) (protocol.CastResponse, error) {
	if req.IdempotencyKey == "" {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_IDEMPOTENCY_REQUIRED", "idempotency_key is required", false, nil)
	}
	requestHash, err := protocol.HashCanonical(req)
	if err != nil {
		return protocol.CastResponse{}, Internal("hash cast request", err)
	}
	if existingHash, existingResponse, ok, err := s.store.LookupIdempotency(ctx, req.IdempotencyKey); err != nil {
		return protocol.CastResponse{}, Internal("read idempotency", err)
	} else if ok {
		if existingHash != requestHash {
			return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_IDEMPOTENCY_MISMATCH", "idempotency key reused with different body", false, nil)
		}
		var out protocol.CastResponse
		if err := decodeStrictJSON([]byte(existingResponse), &out); err != nil {
			return protocol.CastResponse{}, Internal("decode idempotent response", err)
		}
		return out, nil
	}

	manifest, err := s.activeManifest(ctx)
	if err != nil {
		return protocol.CastResponse{}, err
	}
	if err := enforceElectionWindow(manifest, time.Now().UTC()); err != nil {
		return protocol.CastResponse{}, err
	}
	if req.ElectionID != manifest.ElectionID || req.ManifestID != manifest.ManifestID {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_BAD_MANIFEST", "request election or manifest id mismatch", false, nil)
	}

	closed, err := s.pollsClosed(ctx)
	if err != nil {
		return protocol.CastResponse{}, Internal("read polling state", err)
	}
	if closed {
		return protocol.CastResponse{}, NewAppError(http.StatusConflict, "ELECTION_CLOSED", "polls are closed on this machine", false, nil)
	}

	challengeRec, found, err := s.store.GetChallenge(ctx, req.ChallengeID)
	if err != nil {
		return protocol.CastResponse{}, Internal("read challenge", err)
	}
	if !found || challengeRec.Challenge != req.Challenge {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_PROOF_INVALID", "challenge not found", false, nil)
	}
	if challengeRec.UsedAt != nil {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_PROOF_INVALID", "challenge already used", false, nil)
	}
	if time.Now().UTC().After(challengeRec.ExpiresAt) {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_CHALLENGE_EXPIRED", "challenge expired", true, nil)
	}

	if req.Proof.CredentialPub == "" {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_PROOF_INVALID", "credential_pub is required", false, nil)
	}
	expectedNullifier := protocol.ComputeNullifier(req.Proof.CredentialPub, req.ElectionID)
	if req.Nullifier != expectedNullifier {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_PROOF_INVALID", "nullifier derivation mismatch", false, nil)
	}

	if used, err := s.store.HasNullifier(ctx, req.Nullifier); err != nil {
		return protocol.CastResponse{}, Internal("query nullifier", err)
	} else if used {
		return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_NULLIFIER_USED", "nullifier already used", false, nil)
	}

	if seen, err := s.store.HasBallotHash(ctx, req.Ballot.BallotHash); err != nil {
		return protocol.CastResponse{}, Internal("query ballot hash", err)
	} else if seen {
		return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_BALLOT_INVALID", "ballot hash already present", false, nil)
	}

	cipherBytes, err := decodeBase64Loose(req.Ballot.Ciphertext)
	if err != nil {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_BALLOT_INVALID", "ciphertext must be base64 encoded", false, err)
	}
	if protocol.SHA256B64u(cipherBytes) != req.Ballot.BallotHash {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_BALLOT_INVALID", "ballot hash mismatch", false, nil)
	}
	if req.Ballot.WrappedBallotKey == "" || req.Ballot.WrappedBallotKeyEP == "" {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_BALLOT_INVALID", "wrapped ballot key fields are required", false, nil)
	}
	if req.Ballot.BallotID == "" {
		return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_BALLOT_INVALID", "ballot_id is required", false, nil)
	}

	receipt, err := s.store.FinalizeCast(
		ctx,
		storage.FinalizeCastInput{
			Request:    req,
			MachineID:  s.machineID,
			PrecinctID: s.precinctID,
			KeyID:      s.signer.KeyID,
		},
		func(sth protocol.SignedTreeHead) (string, error) {
			payload, err := protocol.STHSignaturePayload(sth)
			if err != nil {
				return "", err
			}
			return s.signer.Sign(payload), nil
		},
		func(receipt protocol.CastReceipt) (string, error) {
			payload, err := protocol.ReceiptSignaturePayload(receipt)
			if err != nil {
				return "", err
			}
			return s.signer.Sign(payload), nil
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrChallengeMissing), errors.Is(err, storage.ErrChallengeInvalid):
			return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_PROOF_INVALID", "challenge not found", false, err)
		case errors.Is(err, storage.ErrChallengeExpired):
			return protocol.CastResponse{}, NewAppError(http.StatusBadRequest, "EWP_CHALLENGE_EXPIRED", "challenge expired", true, err)
		case errors.Is(err, storage.ErrChallengeUsed), errors.Is(err, storage.ErrNullifierExists), errors.Is(err, storage.ErrBallotHashExists), errors.Is(err, storage.ErrLeafExists):
			if recovered, ok, recErr := s.recoverCastByChallenge(ctx, req, requestHash); recErr != nil {
				return protocol.CastResponse{}, Internal("recover cast from challenge", recErr)
			} else if ok {
				return recovered, nil
			}
			switch {
			case errors.Is(err, storage.ErrChallengeUsed):
				return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_PROOF_INVALID", "challenge already used", false, err)
			case errors.Is(err, storage.ErrNullifierExists):
				return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_NULLIFIER_USED", "nullifier already used", false, err)
			default:
				return protocol.CastResponse{}, NewAppError(http.StatusConflict, "EWP_BALLOT_INVALID", "ballot already recorded", false, err)
			}
		default:
			return protocol.CastResponse{}, Internal("finalize cast transaction", err)
		}
	}

	out := protocol.CastResponse{Status: "cast_recorded", CastReceipt: receipt}
	if raw, err := protocol.CanonicalJSON(out); err == nil {
		_ = s.store.SaveIdempotency(ctx, req.IdempotencyKey, requestHash, string(raw))
	}
	return out, nil
}

func (s *MachineService) recoverCastByChallenge(
	ctx context.Context,
	req protocol.CastBallotRequest,
	requestHash string,
) (protocol.CastResponse, bool, error) {
	receipt, found, err := s.store.GetReceiptByChallenge(ctx, req.ChallengeID)
	if err != nil || !found {
		return protocol.CastResponse{}, false, err
	}
	if receipt.ElectionID != req.ElectionID || receipt.ManifestID != req.ManifestID || receipt.BallotHash != req.Ballot.BallotHash {
		return protocol.CastResponse{}, false, nil
	}
	out := protocol.CastResponse{Status: "cast_recorded", CastReceipt: receipt}
	if raw, err := protocol.CanonicalJSON(out); err == nil {
		_ = s.store.SaveIdempotency(ctx, req.IdempotencyKey, requestHash, string(raw))
	}
	return out, true, nil
}

func (s *MachineService) VerifyReceipt(ctx context.Context, req protocol.VerifyReceiptRequest) (protocol.VerifyReceiptResponse, error) {
	checks := make([]protocol.VerifyCheck, 0, 7)

	manifest, found, err := s.store.GetElectionManifest(ctx)
	if err != nil {
		return protocol.VerifyReceiptResponse{}, Internal("read election manifest", err)
	}
	if found && manifest.ManifestID == req.Receipt.ManifestID {
		checks = append(checks, protocol.VerifyCheck{Name: "manifest_loaded", Status: "ok", Details: manifest.ManifestID})
	} else {
		checks = append(checks, protocol.VerifyCheck{Name: "manifest_loaded", Status: "fail", Details: "manifest mismatch or missing"})
	}

	receiptPayload, err := protocol.ReceiptSignaturePayload(req.Receipt)
	receiptSigOK := err == nil && machinecrypto.Verify(s.signer.Public, receiptPayload, req.Receipt.Signature)
	if receiptSigOK {
		checks = append(checks, protocol.VerifyCheck{Name: "receipt_signature", Status: "ok", Details: req.Receipt.KeyID})
	} else {
		checks = append(checks, protocol.VerifyCheck{Name: "receipt_signature", Status: "fail", Details: "receipt signature invalid"})
	}

	sthPayload, err := protocol.STHSignaturePayload(req.Receipt.BBSTH)
	sthSigOK := err == nil && machinecrypto.Verify(s.signer.Public, sthPayload, req.Receipt.BBSTH.Signature)
	if sthSigOK {
		checks = append(checks, protocol.VerifyCheck{Name: "bb_sth_signature", Status: "ok", Details: req.Receipt.BBSTH.KeyID})
	} else {
		checks = append(checks, protocol.VerifyCheck{Name: "bb_sth_signature", Status: "fail", Details: "signed tree head signature invalid"})
	}

	leafIndex, leafFound, err := s.store.FindLeafIndex(ctx, req.Receipt.BBLeafHash)
	if err != nil {
		return protocol.VerifyReceiptResponse{}, Internal("find leaf", err)
	}
	if !leafFound {
		checks = append(checks, protocol.VerifyCheck{Name: "bb_leaf_exists", Status: "fail", Details: "leaf hash not found"})
		checks = append(checks, protocol.VerifyCheck{Name: "bb_inclusion_proof", Status: "fail", Details: "missing leaf"})
	} else {
		checks = append(checks, protocol.VerifyCheck{Name: "bb_leaf_exists", Status: "ok", Details: fmt.Sprintf("leaf_index=%d", leafIndex)})
		leafHashes, err := s.store.ListLeafHashes(ctx)
		if err != nil {
			return protocol.VerifyReceiptResponse{}, Internal("list leaf hashes", err)
		}
		if req.Receipt.BBSTH.TreeSize <= 0 || req.Receipt.BBSTH.TreeSize > len(leafHashes) {
			checks = append(checks, protocol.VerifyCheck{Name: "bb_inclusion_proof", Status: "fail", Details: "receipt tree size is out of range"})
		} else if leafIndex < 0 || leafIndex >= req.Receipt.BBSTH.TreeSize {
			checks = append(checks, protocol.VerifyCheck{Name: "bb_inclusion_proof", Status: "fail", Details: "leaf index exceeds receipt tree size"})
		} else {
			proofLeaves := leafHashes[:req.Receipt.BBSTH.TreeSize]
			proof, err := protocol.ComputeInclusionProof(proofLeaves, leafIndex)
			if err != nil {
				return protocol.VerifyReceiptResponse{}, Internal("compute inclusion proof", err)
			}
			proofValid, err := protocol.VerifyInclusionProof(proof)
			if err != nil {
				return protocol.VerifyReceiptResponse{}, Internal("verify inclusion proof", err)
			}
			rootMatches := proof.RootHash == req.Receipt.BBSTH.RootHash
			if proofValid && rootMatches {
				checks = append(checks, protocol.VerifyCheck{Name: "bb_inclusion_proof", Status: "ok", Details: fmt.Sprintf("tree_size=%d", proof.TreeSize)})
			} else {
				checks = append(checks, protocol.VerifyCheck{Name: "bb_inclusion_proof", Status: "fail", Details: "proof failed or root mismatch"})
			}
		}
	}

	stored, storedFound, err := s.store.GetReceipt(ctx, req.Receipt.ReceiptID)
	if err != nil {
		return protocol.VerifyReceiptResponse{}, Internal("read stored receipt", err)
	}
	if !storedFound {
		checks = append(checks, protocol.VerifyCheck{Name: "local_receipt_record", Status: "fail", Details: "receipt id not found"})
		checks = append(checks, protocol.VerifyCheck{Name: "votechain_anchor", Status: "fail", Details: "missing local receipt"})
	} else {
		if stored.BallotHash == req.Receipt.BallotHash && stored.BBLeafHash == req.Receipt.BBLeafHash {
			checks = append(checks, protocol.VerifyCheck{Name: "local_receipt_record", Status: "ok", Details: stored.ReceiptID})
		} else {
			checks = append(checks, protocol.VerifyCheck{Name: "local_receipt_record", Status: "fail", Details: "stored receipt mismatch"})
		}
		if stored.Anchor.TxID == req.Receipt.Anchor.TxID && stored.Anchor.STHRootHash == req.Receipt.Anchor.STHRootHash {
			checks = append(checks, protocol.VerifyCheck{Name: "votechain_anchor", Status: "ok", Details: stored.Anchor.TxID})
		} else {
			checks = append(checks, protocol.VerifyCheck{Name: "votechain_anchor", Status: "fail", Details: "anchor mismatch"})
		}
	}

	status := "ok"
	for _, check := range checks {
		if check.Status != "ok" {
			status = "fail"
			break
		}
	}

	return protocol.VerifyReceiptResponse{Status: status, Checks: checks}, nil
}

func (s *MachineService) ClosePolls(ctx context.Context) (protocol.ClosePollsResponse, error) {
	manifest, err := s.activeManifest(ctx)
	if err != nil {
		return protocol.ClosePollsResponse{}, err
	}
	closed, err := s.pollsClosed(ctx)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("read polling state", err)
	}
	if closed {
		return protocol.ClosePollsResponse{}, NewAppError(http.StatusConflict, "ELECTION_CLOSED", "polls are already closed on this machine", false, nil)
	}

	leafHashes, err := s.store.ListLeafHashes(ctx)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("list leaf hashes", err)
	}

	finalSTH, sthFound, err := s.store.LatestSTH(ctx)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("read latest tree head", err)
	}
	if !sthFound {
		root, err := protocol.ComputeMerkleRoot(leafHashes)
		if err != nil {
			return protocol.ClosePollsResponse{}, Internal("compute closing root hash", err)
		}
		ts := time.Now().UTC()
		sig, err := s.signSTH(len(leafHashes), root, ts)
		if err != nil {
			return protocol.ClosePollsResponse{}, Internal("sign closing tree head", err)
		}
		finalSTH = protocol.SignedTreeHead{
			TreeSize:  len(leafHashes),
			RootHash:  root,
			Timestamp: ts,
			KeyID:     s.signer.KeyID,
			Signature: sig,
		}
		if err := s.store.SaveSTH(ctx, finalSTH); err != nil {
			return protocol.ClosePollsResponse{}, Internal("save closing tree head", err)
		}
	}

	receipts, err := s.store.ListReceipts(ctx)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("list receipts", err)
	}

	bundleID, err := protocol.RandomID("bundle")
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("generate bundle id", err)
	}
	createdAt := time.Now().UTC()

	bundle := protocol.ExportBundle{
		BundleID:   bundleID,
		CreatedAt:  createdAt,
		MachineID:  s.machineID,
		PrecinctID: s.precinctID,
		ElectionID: manifest.ElectionID,
		ManifestID: manifest.ManifestID,
		FinalSTH:   finalSTH,
		LeafHashes: leafHashes,
		Receipts:   receipts,
		KeyID:      s.signer.KeyID,
	}

	integrityHash, err := s.computeBundleIntegrity(bundle)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("compute bundle integrity", err)
	}
	bundle.IntegrityHash = integrityHash
	bundleSigPayload, err := protocol.ExportBundleSignaturePayload(bundle)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("encode bundle signature payload", err)
	}
	bundle.Signature = s.signer.Sign(bundleSigPayload)

	bundleRaw, err := protocol.CanonicalJSON(bundle)
	if err != nil {
		return protocol.ClosePollsResponse{}, Internal("encode bundle", err)
	}
	bundlePath := filepath.Join(s.exportDir, bundleID+".json")
	if err := os.WriteFile(bundlePath, append(bundleRaw, '\n'), 0o600); err != nil {
		return protocol.ClosePollsResponse{}, Internal("write bundle", err)
	}
	bundleSHA := protocol.SHA256Hex(bundleRaw)
	if err := s.store.SaveExportBundle(ctx, bundle, bundlePath, bundleSHA); err != nil {
		return protocol.ClosePollsResponse{}, Internal("record bundle", err)
	}
	if err := s.store.SetMeta(ctx, "polls_closed", "true"); err != nil {
		return protocol.ClosePollsResponse{}, Internal("mark polls closed", err)
	}

	return protocol.ClosePollsResponse{
		Status:       "polls_closed",
		ClosedAt:     createdAt,
		BundlePath:   bundlePath,
		BundleSHA256: bundleSHA,
		FinalSTH:     finalSTH,
		BallotCount:  len(receipts),
	}, nil
}

func (s *MachineService) Health(ctx context.Context) (protocol.HealthResponse, error) {
	manifest, found, err := s.store.GetElectionManifest(ctx)
	if err != nil {
		return protocol.HealthResponse{}, Internal("read election manifest", err)
	}
	count, err := s.store.CountBallots(ctx)
	if err != nil {
		return protocol.HealthResponse{}, Internal("count ballots", err)
	}
	pollsClosed, err := s.pollsClosed(ctx)
	if err != nil {
		return protocol.HealthResponse{}, Internal("read polling state", err)
	}
	latestSTH, sthFound, err := s.store.LatestSTH(ctx)
	if err != nil {
		return protocol.HealthResponse{}, Internal("read tree head", err)
	}
	resp := protocol.HealthResponse{
		Service:     s.service,
		Version:     s.version,
		MachineID:   s.machineID,
		Mode:        s.mode,
		PollsClosed: pollsClosed,
		BallotCount: count,
	}
	if found {
		resp.ElectionID = manifest.ElectionID
		resp.ManifestID = manifest.ManifestID
	}
	if sthFound {
		resp.CurrentSTH = latestSTH.RootHash
	}
	return resp, nil
}

func (s *MachineService) activeManifest(ctx context.Context) (protocol.ElectionManifest, error) {
	manifest, found, err := s.store.GetElectionManifest(ctx)
	if err != nil {
		return protocol.ElectionManifest{}, Internal("read election manifest", err)
	}
	if !found {
		return protocol.ElectionManifest{}, NewAppError(http.StatusConflict, "ELECTION_NOT_LOADED", "no election manifest loaded", false, nil)
	}
	return manifest, nil
}

func (s *MachineService) pollsClosed(ctx context.Context) (bool, error) {
	v, ok, err := s.store.GetMeta(ctx, "polls_closed")
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes", nil
}

func (s *MachineService) signSTH(treeSize int, rootHash string, ts time.Time) (string, error) {
	payload, err := protocol.STHSignaturePayload(protocol.SignedTreeHead{
		TreeSize:  treeSize,
		RootHash:  rootHash,
		Timestamp: ts,
		KeyID:     s.signer.KeyID,
	})
	if err != nil {
		return "", err
	}
	return s.signer.Sign(payload), nil
}

func (s *MachineService) signReceipt(receipt protocol.CastReceipt) (string, error) {
	payload, err := protocol.ReceiptSignaturePayload(receipt)
	if err != nil {
		return "", err
	}
	return s.signer.Sign(payload), nil
}

func (s *MachineService) computeBundleIntegrity(bundle protocol.ExportBundle) (string, error) {
	return protocol.ComputeExportBundleIntegrity(bundle)
}

func enforceElectionWindow(manifest protocol.ElectionManifest, now time.Time) error {
	if now.Before(manifest.NotBefore) {
		return NewAppError(http.StatusConflict, "ELECTION_NOT_ACTIVE", "election has not started", false, nil)
	}
	if now.After(manifest.NotAfter) {
		return NewAppError(http.StatusConflict, "ELECTION_NOT_ACTIVE", "election has ended", false, nil)
	}
	return nil
}

func validateManifest(m protocol.ElectionManifest) error {
	if m.ElectionID == "" {
		return errors.New("manifest election_id is required")
	}
	if m.JurisdictionID == "" {
		return errors.New("manifest jurisdiction_id is required")
	}
	if m.ManifestID == "" {
		return errors.New("manifest manifest_id is required")
	}
	if m.NotBefore.IsZero() || m.NotAfter.IsZero() {
		return errors.New("manifest not_before and not_after are required")
	}
	if !m.NotAfter.After(m.NotBefore) {
		return errors.New("manifest not_after must be after not_before")
	}
	if len(m.Contests) == 0 {
		return errors.New("manifest contests must not be empty")
	}
	for _, contest := range m.Contests {
		if contest.ContestID == "" {
			return errors.New("contest_id is required")
		}
		if len(contest.Options) == 0 {
			return fmt.Errorf("contest %s has no options", contest.ContestID)
		}
	}
	return nil
}

func decodeStrictJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("json payload must contain a single object")
	}
	return nil
}

func decodeBase64Loose(in string) ([]byte, error) {
	in = strings.TrimSpace(in)
	candidates := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	}
	for _, fn := range candidates {
		if b, err := fn(in); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
