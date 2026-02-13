package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type IngestService struct {
	store    *postgres.Store
	registry *MachineRegistry
	verifier *BundleVerifier
	service  string
	version  string
}

type IngestParams struct {
	Store               *postgres.Store
	Registry            *MachineRegistry
	RequireMachineKeyID bool
	ServiceName         string
	Version             string
}

func NewIngest(params IngestParams) (*IngestService, error) {
	if params.Store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if params.Registry == nil {
		return nil, fmt.Errorf("machine registry is required")
	}
	if params.ServiceName == "" {
		params.ServiceName = "votechain-ingest"
	}
	if params.Version == "" {
		params.Version = "dev"
	}
	return &IngestService{
		store:    params.Store,
		registry: params.Registry,
		verifier: &BundleVerifier{RequireMachineKeyID: params.RequireMachineKeyID},
		service:  params.ServiceName,
		version:  params.Version,
	}, nil
}

func (s *IngestService) IngestBundle(ctx context.Context, req protocol.IngestBundleRequest) (protocol.IngestBundleResponse, error) {
	if req.Bundle.BundleID == "" {
		return protocol.IngestBundleResponse{}, NewAppError(http.StatusBadRequest, "INGEST_BAD_BUNDLE", "bundle_id is required", false, nil)
	}
	if req.Bundle.MachineID == "" {
		return protocol.IngestBundleResponse{}, NewAppError(http.StatusBadRequest, "INGEST_BAD_BUNDLE", "machine_id is required", false, nil)
	}
	machine, ok := s.registry.Lookup(req.Bundle.MachineID)
	if !ok {
		return protocol.IngestBundleResponse{}, NewAppError(http.StatusForbidden, "INGEST_MACHINE_UNTRUSTED", "machine is not in trusted registry", false, nil)
	}

	verification, err := s.verifier.Verify(req.Bundle, machine)
	if err != nil {
		return protocol.IngestBundleResponse{}, Internal("verify ingest bundle", err)
	}
	if verification.Status != "ok" {
		return protocol.IngestBundleResponse{}, NewAppError(
			http.StatusBadRequest,
			"INGEST_BUNDLE_INVALID",
			"bundle failed verification checks",
			false,
			nil,
		)
	}

	bundleRaw, err := protocol.CanonicalJSON(req.Bundle)
	if err != nil {
		return protocol.IngestBundleResponse{}, Internal("encode ingest bundle", err)
	}
	bundleSHA := protocol.SHA256Hex(bundleRaw)
	receivedAt := time.Now().UTC()
	err = s.store.SaveVerifiedBundle(ctx, postgres.BundleIngestRecord{
		Bundle:             req.Bundle,
		BundleSHA256:       bundleSHA,
		VerificationStatus: verification.Status,
		VerificationChecks: verification.Checks,
		ReceivedAt:         receivedAt,
	})
	if err != nil {
		switch err {
		case postgres.ErrBundleAlreadyIngested:
			return protocol.IngestBundleResponse{
				Status:     "bundle_already_ingested",
				BundleID:   req.Bundle.BundleID,
				MachineID:  req.Bundle.MachineID,
				PrecinctID: req.Bundle.PrecinctID,
				ElectionID: req.Bundle.ElectionID,
				ReceivedAt: receivedAt,
				Checks:     verification.Checks,
			}, nil
		case postgres.ErrBundleConflict:
			return protocol.IngestBundleResponse{}, NewAppError(http.StatusConflict, "INGEST_BUNDLE_CONFLICT", "bundle_id already exists with different content", false, err)
		default:
			return protocol.IngestBundleResponse{}, Internal("persist ingest bundle", err)
		}
	}

	return protocol.IngestBundleResponse{
		Status:     "bundle_ingested",
		BundleID:   req.Bundle.BundleID,
		MachineID:  req.Bundle.MachineID,
		PrecinctID: req.Bundle.PrecinctID,
		ElectionID: req.Bundle.ElectionID,
		ReceivedAt: receivedAt,
		Checks:     verification.Checks,
	}, nil
}

func (s *IngestService) Health(ctx context.Context) map[string]any {
	return map[string]any{
		"service": s.service,
		"version": s.version,
		"status":  "ok",
		"time":    time.Now().UTC(),
	}
}
