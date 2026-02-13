package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

func main() {
	configPath := flag.String("config", "configs/ingest.yaml", "path to ingest config")
	bundlePath := flag.String("bundle", "", "path to bundle json file")
	flag.Parse()

	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "-bundle is required")
		os.Exit(1)
	}

	cfg, err := config.LoadIngest(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	store, err := postgres.Open(context.Background(), cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	registry, err := service.LoadMachineRegistry(cfg.MachineRegistry.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "registry error: %v\n", err)
		os.Exit(1)
	}

	ingestSvc, err := service.NewIngest(service.IngestParams{
		Store:               store,
		Registry:            registry,
		RequireMachineKeyID: *cfg.Security.RequireMachineKeyID,
		ServiceName:         cfg.Logging.Service,
		Version:             cfg.Logging.Version,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "service error: %v\n", err)
		os.Exit(1)
	}

	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read bundle error: %v\n", err)
		os.Exit(1)
	}

	req, err := parseBundleRequest(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle parse error: %v\n", err)
		os.Exit(1)
	}

	resp, err := ingestSvc.IngestBundle(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "encode response error: %v\n", err)
		os.Exit(1)
	}
}

func parseBundleRequest(raw []byte) (protocol.IngestBundleRequest, error) {
	var wrapped protocol.IngestBundleRequest
	if err := decodeStrict(raw, &wrapped); err == nil && wrapped.Bundle.BundleID != "" {
		return wrapped, nil
	}
	var bundle protocol.ExportBundle
	if err := decodeStrict(raw, &bundle); err != nil {
		return protocol.IngestBundleRequest{}, err
	}
	return protocol.IngestBundleRequest{Bundle: bundle}, nil
}

func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}
