package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/votechain/votechain-machine/internal/api"
	"github.com/votechain/votechain-machine/internal/config"
	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/service"
	"github.com/votechain/votechain-machine/internal/storage/postgres"
)

type IngestApplication struct {
	Server *http.Server
	Store  *postgres.Store
}

func BuildIngest(ctx context.Context, cfg *config.IngestConfig, logger *slog.Logger) (*IngestApplication, error) {
	store, err := postgres.Open(ctx, cfg.Storage.PostgresDSN, cfg.Storage.MaxConns, cfg.Storage.MinConns)
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	registry, err := service.LoadMachineRegistry(cfg.MachineRegistry.Path)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load machine registry: %w", err)
	}

	ingestSvc, err := service.NewIngest(service.IngestParams{
		Store:               store,
		Registry:            registry,
		RequireMachineKeyID: *cfg.Security.RequireMachineKeyID,
		ServiceName:         cfg.Logging.Service,
		Version:             cfg.Logging.Version,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("build ingest service: %w", err)
	}

	handler := api.NewIngestHandler(ingestSvc, cfg.Security.MaxBodyBytes)
	router := handler.Router()

	if *cfg.Security.EnableIPAllowList {
		mw, err := api.IPAllowListMiddleware(cfg.Security.TrustedCIDRs)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("configure ip allow list: %w", err)
		}
		router = mw(router)
	}
	if *cfg.Security.EnableBearerAuth {
		router = api.BearerAuthMiddleware(cfg.Security.BearerToken)(router)
	}

	env := logging.Environment{
		Service: cfg.Logging.Service,
		Version: cfg.Logging.Version,
		Commit:  cfg.Logging.Commit,
		Region:  cfg.Logging.Region,
	}
	root := logging.Middleware(logger, env)(router)

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           root,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	return &IngestApplication{Server: server, Store: store}, nil
}

func (a *IngestApplication) Shutdown(ctx context.Context) error {
	defer a.Store.Close()
	return a.Server.Shutdown(ctx)
}
